package handlers

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"

	"github.com/babs/mcp-auth-proxy/token"
)

// idpRefreshMaxBody caps how much of an IdP token response is read. A
// token response is a few KB; the cap only stops a misbehaving endpoint
// from streaming an unbounded body into memory.
const idpRefreshMaxBody = 1 << 20

// idpRefreshKind classifies a failed refresh_token grant by what the
// caller should do with the client's code or refresh token.
type idpRefreshKind int

const (
	// idpRefreshUnavailable: the IdP most likely did not process the
	// grant, so the client's token is released for a retry. A timeout
	// after the request went out is the one case where the IdP may have
	// rotated its refresh token anyway; an IdP that revokes on reuse
	// then ends the session at the retry.
	idpRefreshUnavailable idpRefreshKind = iota
	// idpRefreshRejected: the IdP refused the grant itself; the IdP
	// session is gone and the user has to sign in again.
	idpRefreshRejected
	// idpRefreshFailed: an error that waiting will not clear, or a 2xx
	// without a usable access token, after which the IdP has probably
	// rotated its refresh token already. The client's token stays spent.
	// The classification itself is the switch in do().
	idpRefreshFailed
)

func (k idpRefreshKind) String() string {
	switch k {
	case idpRefreshRejected:
		return "rejected"
	case idpRefreshFailed:
		return "failed"
	default:
		return "unavailable"
	}
}

// idpRejectedCodes are the IdP error codes that mean "this refresh
// token will not work again": the user has to sign in. invalid_scope is
// in the set because the usual cause is an operator who changed
// OIDC_EXTRA_SCOPES: a new sign-in collects consent for the new list.
var idpRejectedCodes = map[string]struct{}{
	"invalid_grant":        {},
	"interaction_required": {},
	"login_required":       {},
	"consent_required":     {},
	"invalid_scope":        {},
}

// idpClientAuthCodes blame the proxy's own client credentials. The IdP
// rejects those before it looks at the grant, so the refresh token is
// intact: classified unavailable, so sessions survive until the operator
// fixes OIDC_CLIENT_SECRET instead of every user being signed out.
var idpClientAuthCodes = map[string]struct{}{
	"invalid_client":      {},
	"unauthorized_client": {},
}

// idpTransientCodes are RFC 6749 §4.1.2.1 codes an IdP uses for "try
// again". Honoured on a 4xx: a 5xx is unavailable anyway, a 3xx or a
// 2xx is failed whatever its body.
var idpTransientCodes = map[string]struct{}{
	"temporarily_unavailable": {},
	"server_error":            {},
}

// idpClientAuthRetryAfter paces clients while the proxy's own client
// credentials are refused: only an operator fix clears it.
const idpClientAuthRetryAfter = 60 * time.Second

// idpMaxInFlight bounds concurrent refresh calls, so a hanging IdP
// cannot hold one goroutine and socket per refreshing client. A call
// over the bound fails at once WITHOUT reaching the IdP: queueing it
// would send the grant late and lose the answer to the deadline.
const idpMaxInFlight = 64

// idpTokens is the IdP's answer to a refresh_token grant.
type idpTokens struct {
	AccessToken string
	// RefreshToken is empty when the IdP did not rotate the refresh
	// token (RFC 6749 §6 makes rotation optional); the caller keeps
	// the one it sent.
	RefreshToken string
	// IDToken is the raw, UNVERIFIED id_token, when the IdP returned
	// one. The caller must verify it before trusting any claim.
	IDToken string
	// ExpiresAt comes from expires_in, capped by the access token's own
	// `exp` when the token is a JWT. Zero when neither is available.
	ExpiresAt time.Time
}

// idpRefreshError describes a failed refresh_token grant. The message
// carries the IdP's error code and status only: its error_description is
// free text an IdP may fill with the grant it was sent.
type idpRefreshError struct {
	Kind   idpRefreshKind
	Code   string
	Status int
	// RetryAfter is the wait the IdP's answer asks for; zero when none.
	RetryAfter time.Duration
	Err        error
}

func (e *idpRefreshError) Error() string {
	msg := "idp refresh " + e.Kind.String()
	if e.Status != 0 {
		msg += fmt.Sprintf(" (status %d)", e.Status)
	}
	if e.Code != "" {
		msg += ": " + e.Code
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *idpRefreshError) Unwrap() error { return e.Err }

// IdPRefresher runs the OAuth 2.0 refresh_token grant (RFC 6749 §6)
// against the IdP token endpoint, always with an explicit scope.
//
// The scope is mandatory: without it some IdPs (Entra ID) pick the new
// access token's audience themselves, and oauth2.TokenSource cannot
// send one.
//
// AutoDetect (what go-oidc's Endpoint() yields) tries HTTP Basic, then
// form parameters on a 4xx that is neither a refusal of the grant nor a
// 429. The style
// is remembered only once the IdP has accepted the client credentials.
type IdPRefresher struct {
	clientID     string
	clientSecret string
	tokenURL     string
	authStyle    oauth2.AuthStyle
	scope        string
	timeout      time.Duration
	client       *http.Client
	inFlight     chan struct{}
	// detected caches the style AutoDetect settled on (0 = not yet).
	detected atomic.Int32
}

// NewIdPRefresher builds a refresher from the proxy's OIDC client
// configuration; scopes are cfg.Scopes. timeout bounds one Refresh,
// both auth-style attempts included.
func NewIdPRefresher(cfg *oauth2.Config, timeout time.Duration) *IdPRefresher {
	return &IdPRefresher{
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		tokenURL:     cfg.Endpoint.TokenURL,
		authStyle:    cfg.Endpoint.AuthStyle,
		scope:        strings.Join(cfg.Scopes, " "),
		timeout:      timeout,
		inFlight:     make(chan struct{}, idpMaxInFlight),
		client: &http.Client{
			// A token endpoint has no reason to redirect, and following
			// a 307 would re-POST the refresh token and the client
			// secret to whatever host the Location names.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Refresh redeems refreshToken. The error is always an *idpRefreshError.
func (r *IdPRefresher) Refresh(ctx context.Context, refreshToken string) (*idpTokens, error) {
	select {
	case r.inFlight <- struct{}{}:
		defer func() { <-r.inFlight }()
	default:
		return nil, &idpRefreshError{Kind: idpRefreshUnavailable, Err: errors.New("too many refresh calls in flight")}
	}
	// One deadline for the whole call, so the AutoDetect fallback cannot
	// double the time a client waits.
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	style := r.authStyle
	if style == oauth2.AuthStyleAutoDetect {
		style = oauth2.AuthStyle(r.detected.Load())
	}
	if style != oauth2.AuthStyleAutoDetect {
		return r.do(ctx, refreshToken, style)
	}

	tokens, err := r.do(ctx, refreshToken, oauth2.AuthStyleInHeader)
	if credentialsAccepted(err) {
		r.detected.Store(int32(oauth2.AuthStyleInHeader))
		return tokens, err
	}
	if !retryOtherStyle(err) {
		return tokens, err
	}
	tokens, err = r.do(ctx, refreshToken, oauth2.AuthStyleInParams)
	if credentialsAccepted(err) {
		r.detected.Store(int32(oauth2.AuthStyleInParams))
	}
	return tokens, err
}

// credentialsAccepted reports an answer that proves the IdP accepted
// the client credentials: success, or a refusal of the grant itself.
func credentialsAccepted(err error) bool {
	var re *idpRefreshError
	return err == nil || (errors.As(err, &re) && re.Kind == idpRefreshRejected)
}

// retryOtherStyle reports a 4xx that may be the IdP refusing this auth
// style (invalid_client, a 401, or a 400 such as "client_id missing").
// Only called once credentialsAccepted has ruled out a refusal of the
// grant. A 4xx means the IdP did not process the grant, so resending the same
// refresh token with the other style is safe. Never on a 5xx, a
// transport error or a 2xx, where the token may already have been used.
func retryOtherStyle(err error) bool {
	var re *idpRefreshError
	if !errors.As(err, &re) {
		return false
	}
	return re.Status >= 400 && re.Status < 500 && re.Status != http.StatusTooManyRequests
}

func (r *IdPRefresher) do(ctx context.Context, refreshToken string, style oauth2.AuthStyle) (*idpTokens, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"scope":         {r.scope},
	}
	if style == oauth2.AuthStyleInParams {
		form.Set("client_id", r.clientID)
		form.Set("client_secret", r.clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &idpRefreshError{Kind: idpRefreshFailed, Err: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if style == oauth2.AuthStyleInHeader {
		// RFC 6749 §2.3.1: form-encode both halves before Basic.
		req.SetBasicAuth(url.QueryEscape(r.clientID), url.QueryEscape(r.clientSecret))
	}

	start := time.Now()
	resp, err := r.client.Do(req)
	if err != nil {
		// A transport error can embed the request URL but never the
		// body, so the refresh token cannot leak through it.
		return nil, &idpRefreshError{Kind: idpRefreshUnavailable, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, idpRefreshMaxBody))
	if err != nil {
		// After a 2xx the IdP has processed the grant and probably
		// rotated its refresh token: retrying with the old one could
		// trip reuse detection at the IdP, so the token stays spent.
		kind := idpRefreshUnavailable
		if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
			kind = idpRefreshFailed
		}
		return nil, &idpRefreshError{Kind: kind, Status: resp.StatusCode, Err: fmt.Errorf("read response: %w", err)}
	}

	var body idpTokenResponse
	parseErr := json.Unmarshal(raw, &body)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// A mistyped sibling field still leaves body.Error filled.
		var typeErr *json.UnmarshalTypeError
		code := ""
		if parseErr == nil || errors.As(parseErr, &typeErr) {
			code = sanitizeErrorDescription(r.redact(body.Error, refreshToken))
		}
		return nil, classifyIdPError(resp.StatusCode, code, resp.Header)
	}
	if isObject := bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")); parseErr != nil || !isObject {
		// A 2xx that is not a JSON object did not come from a token
		// endpoint. A malformed object did: the grant was processed.
		kind := idpRefreshUnavailable
		if isObject {
			kind = idpRefreshFailed
		}
		return nil, &idpRefreshError{Kind: kind, Status: resp.StatusCode, Err: errors.New("malformed token response")}
	}
	return body.tokens(resp.StatusCode, start)
}

// idpTokenResponse is the token endpoint's JSON, success or error.
type idpTokenResponse struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	RefreshToken string          `json:"refresh_token"`
	IDToken      string          `json:"id_token"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
	Error        string          `json:"error"`
}

// classifyIdPError classifies a non-2xx answer by what the caller should
// do with the client's token. code is the IdP's `error`, "" when absent.
func classifyIdPError(status int, code string, h http.Header) *idpRefreshError {
	e := &idpRefreshError{Status: status, Code: code}
	_, rejected := idpRejectedCodes[code]
	_, clientAuth := idpClientAuthCodes[code]
	_, transient := idpTransientCodes[code]
	switch {
	case status >= 300 && status < 400:
		// Never followed (CheckRedirect), so the IdP never saw the
		// grant. Paced long: a redirecting token URL or a maintenance
		// redirect does not clear in seconds.
		e.Kind = idpRefreshUnavailable
		e.RetryAfter = idpClientAuthRetryAfter
	// RFC 6749 §5.2 puts grant errors on 400 (401 for client
	// authentication); a 5xx is an outage whatever its body says.
	case status >= 500 || status == http.StatusTooManyRequests || transient:
		e.Kind = idpRefreshUnavailable
		e.RetryAfter = retryAfterSeconds(h)
	case rejected:
		e.Kind = idpRefreshRejected
	case status == http.StatusUnauthorized || clientAuth:
		e.Kind = idpRefreshUnavailable
		e.RetryAfter = idpClientAuthRetryAfter
	case code == "":
		// No OAuth error member: something in front of the token
		// endpoint answered (maintenance page, WAF, ingress), so the
		// IdP never saw the grant. Paced like a client-auth failure:
		// a 404 or a WAF block does not clear in seconds.
		e.Kind = idpRefreshUnavailable
		e.RetryAfter = idpClientAuthRetryAfter
	default:
		e.Kind = idpRefreshFailed
	}
	return e
}

// tokens turns a 2xx answer into idpTokens. Every refusal here is
// failed: the IdP processed the grant, so the client's token is spent.
// start is when the request went out.
func (b *idpTokenResponse) tokens(status int, start time.Time) (*idpTokens, error) {
	if b.AccessToken == "" {
		return nil, &idpRefreshError{Kind: idpRefreshFailed, Status: status, Err: errors.New("response has no access_token")}
	}
	if b.TokenType != "" && !strings.EqualFold(b.TokenType, "bearer") {
		// Forwarded as `Authorization: Bearer`; a DPoP- or MAC-bound
		// token would be refused upstream, so fail where it is visible.
		return nil, &idpRefreshError{Kind: idpRefreshFailed, Status: status, Err: fmt.Errorf("unsupported token_type %q", sanitizeErrorDescription(b.TokenType))}
	}
	tokens := &idpTokens{AccessToken: b.AccessToken, RefreshToken: b.RefreshToken, IDToken: b.IDToken}
	if secs, ok := parseExpiresIn(b.ExpiresIn); ok {
		if secs <= 0 {
			return nil, &idpRefreshError{Kind: idpRefreshFailed, Status: status, Err: errors.New("access token already expired (expires_in <= 0)")}
		}
		// Measured from before the request went out, so network time
		// shortens the lifetime instead of stretching it.
		tokens.ExpiresAt = start.Add(time.Duration(secs) * time.Second)
	}
	// A JWT access token states its own expiry. Used as an upper bound,
	// and as the only bound when the IdP sent no expires_in — the proxy
	// token must never outlive what it forwards. Read unverified: the
	// value can only shorten the proxy token, never extend it.
	if exp, ok := jwtExpiry(b.AccessToken); ok && (tokens.ExpiresAt.IsZero() || exp.Before(tokens.ExpiresAt)) {
		tokens.ExpiresAt = exp
	}
	return tokens, nil
}

// forSealing returns what the new proxy tokens carry: the IdP access
// token, and the IdP refresh token to keep (RFC 6749 §6: the IdP may
// not rotate the one it was sent). Zero values on a nil receiver, which
// is what redeemIdPRefresh returns with forwarding off.
func (t *idpTokens) forSealing(sentRefreshToken string) (token.IdPToken, string) {
	if t == nil {
		return token.IdPToken{}, ""
	}
	return token.IdPToken{AccessToken: t.AccessToken, ExpiresAt: t.ExpiresAt}, cmp.Or(t.RefreshToken, sentRefreshToken)
}

// redact removes the refresh token and the client secret from the error
// code the IdP sent back, which reaches the proxy's logs.
func (r *IdPRefresher) redact(s, refreshToken string) string {
	for _, secret := range []string{refreshToken, r.clientSecret} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "[redacted]")
		}
	}
	return s
}

// jwtExpiry returns the `exp` claim of a JWS compact token without
// verifying it; ok is false for anything that is not one.
func jwtExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == "" {
		return time.Time{}, false
	}
	secs, err := claims.Exp.Int64()
	if err != nil {
		f, ferr := claims.Exp.Float64()
		if ferr != nil {
			return time.Time{}, false
		}
		secs = int64(f) // out of range lands outside (0, jwtExpMax] on every platform
	}
	// Above jwtExpMax time.Unix wraps into the past: read as "not stated".
	if secs <= 0 || secs > jwtExpMax {
		return time.Time{}, false
	}
	return time.Unix(secs, 0), true
}

// parseExpiresIn accepts expires_in as a JSON number or a numeric
// string — both appear in the wild. ok is false when it is absent, null
// or unparsable ("not stated"); a stated value may be zero or negative.
func parseExpiresIn(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	s := strings.Trim(string(raw), `"`)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		f, ferr := strconv.ParseFloat(s, 64)
		if ferr != nil || f != f { // f != f: NaN
			return 0, false
		}
		// Clamped before the conversion: int64(1e30) is not portable.
		n = int64(max(min(f, maxExpiresInSeconds), -1))
	}
	// Clamp so the Duration multiplication cannot overflow; the proxy
	// caps its own token at an hour anyway.
	return min(n, maxExpiresInSeconds), true
}

// retryAfterSeconds reads a delay-seconds Retry-After; zero when absent
// or in HTTP-date form.
func retryAfterSeconds(h http.Header) time.Duration {
	n, err := strconv.Atoi(h.Get("Retry-After"))
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(min(n, maxExpiresInSeconds)) * time.Second
}

// jwtExpMax is the largest `exp` jwtExpiry accepts (about year 36812).
const jwtExpMax = 1 << 40

// maxExpiresInSeconds bounds a stated IdP token lifetime (one year).
const maxExpiresInSeconds = 365 * 24 * 3600
