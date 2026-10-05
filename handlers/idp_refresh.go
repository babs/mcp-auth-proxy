package handlers

import (
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
)

// idpRefreshMaxBody caps how much of an IdP token response is read. A
// token response is a few KB; the cap only stops a misbehaving endpoint
// from streaming an unbounded body into memory.
const idpRefreshMaxBody = 1 << 20

// IdPRefreshKind classifies a failed refresh_token grant by what the
// caller should do with the client's code or refresh token.
type IdPRefreshKind int

const (
	// IdPRefreshUnavailable: the IdP most likely did not process the
	// grant (transport error, timeout, 5xx, 429) or refused the proxy's
	// own client credentials, so the client's token is released for a
	// retry. A timeout after the request went out is the one case where
	// the IdP may have rotated its refresh token anyway; an IdP that
	// revokes on reuse then ends the session at the retry, the same
	// outcome a sign-in would have had.
	IdPRefreshUnavailable IdPRefreshKind = iota
	// IdPRefreshRejected: the IdP refused the grant itself; the IdP
	// session is gone and the user has to sign in again.
	IdPRefreshRejected
	// IdPRefreshFailed: an error that waiting will not clear — a
	// permanent 4xx, or a 2xx without a usable access token. After a
	// 2xx the IdP has probably rotated its refresh token already, so
	// retrying with the old one would trip reuse detection at IdPs that
	// revoke on reuse. The client's token stays spent.
	IdPRefreshFailed
)

func (k IdPRefreshKind) String() string {
	switch k {
	case IdPRefreshRejected:
		return "rejected"
	case IdPRefreshFailed:
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

// IdPTokens is the IdP's answer to a refresh_token grant.
type IdPTokens struct {
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

// IdPRefreshError describes a failed refresh_token grant. The message
// carries the IdP's error code, status and description (with the
// refresh token redacted), never a token.
type IdPRefreshError struct {
	Kind   IdPRefreshKind
	Code   string
	Status int
	Err    error
}

func (e *IdPRefreshError) Error() string {
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

func (e *IdPRefreshError) Unwrap() error { return e.Err }

// IdPRefresher runs the OAuth 2.0 refresh_token grant (RFC 6749 §6)
// against the IdP token endpoint, always with an explicit scope.
//
// Hand-written rather than oauth2.TokenSource because x/oauth2 cannot
// add a scope to a refresh request, and without one some IdPs (Entra
// ID among them) pick the audience of the new access token themselves:
// the upstream would then receive a token minted for another API.
//
// Client authentication follows the endpoint's AuthStyle like x/oauth2
// does. AutoDetect (what go-oidc's Endpoint() yields) tries HTTP Basic
// first and falls back to form parameters when the IdP answers with any
// 4xx that is not a refusal of the grant itself; the style is
// remembered only once a call succeeds or the IdP refuses the grant,
// since both prove it accepted the client credentials.
type IdPRefresher struct {
	clientID     string
	clientSecret string
	tokenURL     string
	authStyle    oauth2.AuthStyle
	scope        string
	timeout      time.Duration
	client       *http.Client
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

// Refresh redeems refreshToken. The error is always an *IdPRefreshError.
func (r *IdPRefresher) Refresh(ctx context.Context, refreshToken string) (*IdPTokens, error) {
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
	var re *IdPRefreshError
	return err == nil || (errors.As(err, &re) && re.Kind == IdPRefreshRejected)
}

// retryOtherStyle reports a 4xx that may be the IdP refusing this auth
// style (invalid_client, a 401, or a 400 such as "client_id missing").
// A 4xx means the IdP did not process the grant, so resending the same
// refresh token with the other style is safe. Never on a 5xx, a
// transport error or a 2xx, where the token may already have been used.
func retryOtherStyle(err error) bool {
	var re *IdPRefreshError
	if !errors.As(err, &re) || re.Kind == IdPRefreshRejected {
		return false
	}
	return re.Status >= 400 && re.Status < 500 && re.Status != http.StatusTooManyRequests
}

func (r *IdPRefresher) do(ctx context.Context, refreshToken string, style oauth2.AuthStyle) (*IdPTokens, error) {
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
		return nil, &IdPRefreshError{Kind: IdPRefreshFailed, Err: err}
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
		return nil, &IdPRefreshError{Kind: IdPRefreshUnavailable, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, idpRefreshMaxBody))
	if err != nil {
		// After a 2xx the IdP has processed the grant and probably
		// rotated its refresh token: retrying with the old one could
		// trip reuse detection at the IdP, so the token stays spent.
		kind := IdPRefreshUnavailable
		if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
			kind = IdPRefreshFailed
		}
		return nil, &IdPRefreshError{Kind: kind, Status: resp.StatusCode, Err: fmt.Errorf("read response: %w", err)}
	}

	var body struct {
		AccessToken      string          `json:"access_token"`
		TokenType        string          `json:"token_type"`
		RefreshToken     string          `json:"refresh_token"`
		IDToken          string          `json:"id_token"`
		ExpiresIn        json.RawMessage `json:"expires_in"`
		Error            string          `json:"error"`
		ErrorDescription string          `json:"error_description"`
	}
	parseErr := json.Unmarshal(raw, &body)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &IdPRefreshError{Status: resp.StatusCode}
		if parseErr == nil && body.Error != "" {
			e.Code = sanitizeErrorDescription(r.redact(body.Error, refreshToken))
			if d := sanitizeErrorDescription(r.redact(body.ErrorDescription, refreshToken)); d != "" {
				e.Err = errors.New(d)
			}
		}
		_, rejected := idpRejectedCodes[e.Code]
		_, clientAuth := idpClientAuthCodes[e.Code]
		switch {
		// RFC 6749 §5.2 puts grant errors on 400 (401 for client
		// authentication); a 5xx is an outage whatever its body says.
		case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
			e.Kind = IdPRefreshUnavailable
		case resp.StatusCode >= 400 && rejected:
			e.Kind = IdPRefreshRejected
		case resp.StatusCode == http.StatusUnauthorized || clientAuth:
			e.Kind = IdPRefreshUnavailable
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			// A redirect means the grant never reached a token endpoint.
			e.Kind = IdPRefreshUnavailable
		default:
			e.Kind = IdPRefreshFailed
		}
		return nil, e
	}
	if parseErr != nil {
		return nil, &IdPRefreshError{Kind: IdPRefreshFailed, Status: resp.StatusCode, Err: fmt.Errorf("decode response: %w", parseErr)}
	}
	if body.AccessToken == "" {
		return nil, &IdPRefreshError{Kind: IdPRefreshFailed, Status: resp.StatusCode, Err: errors.New("response has no access_token")}
	}
	if body.TokenType != "" && !strings.EqualFold(body.TokenType, "bearer") {
		// Forwarded as `Authorization: Bearer`; a DPoP- or MAC-bound
		// token would be refused upstream, so fail where it is visible.
		return nil, &IdPRefreshError{Kind: IdPRefreshFailed, Status: resp.StatusCode, Err: fmt.Errorf("unsupported token_type %q", sanitizeErrorDescription(body.TokenType))}
	}

	tokens := &IdPTokens{
		AccessToken:  body.AccessToken,
		RefreshToken: body.RefreshToken,
		IDToken:      body.IDToken,
	}
	if secs, ok := parseExpiresIn(body.ExpiresIn); ok {
		// Measured from before the request went out, so network time
		// shortens the lifetime instead of stretching it.
		tokens.ExpiresAt = start.Add(time.Duration(secs) * time.Second)
	}
	// A JWT access token states its own expiry. Used as an upper bound,
	// and as the only bound when the IdP sent no expires_in — the proxy
	// token must never outlive what it forwards. Read unverified: the
	// value can only shorten the proxy token, never extend it.
	if exp, ok := jwtExpiry(body.AccessToken); ok && (tokens.ExpiresAt.IsZero() || exp.Before(tokens.ExpiresAt)) {
		tokens.ExpiresAt = exp
	}
	return tokens, nil
}

// redact removes the refresh token and the client secret from text the
// IdP chose to send back (an IdP that echoes the grant in its error
// description would otherwise leak both into the proxy's logs).
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
		secs = int64(f)
	}
	if secs <= 0 {
		return time.Time{}, false
	}
	return time.Unix(secs, 0), true
}

// parseExpiresIn accepts expires_in as a JSON number or a numeric
// string — both appear in the wild. Non-positive or unparsable values
// read as "not stated".
func parseExpiresIn(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	s := strings.Trim(string(raw), `"`)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		f, ferr := strconv.ParseFloat(s, 64)
		if ferr != nil {
			return 0, false
		}
		n = int64(f)
	}
	if n <= 0 {
		return 0, false
	}
	// Clamp so the Duration multiplication cannot overflow; the proxy
	// caps its own token at an hour anyway.
	return min(n, maxExpiresInSeconds), true
}

// maxExpiresInSeconds bounds a stated IdP token lifetime (one year).
const maxExpiresInSeconds = 365 * 24 * 3600
