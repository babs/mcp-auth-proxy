package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	"github.com/babs/mcp-auth-proxy/replay"
	"github.com/babs/mcp-auth-proxy/token"
)

const (
	fwdRedirectURI = "https://app.example.com/callback"
	fwdVerifier    = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	fwdIdPRT       = "idp-refresh-token-original"
	fwdIdPAT       = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJhcGk6Ly91cHN0cmVhbSJ9.c2lnbmF0dXJl"
	fwdIdPRTNext   = "idp-refresh-token-rotated"
)

// forwardingCallback drives /authorize then /callback against a fake IdP
// token endpoint answering with idpResponse, and returns the /callback
// response.
func forwardingCallback(t *testing.T, tm *token.Manager, idpResponse map[string]any, forward bool, logger ...*zap.Logger) *httptest.ResponseRecorder {
	t.Helper()
	encClientID, _ := registerClient(t, tm, []string{fwdRedirectURI})
	oauth2Cfg := testOAuth2Config()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {fwdRedirectURI},
		"code_challenge":        {pkceChallenge(fwdVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state"},
	}
	rr := httptest.NewRecorder()
	Authorize(tm, zap.NewNop(), testBaseURL, oauth2Cfg, AuthorizeConfig{PKCERequired: true})(
		rr, httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d: %s", rr.Code, rr.Body.String())
	}
	idpURL, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse IdP Location: %v", err)
	}
	state := idpURL.Query().Get("state")
	nonce := idpURL.Query().Get("nonce")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(idpResponse)
	}))
	t.Cleanup(upstream.Close)
	oauth2Cfg.Endpoint.TokenURL = upstream.URL + "/token"

	claims, _ := json.Marshal(map[string]any{"sub": "user-sub", "email": "user@example.com", "nonce": nonce})
	verify := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		tok := &oidc.IDToken{Subject: "user-sub", Nonce: nonce}
		setIDTokenClaims(t, tok, claims)
		return tok, nil
	}

	log := zap.NewNop()
	if len(logger) > 0 {
		log = logger[0]
	}
	cbRR := httptest.NewRecorder()
	CallbackWithVerifyFunc(tm, log, testBaseURL, oauth2Cfg, verify, CallbackConfig{ForwardIdPToken: forward})(
		cbRR, httptest.NewRequest(http.MethodGet, "/callback?code=fake&state="+url.QueryEscape(state), nil))
	return cbRR
}

func codeFromRedirect(t *testing.T, tm *token.Manager, rr *httptest.ResponseRecorder) sealedCode {
	t.Helper()
	if rr.Code != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d: %s", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	var sc sealedCode
	if err := tm.OpenJSON(loc.Query().Get("code"), &sc, token.PurposeCode); err != nil {
		t.Fatalf("open code: %v", err)
	}
	return sc
}

func TestCallback_Forwarding_SealsIdPRefreshTokenIntoCode(t *testing.T) {
	tm := newTestTokenManager(t)
	rr := forwardingCallback(t, tm, map[string]any{
		"access_token": "callback-at", "token_type": "Bearer", "id_token": "dummy", "refresh_token": fwdIdPRT,
	}, true)

	sc := codeFromRedirect(t, tm, rr)
	if sc.IdPRefreshToken != fwdIdPRT {
		t.Errorf("code IdPRefreshToken = %q, want the IdP refresh token", sc.IdPRefreshToken)
	}
	if loc := rr.Header().Get("Location"); strings.Contains(loc, fwdIdPRT) || strings.Contains(loc, "callback-at") {
		t.Errorf("redirect URL carries an IdP token in clear: %s", loc)
	}
}

func TestCallback_Forwarding_MissingRefreshTokenFailsSignIn(t *testing.T) {
	tm := newTestTokenManager(t)
	rr := forwardingCallback(t, tm, map[string]any{
		"access_token": "callback-at", "token_type": "Bearer", "id_token": "dummy",
	}, true)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Errorf("a code was issued anyway: %s", loc)
	}
	var body OAuthError
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body.Error != "server_error" || body.ErrorCode != codeIdPRefreshTokenMissing {
		t.Errorf("body = %+v, want server_error / %s", body, codeIdPRefreshTokenMissing)
	}
}

// Default mode must keep dropping the IdP refresh token: nothing new
// rides in the code unless the operator opted in.
func TestCallback_DefaultMode_DropsIdPRefreshToken(t *testing.T) {
	tm := newTestTokenManager(t)
	rr := forwardingCallback(t, tm, map[string]any{
		"access_token": "callback-at", "token_type": "Bearer", "id_token": "dummy", "refresh_token": fwdIdPRT,
	}, false)

	sc := codeFromRedirect(t, tm, rr)
	if sc.IdPRefreshToken != "" {
		t.Errorf("default mode sealed the IdP refresh token into the code")
	}
}

// fakeIdP is a token endpoint for the refresh_token grant whose answer
// the test can switch between calls.
type fakeIdP struct {
	srv      *httptest.Server
	calls    atomic.Int32
	lastForm atomic.Value // url.Values
	respond  atomic.Value // func(http.ResponseWriter)
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	f := &fakeIdP{}
	f.succeed(fwdIdPAT, fwdIdPRTNext, 3600)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		_ = r.ParseForm()
		f.lastForm.Store(r.PostForm)
		f.respond.Load().(func(http.ResponseWriter))(w)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) succeed(at, rt string, expiresIn int) {
	f.respond.Store(func(w http.ResponseWriter) {
		body := map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": expiresIn}
		if rt != "" {
			body["refresh_token"] = rt
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
}

func (f *fakeIdP) fail(status int, code string) {
	f.respond.Store(func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
	})
}

func (f *fakeIdP) refresher() *IdPRefresher {
	cfg := testOAuth2Config()
	cfg.Endpoint = oauth2.Endpoint{TokenURL: f.srv.URL, AuthStyle: oauth2.AuthStyleInParams}
	cfg.Scopes = []string{"openid", "email", "profile", "api://upstream-app/access_as_user"}
	return NewIdPRefresher(cfg, 5*time.Second)
}

// sealForwardingCode mints a code as /callback does in forwarding mode.
func sealForwardingCode(t *testing.T, tm *token.Manager, clientUUID, idpRT string) string {
	t.Helper()
	sc := sealedCode{
		TokenID:         uuid.New().String(),
		FamilyID:        uuid.New().String(),
		ClientID:        clientUUID,
		RedirectURI:     fwdRedirectURI,
		CodeChallenge:   pkceChallenge(fwdVerifier),
		Subject:         "user-sub",
		Email:           "user@example.com",
		Groups:          []string{"staff"},
		Typ:             token.PurposeCode,
		Audience:        testBaseURL,
		ExpiresAt:       time.Now().Add(time.Minute),
		IdPRefreshToken: idpRT,
	}
	code, err := tm.SealJSON(sc, token.PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	return code
}

func postCodeGrant(t *testing.T, h http.HandlerFunc, encClientID, code string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {fwdRedirectURI},
		"client_id":     {encClientID},
		"code_verifier": {fwdVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func forwardingTokenHandler(tm *token.Manager, logger *zap.Logger, store replay.Store, idp *fakeIdP, limiter *rate.Limiter, allowedGroups ...string) http.HandlerFunc {
	return Token(tm, logger, testBaseURL, time.Time{}, store, TokenConfig{
		ForwardIdPToken:    true,
		IdPRefresher:       idp.refresher(),
		IdPExchangeLimiter: limiter,
		VerifyIDToken:      fakeVerifyIDToken,
		GroupsClaim:        "groups",
		AllowedGroups:      allowedGroups,
	})
}

// fakeIDToken encodes claims as a stand-in id_token that
// fakeVerifyIDToken accepts. A value without the prefix fails
// verification, like a forged or foreign token would.
func fakeIDToken(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return "fake-idt:" + string(b)
}

func fakeVerifyIDToken(_ context.Context, raw string) (*oidc.IDToken, error) {
	body, ok := strings.CutPrefix(raw, "fake-idt:")
	if !ok {
		return nil, errors.New("signature verification failed")
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal([]byte(body), &claims); err != nil {
		return nil, err
	}
	tok := &oidc.IDToken{Subject: claims.Sub}
	v := reflect.ValueOf(tok).Elem().FieldByName("claims")
	// #nosec G103 -- test-only, same technique as setIDTokenClaims.
	reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().SetBytes([]byte(body))
	return tok, nil
}

func decodeTokenResponse(t *testing.T, rr *httptest.ResponseRecorder) (accessToken, refreshToken string, expiresIn int) {
	t.Helper()
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode token response: %v (%s)", err, rr.Body.String())
	}
	return body.AccessToken, body.RefreshToken, body.ExpiresIn
}

func oauthErrorOf(t *testing.T, rr *httptest.ResponseRecorder) OAuthError {
	t.Helper()
	var body OAuthError
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v (%s)", err, rr.Body.String())
	}
	return body
}

func TestToken_Forwarding_CodeGrantRedeemsIdPRefreshToken(t *testing.T) {
	tm := newTestTokenManager(t)
	tm.SetMaxSealedLen(token.PurposeAccess, token.ForwardingMaxSealedLen)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	idp := newFakeIdP(t)
	idp.succeed(fwdIdPAT, fwdIdPRTNext, 1800)

	rr := postCodeGrant(t, forwardingTokenHandler(tm, zap.NewNop(), replay.NewMemoryStore(), idp, nil), encClientID, sealForwardingCode(t, tm, clientUUID, fwdIdPRT))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	form := idp.lastForm.Load().(url.Values)
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != fwdIdPRT {
		t.Errorf("IdP received %v, want the sealed refresh token on a refresh_token grant", form)
	}
	if form.Get("scope") != "openid email profile api://upstream-app/access_as_user" {
		t.Errorf("IdP scope = %q, want the explicit configured list", form.Get("scope"))
	}

	at, rt, expiresIn := decodeTokenResponse(t, rr)
	// IdP token lives 30 min; the proxy token must stop a minute earlier.
	if expiresIn > 29*60 || expiresIn < 29*60-5 {
		t.Errorf("expires_in = %d, want ~%d (IdP lifetime minus 60 s)", expiresIn, 29*60)
	}
	claims, err := tm.Validate(at)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.IdPAccessToken != fwdIdPAT {
		t.Errorf("access token does not carry the IdP access token")
	}
	var sr sealedRefresh
	if err := tm.OpenJSON(rt, &sr, token.PurposeRefresh); err != nil {
		t.Fatalf("open refresh: %v", err)
	}
	if sr.IdPRefreshToken != fwdIdPRTNext {
		t.Errorf("refresh token carries %q, want the rotated IdP refresh token", sr.IdPRefreshToken)
	}
	for _, secret := range []string{fwdIdPAT, fwdIdPRT, fwdIdPRTNext} {
		if strings.Contains(rr.Body.String(), secret) {
			t.Errorf("token response carries an IdP token in clear")
		}
	}
}

func TestToken_Forwarding_KeepsIdPRefreshTokenWhenNotRotated(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	idp := newFakeIdP(t)
	idp.succeed(fwdIdPAT, "", 7200)

	rr := postCodeGrant(t, forwardingTokenHandler(tm, zap.NewNop(), nil, idp, nil), encClientID, sealForwardingCode(t, tm, clientUUID, fwdIdPRT))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	_, rt, expiresIn := decodeTokenResponse(t, rr)
	if expiresIn > 3600 || expiresIn < 3595 {
		t.Errorf("expires_in = %d, want ~3600 (ttl shorter than IdP lifetime minus skew)", expiresIn)
	}
	var sr sealedRefresh
	if err := tm.OpenJSON(rt, &sr, token.PurposeRefresh); err != nil {
		t.Fatal(err)
	}
	if sr.IdPRefreshToken != fwdIdPRT {
		t.Errorf("refresh token carries %q, want the unchanged IdP refresh token", sr.IdPRefreshToken)
	}
}

// The IdP refused the grant: the user must sign in again, and the code
// stays spent.
func TestToken_Forwarding_IdPRejectionKeepsCodeSpent(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	idp := newFakeIdP(t)
	idp.fail(http.StatusBadRequest, "invalid_grant")
	store := replay.NewMemoryStore()
	defer func() { _ = store.Close() }()
	h := forwardingTokenHandler(tm, zap.NewNop(), store, idp, nil)
	code := sealForwardingCode(t, tm, clientUUID, fwdIdPRT)

	rr := postCodeGrant(t, h, encClientID, code)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if body := oauthErrorOf(t, rr); body.Error != "invalid_grant" || body.ErrorCode != codeIdPRefreshRejected {
		t.Errorf("body = %+v, want invalid_grant / %s", body, codeIdPRefreshRejected)
	}

	idp.succeed(fwdIdPAT, fwdIdPRTNext, 3600)
	if again := postCodeGrant(t, h, encClientID, code); oauthErrorOf(t, again).ErrorCode != codeCodeReplay {
		t.Errorf("retry after rejection: %s, want code_replay", again.Body.String())
	}
}

// An IdP outage must not burn the code: the client retries the same one
// once the IdP is back.
func TestToken_Forwarding_IdPOutageReleasesCode(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	idp := newFakeIdP(t)
	idp.fail(http.StatusServiceUnavailable, "temporarily_unavailable")
	store := replay.NewMemoryStore()
	defer func() { _ = store.Close() }()
	h := forwardingTokenHandler(tm, zap.NewNop(), store, idp, nil)
	code := sealForwardingCode(t, tm, clientUUID, fwdIdPRT)

	rr := postCodeGrant(t, h, encClientID, code)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", rr.Code, rr.Body.String())
	}
	if body := oauthErrorOf(t, rr); body.Error != "temporarily_unavailable" || body.ErrorCode != codeIdPRefreshUnavailable {
		t.Errorf("body = %+v, want temporarily_unavailable / %s", body, codeIdPRefreshUnavailable)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("503 without Retry-After")
	}

	idp.succeed(fwdIdPAT, fwdIdPRTNext, 3600)
	if again := postCodeGrant(t, h, encClientID, code); again.Code != http.StatusOK {
		t.Fatalf("retry after outage: %d %s, want 200", again.Code, again.Body.String())
	}
}

// Throttled after the claim: the claim is released, so the same code
// works once the bucket refills (a spent claim would read as replay).
func TestToken_Forwarding_ThrottledReleasesClaim(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	idp := newFakeIdP(t)
	store := replay.NewMemoryStore()
	defer func() { _ = store.Close() }()
	code := sealForwardingCode(t, tm, clientUUID, fwdIdPRT)

	rr := postCodeGrant(t, forwardingTokenHandler(tm, zap.NewNop(), store, idp, rate.NewLimiter(0, 0)), encClientID, code)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", rr.Code, rr.Body.String())
	}
	if body := oauthErrorOf(t, rr); body.ErrorCode != codeIdPExchangeThrottled {
		t.Errorf("error_code = %q, want %s", body.ErrorCode, codeIdPExchangeThrottled)
	}
	if n := idp.calls.Load(); n != 0 {
		t.Errorf("IdP called %d times while throttled", n)
	}
	if again := postCodeGrant(t, forwardingTokenHandler(tm, zap.NewNop(), store, idp, nil), encClientID, code); again.Code != http.StatusOK {
		t.Fatalf("retry once the bucket refills: %d %s, want 200", again.Code, again.Body.String())
	}
}

// A code minted before forwarding was switched on has no IdP token to
// forward: refuse without calling the IdP and without burning the code.
func TestToken_Forwarding_PreUpgradeCode(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	idp := newFakeIdP(t)
	store := replay.NewMemoryStore()
	defer func() { _ = store.Close() }()
	h := forwardingTokenHandler(tm, zap.NewNop(), store, idp, nil)
	code := sealForwardingCode(t, tm, clientUUID, "")

	for range 2 {
		rr := postCodeGrant(t, h, encClientID, code)
		if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.ErrorCode != codeIdPTokenMissing {
			t.Fatalf("got %d %+v, want 400 %s (not code_replay on the second try)", rr.Code, body, codeIdPTokenMissing)
		}
	}
	if n := idp.calls.Load(); n != 0 {
		t.Errorf("IdP called %d times for a code without an IdP token", n)
	}
}

func TestToken_Forwarding_IdPTokenTooShortLived(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	idp := newFakeIdP(t)
	idp.succeed(fwdIdPAT, fwdIdPRTNext, 30)

	rr := postCodeGrant(t, forwardingTokenHandler(tm, zap.NewNop(), nil, idp, nil), encClientID, sealForwardingCode(t, tm, clientUUID, fwdIdPRT))
	// 400, not 500: the IdP refresh token was redeemed, the code is
	// spent, and a retry would only read as a replay.
	if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.ErrorCode != codeTokenIssueFailed {
		t.Errorf("got %d %+v, want 400 invalid_grant / %s", rr.Code, body, codeTokenIssueFailed)
	}
}

// releaseFailingStore claims normally but cannot release.
type releaseFailingStore struct{ *replay.MemoryStore }

func (s releaseFailingStore) Release(context.Context, string) error {
	return errors.New("redis: connection reset")
}

// When the claim cannot be given back, a retry would read as a replay:
// the client must not be invited to retry with the same code.
func TestToken_Forwarding_ReleaseFailureIsNotRetryable(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	idp := newFakeIdP(t)
	idp.fail(http.StatusBadGateway, "")
	mem := replay.NewMemoryStore()
	defer func() { _ = mem.Close() }()
	core, logs := observer.New(zap.ErrorLevel)

	rr := postCodeGrant(t, forwardingTokenHandler(tm, zap.New(core), releaseFailingStore{mem}, idp, nil), encClientID, sealForwardingCode(t, tm, clientUUID, fwdIdPRT))
	if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.ErrorCode != codeIdPRefreshUnavailable {
		t.Fatalf("got %d %+v, want 400 invalid_grant / %s", rr.Code, body, codeIdPRefreshUnavailable)
	}
	if ra := rr.Header().Get("Retry-After"); ra != "" {
		t.Errorf("Retry-After = %q on a non-retryable answer", ra)
	}
	if logs.FilterMessage("replay_claim_release_failed").Len() != 1 {
		t.Errorf("release failure not logged; got %v", logs.All())
	}
}

// A 2xx without a usable token: the IdP has probably rotated its refresh
// token already, so the code stays spent and no retry is invited.
func TestToken_Forwarding_UnusableIdPAnswerKeepsCodeSpent(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	idp := newFakeIdP(t)
	idp.respond.Store(func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"Bearer","refresh_token":"rotated-anyway"}`))
	})
	store := replay.NewMemoryStore()
	defer func() { _ = store.Close() }()
	h := forwardingTokenHandler(tm, zap.NewNop(), store, idp, nil)
	code := sealForwardingCode(t, tm, clientUUID, fwdIdPRT)

	rr := postCodeGrant(t, h, encClientID, code)
	if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.ErrorCode != codeIdPRefreshFailed {
		t.Fatalf("got %d %+v, want 400 invalid_grant / %s", rr.Code, body, codeIdPRefreshFailed)
	}
	if rr.Header().Get("Retry-After") != "" {
		t.Error("Retry-After on a failure waiting will not clear")
	}
	idp.succeed(fwdIdPAT, fwdIdPRTNext, 3600)
	if again := postCodeGrant(t, h, encClientID, code); oauthErrorOf(t, again).ErrorCode != codeCodeReplay {
		t.Errorf("retry: %s, want code_replay (the code stays spent)", again.Body.String())
	}
}

// Replays of a spent code are refused by the claim before they can take
// a token from the shared IdP bucket.
func TestToken_Forwarding_ReplaysDoNotDrainIdPBucket(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	idp := newFakeIdP(t)
	store := replay.NewMemoryStore()
	defer func() { _ = store.Close() }()
	h := forwardingTokenHandler(tm, zap.NewNop(), store, idp, rate.NewLimiter(0, 2))

	spent := sealForwardingCode(t, tm, clientUUID, fwdIdPRT)
	if rr := postCodeGrant(t, h, encClientID, spent); rr.Code != http.StatusOK {
		t.Fatalf("first redemption: %d %s", rr.Code, rr.Body.String())
	}
	for range 3 {
		if rr := postCodeGrant(t, h, encClientID, spent); oauthErrorOf(t, rr).ErrorCode != codeCodeReplay {
			t.Fatalf("replay: %s, want code_replay", rr.Body.String())
		}
	}
	if rr := postCodeGrant(t, h, encClientID, sealForwardingCode(t, tm, clientUUID, fwdIdPRT)); rr.Code != http.StatusOK {
		t.Errorf("fresh code after replays: %d %s, want 200 (the bucket still has a token)", rr.Code, rr.Body.String())
	}
}

// A client that hangs up during the IdP call still gets its code back:
// the release runs on a context detached from the request.
func TestToken_Forwarding_ClientHangUpReleasesCode(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	idp := newFakeIdP(t)
	reached := make(chan struct{})
	unblock := make(chan struct{})
	idp.respond.Store(func(w http.ResponseWriter) {
		close(reached)
		<-unblock
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	store := replay.NewMemoryStore()
	defer func() { _ = store.Close() }()
	h := forwardingTokenHandler(tm, zap.NewNop(), store, idp, nil)
	code := sealForwardingCode(t, tm, clientUUID, fwdIdPRT)

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {fwdRedirectURI},
		"client_id": {encClientID}, "code_verifier": {fwdVerifier},
	}
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	done := make(chan struct{})
	go func() {
		defer close(done)
		h(httptest.NewRecorder(), req)
	}()
	<-reached
	cancel()
	<-done
	close(unblock)

	idp.succeed(fwdIdPAT, fwdIdPRTNext, 3600)
	if again := postCodeGrant(t, h, encClientID, code); again.Code != http.StatusOK {
		t.Fatalf("retry after hang-up: %d %s, want 200", again.Code, again.Body.String())
	}
}

// No IdP token value may reach a log line, whatever the outcome — the
// callback included, and an IdP that echoes the grant in its errors.
func TestToken_Forwarding_NeverLogsIdPTokens(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	idp := newFakeIdP(t)
	core, logs := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	store := replay.NewMemoryStore()
	defer func() { _ = store.Close() }()
	h := forwardingTokenHandler(tm, logger, store, idp, nil)
	echo := func(status int, code string) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "grant " + fwdIdPRT + " refused"})
		}
	}

	forwardingCallback(t, tm, map[string]any{
		"access_token": "callback-at", "token_type": "Bearer", "id_token": "dummy", "refresh_token": fwdIdPRT,
	}, true, logger)
	for _, respond := range []func(http.ResponseWriter){
		func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fwdIdPAT, "token_type": "Bearer", "expires_in": 3600, "refresh_token": fwdIdPRTNext})
		},
		echo(http.StatusBadRequest, "invalid_grant"),
		echo(http.StatusInternalServerError, "server_error"),
		echo(http.StatusBadRequest, "invalid_request"),
	} {
		idp.respond.Store(respond)
		postCodeGrant(t, h, encClientID, sealForwardingCode(t, tm, clientUUID, fwdIdPRT))
	}

	for _, event := range []string{"callback_success", "token_issued", "idp_refresh_rejected", "idp_refresh_unavailable", "idp_refresh_failed"} {
		if logs.FilterMessage(event).Len() == 0 {
			t.Errorf("no %q line captured — the hygiene check would not cover that path", event)
		}
	}
	for _, entry := range logs.All() {
		line := entry.Message
		for k, v := range entry.ContextMap() {
			line += " " + k + "=" + toString(v)
		}
		for _, secret := range []string{fwdIdPAT, fwdIdPRT, fwdIdPRTNext, "callback-at"} {
			if strings.Contains(line, secret) {
				t.Errorf("log line carries an IdP token: %s", line)
			}
		}
	}
}

func toString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestToken_ForwardingWithoutVerifierPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Token accepted ForwardIdPToken without a VerifyIDToken")
		}
	}()
	Token(newTestTokenManager(t), zap.NewNop(), testBaseURL, time.Time{}, nil, TokenConfig{ForwardIdPToken: true, IdPRefresher: &IdPRefresher{}})
}

// Default mode keeps the fixed expires_in and an unchanged refresh
// payload.
func TestToken_DefaultMode_CodeGrantUnchanged(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	rr := postCodeGrant(t, Token(tm, zap.NewNop(), testBaseURL, time.Time{}, nil, TokenConfig{}), encClientID, sealForwardingCode(t, tm, clientUUID, ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	at, rt, expiresIn := decodeTokenResponse(t, rr)
	if expiresIn != 3600 {
		t.Errorf("expires_in = %d, want 3600", expiresIn)
	}
	claims, err := tm.Validate(at)
	if err != nil {
		t.Fatal(err)
	}
	if claims.IdPAccessToken != "" {
		t.Error("default mode minted an access token with an IdP token")
	}
	var sr sealedRefresh
	if err := tm.OpenJSON(rt, &sr, token.PurposeRefresh); err != nil {
		t.Fatal(err)
	}
	if sr.IdPRefreshToken != "" {
		t.Error("default mode sealed an IdP refresh token")
	}
}

// An IdP refresh token too large for the code's open() cap fails the
// sign-in at /callback instead of producing a code /token cannot open.
func TestCallback_Forwarding_OversizedCodeRefused(t *testing.T) {
	tm := newTestTokenManager(t)
	tm.SetMaxSealedLen(token.PurposeCode, token.ForwardingMaxSealedLen)
	rr := forwardingCallback(t, tm, map[string]any{
		"access_token": "callback-at", "token_type": "Bearer", "id_token": "dummy", "refresh_token": strings.Repeat("r", 70<<10),
	}, true)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rr.Code, rr.Body.String())
	}
	if body := oauthErrorOf(t, rr); body.ErrorCode != codeCodeSealFailed {
		t.Errorf("error_code = %q, want %s", body.ErrorCode, codeCodeSealFailed)
	}
	if rr.Header().Get("Location") != "" {
		t.Error("a code was issued anyway")
	}
}
