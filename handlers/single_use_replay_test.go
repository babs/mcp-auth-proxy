package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/replay"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

// erroringStore is a replay.Store stub for driving the
// replay-store-error fail-closed branch on /consent and /callback.
// Each method has its own optional override so future tests can
// fail one operation while leaving the others healthy. A nil
// override falls back to the shared `err` field. `err` itself nil
// makes the method a no-op success.
type erroringStore struct {
	err                error
	claimOnceErr       error
	markErr            error
	existsErr          error
	claimOrCheckFamErr error
}

func (e *erroringStore) effective(specific error) error {
	if specific != nil {
		return specific
	}
	return e.err
}

func (e *erroringStore) ClaimOnce(_ context.Context, _ string, _ time.Duration) error {
	return e.effective(e.claimOnceErr)
}
func (e *erroringStore) Mark(_ context.Context, _ string, _ time.Duration) error {
	return e.effective(e.markErr)
}
func (e *erroringStore) Exists(_ context.Context, _ string) (bool, error) {
	if err := e.effective(e.existsErr); err != nil {
		return false, err
	}
	return false, nil
}
func (e *erroringStore) ClaimOrCheckFamily(_ context.Context, _, _ string, _, _, _ time.Duration) (bool, bool, bool, error) {
	if err := e.effective(e.claimOrCheckFamErr); err != nil {
		return false, false, false, err
	}
	return false, false, false, nil
}
func (e *erroringStore) Close() error { return nil }

// mintConsentTokenWithJTI seals a consent blob carrying the given
// JTI. Mirrors mintConsentToken from consent_test.go but exposes the
// claim key so tests can drive the replay branch deterministically.
func mintConsentTokenWithJTI(t *testing.T, tm *token.Manager, jti string) string {
	t.Helper()
	consent := sealedConsent{
		JTI:           jti,
		ClientID:      uuid.New().String(),
		ClientName:    "Friendly App",
		RedirectURI:   "https://app.example.com/cb",
		OriginalState: "client-state",
		CodeChallenge: pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
		Resource:      testBaseURL + "/mcp",
		Typ:           token.PurposeConsent,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(consentTTL),
	}
	tok, err := tm.SealJSON(consent, token.PurposeConsent)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	return tok
}

// TestConsent_SingleUse_ReplayDetected pins T1.2: when a replay store
// is wired and the consent token carries a JTI, the second POST of
// the same token is rejected with 400 invalid_request +
// error_code=consent_replay, and mcp_auth_replay_detected_total{kind="consent"}
// increments by exactly one.
func TestConsent_SingleUse_ReplayDetected(t *testing.T) {
	tm := newTestTokenManager(t)
	store := replay.NewMemoryStore()
	defer store.Close()

	tok := mintConsentTokenWithJTI(t, tm, uuid.NewString())

	before := testutil.ToFloat64(metrics.ReplayDetected.WithLabelValues("consent"))
	approvedBefore := testutil.ToFloat64(metrics.ConsentDecisions.WithLabelValues("approved"))

	post := func() *httptest.ResponseRecorder {
		form := url.Values{"consent_token": {tok}, "action": {"approve"}}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/consent", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{ReplayStore: store})(rr, req)
		return rr
	}

	first := post()
	if first.Code != http.StatusFound {
		t.Fatalf("first POST: want 302, got %d: %s", first.Code, first.Body.String())
	}

	second := post()
	if second.Code != http.StatusBadRequest {
		t.Fatalf("replayed POST: want 400, got %d: %s", second.Code, second.Body.String())
	}
	var oauthErr OAuthError
	if err := json.NewDecoder(second.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", oauthErr.Error)
	}
	if oauthErr.ErrorCode != "consent_replay" {
		t.Errorf("error_code = %q, want consent_replay", oauthErr.ErrorCode)
	}

	if got := testutil.ToFloat64(metrics.ReplayDetected.WithLabelValues("consent")); got-before != 1 {
		t.Errorf("ReplayDetected{kind=consent} delta = %v, want 1", got-before)
	}
	// First POST took the approve branch; only that one should
	// have ticked the approved counter. Pins that the replay
	// rejection sits BEFORE the decision counter so a flooded
	// replay does not inflate consent-funnel metrics.
	if got := testutil.ToFloat64(metrics.ConsentDecisions.WithLabelValues("approved")); got-approvedBefore != 1 {
		t.Errorf("ConsentDecisions{decision=approved} delta = %v, want 1 (replay must not double-count)", got-approvedBefore)
	}
}

// TestConsent_SingleUse_ClaimsBeforeDeny pins that the JTI is
// claimed BEFORE the deny branch — a captured token cannot be
// replayed for either decision.
func TestConsent_SingleUse_ClaimsBeforeDeny(t *testing.T) {
	tm := newTestTokenManager(t)
	store := replay.NewMemoryStore()
	defer store.Close()

	tok := mintConsentTokenWithJTI(t, tm, uuid.NewString())

	post := func(action string) *httptest.ResponseRecorder {
		form := url.Values{"consent_token": {tok}, "action": {action}}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/consent", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{ReplayStore: store})(rr, req)
		return rr
	}

	if got := post("deny").Code; got != http.StatusFound {
		t.Fatalf("first deny: want 302, got %d", got)
	}
	// Replayed deny — token already claimed; must be rejected.
	second := post("deny")
	if second.Code != http.StatusBadRequest {
		t.Fatalf("replayed deny: want 400, got %d: %s", second.Code, second.Body.String())
	}
}

// TestConsent_SingleUse_NilStoreFallback pins the configured-opt-out
// path: when ReplayStore is nil the handler falls through to the
// prior stateless behavior (token replayable within TTL). Mirrors
// the /token nil-replayStore semantics.
func TestConsent_SingleUse_NilStoreFallback(t *testing.T) {
	tm := newTestTokenManager(t)
	tok := mintConsentTokenWithJTI(t, tm, uuid.NewString())

	post := func() *httptest.ResponseRecorder {
		form := url.Values{"consent_token": {tok}, "action": {"approve"}}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/consent", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{})(rr, req)
		return rr
	}
	if got := post().Code; got != http.StatusFound {
		t.Fatalf("first POST: want 302, got %d", got)
	}
	if got := post().Code; got != http.StatusFound {
		t.Fatalf("second POST (nil store): want 302, got %d", got)
	}
}

// TestConsent_SingleUse_LegacyEmptyJTI pins the in-flight-rollout
// fallback: a consent token sealed by an older binary lacks JTI
// and must still be redeemable within its TTL even when ReplayStore
// is wired. Without this back-compat, every in-flight token
// during the deploy window would 503.
func TestConsent_SingleUse_LegacyEmptyJTI(t *testing.T) {
	tm := newTestTokenManager(t)
	store := replay.NewMemoryStore()
	defer store.Close()

	tok := mintConsentTokenWithJTI(t, tm, "") // legacy

	form := url.Values{"consent_token": {tok}, "action": {"approve"}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{ReplayStore: store})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("legacy token (empty JTI): want 302, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestConsent_SingleUse_StoreErrorFailClosed pins the
// fail-closed-on-backend-error policy: the user opted into replay
// defense by configuring a store, so a transient store outage must
// not silently downgrade to stateless behavior. Returns 503 with
// error_code=replay_store_unavailable, mirroring /token.
func TestConsent_SingleUse_StoreErrorFailClosed(t *testing.T) {
	tm := newTestTokenManager(t)
	store := &erroringStore{err: errors.New("redis blew up")}

	tok := mintConsentTokenWithJTI(t, tm, uuid.NewString())

	before := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("replay_store_unavailable"))

	form := url.Values{"consent_token": {tok}, "action": {"approve"}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{ReplayStore: store})(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d: %s", rr.Code, rr.Body.String())
	}
	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.ErrorCode != "replay_store_unavailable" {
		t.Errorf("error_code = %q, want replay_store_unavailable", oauthErr.ErrorCode)
	}
	if got := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("replay_store_unavailable")); got-before != 1 {
		t.Errorf("AccessDenied{reason=replay_store_unavailable} delta = %v, want 1", got-before)
	}
}

// --- T2.1: callback sealed-state ClaimOnce ---

// mintCallbackSession seals a session with the given SessionID for
// driving /callback through to the upstream-exchange step. The
// upstream exchange is stubbed via verifyFunc panicking — the
// replay rejection MUST fire BEFORE that point.
func mintCallbackSession(t *testing.T, tm *token.Manager, sid string) string {
	t.Helper()
	s := sealedSession{
		ClientID:      uuid.New().String(),
		RedirectURI:   "https://app.example.com/cb",
		OriginalState: "client-state",
		Nonce:         "n",
		PKCEVerifier:  oauth2.GenerateVerifier(),
		SessionID:     sid,
		Typ:           token.PurposeSession,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	state, err := tm.SealJSON(s, token.PurposeSession)
	if err != nil {
		t.Fatalf("seal session: %v", err)
	}
	return state
}

// TestCallback_SingleUse_ReplayDetected pins T2.1: when a replay
// store is wired and the sealed state carries a SessionID, a second
// /callback hit on the same state is rejected BEFORE the upstream
// IdP exchange (no fan-out, no audit-log noise). Returns 400
// invalid_request + error_code=callback_state_replay,
// mcp_auth_replay_detected_total{kind="callback_state"} increments.
func TestCallback_SingleUse_ReplayDetected(t *testing.T) {
	tm := newTestTokenManager(t)
	store := replay.NewMemoryStore()
	defer store.Close()
	oauth2Cfg := testOAuth2Config()
	exchanged := 0
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		// Replay branch must short-circuit before this is called on
		// the second hit. The first hit will reach Exchange and fail
		// (no real IdP) — that's fine, the replay test is about
		// hit #2.
		exchanged++
		return nil, errors.New("not used")
	}

	state := mintCallbackSession(t, tm, uuid.NewString())

	before := testutil.ToFloat64(metrics.ReplayDetected.WithLabelValues("callback_state"))

	hit := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/callback?code=fake&state="+url.QueryEscape(state), nil)
		rr := httptest.NewRecorder()
		CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc, CallbackConfig{ReplayStore: store})(rr, req)
		return rr
	}

	first := hit()
	// First hit reaches Exchange (which fails: no real IdP) — the
	// replay claim already happened. This is what we want: the
	// claim must be recorded even when the downstream exchange
	// fails, otherwise a flaky upstream lets a stolen state be
	// retried.
	_ = first

	second := hit()
	if second.Code != http.StatusBadRequest {
		t.Fatalf("replayed /callback: want 400, got %d: %s", second.Code, second.Body.String())
	}
	var oauthErr OAuthError
	if err := json.NewDecoder(second.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.ErrorCode != "callback_state_replay" {
		t.Errorf("error_code = %q, want callback_state_replay", oauthErr.ErrorCode)
	}

	if got := testutil.ToFloat64(metrics.ReplayDetected.WithLabelValues("callback_state")); got-before != 1 {
		t.Errorf("ReplayDetected{kind=callback_state} delta = %v, want 1", got-before)
	}
}

// TestCallback_SingleUse_LegacyEmptySID pins the in-flight-rollout
// fallback for /callback: a state sealed by an older binary has no
// SessionID and must not 503 the user out of their auth flow.
//
// Asserts negatively — the replay-rejection and store-error error
// codes must NOT appear. The downstream IdP exchange will fail
// (no real IdP) producing some other error; that's expected and
// not what this test pins.
func TestCallback_SingleUse_LegacyEmptySID(t *testing.T) {
	tm := newTestTokenManager(t)
	store := replay.NewMemoryStore()
	defer store.Close()
	oauth2Cfg := testOAuth2Config()
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		return nil, errors.New("not used")
	}

	state := mintCallbackSession(t, tm, "") // legacy

	req := httptest.NewRequest(http.MethodGet, "/callback?code=fake&state="+url.QueryEscape(state), nil)
	rr := httptest.NewRecorder()
	CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc, CallbackConfig{ReplayStore: store})(rr, req)

	var oauthErr OAuthError
	_ = json.NewDecoder(rr.Body).Decode(&oauthErr) // body shape is best-effort here
	if oauthErr.ErrorCode == "callback_state_replay" {
		t.Fatalf("legacy state (empty SessionID) hit the replay-rejection branch")
	}
	if oauthErr.ErrorCode == "replay_store_unavailable" {
		t.Fatalf("legacy state (empty SessionID) hit the store-error branch")
	}
}

// TestCallback_SingleUse_StoreErrorFailClosed pins the
// fail-closed-on-store-error policy on /callback. Same shape as
// the consent test.
func TestCallback_SingleUse_StoreErrorFailClosed(t *testing.T) {
	tm := newTestTokenManager(t)
	store := &erroringStore{err: errors.New("redis blew up")}
	oauth2Cfg := testOAuth2Config()
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		t.Fatalf("verifyFunc must not run after replay-store error")
		return nil, nil
	}

	state := mintCallbackSession(t, tm, uuid.NewString())

	before := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("replay_store_unavailable"))

	req := httptest.NewRequest(http.MethodGet, "/callback?code=fake&state="+url.QueryEscape(state), nil)
	rr := httptest.NewRecorder()
	CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc, CallbackConfig{ReplayStore: store})(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d: %s", rr.Code, rr.Body.String())
	}
	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.ErrorCode != "replay_store_unavailable" {
		t.Errorf("error_code = %q, want replay_store_unavailable", oauthErr.ErrorCode)
	}
	if got := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("replay_store_unavailable")); got-before != 1 {
		t.Errorf("AccessDenied{reason=replay_store_unavailable} delta = %v, want 1", got-before)
	}
}

// --- T2.2: outbound rate-bucket on the /callback IdP exchange ---

// TestCallback_IdPExchangeThrottled pins T2.2: when the wired
// rate.Limiter rejects the call, /callback returns 503
// temporarily_unavailable + error_code=idp_exchange_throttled
// BEFORE reaching the upstream IdP exchange. The verifyFunc must
// not run, and mcp_auth_idp_exchange_throttled_total increments.
func TestCallback_IdPExchangeThrottled(t *testing.T) {
	tm := newTestTokenManager(t)
	oauth2Cfg := testOAuth2Config()
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		t.Fatalf("verifyFunc must not run when the IdP exchange is throttled")
		return nil, nil
	}

	// Tiny rate + 1-token burst, drained immediately, models an
	// exhausted bucket that won't refill within the test window
	// (replenishes at 1/1000s ≈ once every ~17min). More
	// future-proof than rate.NewLimiter(0, 0): the upstream
	// `golang.org/x/time/rate` package contract for "rate=0,
	// burst=0" has shifted between versions, but a real positive
	// rate with the burst pre-drained is unambiguously empty.
	limiter := rate.NewLimiter(0.001, 1)
	if !limiter.Allow() {
		t.Fatal("limiter setup: initial Allow should succeed to drain the burst")
	}

	state := mintCallbackSession(t, tm, uuid.NewString())

	before := testutil.ToFloat64(metrics.IdPExchangeThrottled)

	req := httptest.NewRequest(http.MethodGet, "/callback?code=fake&state="+url.QueryEscape(state), nil)
	rr := httptest.NewRecorder()
	CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc, CallbackConfig{IdPExchangeLimiter: limiter})(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Retry-After"); got == "" {
		t.Errorf("want Retry-After header, got empty")
	}
	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "temporarily_unavailable" {
		t.Errorf("error = %q, want temporarily_unavailable", oauthErr.Error)
	}
	if oauthErr.ErrorCode != "idp_exchange_throttled" {
		t.Errorf("error_code = %q, want idp_exchange_throttled", oauthErr.ErrorCode)
	}
	if got := testutil.ToFloat64(metrics.IdPExchangeThrottled); got-before != 1 {
		t.Errorf("IdPExchangeThrottled delta = %v, want 1", got-before)
	}
}

// TestCallback_IdPExchangeNoLimiter pins the back-compat path:
// when no limiter is wired (the default) /callback proceeds to the
// IdP exchange exactly as it did before T2.2. Any operator who
// leaves IDP_EXCHANGE_RATE_PER_SEC unset gets the previous
// behavior with no throttling overhead.
func TestCallback_IdPExchangeNoLimiter(t *testing.T) {
	tm := newTestTokenManager(t)
	oauth2Cfg := testOAuth2Config()
	exchangeReached := false
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		exchangeReached = true
		return nil, errors.New("not used — exchange happens before verify")
	}

	state := mintCallbackSession(t, tm, uuid.NewString())

	req := httptest.NewRequest(http.MethodGet, "/callback?code=fake&state="+url.QueryEscape(state), nil)
	rr := httptest.NewRecorder()
	CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc, CallbackConfig{})(rr, req)

	// We don't assert the final status — the upstream Exchange
	// fails (no real IdP) and that path returns 502 — what we
	// pin is that the throttle branch did NOT short-circuit.
	if rr.Code == http.StatusServiceUnavailable {
		var oauthErr OAuthError
		if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err == nil && oauthErr.ErrorCode == "idp_exchange_throttled" {
			t.Fatalf("nil limiter must not throttle: %s", rr.Body.String())
		}
	}
	// verifyFunc would only run after a successful Exchange; with a
	// fake config Exchange itself errors first. The point is no
	// throttle-branch short-circuit. exchangeReached being false is
	// expected here; just confirm we didn't 503-throttle.
	_ = exchangeReached
}

// TestAuthorize_RenderConsent_PopulatesJTI pins that GET /authorize
// (consent-fork enabled) seals a non-empty JTI into the consent
// blob. Without this, the per-render single-use defense degrades
// silently to the legacy back-compat fallback.
func TestAuthorize_RenderConsent_PopulatesJTI(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, _ := registerClientNamed(t, tm, []string{"https://app.example.com/callback"}, "App")

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {pkceChallenge(codeVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	authorizeConsentEnabled(tm)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	// Extract the consent_token from the form. The page is small
	// enough that a substring search is cheaper than an HTML parse.
	const marker = `name="consent_token" value="`
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("consent_token input not found in body")
	}
	rest := body[idx+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("consent_token close-quote not found")
	}
	tok := rest[:end]

	var consent sealedConsent
	if err := tm.OpenJSON(tok, &consent, token.PurposeConsent); err != nil {
		t.Fatalf("OpenJSON consent: %v", err)
	}
	if consent.JTI == "" {
		t.Errorf("sealedConsent.JTI is empty — per-render claim slot not populated")
	}
}

// --- T2.3: refresh-token race grace window ---

// TestTokenRefresh_RaceGrace_RacingReturns429 pins T2.3 happy path:
// when the operator configures a non-zero RefreshRaceGrace and a
// second submit of the same refresh lands inside that window, the
// response is 429 + error_code=refresh_concurrent_submit AND the
// family is NOT revoked. The first refresh that already succeeded
// stays usable.
func TestTokenRefresh_RaceGrace_RacingReturns429(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	store := replay.NewMemoryStore()
	defer store.Close()

	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	// Mint a refresh token with FamilyID/TokenID populated.
	familyID := uuid.New().String()
	original := sealedRefresh{
		TokenID:   uuid.New().String(),
		FamilyID:  familyID,
		Subject:   "user-sub",
		Email:     "user@example.com",
		ClientID:  internalID,
		Typ:       token.PurposeRefresh,
		Audience:  testBaseURL,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	originalStr, err := tm.SealJSON(original, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	exchange := func() *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {originalStr},
			"client_id":     {encClientID},
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		Token(tm, logger, testBaseURL, time.Time{}, store, TokenConfig{RefreshRaceGrace: 5 * time.Second})(rr, req)
		return rr
	}

	// First rotation succeeds, claims the TokenID.
	first := exchange()
	if first.Code != http.StatusOK {
		t.Fatalf("first rotation: want 200, got %d: %s", first.Code, first.Body.String())
	}

	racingBefore := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("refresh_concurrent_submit"))
	familyRevokedBefore := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("refresh_family_revoked"))
	reuseBefore := testutil.ToFloat64(metrics.ReplayDetected.WithLabelValues("refresh"))

	// Second submit of the SAME refresh, within the 5s grace window.
	second := exchange()
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("racing rotation: want 429, got %d: %s", second.Code, second.Body.String())
	}
	if got := second.Header().Get("Retry-After"); got == "" {
		t.Errorf("racing rotation: want Retry-After header, got empty")
	}
	var racingErr OAuthError
	if err := json.NewDecoder(second.Body).Decode(&racingErr); err != nil {
		t.Fatalf("decode racing: %v", err)
	}
	if racingErr.ErrorCode != "refresh_concurrent_submit" {
		t.Errorf("error_code = %q, want refresh_concurrent_submit", racingErr.ErrorCode)
	}

	if got := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("refresh_concurrent_submit")); got-racingBefore != 1 {
		t.Errorf("AccessDenied{reason=refresh_concurrent_submit} delta = %v, want 1", got-racingBefore)
	}
	// Family must NOT be revoked — that's the whole point of the grace window.
	if got := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("refresh_family_revoked")); got != familyRevokedBefore {
		t.Errorf("AccessDenied{reason=refresh_family_revoked} delta = %v, want 0", got-familyRevokedBefore)
	}
	if got := testutil.ToFloat64(metrics.ReplayDetected.WithLabelValues("refresh")); got != reuseBefore {
		t.Errorf("ReplayDetected{kind=refresh} delta = %v, want 0", got-reuseBefore)
	}
}

// TestTokenRefresh_RaceGrace_ZeroDisablesGrace pins that
// RefreshRaceGrace=0 keeps the strict pre-T2.3 behavior: every
// collision is reuse, the family is revoked. Operators who want
// the strict mode can opt out of the grace window by setting
// REFRESH_RACE_GRACE_SEC=0.
func TestTokenRefresh_RaceGrace_ZeroDisablesGrace(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	store := replay.NewMemoryStore()
	defer store.Close()

	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	familyID := uuid.New().String()
	original := sealedRefresh{
		TokenID:   uuid.New().String(),
		FamilyID:  familyID,
		Subject:   "user-sub",
		Email:     "user@example.com",
		ClientID:  internalID,
		Typ:       token.PurposeRefresh,
		Audience:  testBaseURL,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	originalStr, err := tm.SealJSON(original, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	exchange := func() *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {originalStr},
			"client_id":     {encClientID},
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		Token(tm, logger, testBaseURL, time.Time{}, store, TokenConfig{RefreshRaceGrace: 0})(rr, req)
		return rr
	}

	if got := exchange().Code; got != http.StatusOK {
		t.Fatalf("first rotation: want 200, got %d", got)
	}
	second := exchange()
	if second.Code != http.StatusBadRequest {
		t.Fatalf("strict-mode collision: want 400, got %d: %s", second.Code, second.Body.String())
	}
	var oauthErr OAuthError
	if err := json.NewDecoder(second.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.ErrorCode != "refresh_reuse_detected" {
		t.Errorf("error_code = %q, want refresh_reuse_detected", oauthErr.ErrorCode)
	}
}

// --- T4.3: authorize_initiated funnel counter ---

// TestAuthorize_Initiated_IncrementsOnConsentFork pins T4.3 on
// the consent-fork path: every validated GET /authorize that
// enters the consent renderer increments
// mcp_auth_authorize_initiated_total exactly once.
func TestAuthorize_Initiated_IncrementsOnConsentFork(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, _ := registerClientNamed(t, tm, []string{"https://app.example.com/callback"}, "App")

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {pkceChallenge(codeVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state"},
	}

	before := testutil.ToFloat64(metrics.AuthorizeInitiated)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	authorizeConsentEnabled(tm)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(metrics.AuthorizeInitiated) - before; got != 1 {
		t.Errorf("AuthorizeInitiated delta = %v, want 1", got)
	}
}

// TestAuthorize_Initiated_IncrementsOnSilentFork pins T4.3 on
// the silent-redirect path (RenderConsentPage=false): the same
// counter increments whether the proxy renders a consent page or
// redirects directly to the IdP. Funnel math doesn't fork on
// build flag.
func TestAuthorize_Initiated_IncrementsOnSilentFork(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, _ := registerClientNamed(t, tm, []string{"https://app.example.com/callback"}, "App")

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {pkceChallenge(codeVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state"},
	}

	before := testutil.ToFloat64(metrics.AuthorizeInitiated)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	Authorize(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), AuthorizeConfig{
		PKCERequired:      true,
		ResourceURIs:      []string{testBaseURL + "/mcp"},
		CanonicalResource: testBaseURL + "/mcp",
	})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("want 302, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := testutil.ToFloat64(metrics.AuthorizeInitiated) - before; got != 1 {
		t.Errorf("AuthorizeInitiated delta = %v, want 1", got)
	}
}

// TestAuthorize_Initiated_NotIncrementedOnPreValidationReject
// pins that every pre-funnel reject path skips the counter. The
// table covers the four classes that share the "redirectAuthzError
// before increment" or "writeOAuthError before increment" shape:
// unknown client (JSON-error path), unsupported response_type
// (redirect-error path), invalid resource (redirect-error path),
// and missing state in strict mode (redirect-error path). Without
// this guarantee the funnel math initiated → tokens_issued would
// inflate with traffic that never reached Phase 3.
func TestAuthorize_Initiated_NotIncrementedOnPreValidationReject(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, _ := registerClientNamed(t, tm, []string{"https://app.example.com/callback"}, "App")
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	chal := pkceChallenge(codeVerifier)

	tests := []struct {
		name string
		q    url.Values
	}{
		{
			name: "unknown_client_id",
			q: url.Values{
				"response_type":         {"code"},
				"client_id":             {"not-a-real-client"},
				"redirect_uri":          {"https://app.example.com/callback"},
				"code_challenge":        {chal},
				"code_challenge_method": {"S256"},
				"state":                 {"s"},
			},
		},
		{
			name: "unsupported_response_type",
			q: url.Values{
				"response_type":         {"token"},
				"client_id":             {encClientID},
				"redirect_uri":          {"https://app.example.com/callback"},
				"code_challenge":        {chal},
				"code_challenge_method": {"S256"},
				"state":                 {"s"},
			},
		},
		{
			name: "invalid_resource",
			q: url.Values{
				"response_type":         {"code"},
				"client_id":             {encClientID},
				"redirect_uri":          {"https://app.example.com/callback"},
				"code_challenge":        {chal},
				"code_challenge_method": {"S256"},
				"state":                 {"s"},
				"resource":              {"https://other-resource.example.com/api"},
			},
		},
		{
			name: "state_missing_strict",
			q: url.Values{
				"response_type":         {"code"},
				"client_id":             {encClientID},
				"redirect_uri":          {"https://app.example.com/callback"},
				"code_challenge":        {chal},
				"code_challenge_method": {"S256"},
				// state intentionally absent
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := testutil.ToFloat64(metrics.AuthorizeInitiated)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+tc.q.Encode(), nil)
			rr := httptest.NewRecorder()
			Authorize(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), AuthorizeConfig{
				PKCERequired:      true,
				ResourceURIs:      []string{testBaseURL + "/mcp"},
				CanonicalResource: testBaseURL + "/mcp",
				// CompatAllowStateless stays false → state-missing
				// rejects in strict mode rather than synthesizing.
			})(rr, req)

			// Each row above causes either a 400 (JSON path) or a
			// 302 (redirect-error path). Both shapes mean the
			// request was rejected before the funnel point — the
			// counter must NOT have moved.
			if rr.Code != http.StatusBadRequest && rr.Code != http.StatusFound {
				t.Fatalf("%s: unexpected status %d (want 400 or 302): %s", tc.name, rr.Code, rr.Body.String())
			}
			if got := testutil.ToFloat64(metrics.AuthorizeInitiated) - before; got != 0 {
				t.Errorf("%s: AuthorizeInitiated delta = %v, want 0 (pre-funnel reject must not increment)", tc.name, got)
			}
		})
	}
}

// TestAuthorize_SilentRedirect_PopulatesSessionID pins that the
// inline /authorize path (RenderConsentPage=false) seals a non-empty
// SessionID into the session blob. /callback's per-state replay
// claim depends on this.
func TestAuthorize_SilentRedirect_PopulatesSessionID(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, _ := registerClientNamed(t, tm, []string{"https://app.example.com/callback"}, "App")

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {pkceChallenge(codeVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	// Silent path — consent fork off.
	Authorize(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), AuthorizeConfig{
		PKCERequired:      true,
		ResourceURIs:      []string{testBaseURL + "/mcp"},
		CanonicalResource: testBaseURL + "/mcp",
	})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("want 302, got %d: %s", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	idpState := loc.Query().Get("state")
	var sess sealedSession
	if err := tm.OpenJSON(idpState, &sess, token.PurposeSession); err != nil {
		t.Fatalf("OpenJSON session: %v", err)
	}
	if sess.SessionID == "" {
		t.Errorf("sealedSession.SessionID is empty — per-session claim slot not populated")
	}
}
