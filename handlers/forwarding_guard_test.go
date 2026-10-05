package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/time/rate"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/replay"
	"github.com/babs/mcp-auth-proxy/token"
)

// The code travels in a redirect URL: only the IdP refresh token may be
// sealed into it, never the access token.
func TestCallback_Forwarding_AccessTokenStaysOutOfCode(t *testing.T) {
	tm := newTestTokenManager(t)
	rr := forwardingCallback(t, tm, map[string]any{
		"access_token": "callback-at", "token_type": "Bearer", "id_token": "dummy", "refresh_token": fwdIdPRT,
	}, true)
	loc, err := rr.Result().Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	var raw json.RawMessage
	if err := tm.OpenJSON(loc.Query().Get("code"), &raw, token.PurposeCode); err != nil {
		t.Fatalf("open code: %v", err)
	}
	if strings.Contains(string(raw), "callback-at") {
		t.Errorf("the IdP access token is sealed into the code: %s", raw)
	}
}

// RFC 8707 resource and client binding survive both grants.
func TestToken_Forwarding_BindingsCarried(t *testing.T) {
	const resource = testBaseURL + "/mcp"
	f := newRefreshFixture(t)
	f.tm.SetMaxSealedLen(token.PurposeCode, token.ForwardingMaxSealedLen)
	code, err := f.tm.SealJSON(sealedCode{
		TokenID: uuid.New().String(), FamilyID: uuid.New().String(), ClientID: f.clientUUID,
		RedirectURI: fwdRedirectURI, CodeChallenge: pkceChallenge(fwdVerifier),
		Subject: "user-sub", Email: "user@example.com", Typ: token.PurposeCode, Audience: testBaseURL,
		Resource: resource, ExpiresAt: time.Now().Add(time.Minute), IdPRefreshToken: fwdIdPRT,
	}, token.PurposeCode)
	if err != nil {
		t.Fatal(err)
	}
	h := Token(f.tm, zap.NewNop(), testBaseURL, time.Time{}, f.store, TokenConfig{
		ForwardIdPToken: true, IdPRefresher: f.idp.refresher(), VerifyIDToken: fakeVerifyIDToken,
	}, resource)

	check := func(step string, rrCode int, body string, at, rt string) string {
		t.Helper()
		if rrCode != http.StatusOK {
			t.Fatalf("%s: %d %s", step, rrCode, body)
		}
		claims, err := f.tm.Validate(at)
		if err != nil {
			t.Fatalf("%s: validate: %v", step, err)
		}
		var sr sealedRefresh
		if err := f.tm.OpenJSON(rt, &sr, token.PurposeRefresh); err != nil {
			t.Fatalf("%s: open refresh: %v", step, err)
		}
		if claims.Resource != resource || claims.ClientID != f.clientUUID || claims.Subject != "user-sub" {
			t.Errorf("%s: access token bindings = resource %q client %q sub %q", step, claims.Resource, claims.ClientID, claims.Subject)
		}
		if sr.Resource != resource || sr.ClientID != f.clientUUID {
			t.Errorf("%s: refresh token bindings = resource %q client %q", step, sr.Resource, sr.ClientID)
		}
		return rt
	}
	rr := postCodeGrant(t, h, f.encClientID, code)
	at, rt, _ := decodeTokenResponse(t, rr)
	rt = check("code grant", rr.Code, rr.Body.String(), at, rt)
	rr = postRefreshGrant(t, h, f.encClientID, rt)
	at, rt, _ = decodeTokenResponse(t, rr)
	check("refresh grant", rr.Code, rr.Body.String(), at, rt)
}

// mcp_auth_idp_refresh_total is what the IdP-outage runbook alerts on.
func TestTokenRefresh_Forwarding_ResultMetrics(t *testing.T) {
	cases := []struct {
		label   string
		arrange func(f *refreshFixture) *rate.Limiter
	}{
		{label: "ok", arrange: func(f *refreshFixture) *rate.Limiter { return nil }},
		{label: "rejected", arrange: func(f *refreshFixture) *rate.Limiter { f.idp.fail(400, "invalid_grant"); return nil }},
		{label: "unavailable", arrange: func(f *refreshFixture) *rate.Limiter { f.idp.fail(503, "temporarily_unavailable"); return nil }},
		{label: "failed", arrange: func(f *refreshFixture) *rate.Limiter { f.idp.fail(400, "invalid_request"); return nil }},
		{label: "throttled", arrange: func(f *refreshFixture) *rate.Limiter { return rate.NewLimiter(0, 0) }},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			f := newRefreshFixture(t)
			limiter := tc.arrange(f)
			rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
			before := testutil.ToFloat64(metrics.IdPRefresh.WithLabelValues(tc.label))
			bucket := testutil.ToFloat64(metrics.IdPExchangeThrottled)

			postRefreshGrant(t, f.handler(zap.NewNop(), limiter), f.encClientID, rt)

			if got := testutil.ToFloat64(metrics.IdPRefresh.WithLabelValues(tc.label)) - before; got != 1 {
				t.Errorf("idp_refresh_total{result=%q} delta = %v, want 1", tc.label, got)
			}
			wantBucket := 0.0
			if tc.label == "throttled" {
				wantBucket = 1
			}
			if got := testutil.ToFloat64(metrics.IdPExchangeThrottled) - bucket; got != wantBucket {
				t.Errorf("idp_exchange_throttled_total delta = %v, want %v", got, wantBucket)
			}
		})
	}
}

// A token minted before the mode was switched on is counted where the
// middleware counts the same condition.
func TestToken_Forwarding_PreUpgradeTokensCounted(t *testing.T) {
	f := newRefreshFixture(t)
	before := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("idp_token_missing"))
	h := f.handler(zap.NewNop(), nil)

	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "", time.Now())
	postRefreshGrant(t, h, f.encClientID, rt)
	postCodeGrant(t, h, f.encClientID, sealForwardingCode(t, f.tm, f.clientUUID, ""))

	if got := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("idp_token_missing")) - before; got != 2 {
		t.Errorf("access_denied{idp_token_missing} delta = %v, want 2", got)
	}
}

// An answer that did not come from the token endpoint (WAF, maintenance
// page) must leave the refresh token usable: the IdP never saw it.
func TestTokenRefresh_Forwarding_NonOAuthAnswerKeepsRefreshToken(t *testing.T) {
	answers := map[string]func(http.ResponseWriter){
		"403_html": func(w http.ResponseWriter) { w.WriteHeader(403); _, _ = w.Write([]byte("<html>blocked</html>")) },
		"200_html": func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>maintenance</html>")) },
		"302_maintenance_redirect": func(w http.ResponseWriter) {
			w.Header().Set("Location", "https://maintenance.invalid/")
			w.WriteHeader(http.StatusFound)
		},
	}
	for name, answer := range answers {
		t.Run(name, func(t *testing.T) {
			f := newRefreshFixture(t)
			h := f.handler(zap.NewNop(), nil)
			rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

			f.idp.respond.Store(answer)
			rr := postRefreshGrant(t, h, f.encClientID, rt)
			if body := oauthErrorOf(t, rr); rr.Code != http.StatusServiceUnavailable || body.ErrorCode != codeIdPRefreshUnavailable {
				t.Fatalf("got %d %+v, want 503 %s", rr.Code, body, codeIdPRefreshUnavailable)
			}
			f.idp.succeed("at-2", "rt-3", 3600)
			if rr := postRefreshGrant(t, h, f.encClientID, rt); rr.Code != http.StatusOK {
				t.Errorf("retry with the same refresh token: %d %s, want 200", rr.Code, rr.Body.String())
			}
		})
	}
}

// The client is paced by the IdP's own Retry-After when it is larger,
// capped, and by a long wait when only an operator fix helps.
func TestTokenRefresh_Forwarding_RetryAfter(t *testing.T) {
	cases := []struct {
		name     string
		answer   func(http.ResponseWriter)
		min, max int
	}{
		{name: "idp_retry_after_capped", answer: func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "900")
			w.WriteHeader(429)
		}, min: 120, max: 120},
		{name: "idp_retry_after_small_keeps_floor", answer: func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(503)
		}, min: 2, max: 4},
		{name: "client_credentials_refused", answer: func(w http.ResponseWriter) {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		}, min: 60, max: 60},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshFixture(t)
			f.idp.respond.Store(tc.answer)
			rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
			rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil), f.encClientID, rt)
			got, err := strconv.Atoi(rr.Header().Get("Retry-After"))
			if rr.Code != http.StatusServiceUnavailable || err != nil || got < tc.min || got > tc.max {
				t.Errorf("status %d Retry-After %q, want 503 and %d..%d", rr.Code, rr.Header().Get("Retry-After"), tc.min, tc.max)
			}
		})
	}
}

// A replayed code or refresh token is refused before the IdP is called.
func TestToken_Forwarding_ReplaysNeverReachIdP(t *testing.T) {
	f := newRefreshFixture(t)
	h := f.handler(zap.NewNop(), nil) // no race grace: a second submit is a reuse

	code := sealForwardingCode(t, f.tm, f.clientUUID, fwdIdPRT)
	if rr := postCodeGrant(t, h, f.encClientID, code); rr.Code != http.StatusOK {
		t.Fatalf("code grant: %d %s", rr.Code, rr.Body.String())
	}
	if rr := postCodeGrant(t, h, f.encClientID, code); oauthErrorOf(t, rr).ErrorCode != codeCodeReplay {
		t.Fatalf("code replay: %s", rr.Body.String())
	}
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
	if rr := postRefreshGrant(t, h, f.encClientID, rt); rr.Code != http.StatusOK {
		t.Fatalf("refresh grant: %d %s", rr.Code, rr.Body.String())
	}
	if rr := postRefreshGrant(t, h, f.encClientID, rt); oauthErrorOf(t, rr).ErrorCode != codeRefreshReuse {
		t.Fatalf("refresh replay: %s", rr.Body.String())
	}
	if n := f.idp.calls.Load(); n != 2 {
		t.Errorf("IdP called %d times, want 2 (one per legitimate grant)", n)
	}
}

func policyIDToken(t *testing.T, claims map[string]any) *oidc.IDToken {
	t.Helper()
	tok, err := fakeVerifyIDToken(context.Background(), fakeIDToken(claims))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// The sign-in policy shared by /callback and the refresh: rule order,
// the denial counter, and silence about groups on an email denial.
func TestCheckIdentityPolicy(t *testing.T) {
	no, yes := false, true
	cases := []struct {
		name          string
		claims        map[string]any
		emailVerified *bool
		allowed       []string
		wantDenial    string
		wantGroups    []string
		wantPresent   bool
	}{
		{name: "admitted", claims: map[string]any{"groups": []string{"staff"}}, emailVerified: &yes, allowed: []string{"staff"}, wantGroups: []string{"staff"}, wantPresent: true},
		{name: "no_claim_no_allowlist", claims: map[string]any{}, wantPresent: false},
		{name: "email_first", claims: map[string]any{"groups": []string{"a,b"}}, emailVerified: &no, allowed: []string{"staff"}, wantDenial: denyEmailUnverified},
		{name: "email_denial_ignores_group_shape", claims: map[string]any{"groups": "a b"}, emailVerified: &no, wantDenial: denyEmailUnverified},
		{name: "invalid_name_before_allowlist", claims: map[string]any{"groups": []string{"a,b"}}, allowed: []string{"staff"}, wantDenial: denyGroupInvalid, wantGroups: []string{"a,b"}, wantPresent: true},
		{name: "not_allowed", claims: map[string]any{"groups": []string{"interns"}}, allowed: []string{"staff"}, wantDenial: denyGroup, wantGroups: []string{"interns"}, wantPresent: true},
		{name: "missing_claim_with_allowlist", claims: map[string]any{}, allowed: []string{"staff"}, wantDenial: denyGroup},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			shape := testutil.ToFloat64(metrics.GroupsClaimShapeMismatch)
			var before float64
			if tc.wantDenial != "" {
				before = testutil.ToFloat64(metrics.AccessDenied.WithLabelValues(tc.wantDenial))
			}

			groups, present, denial := checkIdentityPolicy(policyIDToken(t, tc.claims), tc.emailVerified, "groups", tc.allowed, zap.New(core), "user-sub")

			if denial != tc.wantDenial || present != tc.wantPresent || !slices.Equal(groups, tc.wantGroups) {
				t.Errorf("got groups=%v present=%v denial=%q, want %v %v %q", groups, present, denial, tc.wantGroups, tc.wantPresent, tc.wantDenial)
			}
			if tc.wantDenial != "" {
				if got := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues(tc.wantDenial)) - before; got != 1 {
					t.Errorf("access_denied{%s} delta = %v, want 1", tc.wantDenial, got)
				}
			}
			if tc.wantDenial == denyEmailUnverified && (logs.Len() != 0 || testutil.ToFloat64(metrics.GroupsClaimShapeMismatch) != shape) {
				t.Errorf("an email denial logged or counted something about groups: %v", logs.All())
			}
		})
	}
}

// Whatever ALLOWED_GROUPS says, an id_token that cannot be verified or
// parsed is refused.
func TestTokenRefresh_Forwarding_UnusableIDTokenAlwaysRefused(t *testing.T) {
	idTokens := map[string]string{
		"unverifiable":      `{"sub":"user-sub"}`,
		"unparsable_claims": fakeIDToken(map[string]any{"sub": "user-sub", "email": 5}),
	}
	for name, idToken := range idTokens {
		for _, allowed := range [][]string{nil, {"staff"}} {
			f := newRefreshFixture(t)
			f.idp.respond.Store(idpAnswer("at-2", "rt-3", idToken, 3600))
			rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
			rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil, allowed...), f.encClientID, rt)
			if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.ErrorCode != codeIDTokenVerificationFailed {
				t.Errorf("%s, allowed=%v: got %d %+v, want 400 %s", name, allowed, rr.Code, body, codeIDTokenVerificationFailed)
			}
		}
	}
}

// The id_token is verified on a context that outlives a client hang-up
// (the IdP has already rotated) and is bounded.
func TestRefreshIdentity_VerifyContextDetachedAndBounded(t *testing.T) {
	var sawErr error
	var sawDeadline bool
	cfg := TokenConfig{VerifyIDToken: func(ctx context.Context, raw string) (*oidc.IDToken, error) {
		sawErr = ctx.Err()
		if d, ok := ctx.Deadline(); ok && time.Until(d) <= oidcExchangeTTL {
			sawDeadline = true
		}
		return fakeVerifyIDToken(ctx, raw)
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/token", nil)
	prev := &sealedRefresh{Subject: "user-sub", Email: "user@example.com"}

	_, _, ok := refreshIdentity(httptest.NewRecorder(), req, cfg, zap.NewNop(), fakeIDToken(map[string]any{"sub": "user-sub"}), prev)
	if !ok || sawErr != nil || !sawDeadline {
		t.Errorf("ok=%v, verify ctx err=%v, bounded=%v; want true, nil, true", ok, sawErr, sawDeadline)
	}
}

func TestTokenRefresh_Forwarding_SubjectMismatchCounted(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", fakeIDToken(map[string]any{"sub": "someone-else"}), 3600))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
	before := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("id_token_verification_failed"))
	postRefreshGrant(t, f.handler(zap.NewNop(), nil), f.encClientID, rt)
	if got := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("id_token_verification_failed")) - before; got != 1 {
		t.Errorf("access_denied{id_token_verification_failed} delta = %v, want 1", got)
	}
}

// ctxStore is a MemoryStore whose calls fail on a dead context, as a
// Redis store's would, and that records the keys it is asked to claim.
type ctxStore struct {
	*replay.MemoryStore
	claimed []string
}

func (s *ctxStore) Release(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.MemoryStore.Release(ctx, key)
}

func (s *ctxStore) ClaimOnce(ctx context.Context, key string, ttl time.Duration) error {
	s.claimed = append(s.claimed, key)
	return s.MemoryStore.ClaimOnce(ctx, key, ttl)
}

func (s *ctxStore) ClaimOrCheckFamily(ctx context.Context, familyKey, claimKey string, claimTTL, familyTTL, grace time.Duration) (bool, bool, bool, error) {
	s.claimed = append(s.claimed, claimKey)
	return s.MemoryStore.ClaimOrCheckFamily(ctx, familyKey, claimKey, claimTTL, familyTTL, grace)
}

// The claim is given back even when the client has hung up.
func TestReleaseForRetry_SurvivesClientHangUp(t *testing.T) {
	f := newRefreshFixture(t)
	store := &ctxStore{MemoryStore: f.store}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/token", nil)
	if !releaseForRetry(req, store, "some-claim", zap.NewNop(), "test") {
		t.Error("release failed on a hung-up client: its retry would read as a replay")
	}
}

// Each grant claims under its own namespace, and the release names the
// same key: a retry after an IdP outage must find the claim gone.
func TestToken_Forwarding_ClaimKeys(t *testing.T) {
	f := newRefreshFixture(t)
	store := &ctxStore{MemoryStore: f.store}
	h := forwardingTokenHandler(f.tm, zap.NewNop(), store, f.idp, nil)

	code := sealForwardingCode(t, f.tm, f.clientUUID, fwdIdPRT)
	var sc sealedCode
	if err := f.tm.OpenJSON(code, &sc, token.PurposeCode); err != nil {
		t.Fatal(err)
	}
	postCodeGrant(t, h, f.encClientID, code)
	rt, sr := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
	postRefreshGrant(t, h, f.encClientID, rt)

	want := []string{replay.NamespacedKey("authz_code", sc.TokenID), replay.NamespacedKey("refresh", sr.TokenID)}
	if !slices.Equal(store.claimed, want) {
		t.Errorf("claimed keys = %v, want %v", store.claimed, want)
	}
}

// An IdP that does not rotate its refresh token: the one that was sent
// is kept on the refresh grant too.
func TestTokenRefresh_Forwarding_KeepsIdPRefreshTokenWhenNotRotated(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "", "", 3600))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
	rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil), f.encClientID, rt)
	_, newRT, _ := decodeTokenResponse(t, rr)
	var sr sealedRefresh
	if err := f.tm.OpenJSON(newRT, &sr, token.PurposeRefresh); err != nil || sr.IdPRefreshToken != "rt-2" {
		t.Errorf("rotated refresh carries IdP refresh token %q (err %v), want the one that was sent", sr.IdPRefreshToken, err)
	}
}

// A replayed refresh token is refused before it can spend a bucket token.
func TestTokenRefresh_Forwarding_ReplaysDoNotDrainIdPBucket(t *testing.T) {
	f := newRefreshFixture(t)
	h := f.handler(zap.NewNop(), rate.NewLimiter(0, 2))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
	if rr := postRefreshGrant(t, h, f.encClientID, rt); rr.Code != http.StatusOK {
		t.Fatalf("first refresh: %d %s", rr.Code, rr.Body.String())
	}
	for range 3 {
		postRefreshGrant(t, h, f.encClientID, rt)
	}
	other, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-9", time.Now())
	if rr := postRefreshGrant(t, h, f.encClientID, other); rr.Code != http.StatusOK {
		t.Errorf("another session after the replays: %d %s, want 200 (the bucket still has a token)", rr.Code, rr.Body.String())
	}
}

// An IdP refresh token too large for the refresh open() cap, on the code
// grant: 400, never the default-mode 500 (the code is already spent).
func TestToken_Forwarding_OversizedRefreshTokenRefused(t *testing.T) {
	f := newRefreshFixture(t)
	f.tm.SetMaxSealedLen(token.PurposeRefresh, token.ForwardingMaxSealedLen)
	f.idp.respond.Store(idpAnswer("at-2", strings.Repeat("r", 70<<10), "", 3600))
	rr := postCodeGrant(t, f.handler(zap.NewNop(), nil), f.encClientID, sealForwardingCode(t, f.tm, f.clientUUID, fwdIdPRT))
	if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.ErrorCode != codeTokenIssueFailed {
		t.Errorf("got %d %+v, want 400 invalid_grant / %s", rr.Code, body, codeTokenIssueFailed)
	}
}

// An email denial on refresh says nothing about the groups claim.
func TestTokenRefresh_Forwarding_EmailDenialSilentAboutGroups(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", fakeIDToken(map[string]any{"sub": "user-sub", "email_verified": false}), 3600))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
	core, logs := observer.New(zap.WarnLevel)

	rr := postRefreshGrant(t, f.handler(zap.New(core), nil), f.encClientID, rt)
	if body := oauthErrorOf(t, rr); body.ErrorCode != codeEmailNotVerified {
		t.Fatalf("got %d %+v, want %s", rr.Code, body, codeEmailNotVerified)
	}
	if logs.FilterMessage("idp_refresh_groups_claim_missing").Len() != 0 {
		t.Errorf("email denial also warned about the groups claim: %v", logs.All())
	}
}
