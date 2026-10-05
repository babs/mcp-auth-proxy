package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/time/rate"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/replay"
	"github.com/babs/mcp-auth-proxy/token"
)

// sealForwardingRefresh mints a refresh token as a forwarding-mode code
// grant does.
func sealForwardingRefresh(t *testing.T, tm *token.Manager, clientUUID, idpRT string, familyIssuedAt time.Time) (string, sealedRefresh) {
	t.Helper()
	now := time.Now()
	sr := sealedRefresh{
		TokenID:         uuid.New().String(),
		FamilyID:        uuid.New().String(),
		Subject:         "user-sub",
		Email:           "user@example.com",
		Groups:          []string{"staff"},
		ClientID:        clientUUID,
		Typ:             token.PurposeRefresh,
		Audience:        testBaseURL,
		IssuedAt:        now,
		FamilyIssuedAt:  familyIssuedAt,
		ExpiresAt:       now.Add(7 * 24 * time.Hour),
		IdPRefreshToken: idpRT,
	}
	tok, err := tm.SealJSON(sr, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	return tok, sr
}

func postRefreshGrant(t *testing.T, h http.HandlerFunc, encClientID, refreshToken string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {encClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

// idpAnswer is a refresh_token grant success; idToken may be empty.
func idpAnswer(at, rt, idToken string, expiresIn int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		body := map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": expiresIn}
		if rt != "" {
			body["refresh_token"] = rt
		}
		if idToken != "" {
			body["id_token"] = idToken
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

type refreshFixture struct {
	tm          *token.Manager
	encClientID string
	clientUUID  string
	idp         *fakeIdP
	store       *replay.MemoryStore
}

func newRefreshFixture(t *testing.T) *refreshFixture {
	t.Helper()
	tm := newTestTokenManager(t)
	tm.SetMaxSealedLen(token.PurposeAccess, token.ForwardingMaxSealedLen)
	encClientID, clientUUID := registerClient(t, tm, []string{fwdRedirectURI})
	store := replay.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })
	return &refreshFixture{tm: tm, encClientID: encClientID, clientUUID: clientUUID, idp: newFakeIdP(t), store: store}
}

func (f *refreshFixture) handler(logger *zap.Logger, limiter *rate.Limiter, allowedGroups ...string) http.HandlerFunc {
	return forwardingTokenHandler(f.tm, logger, f.store, f.idp, limiter, allowedGroups...)
}

func TestTokenRefresh_Forwarding_RenewsIdPTokens(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", fakeIDToken(map[string]any{
		"sub": "user-sub", "email": "user@example.com", "groups": []string{"staff"},
	}), 1800))
	rt, prev := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

	rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil), f.encClientID, rt)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	form := f.idp.lastForm.Load().(url.Values)
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "rt-2" || form.Get("scope") == "" {
		t.Errorf("IdP received %v, want a refresh grant with the sealed token and an explicit scope", form)
	}

	at, newRT, expiresIn := decodeTokenResponse(t, rr)
	if expiresIn > 29*60 || expiresIn < 29*60-5 {
		t.Errorf("expires_in = %d, want ~%d", expiresIn, 29*60)
	}
	claims, err := f.tm.Validate(at)
	if err != nil {
		t.Fatal(err)
	}
	if claims.IdPAccessToken != "at-2" {
		t.Errorf("access token carries %q, want the renewed IdP access token", claims.IdPAccessToken)
	}
	var sr sealedRefresh
	if err := f.tm.OpenJSON(newRT, &sr, token.PurposeRefresh); err != nil {
		t.Fatal(err)
	}
	if sr.IdPRefreshToken != "rt-3" || sr.FamilyID != prev.FamilyID || !sr.FamilyIssuedAt.Equal(prev.FamilyIssuedAt) {
		t.Errorf("rotated refresh = %+v, want rt-3 in the same family", sr)
	}
	for _, secret := range []string{"at-2", "rt-2", "rt-3"} {
		if strings.Contains(rr.Body.String(), `"`+secret+`"`) {
			t.Errorf("token response carries IdP token %q in clear", secret)
		}
	}
}

func TestTokenRefresh_Forwarding_IdPRejectionNeedsSignIn(t *testing.T) {
	for _, code := range []string{"invalid_grant", "interaction_required"} {
		t.Run(code, func(t *testing.T) {
			f := newRefreshFixture(t)
			f.idp.fail(http.StatusBadRequest, code)
			rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

			rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil), f.encClientID, rt)
			if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.ErrorCode != codeIdPRefreshRejected {
				t.Errorf("got %d %+v, want 400 invalid_grant / %s", rr.Code, body, codeIdPRefreshRejected)
			}
		})
	}
}

// IdP 5xx, timeout or local throttle: 503, and the SAME refresh token
// works once the IdP is back.
func TestTokenRefresh_Forwarding_TransientFailuresKeepRefreshToken(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(f *refreshFixture)
		limiter func() *rate.Limiter
		code    string
	}{
		{name: "idp_5xx", setup: func(f *refreshFixture) { f.idp.fail(http.StatusInternalServerError, "server_error") }, code: codeIdPRefreshUnavailable},
		{name: "idp_429", setup: func(f *refreshFixture) { f.idp.fail(http.StatusTooManyRequests, "slow_down") }, code: codeIdPRefreshUnavailable},
		{name: "throttled", setup: func(*refreshFixture) {}, limiter: func() *rate.Limiter { return rate.NewLimiter(0, 0) }, code: codeIdPExchangeThrottled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshFixture(t)
			tc.setup(f)
			var limiter *rate.Limiter
			if tc.limiter != nil {
				limiter = tc.limiter()
			}
			rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

			rr := postRefreshGrant(t, f.handler(zap.NewNop(), limiter), f.encClientID, rt)
			if body := oauthErrorOf(t, rr); rr.Code != http.StatusServiceUnavailable || body.Error != "temporarily_unavailable" || body.ErrorCode != tc.code {
				t.Fatalf("got %d %+v, want 503 temporarily_unavailable / %s", rr.Code, body, tc.code)
			}
			if rr.Header().Get("Retry-After") == "" {
				t.Error("503 without Retry-After")
			}

			f.idp.respond.Store(idpAnswer("at-2", "rt-3", "", 3600))
			// Outside the grace window as well: a released claim must
			// not read as a racing peer either.
			if again := postRefreshGrant(t, f.handler(zap.NewNop(), nil), f.encClientID, rt); again.Code != http.StatusOK {
				t.Fatalf("retry with the same refresh token: %d %s, want 200", again.Code, again.Body.String())
			}
		})
	}
}

func TestTokenRefresh_Forwarding_Timeout(t *testing.T) {
	f := newRefreshFixture(t)
	block := make(chan struct{})
	defer close(block)
	f.idp.respond.Store(func(http.ResponseWriter) { waitOrGiveUp(block) })
	cfg := TokenConfig{
		ForwardIdPToken: true,
		IdPRefresher:    f.idp.refresher(),
		VerifyIDToken:   fakeVerifyIDToken,
	}
	cfg.IdPRefresher.timeout = 200 * time.Millisecond
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

	rr := postRefreshGrant(t, Token(f.tm, zap.NewNop(), testBaseURL, time.Time{}, f.store, cfg), f.encClientID, rt)
	if body := oauthErrorOf(t, rr); rr.Code != http.StatusServiceUnavailable || body.ErrorCode != codeIdPRefreshUnavailable {
		t.Errorf("got %d %+v, want 503 %s", rr.Code, body, codeIdPRefreshUnavailable)
	}
}

func TestTokenRefresh_Forwarding_SubjectMismatchRefused(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", fakeIDToken(map[string]any{"sub": "someone-else"}), 3600))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

	rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil), f.encClientID, rt)
	if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.ErrorCode != codeIDTokenVerificationFailed {
		t.Errorf("got %d %+v, want 400 invalid_grant / %s", rr.Code, body, codeIDTokenVerificationFailed)
	}
	if strings.Contains(rr.Body.String(), "access_token") {
		t.Error("tokens issued despite a subject mismatch")
	}
}

func TestTokenRefresh_Forwarding_GroupRemovalBlocksAtNextRefresh(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", fakeIDToken(map[string]any{"sub": "user-sub", "groups": []string{"interns"}}), 3600))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

	rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil, "staff"), f.encClientID, rt)
	if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.ErrorCode != codeGroupNotAllowed {
		t.Errorf("got %d %+v, want 400 invalid_grant / %s", rr.Code, body, codeGroupNotAllowed)
	}
}

func TestTokenRefresh_Forwarding_IdentityPolicyReapplied(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		code   string
	}{
		{name: "email_unverified", claims: map[string]any{"sub": "user-sub", "email_verified": false, "groups": []string{"staff"}}, code: codeEmailNotVerified},
		{name: "group_invalid", claims: map[string]any{"sub": "user-sub", "groups": []string{"staff,admins"}}, code: codeGroupInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRefreshFixture(t)
			f.idp.respond.Store(idpAnswer("at-2", "rt-3", fakeIDToken(tc.claims), 3600))
			rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

			rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil), f.encClientID, rt)
			if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.ErrorCode != tc.code {
				t.Errorf("got %d %+v, want 400 %s", rr.Code, body, tc.code)
			}
		})
	}
}

// A verified refresh id_token updates email and groups.
func TestTokenRefresh_Forwarding_IdentityUpdatedFromVerifiedIDToken(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", fakeIDToken(map[string]any{
		"sub": "user-sub", "email": "renamed@example.com", "groups": []string{"staff", "leads"},
	}), 3600))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

	rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil, "staff"), f.encClientID, rt)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	at, newRT, _ := decodeTokenResponse(t, rr)
	claims, _ := f.tm.Validate(at)
	if claims.Email != "renamed@example.com" || !slices.Equal(claims.Groups, []string{"staff", "leads"}) {
		t.Errorf("access token identity = %q %q, want the refreshed values", claims.Email, claims.Groups)
	}
	var sr sealedRefresh
	_ = f.tm.OpenJSON(newRT, &sr, token.PurposeRefresh)
	if sr.Email != "renamed@example.com" || !slices.Equal(sr.Groups, []string{"staff", "leads"}) {
		t.Errorf("rotated refresh identity = %q %q, want the refreshed values", sr.Email, sr.Groups)
	}
}

// An absent id_token keeps the previous identity and logs a warning.
func TestTokenRefresh_Forwarding_NoIDTokenKeepsPrevious(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", "", 3600))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
	core, logs := observer.New(zap.WarnLevel)

	rr := postRefreshGrant(t, f.handler(zap.New(core), nil, "staff"), f.encClientID, rt)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	at, _, _ := decodeTokenResponse(t, rr)
	claims, _ := f.tm.Validate(at)
	if claims.Email != "user@example.com" || !slices.Equal(claims.Groups, []string{"staff"}) {
		t.Errorf("identity = %q %q, want the previous values unchanged", claims.Email, claims.Groups)
	}
	if logs.FilterMessage("idp_refresh_id_token_missing").Len() != 1 {
		t.Errorf("no idp_refresh_id_token_missing warning; got %v", logs.All())
	}
}

// A present id_token that fails verification is refused: keeping the
// previous groups would let a removed user outlast an IdP key problem.
func TestTokenRefresh_Forwarding_UnverifiableIDTokenRefused(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", `{"sub":"user-sub","groups":["staff"]}`, 3600))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
	core, logs := observer.New(zap.WarnLevel)
	denied := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("id_token_verification_failed"))

	rr := postRefreshGrant(t, f.handler(zap.New(core), nil, "staff"), f.encClientID, rt)
	if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.ErrorCode != codeIDTokenVerificationFailed {
		t.Fatalf("got %d %+v, want 400 invalid_grant / %s", rr.Code, body, codeIDTokenVerificationFailed)
	}
	if logs.FilterMessage("idp_refresh_id_token_unverified").Len() != 1 {
		t.Errorf("no idp_refresh_id_token_unverified warning; got %v", logs.All())
	}
	if got := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("id_token_verification_failed")) - denied; got != 1 {
		t.Errorf("access_denied{id_token_verification_failed} delta = %v, want 1", got)
	}
}

// A verified id_token without an email keeps the previous one, on both
// the access token and the rotated refresh token.
func TestTokenRefresh_Forwarding_MissingEmailKeepsPrevious(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", fakeIDToken(map[string]any{"sub": "user-sub", "groups": []string{"staff"}}), 3600))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

	rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil, "staff"), f.encClientID, rt)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	at, newRT, _ := decodeTokenResponse(t, rr)
	claims, _ := f.tm.Validate(at)
	var sr sealedRefresh
	_ = f.tm.OpenJSON(newRT, &sr, token.PurposeRefresh)
	if claims.Email != "user@example.com" || sr.Email != "user@example.com" {
		t.Errorf("email = %q / %q, want the previous one kept", claims.Email, sr.Email)
	}
}

// An IdP token too short-lived to mint from: the refresh token is spent
// (the IdP already rotated), so the answer is 400, never a 5xx.
func TestTokenRefresh_Forwarding_IdPTokenTooShortLived(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", "", 90))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

	rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil), f.encClientID, rt)
	if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.ErrorCode != codeTokenIssueFailed {
		t.Fatalf("got %d %+v, want 400 invalid_grant / %s", rr.Code, body, codeTokenIssueFailed)
	}
}

// A refresh token minted before forwarding was switched on: refused
// without an IdP call and without burning it.
func TestTokenRefresh_Forwarding_PreUpgradeRefreshToken(t *testing.T) {
	f := newRefreshFixture(t)
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "", time.Now())
	h := f.handler(zap.NewNop(), nil)

	for range 2 {
		rr := postRefreshGrant(t, h, f.encClientID, rt)
		if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.ErrorCode != codeIdPTokenMissing {
			t.Fatalf("got %d %+v, want 400 %s (not reuse on the second try)", rr.Code, body, codeIdPTokenMissing)
		}
	}
	if n := f.idp.calls.Load(); n != 0 {
		t.Errorf("IdP called %d times", n)
	}
}

// REVOKE_BEFORE and a revoked family refuse exactly as today, without
// calling the IdP.
func TestTokenRefresh_Forwarding_RevocationNeverReachesIdP(t *testing.T) {
	t.Run("revoke_before", func(t *testing.T) {
		f := newRefreshFixture(t)
		rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now().Add(-time.Hour))
		h := Token(f.tm, zap.NewNop(), testBaseURL, time.Now().Add(-time.Minute), f.store, TokenConfig{
			ForwardIdPToken: true, IdPRefresher: f.idp.refresher(), VerifyIDToken: fakeVerifyIDToken,
		})
		rr := postRefreshGrant(t, h, f.encClientID, rt)
		if body := oauthErrorOf(t, rr); body.ErrorCode != codeRefreshRevokedCutoff {
			t.Errorf("got %+v, want %s", body, codeRefreshRevokedCutoff)
		}
		if n := f.idp.calls.Load(); n != 0 {
			t.Errorf("IdP called %d times", n)
		}
	})
	t.Run("family_revoked", func(t *testing.T) {
		f := newRefreshFixture(t)
		rt, sr := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
		_ = f.store.Mark(t.Context(), replay.NamespacedKey("refresh_family_revoked", sr.FamilyID), time.Hour)
		rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil), f.encClientID, rt)
		if body := oauthErrorOf(t, rr); body.ErrorCode != codeRefreshFamilyRevoked {
			t.Errorf("got %+v, want %s", body, codeRefreshFamilyRevoked)
		}
		if n := f.idp.calls.Load(); n != 0 {
			t.Errorf("IdP called %d times", n)
		}
	})
}

// Two submits of the same refresh token inside REFRESH_RACE_GRACE_SEC:
// one wins, the other gets 429, the IdP is called once.
func TestTokenRefresh_Forwarding_RacingDoubleSubmit(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", "", 3600))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
	h := Token(f.tm, zap.NewNop(), testBaseURL, time.Time{}, f.store, TokenConfig{
		RefreshRaceGrace: 5 * time.Second,
		ForwardIdPToken:  true, IdPRefresher: f.idp.refresher(), VerifyIDToken: fakeVerifyIDToken,
	})

	first := postRefreshGrant(t, h, f.encClientID, rt)
	second := postRefreshGrant(t, h, f.encClientID, rt)
	if first.Code != http.StatusOK {
		t.Fatalf("first submit: %d %s", first.Code, first.Body.String())
	}
	if body := oauthErrorOf(t, second); second.Code != http.StatusTooManyRequests || body.ErrorCode != codeRefreshConcurrent {
		t.Errorf("second submit: %d %+v, want 429 %s", second.Code, body, codeRefreshConcurrent)
	}
	if n := f.idp.calls.Load(); n != 1 {
		t.Errorf("IdP called %d times, want 1", n)
	}
}

// Default mode: the refresh grant never calls an IdP and keeps its
// fixed expires_in.
func TestTokenRefresh_DefaultModeUnchanged(t *testing.T) {
	f := newRefreshFixture(t)
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-left-over", time.Now())
	rr := postRefreshGrant(t, Token(f.tm, zap.NewNop(), testBaseURL, time.Time{}, f.store, TokenConfig{}), f.encClientID, rt)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	at, newRT, expiresIn := decodeTokenResponse(t, rr)
	if expiresIn != 3600 {
		t.Errorf("expires_in = %d, want 3600", expiresIn)
	}
	if claims, _ := f.tm.Validate(at); claims.IdPAccessToken != "" {
		t.Error("default mode minted an access token with an IdP token")
	}
	var sr sealedRefresh
	_ = f.tm.OpenJSON(newRT, &sr, token.PurposeRefresh)
	if sr.IdPRefreshToken != "" {
		t.Error("default mode carried an IdP refresh token into the rotation")
	}
	if n := f.idp.calls.Load(); n != 0 {
		t.Errorf("IdP called %d times in default mode", n)
	}
}

// Throttled, and the claim cannot be given back: no retry invited.
func TestTokenRefresh_Forwarding_ThrottledReleaseFailure(t *testing.T) {
	f := newRefreshFixture(t)
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
	h := forwardingTokenHandler(f.tm, zap.NewNop(), releaseFailingStore{f.store}, f.idp, rate.NewLimiter(0, 0))

	rr := postRefreshGrant(t, h, f.encClientID, rt)
	if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.ErrorCode != codeIdPExchangeThrottled {
		t.Errorf("got %d %+v, want 400 invalid_grant / %s", rr.Code, body, codeIdPExchangeThrottled)
	}
	if rr.Header().Get("Retry-After") != "" {
		t.Error("Retry-After on a non-retryable answer")
	}
}

// A groups claim of the wrong shape on refresh reads as "no groups",
// exactly as at /callback, so ALLOWED_GROUPS refuses the refresh.
func TestTokenRefresh_Forwarding_GroupsShapeMismatch(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", fakeIDToken(map[string]any{"sub": "user-sub", "groups": "staff"}), 3600))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

	rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil, "staff"), f.encClientID, rt)
	if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.ErrorCode != codeGroupNotAllowed {
		t.Errorf("got %d %+v, want 400 %s", rr.Code, body, codeGroupNotAllowed)
	}
}

// A verified refresh id_token without the groups claim reads as "no
// groups", as at /callback, and says so in its own log line.
func TestTokenRefresh_Forwarding_GroupsClaimMissingIsLogged(t *testing.T) {
	f := newRefreshFixture(t)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", fakeIDToken(map[string]any{"sub": "user-sub", "email": "user@example.com"}), 3600))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())
	core, logs := observer.New(zap.WarnLevel)

	rr := postRefreshGrant(t, f.handler(zap.New(core), nil), f.encClientID, rt)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	at, _, _ := decodeTokenResponse(t, rr)
	if claims, _ := f.tm.Validate(at); len(claims.Groups) != 0 {
		t.Errorf("groups = %q, want none (fail closed, as at /callback)", claims.Groups)
	}
	if logs.FilterMessage("idp_refresh_groups_claim_missing").Len() != 1 {
		t.Errorf("no idp_refresh_groups_claim_missing warning; got %v", logs.All())
	}
}

// An IdP refresh token that would push the rotated refresh token past
// its open() cap is refused at mint time, not handed out unopenable.
func TestTokenRefresh_Forwarding_OversizedRefreshTokenRefused(t *testing.T) {
	f := newRefreshFixture(t)
	f.tm.SetMaxSealedLen(token.PurposeRefresh, token.ForwardingMaxSealedLen)
	f.idp.respond.Store(idpAnswer("at-2", strings.Repeat("r", 70<<10), "", 3600))
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

	rr := postRefreshGrant(t, f.handler(zap.NewNop(), nil), f.encClientID, rt)
	if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.ErrorCode != codeTokenIssueFailed {
		t.Errorf("got %d %+v, want 400 invalid_grant / %s", rr.Code, body, codeTokenIssueFailed)
	}
}

// After a timeout the same refresh token works once the IdP answers.
func TestTokenRefresh_Forwarding_TimeoutThenRetry(t *testing.T) {
	f := newRefreshFixture(t)
	block := make(chan struct{})
	f.idp.respond.Store(func(http.ResponseWriter) { waitOrGiveUp(block) })
	refresher := f.idp.refresher()
	refresher.timeout = 200 * time.Millisecond
	h := Token(f.tm, zap.NewNop(), testBaseURL, time.Time{}, f.store, TokenConfig{
		ForwardIdPToken: true, IdPRefresher: refresher, VerifyIDToken: fakeVerifyIDToken,
	})
	rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2", time.Now())

	if rr := postRefreshGrant(t, h, f.encClientID, rt); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("timeout: %d %s, want 503", rr.Code, rr.Body.String())
	}
	close(block)
	f.idp.respond.Store(idpAnswer("at-2", "rt-3", "", 3600))
	if rr := postRefreshGrant(t, h, f.encClientID, rt); rr.Code != http.StatusOK {
		t.Fatalf("retry after timeout: %d %s, want 200", rr.Code, rr.Body.String())
	}
}

// No IdP token value may reach a log line on any refresh-grant path,
// identity re-check included.
func TestTokenRefresh_Forwarding_NeverLogsIdPTokens(t *testing.T) {
	f := newRefreshFixture(t)
	core, logs := observer.New(zap.DebugLevel)
	h := f.handler(zap.New(core), nil, "staff")
	echo := func(status int, code string) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "grant rt-2-secret refused"})
		}
	}
	for _, respond := range []func(http.ResponseWriter){
		idpAnswer("at-2-secret", "rt-3-secret", fakeIDToken(map[string]any{"sub": "user-sub", "groups": []string{"staff"}}), 3600),
		idpAnswer("at-2-secret", "rt-3-secret", "", 3600),
		idpAnswer("at-2-secret", "rt-3-secret", "not-a-valid-id-token", 3600),
		idpAnswer("at-2-secret", "rt-3-secret", fakeIDToken(map[string]any{"sub": "someone-else"}), 3600),
		idpAnswer("at-2-secret", "rt-3-secret", fakeIDToken(map[string]any{"sub": "user-sub", "groups": []string{"interns"}}), 3600),
		echo(http.StatusBadRequest, "invalid_grant"),
		echo(http.StatusInternalServerError, "server_error"),
		echo(http.StatusBadRequest, "invalid_request"),
	} {
		f.idp.respond.Store(respond)
		rt, _ := sealForwardingRefresh(t, f.tm, f.clientUUID, "rt-2-secret", time.Now())
		postRefreshGrant(t, h, f.encClientID, rt)
	}

	for _, event := range []string{"token_refreshed", "idp_refresh_id_token_missing", "idp_refresh_id_token_unverified", "idp_refresh_subject_mismatch", "access_denied_group", "idp_refresh_rejected", "idp_refresh_unavailable", "idp_refresh_failed"} {
		if logs.FilterMessage(event).Len() == 0 {
			t.Errorf("no %q line captured — the hygiene check would not cover that path", event)
		}
	}
	for _, entry := range logs.All() {
		line := entry.Message
		for k, v := range entry.ContextMap() {
			line += " " + k + "=" + toString(v)
		}
		for _, secret := range []string{"at-2-secret", "rt-2-secret", "rt-3-secret"} {
			if strings.Contains(line, secret) {
				t.Errorf("log line carries an IdP token: %s", line)
			}
		}
	}
}
