package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

// authorizeConsentEnabled mirrors the production wiring of /authorize
// with RenderConsentPage=true. Used to drive the GET /authorize →
// HTML consent page path in handler-level tests.
func authorizeConsentEnabled(tm *token.Manager) http.HandlerFunc {
	return Authorize(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), AuthorizeConfig{
		PKCERequired:      true,
		ResourceURIs:      []string{testBaseURL + "/mcp"},
		CanonicalResource: testBaseURL + "/mcp",
		RenderConsentPage: true,
		ResourceName:      "ACME MCP",
	})
}

// TestAuthorize_RenderConsentPage_HTMLOnApproval pins the GET-side
// of the consent flow: with RenderConsentPage=true, /authorize stops
// after parameter validation and returns a 200 HTML page that
// embeds the sealed consent token. No upstream IdP redirect happens
// at this stage.
func TestAuthorize_RenderConsentPage_HTMLOnApproval(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, _ := registerClientNamed(t, tm, []string{"https://app.example.com/callback"}, "Friendly App")

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := pkceChallenge(codeVerifier)

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	authorizeConsentEnabled(tm)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 HTML, got %d: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html...", ct)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Friendly App") {
		t.Errorf("client_name not rendered in HTML: %q", body)
	}
	if !strings.Contains(body, "ACME MCP") {
		t.Errorf("resource_name not rendered in HTML")
	}
	if !strings.Contains(body, "app.example.com") {
		t.Errorf("redirect host not rendered")
	}
	if !strings.Contains(body, `name="consent_token"`) {
		t.Errorf("consent_token form field missing")
	}
	if !strings.Contains(body, `value="approve"`) || !strings.Contains(body, `value="deny"`) {
		t.Errorf("approve/deny buttons missing")
	}
}

// TestAuthorize_RenderConsentPage_EscapesAttackerClientName pins the
// XSS defense: a malicious client_name registered via DCR cannot
// inject script tags or attribute breakouts into the consent page.
// html/template's contextual escaping is the primary defense; DCR's
// control-byte filter on client_name is a separate layer.
func TestAuthorize_RenderConsentPage_EscapesAttackerClientName(t *testing.T) {
	tm := newTestTokenManager(t)
	const xssAttempt = `<script>alert(1)</script><img src=x onerror=alert(2)>`
	encClientID, _ := registerClientNamed(t, tm, []string{"https://app.example.com/callback"}, xssAttempt)

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := pkceChallenge(codeVerifier)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {"s"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	authorizeConsentEnabled(tm)(rr, req)

	body := rr.Body.String()
	// Real XSS check: the attacker's brackets must come through
	// HTML-escaped so the browser parses them as text, not as
	// tags. The literal substring "onerror=" can still appear in
	// the rendered text — that's just escaped content, no script
	// execution.
	if strings.Contains(body, "<script>") {
		t.Errorf("unescaped <script> tag reached HTML output")
	}
	if strings.Contains(body, "<img ") {
		t.Errorf("unescaped <img tag reached HTML output")
	}
	// Escaped form must be present.
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("expected HTML-escaped form of <script>, got: %q", body)
	}
	if !strings.Contains(body, "&lt;img") {
		t.Errorf("expected HTML-escaped form of <img, got: %q", body)
	}
}

// TestConsent_DenyRedirectsAccessDenied pins the deny path: POST
// /consent with action=deny and a valid sealed token MUST 302 to
// the registered redirect_uri with error=access_denied per
// RFC 6749 §4.1.2.1, carrying back the original state, with a
// proxy-owned (NOT attacker-controlled) error_description.
func TestConsent_DenyRedirectsAccessDenied(t *testing.T) {
	tm := newTestTokenManager(t)
	consentToken := mintConsentToken(t, tm, "https://app.example.com/cb", "client-state")

	form := url.Values{
		"consent_token": {consentToken},
		"action":        {"deny"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("want 302, got %d: %s", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Query().Get("error") != "access_denied" {
		t.Errorf("error = %q, want access_denied", loc.Query().Get("error"))
	}
	if loc.Query().Get("state") != "client-state" {
		t.Errorf("state lost on deny redirect: %q", loc.Query().Get("state"))
	}
	if loc.Host != "app.example.com" {
		t.Errorf("redirect host changed: %q", loc.Host)
	}
	// Pin the proxy-owned, fixed error_description. Mirrors the c6
	// posture on /callback's IdP-error path — a regression that
	// started forwarding caller-supplied text would otherwise slip.
	if got := loc.Query().Get("error_description"); got != "user declined to authorize this client" {
		t.Errorf("error_description = %q, want fixed proxy-owned text", got)
	}
}

// TestConsent_ApproveRedirectsToIdP pins the approve path: POST
// /consent with action=approve and a valid token replays Phase-3 of
// /authorize and 302s to the upstream IdP authorize endpoint, NOT
// to the client's redirect_uri. Also asserts the sealed session
// inherits the consent blob's resource binding (RFC 8707) so a
// regression that loses the binding through the consent fork is
// caught here rather than far downstream at the bearer middleware.
func TestConsent_ApproveRedirectsToIdP(t *testing.T) {
	tm := newTestTokenManager(t)
	consentToken := mintConsentToken(t, tm, "https://app.example.com/cb", "s")

	form := url.Values{
		"consent_token": {consentToken},
		"action":        {"approve"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("want 302, got %d: %s", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	// Upstream IdP host comes from testOAuth2Config().Endpoint.AuthURL.
	// Anything other than the IdP origin (or the client's redirect)
	// is a bug; check it's the IdP, not the client redirect.
	if loc.Host == "app.example.com" {
		t.Errorf("approve redirected to client redirect_uri, want IdP host")
	}
	// state on the IdP redirect is the proxy's sealed session blob,
	// NOT the client's state. The client's state is preserved
	// inside the sealed session for /callback to forward.
	idpState := loc.Query().Get("state")
	if idpState == "s" {
		t.Errorf("client state leaked into IdP redirect; expected sealed session blob")
	}

	// Open the sealed session and pin the resource pass-through.
	// mintConsentToken sets Resource=testBaseURL+"/mcp"; the session
	// MUST inherit it so the eventual access / refresh tokens carry
	// the same RFC 8707 binding the client requested at /authorize.
	var sess sealedSession
	if err := tm.OpenJSON(idpState, &sess, token.PurposeSession); err != nil {
		t.Fatalf("OpenJSON sealed session from IdP redirect: %v", err)
	}
	if sess.Resource != testBaseURL+"/mcp" {
		t.Errorf("sealedSession.Resource = %q, want %q (consent fork dropped the RFC 8707 binding)", sess.Resource, testBaseURL+"/mcp")
	}
	if sess.OriginalState != "s" {
		t.Errorf("sealedSession.OriginalState = %q, want %q", sess.OriginalState, "s")
	}
}

// TestConsent_ApproveSvrPKCE_H6 pins the H6 path through /consent:
// when the consent blob recorded that /authorize was operating in
// PKCE-relaxed mode without a client-supplied code_challenge
// (SvrChallengeRequested=true), the approve handler regenerates a
// server-side PKCE pair, seals SvrVerifier into the session, and
// uses SvrChallenge as the session.CodeChallenge. /token then
// validates the verifier internally on code redemption — same H6
// invariant the silent /authorize path enforces.
func TestConsent_ApproveSvrPKCE_H6(t *testing.T) {
	tm := newTestTokenManager(t)
	// Mint a consent blob with SvrChallengeRequested=true and an
	// empty CodeChallenge — the production shape /authorize seals
	// when PKCE_REQUIRED=false AND client omitted code_challenge.
	consent := sealedConsent{
		ClientID:              uuid.New().String(),
		ClientName:            "Relaxed Client",
		RedirectURI:           "https://app.example.com/cb",
		OriginalState:         "s",
		CodeChallenge:         "", // client did NOT supply one
		SvrChallengeRequested: true,
		Resource:              testBaseURL + "/mcp",
		Typ:                   token.PurposeConsent,
		Audience:              testBaseURL,
		ExpiresAt:             time.Now().Add(consentTTL),
	}
	consentToken, err := tm.SealJSON(consent, token.PurposeConsent)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	form := url.Values{
		"consent_token": {consentToken},
		"action":        {"approve"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{})(rr, req)

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
		t.Fatalf("OpenJSON sealed session: %v", err)
	}
	if sess.SvrVerifier == "" {
		t.Errorf("sealedSession.SvrVerifier empty — H6 server-side PKCE was supposed to be regenerated")
	}
	if sess.SvrChallenge == "" {
		t.Errorf("sealedSession.SvrChallenge empty — H6 server-side PKCE pair incomplete")
	}
	// The challenge MUST be SHA256(verifier) base64-url. Same shape
	// /token verifies on code redemption.
	if got := ComputePKCEChallenge(sess.SvrVerifier); got != sess.SvrChallenge {
		t.Errorf("SvrChallenge != SHA256(SvrVerifier): got %q, want %q", sess.SvrChallenge, got)
	}
	// And the session.CodeChallenge MUST equal SvrChallenge so /token
	// uses the server-minted pair as the PKCE anchor when the client
	// itself has none.
	if sess.CodeChallenge != sess.SvrChallenge {
		t.Errorf("CodeChallenge (%q) should mirror SvrChallenge (%q) on the H6 path", sess.CodeChallenge, sess.SvrChallenge)
	}
}

// TestConsent_RelaxedCSP pins the consent-page CSP override: the
// shared securityHeaders middleware emits `default-src 'none'`
// which blocks the inline <style> block on the consent page; the
// handler overrides CSP for this response only to add
// `style-src 'unsafe-inline'`. Pin both arms — relaxed on consent,
// strict everywhere else — so a future renderConsent change that
// drops the override (page renders unstyled) or loosens it further
// (script-src 'unsafe-inline'?) is caught.
func TestConsent_RelaxedCSP(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, _ := registerClientNamed(t, tm, []string{"https://app.example.com/callback"}, "App")
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := pkceChallenge(codeVerifier)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {"s"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	authorizeConsentEnabled(tm)(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "style-src 'unsafe-inline'") {
		t.Errorf("consent CSP missing style-src 'unsafe-inline' (inline <style> would be blocked): got %q", csp)
	}
	if strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Errorf("consent CSP must NOT relax script-src; the page is JS-free: got %q", csp)
	}
	// Other directives that lock down the page must still be present.
	for _, want := range []string{
		"default-src 'none'",
		"frame-ancestors 'none'",
		"form-action 'self'",
		"base-uri 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("consent CSP missing %q: got %q", want, csp)
		}
	}
}

// TestConsent_DecisionCounters pins the funnel-counter contract:
// every Approve increments mcp_auth_consent_decisions_total{decision=
// "approved"}, every Deny increments {decision="denied"}, and Deny
// MUST NOT bleed into mcp_auth_access_denied_total — that family is
// reserved for actual policy rejections, runbooks alert on it.
func TestConsent_DecisionCounters(t *testing.T) {
	tm := newTestTokenManager(t)
	post := func(t *testing.T, action string) {
		t.Helper()
		consentToken := mintConsentToken(t, tm, "https://app.example.com/cb", "s")
		form := url.Values{
			"consent_token": {consentToken},
			"action":        {action},
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/consent", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{})(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("%s: want 302, got %d: %s", action, rr.Code, rr.Body.String())
		}
	}

	approvedBefore := testutil.ToFloat64(metrics.ConsentDecisions.WithLabelValues("approved"))
	deniedBefore := testutil.ToFloat64(metrics.ConsentDecisions.WithLabelValues("denied"))
	accessDeniedBefore := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("consent_denied"))

	post(t, "approve")
	post(t, "deny")

	if delta := testutil.ToFloat64(metrics.ConsentDecisions.WithLabelValues("approved")) - approvedBefore; delta != 1 {
		t.Errorf("ConsentDecisions{approved} delta = %v, want 1", delta)
	}
	if delta := testutil.ToFloat64(metrics.ConsentDecisions.WithLabelValues("denied")) - deniedBefore; delta != 1 {
		t.Errorf("ConsentDecisions{denied} delta = %v, want 1", delta)
	}
	if delta := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("consent_denied")) - accessDeniedBefore; delta != 0 {
		t.Errorf("AccessDenied{consent_denied} must NOT increment on user-driven deny: delta = %v", delta)
	}
}

// TestConsent_RejectsURLQueryParams pins the same defense /token
// applies: the sealed consent_token must never be carried in the
// URL query — it would land in access logs, browser history, and
// Referer headers.
func TestConsent_RejectsURLQueryParams(t *testing.T) {
	tm := newTestTokenManager(t)
	consentToken := mintConsentToken(t, tm, "https://app.example.com/cb", "s")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		"/consent?consent_token="+url.QueryEscape(consentToken)+"&action=approve",
		strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{})(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for URL-query consent_token, got %d: %s", rr.Code, rr.Body.String())
	}
	var e OAuthError
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if e.Error != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", e.Error)
	}
}

// TestConsent_RejectsBadInputs covers the negative space: missing
// token, foreign-purpose token, expired token, audience mismatch,
// unknown action, Authorization header set, no consent_token field.
func TestConsent_RejectsBadInputs(t *testing.T) {
	tm := newTestTokenManager(t)
	cases := []struct {
		name        string
		consent     string
		action      string
		extraHeader [2]string // {name, value}; "" name to skip
		wantStatus  int
		wantError   string
	}{
		{name: "no_consent_token", consent: "", action: "approve",
			wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "garbage_consent_token", consent: "not-a-real-blob", action: "approve",
			wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "unknown_action", consent: mintConsentToken(t, tm, "https://app.example.com/cb", "s"), action: "shrug",
			wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "authorization_header_present",
			consent: mintConsentToken(t, tm, "https://app.example.com/cb", "s"), action: "approve",
			extraHeader: [2]string{"Authorization", "Basic dXNlcjpwYXNz"},
			wantStatus:  http.StatusUnauthorized, wantError: "invalid_client"},
		{name: "foreign_purpose_token",
			consent: foreignPurposeToken(t, tm), action: "approve",
			wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "expired_token",
			consent: expiredConsentToken(t, tm), action: "approve",
			wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "audience_mismatch_token",
			consent: foreignAudienceConsentToken(t, tm), action: "approve",
			wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{
				"action": {tc.action},
			}
			if tc.consent != "" {
				form.Set("consent_token", tc.consent)
			}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/consent", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.extraHeader[0] != "" {
				req.Header.Set(tc.extraHeader[0], tc.extraHeader[1])
			}
			rr := httptest.NewRecorder()
			Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{})(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tc.wantStatus, rr.Body.String())
			}
			var e OAuthError
			_ = json.Unmarshal(rr.Body.Bytes(), &e)
			if e.Error != tc.wantError {
				t.Errorf("error = %q, want %q", e.Error, tc.wantError)
			}
		})
	}
}

// --- helpers ---

func registerClientNamed(t *testing.T, tm *token.Manager, redirectURIs []string, name string) (encClientID, internalUUID string) {
	t.Helper()
	internalUUID = uuid.New().String()
	sc := sealedClient{
		ID:           internalUUID,
		RedirectURIs: redirectURIs,
		ClientName:   name,
		Typ:          token.PurposeClient,
		Audience:     testBaseURL,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}
	enc, err := tm.SealJSON(sc, token.PurposeClient)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	return enc, internalUUID
}

func mintConsentToken(t *testing.T, tm *token.Manager, redirectURI, state string) string {
	t.Helper()
	consent := sealedConsent{
		ClientID:      uuid.New().String(),
		ClientName:    "Friendly App",
		RedirectURI:   redirectURI,
		OriginalState: state,
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

func foreignPurposeToken(t *testing.T, tm *token.Manager) string {
	t.Helper()
	// A sealedSession blob (different AAD purpose) MUST NOT open as
	// a consent token.
	tok, err := tm.SealJSON(sealedSession{
		Typ:       token.PurposeSession,
		Audience:  testBaseURL,
		ExpiresAt: time.Now().Add(time.Minute),
	}, token.PurposeSession)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	return tok
}

// foreignAudienceConsentToken seals a consent blob whose Audience
// names a different proxy origin. Pins the per-Audience binding on
// PurposeConsent — a token minted by a sibling deployment that
// happens to share the signing secret MUST NOT open here.
func foreignAudienceConsentToken(t *testing.T, tm *token.Manager) string {
	t.Helper()
	consent := sealedConsent{
		ClientID:    uuid.New().String(),
		RedirectURI: "https://app.example.com/cb",
		Resource:    "https://other-proxy.example.com/mcp",
		Typ:         token.PurposeConsent,
		Audience:    "https://other-proxy.example.com",
		ExpiresAt:   time.Now().Add(consentTTL),
	}
	tok, err := tm.SealJSON(consent, token.PurposeConsent)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	return tok
}

func expiredConsentToken(t *testing.T, tm *token.Manager) string {
	t.Helper()
	consent := sealedConsent{
		ClientID:    uuid.New().String(),
		RedirectURI: "https://app.example.com/cb",
		Resource:    testBaseURL + "/mcp",
		Typ:         token.PurposeConsent,
		Audience:    testBaseURL,
		ExpiresAt:   time.Now().Add(-1 * time.Minute),
	}
	tok, err := tm.SealJSON(consent, token.PurposeConsent)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	return tok
}
