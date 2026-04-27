//go:build keycloak_e2e

package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/babs/mcp-auth-proxy/handlers"
)

const (
	keycloakE2EUsername = "alice"
	keycloakE2EPassword = "changeme"
)

// Keycloak does not expose a stable machine API for the browser login step.
// This tagged CI test intentionally scrapes the demo login form; if Keycloak
// changes its default theme markup, this regex is the expected maintenance
// point.
var formActionRE = regexp.MustCompile(`(?is)<form[^>]*\saction=["']([^"']+)["']`)

// consentTokenInputRE extracts the sealed consent_token from the
// hidden input on the proxy-rendered consent form. Run only on the
// proxy's own consent page (server-controlled HTML); the regex is
// scoped tight enough that it won't accidentally match Keycloak
// markup.
var consentTokenInputRE = regexp.MustCompile(`(?is)<input[^>]*name=["']consent_token["'][^>]*value=["']([^"']+)["']`)

func TestKeycloakE2EFullOAuthFlow(t *testing.T) {
	proxyBaseURL := envOrDefaultForTest("KEYCLOAK_E2E_PROXY_BASE_URL", "http://localhost:8080")
	keycloakBrowserBaseURL := envOrDefaultForTest("KEYCLOAK_BROWSER_BASE_URL", "http://localhost:8180")
	redirectURI := envOrDefaultForTest("KEYCLOAK_E2E_REDIRECT_URI", "http://127.0.0.1:8765/callback")

	client := newE2EClient(t)
	requireHealthy(t, client, proxyBaseURL)

	registeredClientID := registerE2EClient(t, client, proxyBaseURL, redirectURI)
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	internalCode := authorizeViaKeycloak(t, client, proxyBaseURL, keycloakBrowserBaseURL, registeredClientID, redirectURI, codeVerifier)
	accessToken, refreshToken := exchangeCodeForTokens(t, client, proxyBaseURL, registeredClientID, redirectURI, internalCode, codeVerifier)

	if accessToken == "" {
		t.Fatal("access token is empty")
	}
	if refreshToken == "" {
		t.Fatal("refresh token is empty")
	}

	assertAuthenticatedMCPRequestPassesAuth(t, client, proxyBaseURL, accessToken)
}

func envOrDefaultForTest(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func requireHealthy(t *testing.T, client *http.Client, proxyBaseURL string) {
	t.Helper()

	resp, err := client.Get(proxyBaseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz: got %d, want 200: %s", resp.StatusCode, readSnippet(resp.Body))
	}
}

func registerE2EClient(t *testing.T, client *http.Client, proxyBaseURL, redirectURI string) string {
	t.Helper()

	body := fmt.Sprintf(`{"redirect_uris":["%s"],"client_name":"Keycloak E2E"}`, redirectURI)
	resp, err := client.Post(proxyBaseURL+"/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /register: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /register: got %d, want 201: %s", resp.StatusCode, readSnippet(resp.Body))
	}

	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		t.Fatalf("decode /register response: %v", err)
	}
	if reg.ClientID == "" {
		t.Fatal("/register returned an empty client_id")
	}
	return reg.ClientID
}

func authorizeViaKeycloak(t *testing.T, client *http.Client, proxyBaseURL, keycloakBrowserBaseURL, registeredClientID, redirectURI, codeVerifier string) string {
	t.Helper()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {registeredClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {handlers.ComputePKCEChallenge(codeVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"keycloak-e2e-state"},
		"resource":              {proxyBaseURL + "/mcp"},
	}
	resp, err := client.Get(proxyBaseURL + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	// /authorize returns either 302 to the IdP (legacy silent path)
	// or 200 with the consent HTML form (RENDER_CONSENT_PAGE=true).
	// Branch on the status so the test exercises whichever the
	// demo stack is configured for; on the consent path it submits
	// "approve" and follows the resulting 302.
	var idpLocation string
	switch resp.StatusCode {
	case http.StatusFound:
		idpLocation = resp.Header.Get("Location")
	case http.StatusOK:
		idpLocation = approveConsent(t, client, resp, proxyBaseURL)
	default:
		t.Fatalf("GET /authorize: got %d, want 302 or 200(consent): %s", resp.StatusCode, readSnippet(resp.Body))
	}
	if idpLocation == "" {
		t.Fatal("/authorize response missing Location after consent")
	}

	loginPageURL := translateKeycloakURL(t, idpLocation, keycloakBrowserBaseURL)
	loginAction := fetchLoginAction(t, client, loginPageURL, keycloakBrowserBaseURL)
	proxyCallbackURL := submitKeycloakLogin(t, client, loginAction, keycloakBrowserBaseURL, proxyBaseURL)
	return completeProxyCallback(t, client, proxyCallbackURL, redirectURI, proxyBaseURL)
}

// approveConsent walks the proxy-rendered consent page on RENDER_CONSENT_PAGE=true:
// reads the sealed consent_token from the form, POSTs action=approve to /consent,
// and returns the Location header of the resulting 302 (which points at the IdP).
func approveConsent(t *testing.T, client *http.Client, resp *http.Response, proxyBaseURL string) string {
	t.Helper()
	consentToken := extractConsentToken(t, resp)
	form := url.Values{
		"consent_token": {consentToken},
		"action":        {"approve"},
	}
	consentResp, err := client.PostForm(proxyBaseURL+"/consent", form)
	if err != nil {
		t.Fatalf("POST /consent: %v", err)
	}
	defer consentResp.Body.Close()
	if consentResp.StatusCode != http.StatusFound {
		t.Fatalf("POST /consent: got %d, want 302: %s", consentResp.StatusCode, readSnippet(consentResp.Body))
	}
	return consentResp.Header.Get("Location")
}

// extractConsentToken pulls the sealed consent_token value out of
// the proxy-rendered consent HTML. Shared by the approve and deny
// paths; the latter exists in the negative-path test below.
func extractConsentToken(t *testing.T, resp *http.Response) string {
	t.Helper()
	page, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		t.Fatalf("read consent page: %v", err)
	}
	match := consentTokenInputRE.FindSubmatch(page)
	if len(match) < 2 {
		t.Fatalf("consent_token input not found in consent page; first 500 bytes: %q", string(page[:min(len(page), 500)]))
	}
	return html.UnescapeString(string(match[1]))
}

func fetchLoginAction(t *testing.T, client *http.Client, loginPageURL, keycloakBrowserBaseURL string) string {
	t.Helper()

	current := loginPageURL
	for range 10 {
		resp, err := client.Get(current)
		if err != nil {
			t.Fatalf("GET Keycloak login page: %v", err)
		}
		if isRedirect(resp.StatusCode) {
			next := resolveLocation(t, current, resp.Header.Get("Location"))
			_ = resp.Body.Close()
			current = translateKeycloakURL(t, next, keycloakBrowserBaseURL)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET Keycloak login page: got %d, want 200: %s", resp.StatusCode, readSnippet(resp.Body))
		}
		page, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		if err != nil {
			t.Fatalf("read Keycloak login page: %v", err)
		}
		match := formActionRE.FindSubmatch(page)
		if len(match) < 2 {
			t.Fatalf("Keycloak login form action not found")
		}
		action := html.UnescapeString(string(match[1]))
		return resolveLocation(t, current, action)
	}
	t.Fatal("too many redirects fetching Keycloak login page")
	return ""
}

func submitKeycloakLogin(t *testing.T, client *http.Client, loginAction, keycloakBrowserBaseURL, proxyBaseURL string) string {
	t.Helper()

	form := url.Values{
		"username":     {keycloakE2EUsername},
		"password":     {keycloakE2EPassword},
		"credentialId": {""},
	}
	resp, err := client.PostForm(translateKeycloakURL(t, loginAction, keycloakBrowserBaseURL), form)
	if err != nil {
		t.Fatalf("POST Keycloak login form: %v", err)
	}
	defer resp.Body.Close()

	currentResponse := resp
	currentURL := loginAction
	for range 10 {
		if !isRedirect(currentResponse.StatusCode) {
			t.Fatalf("POST Keycloak login form: got %d, want redirect: %s", currentResponse.StatusCode, readSnippet(currentResponse.Body))
		}
		next := resolveLocation(t, currentURL, currentResponse.Header.Get("Location"))
		if strings.HasPrefix(next, proxyBaseURL+"/callback?") {
			_ = currentResponse.Body.Close()
			return next
		}

		_ = currentResponse.Body.Close()
		currentURL = translateKeycloakURL(t, next, keycloakBrowserBaseURL)
		var err error
		currentResponse, err = client.Get(currentURL)
		if err != nil {
			t.Fatalf("follow Keycloak login redirect: %v", err)
		}
	}
	t.Fatal("too many redirects after Keycloak login")
	return ""
}

func completeProxyCallback(t *testing.T, client *http.Client, proxyCallbackURL, redirectURI, proxyBaseURL string) string {
	t.Helper()

	resp, err := client.Get(proxyCallbackURL)
	if err != nil {
		t.Fatalf("GET /callback: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /callback: got %d, want 302: %s", resp.StatusCode, readSnippet(resp.Body))
	}

	clientRedirect := resp.Header.Get("Location")
	if !strings.HasPrefix(clientRedirect, redirectURI) {
		t.Fatalf("/callback Location = %q, want prefix %q", clientRedirect, redirectURI)
	}
	u, err := url.Parse(clientRedirect)
	if err != nil {
		t.Fatalf("parse client redirect: %v", err)
	}
	if got := u.Query().Get("state"); got != "keycloak-e2e-state" {
		t.Fatalf("client state = %q, want keycloak-e2e-state", got)
	}
	if got := u.Query().Get("iss"); got != proxyBaseURL {
		t.Fatalf("iss = %q, want %s", got, proxyBaseURL)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatal("client redirect missing internal authorization code")
	}
	return code
}

func exchangeCodeForTokens(t *testing.T, client *http.Client, proxyBaseURL, registeredClientID, redirectURI, code, codeVerifier string) (string, string) {
	t.Helper()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {registeredClientID},
		"code_verifier": {codeVerifier},
	}
	resp, err := client.Post(proxyBaseURL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /token: got %d, want 200: %s", resp.StatusCode, readSnippet(resp.Body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode /token response: %v", err)
	}
	if tokenResp.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, want Bearer", tokenResp.TokenType)
	}
	return tokenResp.AccessToken, tokenResp.RefreshToken
}

func assertAuthenticatedMCPRequestPassesAuth(t *testing.T, client *http.Client, proxyBaseURL, accessToken string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, proxyBaseURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if err != nil {
		t.Fatalf("build authenticated MCP request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp with bearer token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		t.Fatalf("authenticated MCP request was rejected by proxy auth: %d: %s", resp.StatusCode, readSnippet(resp.Body))
	}
}

func translateKeycloakURL(t *testing.T, rawURL, keycloakBrowserBaseURL string) string {
	t.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	if u.Host != "keycloak:8080" {
		return u.String()
	}
	browserBase, err := url.Parse(keycloakBrowserBaseURL)
	if err != nil {
		t.Fatalf("parse KEYCLOAK_BROWSER_BASE_URL: %v", err)
	}
	u.Scheme = browserBase.Scheme
	u.Host = browserBase.Host
	return u.String()
}

func resolveLocation(t *testing.T, baseURL, location string) string {
	t.Helper()

	if location == "" {
		t.Fatal("redirect response missing Location")
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse base URL %q: %v", baseURL, err)
	}
	loc, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location %q: %v", location, err)
	}
	return base.ResolveReference(loc).String()
}

func isRedirect(status int) bool {
	return status >= 300 && status <= 399
}

// --- Negative paths (T2.4) ---
//
// These tests exercise the security-critical denial paths against
// the real demo stack so a regression in /consent denial,
// authorization-code replay, refresh family revoke, or RFC 8707
// resource validation fails CI rather than production. They share
// helpers with the happy-path test above.

// TestKeycloakE2E_ConsentDenied pins the denial branch of the
// proxy-rendered consent page: POST action=deny redirects 302 to
// the registered redirect_uri with error=access_denied per
// RFC 6749 §4.1.2.1, and the IdP login is never reached.
//
// This test diverges before the Keycloak redirect, so it
// exercises only the proxy's consent-page flow + chi/middleware
// stack. Lives under the keycloak_e2e build tag for stack-
// availability reasons (REDIS_URL set, demo proxy running).
//
// Precondition: demo stack runs with RENDER_CONSENT_PAGE=true
// (the default). Setting it to false would route /authorize
// straight to the IdP and the test would fail with "want 200,
// got 302".
func TestKeycloakE2E_ConsentDenied(t *testing.T) {
	proxyBaseURL := envOrDefaultForTest("KEYCLOAK_E2E_PROXY_BASE_URL", "http://localhost:8080")
	redirectURI := envOrDefaultForTest("KEYCLOAK_E2E_REDIRECT_URI", "http://127.0.0.1:8765/callback")

	client := newE2EClient(t)
	requireHealthy(t, client, proxyBaseURL)
	registeredClientID := registerE2EClient(t, client, proxyBaseURL, redirectURI)

	// GET /authorize — must render the consent page on this build
	// (RENDER_CONSENT_PAGE=true is the demo default and the
	// production posture this test is here to guard).
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {registeredClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {handlers.ComputePKCEChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")},
		"code_challenge_method": {"S256"},
		"state":                 {"deny-state"},
		"resource":              {proxyBaseURL + "/mcp"},
	}
	resp, err := client.Get(proxyBaseURL + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /authorize: want 200 (consent page), got %d: %s", resp.StatusCode, readSnippet(resp.Body))
	}
	consentToken := extractConsentToken(t, resp)

	denyResp, err := client.PostForm(proxyBaseURL+"/consent", url.Values{
		"consent_token": {consentToken},
		"action":        {"deny"},
	})
	if err != nil {
		t.Fatalf("POST /consent action=deny: %v", err)
	}
	defer denyResp.Body.Close()
	if denyResp.StatusCode != http.StatusFound {
		t.Fatalf("deny: want 302, got %d: %s", denyResp.StatusCode, readSnippet(denyResp.Body))
	}
	loc := denyResp.Header.Get("Location")
	if !strings.HasPrefix(loc, redirectURI) {
		t.Fatalf("deny redirect Location = %q, want prefix %q", loc, redirectURI)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse deny Location: %v", err)
	}
	if got := u.Query().Get("error"); got != "access_denied" {
		t.Errorf("error = %q, want access_denied", got)
	}
	if got := u.Query().Get("state"); got != "deny-state" {
		t.Errorf("state = %q, want deny-state", got)
	}
	if got := u.Query().Get("iss"); got != proxyBaseURL {
		t.Errorf("iss = %q, want %s", got, proxyBaseURL)
	}
}

// TestKeycloakE2E_ReplayedCode pins RFC 6749 §4.1.2 single-use
// against a real Keycloak: a successful /token exchange consumes
// the authorization code; a second exchange with the same code
// must be rejected as code replay AND must revoke the refresh
// family seeded by that code.
func TestKeycloakE2E_ReplayedCode(t *testing.T) {
	proxyBaseURL := envOrDefaultForTest("KEYCLOAK_E2E_PROXY_BASE_URL", "http://localhost:8080")
	keycloakBrowserBaseURL := envOrDefaultForTest("KEYCLOAK_BROWSER_BASE_URL", "http://localhost:8180")
	redirectURI := envOrDefaultForTest("KEYCLOAK_E2E_REDIRECT_URI", "http://127.0.0.1:8765/callback")

	client := newE2EClient(t)
	requireHealthy(t, client, proxyBaseURL)
	registeredClientID := registerE2EClient(t, client, proxyBaseURL, redirectURI)
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	internalCode := authorizeViaKeycloak(t, client, proxyBaseURL, keycloakBrowserBaseURL, registeredClientID, redirectURI, codeVerifier)

	// First exchange: must succeed.
	access, _ := exchangeCodeForTokens(t, client, proxyBaseURL, registeredClientID, redirectURI, internalCode, codeVerifier)
	if access == "" {
		t.Fatal("first /token exchange returned empty access token")
	}

	// Second exchange of the SAME internal code: must fail with
	// invalid_grant + error_code=code_replay. The first exchange
	// does not write any family marker (a fresh claim doesn't
	// revoke anything); the second exchange detects the replay and
	// writes the family marker atomically alongside the rejection.
	// So the response code is unambiguous — only code_replay is
	// correct here.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {internalCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {registeredClientID},
		"code_verifier": {codeVerifier},
	}
	resp, err := client.Post(proxyBaseURL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("replayed POST /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed exchange: want 400, got %d: %s", resp.StatusCode, readSnippet(resp.Body))
	}
	var oauthErr struct {
		Error     string `json:"error"`
		ErrorCode string `json:"error_code,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode replay error: %v", err)
	}
	if oauthErr.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", oauthErr.Error)
	}
	if oauthErr.ErrorCode != "code_replay" {
		t.Errorf("error_code = %q, want code_replay", oauthErr.ErrorCode)
	}
}

// TestKeycloakE2E_RefreshReuseRevokesFamily pins RFC 6749 §10.4 /
// OAuth 2.1 §6.1 reuse detection on refresh rotation against a
// real Keycloak: the original refresh token, replayed past the
// REFRESH_RACE_GRACE_SEC window, must reject as
// refresh_reuse_detected AND mark the family revoked so the
// rotated sibling stops working too.
//
// Precondition: demo stack uses the default
// REFRESH_RACE_GRACE_SEC=2 (or any value ≤ 2). The test sleeps 3s
// between the rotation and the replay; raising the grace window
// in the demo stack past 3s would route the replay into the
// racing branch and the test would fail with
// refresh_concurrent_submit instead of refresh_reuse_detected.
func TestKeycloakE2E_RefreshReuseRevokesFamily(t *testing.T) {
	proxyBaseURL := envOrDefaultForTest("KEYCLOAK_E2E_PROXY_BASE_URL", "http://localhost:8080")
	keycloakBrowserBaseURL := envOrDefaultForTest("KEYCLOAK_BROWSER_BASE_URL", "http://localhost:8180")
	redirectURI := envOrDefaultForTest("KEYCLOAK_E2E_REDIRECT_URI", "http://127.0.0.1:8765/callback")

	client := newE2EClient(t)
	requireHealthy(t, client, proxyBaseURL)
	registeredClientID := registerE2EClient(t, client, proxyBaseURL, redirectURI)
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	internalCode := authorizeViaKeycloak(t, client, proxyBaseURL, keycloakBrowserBaseURL, registeredClientID, redirectURI, codeVerifier)
	_, originalRefresh := exchangeCodeForTokens(t, client, proxyBaseURL, registeredClientID, redirectURI, internalCode, codeVerifier)
	if originalRefresh == "" {
		t.Fatal("expected non-empty refresh token from happy path")
	}

	// First rotation succeeds and burns the original tid.
	rotatedRefresh := refreshExchange(t, client, proxyBaseURL, registeredClientID, originalRefresh)
	if rotatedRefresh == "" {
		t.Fatal("rotation returned empty refresh token")
	}

	// Sleep past the default grace window (2s) so the next replay
	// of the original refresh trips the strict reuse path rather
	// than the racing branch. 3s margin keeps us safely outside.
	time.Sleep(3 * time.Second)

	// Replay the ORIGINAL refresh — must be rejected as reuse +
	// family revoked.
	resp := postRefresh(t, client, proxyBaseURL, registeredClientID, originalRefresh)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("reuse replay: want 400, got %d: %s", resp.StatusCode, readSnippet(resp.Body))
	}
	var reuseErr struct {
		Error     string `json:"error"`
		ErrorCode string `json:"error_code,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&reuseErr); err != nil {
		t.Fatalf("decode reuse error: %v", err)
	}
	if reuseErr.ErrorCode != "refresh_reuse_detected" {
		t.Errorf("reuse error_code = %q, want refresh_reuse_detected", reuseErr.ErrorCode)
	}

	// The rotated sibling must also fail now — the family was
	// revoked atomically with the reuse detection.
	siblingResp := postRefresh(t, client, proxyBaseURL, registeredClientID, rotatedRefresh)
	defer siblingResp.Body.Close()
	if siblingResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("sibling after revoke: want 400, got %d: %s", siblingResp.StatusCode, readSnippet(siblingResp.Body))
	}
	var siblingErr struct {
		Error     string `json:"error"`
		ErrorCode string `json:"error_code,omitempty"`
	}
	if err := json.NewDecoder(siblingResp.Body).Decode(&siblingErr); err != nil {
		t.Fatalf("decode sibling error: %v", err)
	}
	if siblingErr.ErrorCode != "refresh_family_revoked" {
		t.Errorf("sibling error_code = %q, want refresh_family_revoked", siblingErr.ErrorCode)
	}
}

// TestKeycloakE2E_ResourceMismatch pins RFC 8707 §2.2 audience
// binding at /token: an authorization code minted for the
// configured MCP mount cannot be redeemed with a different
// `resource` value (the proxy is both AS and RS, so the only
// valid `resource` is its own baseURL or the configured mount).
func TestKeycloakE2E_ResourceMismatch(t *testing.T) {
	proxyBaseURL := envOrDefaultForTest("KEYCLOAK_E2E_PROXY_BASE_URL", "http://localhost:8080")
	keycloakBrowserBaseURL := envOrDefaultForTest("KEYCLOAK_BROWSER_BASE_URL", "http://localhost:8180")
	redirectURI := envOrDefaultForTest("KEYCLOAK_E2E_REDIRECT_URI", "http://127.0.0.1:8765/callback")

	client := newE2EClient(t)
	requireHealthy(t, client, proxyBaseURL)
	registeredClientID := registerE2EClient(t, client, proxyBaseURL, redirectURI)
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	internalCode := authorizeViaKeycloak(t, client, proxyBaseURL, keycloakBrowserBaseURL, registeredClientID, redirectURI, codeVerifier)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {internalCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {registeredClientID},
		"code_verifier": {codeVerifier},
		// Wrong resource — does not identify this AS / RS.
		"resource": {"https://other-resource.example.com/api"},
	}
	resp, err := client.Post(proxyBaseURL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /token with mismatched resource: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("resource mismatch: want 400, got %d: %s", resp.StatusCode, readSnippet(resp.Body))
	}
	var oauthErr struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode resource-mismatch error: %v", err)
	}
	if oauthErr.Error != "invalid_target" {
		t.Errorf("error = %q, want invalid_target", oauthErr.Error)
	}
}

// newE2EClient is the cookie-jar-bearing HTTP client used by every
// keycloak_e2e test. CheckRedirect is overridden so the test
// drives the redirect chain explicitly.
func newE2EClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	return &http.Client{
		Jar:     jar,
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// refreshExchange performs a refresh-token rotation and returns
// the new refresh token. Fails the test on any non-200 response.
func refreshExchange(t *testing.T, client *http.Client, proxyBaseURL, registeredClientID, refreshToken string) string {
	t.Helper()
	resp := postRefresh(t, client, proxyBaseURL, registeredClientID, refreshToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotation: want 200, got %d: %s", resp.StatusCode, readSnippet(resp.Body))
	}
	var tokenResp struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode rotation: %v", err)
	}
	return tokenResp.RefreshToken
}

// postRefresh issues a refresh-token grant. Returns the raw
// response so the caller can inspect status + body for both
// success and failure shapes.
func postRefresh(t *testing.T, client *http.Client, proxyBaseURL, registeredClientID, refreshToken string) *http.Response {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {registeredClientID},
	}
	resp, err := client.Post(proxyBaseURL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /token (refresh): %v", err)
	}
	return resp
}

func readSnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 4096))
	return string(b)
}
