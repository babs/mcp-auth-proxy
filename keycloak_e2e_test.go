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

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client := &http.Client{
		Jar:     jar,
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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
	page, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		t.Fatalf("read consent page: %v", err)
	}
	match := consentTokenInputRE.FindSubmatch(page)
	if len(match) < 2 {
		t.Fatalf("consent_token input not found in consent page; first 500 bytes: %q", string(page[:min(len(page), 500)]))
	}
	consentToken := html.UnescapeString(string(match[1]))

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

func readSnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 4096))
	return string(b)
}
