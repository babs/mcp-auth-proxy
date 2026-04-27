package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/babs/mcp-auth-proxy/handlers"
	"github.com/babs/mcp-auth-proxy/middleware"
	"github.com/babs/mcp-auth-proxy/proxy"
	"github.com/babs/mcp-auth-proxy/token"
)

// mockOIDCProvider spins up a fake OIDC provider with discovery, JWKS, and token endpoint.
type mockOIDCProvider struct {
	Server        *httptest.Server
	PrivateKey    *rsa.PrivateKey
	ClientID      string
	EmailVerified *bool // when non-nil, included in issued id_tokens
	// Nonce is echoed into the id_token's "nonce" claim at /token, mimicking a
	// real OIDC provider that received a nonce on the authorization request.
	// Tests set this from the upstream Location header before driving /callback.
	Nonce string
}

func newMockOIDCProvider(t *testing.T) *mockOIDCProvider {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	m := &mockOIDCProvider{
		PrivateKey: privateKey,
		ClientID:   "test-oidc-client",
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		baseURL := m.Server.URL
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                baseURL,
			"authorization_endpoint":                baseURL + "/authorize",
			"token_endpoint":                        baseURL + "/token",
			"jwks_uri":                              baseURL + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{
			Key:       &privateKey.PublicKey,
			KeyID:     "test-key-1",
			Algorithm: "RS256",
			Use:       "sig",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idToken := m.signIDToken(t, "test-subject-123", "user@example.com", "Test User", []string{"mcp-users", "dev"}, m.EmailVerified, m.Nonce)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "upstream-access-token-xyz",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})

	m.Server = httptest.NewServer(mux)
	return m
}

func (m *mockOIDCProvider) signIDToken(t *testing.T, sub, email, name string, groups []string, emailVerified *bool, nonce string) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: m.PrivateKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key-1"),
	)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	now := time.Now()
	claims := map[string]any{
		"iss":   m.Server.URL,
		"sub":   sub,
		"aud":   m.ClientID,
		"email": email,
		"name":  name,
		"iat":   now.Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
	}
	if len(groups) > 0 {
		claims["groups"] = groups
	}
	if emailVerified != nil {
		claims["email_verified"] = *emailVerified
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	raw, err := josejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	return raw
}

func (m *mockOIDCProvider) Close() {
	m.Server.Close()
}

// mockMCPServer records incoming requests for assertions.
type mockMCPServer struct {
	Server            *httptest.Server
	LastRequestSub    string
	LastRequestEmail  string
	LastRequestGroups string
	LastAuthHeader    string
	LastRequestPath   string
	RequestCount      int
}

func newMockMCPServer(t *testing.T) *mockMCPServer {
	t.Helper()
	m := &mockMCPServer{}

	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.LastRequestSub = r.Header.Get("X-User-Sub")
		m.LastRequestEmail = r.Header.Get("X-User-Email")
		m.LastRequestGroups = r.Header.Get("X-User-Groups")
		m.LastAuthHeader = r.Header.Get("Authorization")
		m.LastRequestPath = r.URL.Path
		m.RequestCount++

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))

	return m
}

func (m *mockMCPServer) Close() {
	m.Server.Close()
}

// buildTestProxy wires up the full proxy router using real components
// but pointing at mock OIDC and mock MCP.
func buildTestProxy(t *testing.T, oidcProvider *mockOIDCProvider, mcpServer *mockMCPServer, proxyBaseURL string) http.Handler {
	t.Helper()

	provider, err := oidc.NewProvider(t.Context(), oidcProvider.Server.URL)
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}

	oauth2Cfg := &oauth2.Config{
		ClientID:     oidcProvider.ClientID,
		ClientSecret: "test-oidc-secret",
		Endpoint:     provider.Endpoint(),
		RedirectURL:  proxyBaseURL + "/callback",
		Scopes:       []string{"openid", "email", "profile"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: oidcProvider.ClientID})

	tm, err := token.NewManager([]byte("e2e-test-secret-that-is-at-least-32-bytes!!"))
	if err != nil {
		t.Fatalf("token.NewManager: %v", err)
	}

	proxyHandler, err := proxy.Handler(mcpServer.Server.URL, zap.NewNop(), proxy.Config{})
	if err != nil {
		t.Fatalf("proxy.Handler: %v", err)
	}

	authMW := middleware.NewAuth(tm, zap.NewNop(), proxyBaseURL, "/mcp", time.Time{})

	r := chi.NewRouter()
	registerDiscoveryRoutes(r, proxyBaseURL, "/mcp", "", nil)
	r.Post("/register", handlers.Register(tm, zap.NewNop(), proxyBaseURL))
	r.Get("/authorize", handlers.Authorize(tm, zap.NewNop(), proxyBaseURL, oauth2Cfg, handlers.AuthorizeConfig{
		PKCERequired:      true,
		CanonicalResource: proxyBaseURL + "/mcp",
	}))
	r.Get("/callback", handlers.Callback(tm, zap.NewNop(), proxyBaseURL, oauth2Cfg, verifier, handlers.CallbackConfig{
		GroupsClaim: "groups",
	}))
	r.Post("/token", handlers.Token(tm, zap.NewNop(), proxyBaseURL, time.Time{}, nil, handlers.TokenConfig{}))
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Group(func(r chi.Router) {
		r.Use(authMW.Validate)
		r.Handle("/mcp", proxyHandler)
		r.Handle("/mcp/*", proxyHandler)
	})

	return r
}

func TestE2E_FullOAuthMCPFlow(t *testing.T) {
	// 1. Start mock services
	oidcMock := newMockOIDCProvider(t)
	defer oidcMock.Close()

	mcpMock := newMockMCPServer(t)
	defer mcpMock.Close()

	// 2. Start the proxy
	proxyServer := httptest.NewServer(buildTestProxy(t, oidcMock, mcpMock, "http://proxy.test"))
	defer proxyServer.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 3. Protected Resource Metadata (RFC 9728)
	t.Run("protected_resource_metadata", func(t *testing.T) {
		resp, err := client.Get(proxyServer.URL + "/.well-known/oauth-protected-resource")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var meta map[string]any
		json.NewDecoder(resp.Body).Decode(&meta)

		if meta["resource"] != "http://proxy.test/" {
			t.Errorf("resource = %v, want http://proxy.test/", meta["resource"])
		}
	})

	// 4. Authorization Server Metadata (RFC 8414)
	t.Run("authorization_server_metadata", func(t *testing.T) {
		resp, err := client.Get(proxyServer.URL + "/.well-known/oauth-authorization-server")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		var meta map[string]any
		json.NewDecoder(resp.Body).Decode(&meta)

		if meta["issuer"] != "http://proxy.test" {
			t.Errorf("issuer = %v", meta["issuer"])
		}
		if meta["registration_endpoint"] != "http://proxy.test/register" {
			t.Errorf("registration_endpoint = %v", meta["registration_endpoint"])
		}
	})

	// 5. Unauthenticated request → 401 with WWW-Authenticate
	t.Run("unauthenticated_returns_401_with_www_authenticate", func(t *testing.T) {
		resp, err := client.Get(proxyServer.URL + "/mcp/some-tool")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 401 {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}

		wwwAuth := resp.Header.Get("WWW-Authenticate")
		if !strings.Contains(wwwAuth, "resource_metadata") {
			t.Errorf("WWW-Authenticate missing resource_metadata: %q", wwwAuth)
		}
	})

	// 6. Dynamic Client Registration (RFC 7591)
	var registeredClientID string
	redirectURI := "https://claude.ai/api/mcp/auth_callback"

	t.Run("dynamic_client_registration", func(t *testing.T) {
		body := fmt.Sprintf(`{"redirect_uris":["%s"],"client_name":"Claude"}`, redirectURI)
		resp, err := client.Post(proxyServer.URL+"/register", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 201 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 201, got %d: %s", resp.StatusCode, b)
		}

		var reg map[string]any
		json.NewDecoder(resp.Body).Decode(&reg)
		registeredClientID = reg["client_id"].(string)

		if registeredClientID == "" {
			t.Fatal("client_id is empty")
		}
	})

	// 7. Authorize → redirect to IdP
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := handlers.ComputePKCEChallenge(codeVerifier)
	var callbackState string

	t.Run("authorize_redirects_to_idp", func(t *testing.T) {
		params := url.Values{
			"response_type":         {"code"},
			"client_id":             {registeredClientID},
			"redirect_uri":          {redirectURI},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {"S256"},
			"state":                 {"client-state-abc"},
			"resource":              {"http://proxy.test"},
		}

		resp, err := client.Get(proxyServer.URL + "/authorize?" + params.Encode())
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 302 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 302, got %d: %s", resp.StatusCode, b)
		}

		loc := resp.Header.Get("Location")
		if !strings.Contains(loc, oidcMock.Server.URL) {
			t.Errorf("expected redirect to mock OIDC, got: %s", loc)
		}

		u, err := url.Parse(loc)
		if err != nil {
			t.Fatalf("parse location: %v", err)
		}
		callbackState = u.Query().Get("state")
		if callbackState == "" {
			t.Fatal("state param missing from IdP redirect")
		}
		// Capture the upstream OIDC nonce so the mock IdP can echo it back
		// in the id_token at /token (H3 — upstream code-injection defense).
		oidcMock.Nonce = u.Query().Get("nonce")
		if oidcMock.Nonce == "" {
			t.Fatal("nonce param missing from IdP redirect")
		}
	})

	// 8. Callback — simulate IdP redirecting back with a code
	var internalCode string

	t.Run("callback_exchanges_code_and_redirects", func(t *testing.T) {
		resp, err := client.Get(proxyServer.URL + "/callback?code=fake-upstream-code&state=" + url.QueryEscape(callbackState))
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 302 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 302, got %d: %s", resp.StatusCode, b)
		}

		loc := resp.Header.Get("Location")
		if !strings.HasPrefix(loc, redirectURI) {
			t.Fatalf("expected redirect to %s, got: %s", redirectURI, loc)
		}

		u, err := url.Parse(loc)
		if err != nil {
			t.Fatalf("parse location: %v", err)
		}

		internalCode = u.Query().Get("code")
		if internalCode == "" {
			t.Fatal("internal authorization code missing from redirect")
		}

		returnedState := u.Query().Get("state")
		if returnedState != "client-state-abc" {
			t.Errorf("original state not preserved: got %q", returnedState)
		}
		// RFC 9700 §2.1.4 mix-up defense: the authorization response
		// MUST carry the `iss` parameter so a client talking to
		// multiple ASes can verify the response came from the AS it
		// sent the request to. Value matches `issuer` in AS metadata.
		if iss := u.Query().Get("iss"); iss != "http://proxy.test" {
			t.Errorf("iss param: want %q, got %q", "http://proxy.test", iss)
		}
	})

	// 9. Token exchange with PKCE
	var accessToken, refreshToken string

	t.Run("token_exchange_with_pkce", func(t *testing.T) {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {internalCode},
			"redirect_uri":  {redirectURI},
			"client_id":     {registeredClientID},
			"code_verifier": {codeVerifier},
		}

		resp, err := client.Post(proxyServer.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
		}

		var tokenResp map[string]any
		json.NewDecoder(resp.Body).Decode(&tokenResp)

		accessToken = tokenResp["access_token"].(string)
		if accessToken == "" {
			t.Fatal("access_token is empty")
		}

		refreshToken = tokenResp["refresh_token"].(string)
		if refreshToken == "" {
			t.Fatal("refresh_token is empty")
		}

		if tokenResp["token_type"] != "Bearer" {
			t.Errorf("token_type = %v", tokenResp["token_type"])
		}
	})

	// 10. Authenticated MCP request
	t.Run("authenticated_mcp_request_reaches_upstream", func(t *testing.T) {
		req, _ := http.NewRequest("GET", proxyServer.URL+"/mcp/tools/list", nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
		}

		if mcpMock.RequestCount != 1 {
			t.Errorf("expected 1 upstream request, got %d", mcpMock.RequestCount)
		}
		// UPSTREAM_MCP_URL is origin-only; the proxy forwards the
		// client request path verbatim to the upstream. /mcp/tools/list
		// on the proxy must arrive as /mcp/tools/list upstream — a
		// regression that silently strips or rewrites the path must
		// fail this assertion.
		if mcpMock.LastRequestPath != "/mcp/tools/list" {
			t.Errorf("upstream path = %q, want /mcp/tools/list", mcpMock.LastRequestPath)
		}
		if mcpMock.LastRequestSub != "test-subject-123" {
			t.Errorf("X-User-Sub = %q, want test-subject-123", mcpMock.LastRequestSub)
		}
		if mcpMock.LastRequestEmail != "user@example.com" {
			t.Errorf("X-User-Email = %q, want user@example.com", mcpMock.LastRequestEmail)
		}
		if mcpMock.LastAuthHeader != "" {
			t.Errorf("Authorization header leaked to upstream: %q", mcpMock.LastAuthHeader)
		}
		// Groups from id_token must reach upstream
		if mcpMock.LastRequestGroups != "mcp-users,dev" {
			t.Errorf("X-User-Groups = %q, want mcp-users,dev", mcpMock.LastRequestGroups)
		}
	})

	// 11. Refresh token flow
	t.Run("refresh_token_issues_new_tokens", func(t *testing.T) {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {registeredClientID},
		}

		resp, err := client.Post(proxyServer.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, b)
		}

		var tokenResp map[string]any
		json.NewDecoder(resp.Body).Decode(&tokenResp)

		newAccess := tokenResp["access_token"].(string)
		newRefresh := tokenResp["refresh_token"].(string)

		if newAccess == accessToken {
			t.Error("new access token should differ from old")
		}
		if newRefresh == refreshToken {
			t.Error("new refresh token should differ from old")
		}

		// New access token should work
		req, _ := http.NewRequest("GET", proxyServer.URL+"/mcp/tools/list", nil)
		req.Header.Set("Authorization", "Bearer "+newAccess)

		resp2, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp2.Body.Close()

		if resp2.StatusCode != 200 {
			b, _ := io.ReadAll(resp2.Body)
			t.Fatalf("new token should work, got %d: %s", resp2.StatusCode, b)
		}
	})

	// 12. Health endpoint
	t.Run("healthz", func(t *testing.T) {
		resp, err := client.Get(proxyServer.URL + "/healthz")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
	})
}

// driveAuthToCallback walks a client through registration → authorize → callback
// against the given proxy and returns the /callback response. It is shared by
// the email_verified tests which only differ in the id_token the mock IdP
// emits.
func driveAuthToCallback(t *testing.T, client *http.Client, proxyURL string, oidcMock *mockOIDCProvider) *http.Response {
	t.Helper()

	redirectURI := "https://claude.ai/api/mcp/auth_callback"
	body := fmt.Sprintf(`{"redirect_uris":["%s"],"client_name":"Claude"}`, redirectURI)

	regReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyURL+"/register", strings.NewReader(body))
	if err != nil {
		t.Fatalf("build /register: %v", err)
	}
	regReq.Header.Set("Content-Type", "application/json")
	regResp, err := client.Do(regReq)
	if err != nil {
		t.Fatalf("POST /register: %v", err)
	}
	var reg map[string]any
	if err := json.NewDecoder(regResp.Body).Decode(&reg); err != nil {
		t.Fatalf("decode /register: %v", err)
	}
	if err := regResp.Body.Close(); err != nil {
		t.Fatalf("close /register body: %v", err)
	}
	clientID := reg["client_id"].(string)

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := handlers.ComputePKCEChallenge(codeVerifier)

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {"s"},
	}
	authzReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyURL+"/authorize?"+params.Encode(), nil)
	if err != nil {
		t.Fatalf("build /authorize: %v", err)
	}
	authzResp, err := client.Do(authzReq)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	idpURL, err := url.Parse(authzResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse IdP redirect: %v", err)
	}
	if err := authzResp.Body.Close(); err != nil {
		t.Fatalf("close /authorize body: %v", err)
	}
	state := idpURL.Query().Get("state")
	// Capture upstream nonce so the mock IdP echoes it in the id_token.
	oidcMock.Nonce = idpURL.Query().Get("nonce")

	cbReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyURL+"/callback?code=fake&state="+url.QueryEscape(state), nil)
	if err != nil {
		t.Fatalf("build /callback: %v", err)
	}
	cbResp, err := client.Do(cbReq)
	if err != nil {
		t.Fatalf("GET /callback: %v", err)
	}
	return cbResp
}

// TestE2E_RejectsUnverifiedEmail verifies that when the IdP emits
// email_verified: false in the id_token, /callback refuses to issue an
// authorization code. Forwarding an unverified email to the upstream MCP
// server would let a user impersonate any email they are willing to type
// at a permissive IdP.
func TestE2E_RejectsUnverifiedEmail(t *testing.T) {
	oidcMock := newMockOIDCProvider(t)
	defer oidcMock.Close()
	verified := false
	oidcMock.EmailVerified = &verified

	mcpMock := newMockMCPServer(t)
	defer mcpMock.Close()

	proxyServer := httptest.NewServer(buildTestProxy(t, oidcMock, mcpMock, "http://proxy.test"))
	defer proxyServer.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	cbResp := driveAuthToCallback(t, client, proxyServer.URL, oidcMock)
	defer func() {
		if err := cbResp.Body.Close(); err != nil {
			t.Errorf("close /callback body: %v", err)
		}
	}()

	if cbResp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(cbResp.Body)
		t.Fatalf("expected 403 for unverified email, got %d: %s", cbResp.StatusCode, b)
	}

	var cbErr map[string]any
	if err := json.NewDecoder(cbResp.Body).Decode(&cbErr); err != nil {
		t.Fatalf("decode /callback: %v", err)
	}
	if cbErr["error"] != "access_denied" {
		t.Errorf("expected error=access_denied, got %v", cbErr["error"])
	}
	if cbErr["error_code"] != "email_not_verified" {
		t.Errorf("expected error_code=email_not_verified, got %v", cbErr["error_code"])
	}
}

// TestE2E_AcceptsVerifiedEmail confirms that when the IdP explicitly asserts
// email_verified=true, the callback succeeds — i.e. the new check is not
// overly strict when the claim is present and truthful.
func TestE2E_AcceptsVerifiedEmail(t *testing.T) {
	oidcMock := newMockOIDCProvider(t)
	defer oidcMock.Close()
	verified := true
	oidcMock.EmailVerified = &verified

	mcpMock := newMockMCPServer(t)
	defer mcpMock.Close()

	proxyServer := httptest.NewServer(buildTestProxy(t, oidcMock, mcpMock, "http://proxy.test"))
	defer proxyServer.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	cbResp := driveAuthToCallback(t, client, proxyServer.URL, oidcMock)
	defer func() {
		if err := cbResp.Body.Close(); err != nil {
			t.Errorf("close /callback body: %v", err)
		}
	}()

	if cbResp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(cbResp.Body)
		t.Fatalf("expected 302 for verified email, got %d: %s", cbResp.StatusCode, b)
	}
}
