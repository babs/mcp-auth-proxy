package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"html"
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

	"github.com/babs/mcp-auth-proxy/config"
	"github.com/babs/mcp-auth-proxy/handlers"
	"github.com/babs/mcp-auth-proxy/proxy"
	"github.com/babs/mcp-auth-proxy/replay"
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
	// TokenHandler, when set, answers /token instead of the default
	// authorization_code response (forwarding tests need refresh grants).
	TokenHandler http.HandlerFunc
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
		if m.TokenHandler != nil {
			m.TokenHandler(w, r)
			return
		}
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
// testProxyOptions switches optional features on in buildTestProxy.
type testProxyOptions struct {
	// forwardIdPToken wires UPSTREAM_FORWARD_IDP_TOKEN end to end, with
	// extraScopes appended to the IdP scopes and an in-memory replay
	// store so single-use claims and their release are exercised.
	forwardIdPToken bool
	extraScopes     []string
	// redirectURIsExtra wires REDIRECT_URIS_EXTRA into /register and
	// /authorize.
	redirectURIsExtra config.RedirectAllowlist
	// redirectURIsAllowlist wires REDIRECT_URIS_ALLOWLIST into /register,
	// /authorize and /token.
	redirectURIsAllowlist config.WebRedirectAllowlist
}

func buildTestProxy(t *testing.T, oidcProvider *mockOIDCProvider, mcpServer *mockMCPServer, proxyBaseURL string, renderConsent bool, opts ...testProxyOptions) http.Handler {
	t.Helper()
	var opt testProxyOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	provider, err := oidc.NewProvider(t.Context(), oidcProvider.Server.URL)
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}

	// Built through main's own constructors, so the harness cannot
	// drift from the production wiring.
	cfg := &config.Config{
		OIDCClientID:            oidcProvider.ClientID,
		OIDCClientSecret:        "test-oidc-secret",
		ProxyBaseURL:            proxyBaseURL,
		UpstreamMCPMountPath:    "/mcp",
		GroupsClaim:             "groups",
		OIDCExtraScopes:         opt.extraScopes,
		UpstreamForwardIdPToken: opt.forwardIdPToken,
		ClientRegistrationTTL:   handlers.DefaultClientTTL,
		PKCERequired:            true,
		// Production defaults this true. Most cases run it false to
		// drive the direct-to-IdP path;
		// TestE2E_ConsentFlowThroughProductionRouter runs it true.
		RenderConsentPage:     renderConsent,
		RedirectURIsExtra:     opt.redirectURIsExtra,
		RedirectURIsAllowlist: opt.redirectURIsAllowlist,
	}
	oauth2Cfg := newOAuth2Config(cfg, provider.Endpoint())

	verifier := provider.Verifier(&oidc.Config{ClientID: oidcProvider.ClientID})

	tm, err := token.NewManager([]byte("e2e-test-secret-that-is-at-least-32-bytes!!"))
	if err != nil {
		t.Fatalf("token.NewManager: %v", err)
	}

	var replayStore replay.Store
	idpRefresher := enableForwarding(cfg, tm, oauth2Cfg)
	if opt.forwardIdPToken {
		mem := replay.NewMemoryStore()
		t.Cleanup(func() { _ = mem.Close() })
		replayStore = mem
	}

	proxyHandler, err := proxy.Handler(mcpServer.Server.URL, zap.NewNop(), newProxyConfig(cfg))
	if err != nil {
		t.Fatalf("proxy.Handler: %v", err)
	}

	authMW := newAuthMiddleware(cfg, tm, zap.NewNop())

	r := chi.NewRouter()
	// The production middleware chain, not a bare router: the error
	// page's CSP has to override the securityHeaders baseline, and only
	// this chain puts that baseline there.
	baseMiddleware(r, zap.NewNop(), &config.Config{})
	registerDiscoveryRoutes(r, proxyBaseURL, "/mcp", "", nil)
	// The production wiring, not hand-mounted routes: the e2e suite must
	// exercise the same router shape main builds (BrowserFacing markers
	// included), or the two silently diverge.
	registerOAuthRoutes(r, oauthRoutes{
		Register:      handlers.Register(tm, zap.NewNop(), proxyBaseURL, newRegisterConfig(cfg)),
		Authorize:     handlers.Authorize(tm, zap.NewNop(), proxyBaseURL, oauth2Cfg, newAuthorizeConfig(cfg)),
		Consent:       handlers.Consent(tm, zap.NewNop(), proxyBaseURL, oauth2Cfg, handlers.ConsentConfig{}),
		Callback:      handlers.Callback(tm, zap.NewNop(), proxyBaseURL, oauth2Cfg, verifier, newCallbackConfig(cfg, replayStore, nil)),
		Token:         handlers.Token(tm, zap.NewNop(), proxyBaseURL, time.Time{}, replayStore, newTokenConfig(cfg, idpRefresher, nil, verifier.Verify)),
		RegisterLimit: passthrough, AuthorizeLimit: passthrough, ConsentLimit: passthrough,
		CallbackLimit: passthrough, TokenLimit: passthrough,
	})
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Group(func(r chi.Router) {
		r.Use(authMW.Validate)
		r.Handle("/mcp", proxyHandler)
		r.Handle("/mcp/*", proxyHandler)
	})
	installMethodNotAllowed(r)
	installNotFound(r)

	return r
}

func TestE2E_FullOAuthMCPFlow(t *testing.T) {
	// 1. Start mock services
	oidcMock := newMockOIDCProvider(t)
	defer oidcMock.Close()

	mcpMock := newMockMCPServer(t)
	defer mcpMock.Close()

	// 2. Start the proxy
	proxyServer := httptest.NewServer(buildTestProxy(t, oidcMock, mcpMock, "http://proxy.test", false))
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
	resp, _ := driveAuthToCallbackURI(t, client, proxyURL, oidcMock, "https://claude.ai/api/mcp/auth_callback")
	return resp
}

// e2eCodeVerifier is the PKCE verifier driveAuthToCallbackURI sends.
const e2eCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// driveAuthToCallbackURI runs register → authorize → callback for
// redirectURI and returns the /callback response and the client_id.
func driveAuthToCallbackURI(t *testing.T, client *http.Client, proxyURL string, oidcMock *mockOIDCProvider, redirectURI string) (*http.Response, string) {
	t.Helper()

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
	clientID, ok := reg["client_id"].(string)
	if !ok {
		t.Fatalf("/register returned no client_id: %v", reg)
	}

	codeChallenge := handlers.ComputePKCEChallenge(e2eCodeVerifier)

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
	return cbResp, clientID
}

// TestE2E_CustomSchemeRedirect drives register → authorize → callback
// through the real router with REDIRECT_URIS_EXTRA set, for a scheme
// wildcard and a host-less exact entry.
func TestE2E_CustomSchemeRedirect(t *testing.T) {
	extra, err := config.ParseRedirectAllowlist("warp://*,com.example.app:/cb")
	if err != nil {
		t.Fatalf("ParseRedirectAllowlist: %v", err)
	}
	for _, redirectURI := range []string{"warp://dev.warp.Warp-Stable/mcp/callback", "com.example.app:/cb"} {
		t.Run(redirectURI, func(t *testing.T) {
			oidcMock := newMockOIDCProvider(t)
			defer oidcMock.Close()
			mcpMock := newMockMCPServer(t)
			defer mcpMock.Close()
			proxyServer := httptest.NewServer(buildTestProxy(t, oidcMock, mcpMock, "http://proxy.test", false, testProxyOptions{redirectURIsExtra: extra}))
			defer proxyServer.Close()
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

			resp, clientID := driveAuthToCallbackURI(t, client, proxyServer.URL, oidcMock, redirectURI)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusFound {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("callback: want 302, got %d: %s", resp.StatusCode, b)
			}
			loc := resp.Header.Get("Location")
			if !strings.HasPrefix(loc, redirectURI+"?") {
				t.Fatalf("Location = %q, want prefix %q", loc, redirectURI+"?")
			}
			u, err := url.Parse(loc)
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			q := u.Query()
			if q.Get("code") == "" || q.Get("state") != "s" || q.Get("iss") != "http://proxy.test" {
				t.Fatalf("Location query = %v, want code, state=s, iss=http://proxy.test", q)
			}

			form := url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {q.Get("code")},
				"redirect_uri":  {redirectURI},
				"client_id":     {clientID},
				"code_verifier": {e2eCodeVerifier},
			}
			tokReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyServer.URL+"/token", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatalf("build /token: %v", err)
			}
			tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			tokResp, err := client.Do(tokReq)
			if err != nil {
				t.Fatalf("POST /token: %v", err)
			}
			defer tokResp.Body.Close()
			var tok map[string]any
			if err := json.NewDecoder(tokResp.Body).Decode(&tok); err != nil {
				t.Fatalf("decode /token: %v", err)
			}
			if tokResp.StatusCode != http.StatusOK || tok["access_token"] == nil || tok["access_token"] == "" {
				t.Errorf("/token = %d %v, want 200 with access_token", tokResp.StatusCode, tok)
			}
		})
	}
}

// TestE2E_RedirectURIsAllowlist drives REDIRECT_URIS_ALLOWLIST through
// the production router: an unlisted client is refused at /register, a
// listed one completes register → authorize → callback → token → refresh,
// and a session through a URI a narrower list no longer admits is refused
// at refresh and at /authorize by a deployment sharing the signing secret.
func TestE2E_RedirectURIsAllowlist(t *testing.T) {
	const listed, delisted = "https://agents.example.com/oauth/callback", "https://second.example.com/cb"
	parse := func(raw string) config.WebRedirectAllowlist {
		a, err := config.ParseWebRedirectAllowlist(raw)
		if err != nil {
			t.Fatalf("ParseWebRedirectAllowlist: %v", err)
		}
		return a
	}
	oidcMock := newMockOIDCProvider(t)
	defer oidcMock.Close()
	mcpMock := newMockMCPServer(t)
	defer mcpMock.Close()
	wide := httptest.NewServer(buildTestProxy(t, oidcMock, mcpMock, "http://proxy.test", false, testProxyOptions{redirectURIsAllowlist: parse(listed + "," + delisted)}))
	defer wide.Close()
	narrow := httptest.NewServer(buildTestProxy(t, oidcMock, mcpMock, "http://proxy.test", false, testProxyOptions{redirectURIsAllowlist: parse(listed)}))
	defer narrow.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	do := func(t *testing.T, req *http.Request) (int, map[string]any) {
		t.Helper()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
		}
		defer resp.Body.Close()
		body := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if loc := resp.Header.Get("Location"); loc != "" {
			body["location"] = loc
		}
		return resp.StatusCode, body
	}
	postForm := func(t *testing.T, base string, form url.Values) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return do(t, req)
	}
	// session runs the browser flow on base for redirectURI and redeems
	// the code; it returns the client_id and the refresh token.
	session := func(t *testing.T, base, redirectURI string) (string, string) {
		t.Helper()
		resp, clientID := driveAuthToCallbackURI(t, client, base, oidcMock, redirectURI)
		defer resp.Body.Close()
		loc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil || resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc.String(), redirectURI+"?") {
			t.Fatalf("callback: want 302 to %s, got %d %q", redirectURI, resp.StatusCode, resp.Header.Get("Location"))
		}
		status, tok := postForm(t, base, url.Values{
			"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "redirect_uri": {redirectURI},
			"client_id": {clientID}, "code_verifier": {e2eCodeVerifier},
		})
		refresh, _ := tok["refresh_token"].(string)
		if status != http.StatusOK || refresh == "" {
			t.Fatalf("/token code grant = %d %v, want 200 with a refresh_token", status, tok)
		}
		return clientID, refresh
	}
	refreshOn := func(t *testing.T, base, clientID, refresh string) (int, map[string]any) {
		t.Helper()
		return postForm(t, base, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}})
	}

	t.Run("unlisted client refused at register", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, narrow.URL+"/register", strings.NewReader(`{"redirect_uris":["https://other.example.com/cb"],"client_name":"other"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if status, body := do(t, req); status != http.StatusBadRequest || body["error"] != "invalid_redirect_uri" {
			t.Fatalf("/register = %d %v, want 400 invalid_redirect_uri", status, body)
		}
	})

	t.Run("listed client completes the flow and refreshes", func(t *testing.T) {
		clientID, refresh := session(t, narrow.URL, listed)
		if status, body := refreshOn(t, narrow.URL, clientID, refresh); status != http.StatusOK || body["access_token"] == nil {
			t.Fatalf("refresh = %d %v, want 200 with an access_token", status, body)
		}
	})

	t.Run("session through a de-listed URI is refused", func(t *testing.T) {
		clientID, refresh := session(t, wide.URL, delisted)
		if status, body := refreshOn(t, narrow.URL, clientID, refresh); status != http.StatusBadRequest || body["error"] != "invalid_grant" || body["error_code"] != "redirect_uri_mismatch" {
			t.Fatalf("refresh on the narrowed deployment = %d %v, want 400 invalid_grant redirect_uri_mismatch", status, body)
		}
		params := url.Values{
			"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {delisted}, "state": {"s"},
			"code_challenge": {handlers.ComputePKCEChallenge(e2eCodeVerifier)}, "code_challenge_method": {"S256"},
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, narrow.URL+"/authorize?"+params.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if status, body := do(t, req); status != http.StatusBadRequest || body["location"] != nil || body["error_code"] != "redirect_uri_mismatch" {
			t.Fatalf("/authorize on the narrowed deployment = %d %v, want 400 on the AS", status, body)
		}
	})
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

	proxyServer := httptest.NewServer(buildTestProxy(t, oidcMock, mcpMock, "http://proxy.test", false))
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

	proxyServer := httptest.NewServer(buildTestProxy(t, oidcMock, mcpMock, "http://proxy.test", false))
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

// TestE2E_ConsentFlowThroughProductionRouter drives the consent screen
// the way production serves it (RenderConsentPage defaults true): GET
// /authorize renders the page, the Approve POST comes back as a
// same-origin interstitial, and only then does the flow reach the IdP.
// The rest of the suite runs with consent off, so without this case no
// e2e request ever reached POST /consent even though the router mounts
// it.
func TestE2E_ConsentFlowThroughProductionRouter(t *testing.T) {
	oidcMock := newMockOIDCProvider(t)
	defer oidcMock.Close()
	mcpMock := newMockMCPServer(t)
	defer mcpMock.Close()

	proxyServer := httptest.NewServer(buildTestProxy(t, oidcMock, mcpMock, "http://proxy.test", true))
	defer proxyServer.Close()

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	const redirectURI = "https://app.example.com/callback"

	regBody := strings.NewReader(`{"redirect_uris":["` + redirectURI + `"],"client_name":"e2e consent app"}`)
	regReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyServer.URL+"/register", regBody)
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

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {reg["client_id"].(string)},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {handlers.ComputePKCEChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")},
		"code_challenge_method": {"S256"},
		"state":                 {"s"},
	}
	authzReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proxyServer.URL+"/authorize?"+params.Encode(), nil)
	if err != nil {
		t.Fatalf("build /authorize: %v", err)
	}
	authzResp, err := client.Do(authzReq)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	page, err := io.ReadAll(authzResp.Body)
	if err != nil {
		t.Fatalf("read consent page: %v", err)
	}
	if err := authzResp.Body.Close(); err != nil {
		t.Fatalf("close /authorize body: %v", err)
	}
	if authzResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /authorize: want 200 consent page, got %d: %s", authzResp.StatusCode, page)
	}
	// The page must survive the production middleware chain: its own CSP
	// has to replace the securityHeaders baseline, not be intersected
	// with it.
	if csp := authzResp.Header.Values("Content-Security-Policy"); len(csp) != 1 || !strings.Contains(csp[0], "style-src 'sha256-") {
		t.Errorf("consent page CSP = %q, want exactly one policy naming its style hash", csp)
	}

	consentToken := extractE2EConsentToken(t, string(page))
	form := url.Values{"consent_token": {consentToken}, "action": {"approve"}}
	consentReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyServer.URL+"/consent", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /consent: %v", err)
	}
	consentReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	consentResp, err := client.Do(consentReq)
	if err != nil {
		t.Fatalf("POST /consent: %v", err)
	}
	interstitial, err := io.ReadAll(consentResp.Body)
	if err != nil {
		t.Fatalf("read interstitial: %v", err)
	}
	if err := consentResp.Body.Close(); err != nil {
		t.Fatalf("close /consent body: %v", err)
	}
	// Approve is answered by the same-origin interstitial (200 + meta
	// refresh), never a cross-origin 302 — that is what keeps the
	// consent page's form-action 'self' from blocking the chain.
	if consentResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /consent: want 200 interstitial, got %d: %s", consentResp.StatusCode, interstitial)
	}
	target := extractE2EMetaRefresh(t, string(interstitial))
	if !strings.HasPrefix(target, oidcMock.Server.URL) {
		t.Errorf("interstitial target = %q, want the IdP authorize URL", target)
	}
	idpURL, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse IdP URL: %v", err)
	}
	if idpURL.Query().Get("state") == "" || idpURL.Query().Get("nonce") == "" {
		t.Errorf("interstitial target missing sealed state / nonce: %q", target)
	}
}

// extractE2EConsentToken pulls the sealed consent token out of the
// rendered consent form.
func extractE2EConsentToken(t *testing.T, body string) string {
	t.Helper()
	_, rest, found := strings.Cut(body, `name="consent_token" value="`)
	if !found {
		t.Fatalf("consent_token field not found in page:\n%s", body)
	}
	tok, _, found := strings.Cut(rest, `"`)
	if !found {
		t.Fatal("consent_token close-quote not found")
	}
	return tok
}

// extractE2EMetaRefresh pulls the navigation target out of the
// interstitial's meta refresh, undoing the attribute escaping.
func extractE2EMetaRefresh(t *testing.T, body string) string {
	t.Helper()
	_, rest, found := strings.Cut(body, `content="0;url=`)
	if !found {
		t.Fatalf("meta refresh not found in interstitial:\n%s", body)
	}
	raw, _, found := strings.Cut(rest, `"`)
	if !found {
		t.Fatal("meta refresh close-quote not found")
	}
	return html.UnescapeString(raw)
}
