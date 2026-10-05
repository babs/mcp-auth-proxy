package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/babs/mcp-auth-proxy/handlers"
)

const fwdUpstreamScope = "api://upstream-app/access_as_user"

// forwardingIdP answers the mock IdP's /token for both grants the
// forwarding mode uses. The code exchange returns refresh token rt-1
// (and an access token the proxy must discard); every refresh_token
// grant must present the latest refresh token and the upstream scope,
// and gets access token at-N plus rotated refresh token rt-(N+1).
type forwardingIdP struct {
	t    *testing.T
	m    *mockOIDCProvider
	mu   sync.Mutex
	n    int    // refresh grants answered
	rt   string // refresh token the next grant must present
	errs []string
}

func newForwardingIdP(t *testing.T, m *mockOIDCProvider) *forwardingIdP {
	f := &forwardingIdP{t: t, m: m, rt: "rt-1"}
	m.TokenHandler = f.serve
	return f
}

func (f *forwardingIdP) fail(format string, args ...any) {
	f.errs = append(f.errs, fmt.Sprintf(format, args...))
}

func (f *forwardingIdP) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = r.ParseForm()
	w.Header().Set("Content-Type", "application/json")
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		idToken := f.m.signIDToken(f.t, "test-subject-123", "user@example.com", "Test User", []string{"mcp-users"}, nil, f.m.Nonce)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "at-from-code-exchange",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "rt-1",
			"id_token":      idToken,
		})
	case "refresh_token":
		if got := r.PostForm.Get("refresh_token"); got != f.rt {
			f.fail("refresh grant presented %q, want %q", got, f.rt)
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		if scope := r.PostForm.Get("scope"); !strings.Contains(" "+scope+" ", " "+fwdUpstreamScope+" ") {
			f.fail("refresh grant scope %q lacks %q", scope, fwdUpstreamScope)
		}
		f.n++
		f.rt = fmt.Sprintf("rt-%d", f.n+1)
		// Refresh id_tokens carry no nonce; the proxy verifies them
		// with the same go-oidc verifier as /callback.
		idToken := f.m.signIDToken(f.t, "test-subject-123", "user@example.com", "Test User", []string{"mcp-users"}, nil, "")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  fmt.Sprintf("at-%d", f.n),
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": f.rt,
			"id_token":      idToken,
		})
	default:
		f.fail("unexpected grant_type %q", r.PostForm.Get("grant_type"))
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (f *forwardingIdP) check() {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.errs {
		f.t.Error(e)
	}
}

// forwardingLogin runs register → authorize → callback → code grant and
// returns the client id and the proxy's token response.
func forwardingLogin(t *testing.T, client *http.Client, proxyURL string, oidcMock *mockOIDCProvider) (clientID string, tokenResp map[string]any) {
	t.Helper()
	redirectURI := "https://client.example.com/oauth/callback"
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	resp, err := client.Post(proxyURL+"/register", "application/json",
		strings.NewReader(fmt.Sprintf(`{"redirect_uris":["%s"],"client_name":"Test Client"}`, redirectURI)))
	if err != nil {
		t.Fatalf("POST /register: %v", err)
	}
	var reg map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&reg)
	_ = resp.Body.Close()
	clientID, _ = reg["client_id"].(string)

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {handlers.ComputePKCEChallenge(verifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"s"},
		"scope":                 {"anything the client asks for"},
	}
	resp, err = client.Get(proxyURL + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	_ = resp.Body.Close()
	idpURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse IdP redirect: %v", err)
	}
	// The IdP is asked for the base scopes plus the operator's extra
	// scope — never for what the client sent.
	if got, want := idpURL.Query().Get("scope"), "openid email profile "+fwdUpstreamScope+" offline_access"; got != want {
		t.Errorf("IdP authorize scope = %q, want %q", got, want)
	}
	oidcMock.Nonce = idpURL.Query().Get("nonce")

	resp, err = client.Get(proxyURL + "/callback?code=fake&state=" + url.QueryEscape(idpURL.Query().Get("state")))
	if err != nil {
		t.Fatalf("GET /callback: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/callback status = %d", resp.StatusCode)
	}
	cbURL, _ := url.Parse(resp.Header.Get("Location"))
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "rt-1") || strings.Contains(loc, "at-from-code-exchange") {
		t.Errorf("client redirect carries an IdP token in clear: %s", loc)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {cbURL.Query().Get("code")},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}
	tokenResp = postToken(t, client, proxyURL, form)
	return clientID, tokenResp
}

func postToken(t *testing.T, client *http.Client, proxyURL string, form url.Values) map[string]any {
	t.Helper()
	resp, err := client.Post(proxyURL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/token status = %d: %v", resp.StatusCode, body)
	}
	return body
}

func callMCP(t *testing.T, client *http.Client, proxyURL, accessToken string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, proxyURL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestE2E_ForwardsIdPAccessTokenUpstream(t *testing.T) {
	oidcMock := newMockOIDCProvider(t)
	defer oidcMock.Close()
	idp := newForwardingIdP(t, oidcMock)
	mcpMock := newMockMCPServer(t)
	defer mcpMock.Close()

	proxyServer := httptest.NewServer(buildTestProxy(t, oidcMock, mcpMock, "http://proxy.test", false, testProxyOptions{
		forwardIdPToken: true,
		extraScopes:     []string{fwdUpstreamScope, "offline_access"},
	}))
	defer proxyServer.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	clientID, tokens := forwardingLogin(t, client, proxyServer.URL, oidcMock)
	accessToken, _ := tokens["access_token"].(string)
	for _, secret := range []string{"rt-1", "rt-2", "at-1", "at-from-code-exchange"} {
		if raw, _ := json.Marshal(tokens); strings.Contains(string(raw), `"`+secret+`"`) {
			t.Errorf("token response carries IdP token %q in clear", secret)
		}
	}

	if code := callMCP(t, client, proxyServer.URL, accessToken); code != http.StatusOK {
		t.Fatalf("MCP call status = %d, want 200", code)
	}
	if mcpMock.LastAuthHeader != "Bearer at-1" {
		t.Errorf("upstream Authorization = %q, want the IdP access token from the refresh grant", mcpMock.LastAuthHeader)
	}
	if mcpMock.LastRequestSub != "test-subject-123" || mcpMock.LastRequestEmail != "user@example.com" {
		t.Errorf("identity headers = %q / %q, want them injected as before", mcpMock.LastRequestSub, mcpMock.LastRequestEmail)
	}

	// Each refresh renews the IdP tokens: the upstream sees the new
	// IdP access token, and the IdP sees the rotated refresh token.
	refreshToken, _ := tokens["refresh_token"].(string)
	for i := 2; i <= 3; i++ {
		refreshed := postToken(t, client, proxyServer.URL, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
			"client_id":     {clientID},
		})
		if raw, _ := json.Marshal(refreshed); strings.Contains(string(raw), fmt.Sprintf(`"at-%d"`, i)) || strings.Contains(string(raw), fmt.Sprintf(`"rt-%d"`, i+1)) {
			t.Errorf("refresh %d response carries an IdP token in clear", i-1)
		}
		refreshToken, _ = refreshed["refresh_token"].(string)
		next, _ := refreshed["access_token"].(string)
		if code := callMCP(t, client, proxyServer.URL, next); code != http.StatusOK {
			t.Fatalf("MCP call after refresh %d: status %d", i-1, code)
		}
		if want := fmt.Sprintf("Bearer at-%d", i); mcpMock.LastAuthHeader != want {
			t.Errorf("after refresh %d: upstream Authorization = %q, want %q", i-1, mcpMock.LastAuthHeader, want)
		}
	}
	idp.check()
}
