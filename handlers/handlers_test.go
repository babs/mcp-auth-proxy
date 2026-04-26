package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/babs/mcp-auth-proxy/replay"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const (
	testSecret  = "test-secret-that-is-at-least-32-bytes!!"
	testBaseURL = "https://auth.example.com"
)

func newTestTokenManager(t *testing.T) *token.Manager {
	t.Helper()
	tm, err := token.NewManager([]byte(testSecret))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return tm
}

func testOAuth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "test-oidc-client",
		ClientSecret: "test-oidc-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://idp.example.com/authorize",
			TokenURL: "https://idp.example.com/token",
		},
		RedirectURL: "https://auth.example.com/callback",
		Scopes:      []string{"openid", "email", "profile"},
	}
}

// pkceChallenge computes the S256 code_challenge for a given code_verifier.
func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// registerClient calls the Register handler and returns both the encrypted client_id
// and the internal UUID (for seeding test fixtures).
func registerClient(t *testing.T, tm *token.Manager, redirectURIs []string) (encClientID, internalID string) {
	t.Helper()
	body := map[string]any{"redirect_uris": redirectURIs, "client_name": "test-app"}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	Register(tm, zap.NewNop(), testBaseURL)(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("registerClient: expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp registerResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("registerClient: decode: %v", err)
	}

	var sc sealedClient
	if err := tm.OpenJSON(resp.ClientID, &sc, token.PurposeClient); err != nil {
		t.Fatalf("registerClient: OpenJSON: %v", err)
	}

	return resp.ClientID, sc.ID
}

// sealCode creates an encrypted authorization code for testing.
func sealCode(t *testing.T, tm *token.Manager, clientUUID, redirectURI, codeChallenge, subject, email string) string {
	t.Helper()
	sc := sealedCode{
		TokenID:       uuid.New().String(),
		FamilyID:      uuid.New().String(),
		ClientID:      clientUUID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		Subject:       subject,
		Email:         email,
		Typ:           token.PurposeCode,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	code, err := tm.SealJSON(sc, token.PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	return code
}

// sealRefresh creates an encrypted refresh token for testing.
func sealRefresh(t *testing.T, tm *token.Manager, subject, email, clientUUID string) string {
	t.Helper()
	now := time.Now()
	sr := sealedRefresh{
		TokenID:        uuid.New().String(),
		FamilyID:       uuid.New().String(),
		Subject:        subject,
		Email:          email,
		ClientID:       clientUUID,
		Typ:            token.PurposeRefresh,
		Audience:       testBaseURL,
		IssuedAt:       now,
		FamilyIssuedAt: now,
		ExpiresAt:      now.Add(7 * 24 * time.Hour),
	}
	tok, err := tm.SealJSON(sr, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	return tok
}

func TestWriteOAuthError_OmitsErrorCodeByDefault(t *testing.T) {
	rr := httptest.NewRecorder()

	writeOAuthError(rr, http.StatusBadRequest, "invalid_request", "missing required parameters")

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_request" {
		t.Fatalf("expected invalid_request, got %q", oauthErr.Error)
	}
	if oauthErr.ErrorDescription != "missing required parameters" {
		t.Fatalf("expected human-readable description, got %q", oauthErr.ErrorDescription)
	}
	if oauthErr.ErrorCode != "" {
		t.Fatalf("expected empty error_code, got %q", oauthErr.ErrorCode)
	}
}

func TestWriteOAuthError_IncludesOptionalErrorCode(t *testing.T) {
	rr := httptest.NewRecorder()

	writeOAuthError(rr, http.StatusBadGateway, "server_error", "id token verification failed", "id_token_verification_failed")

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rr.Code)
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "server_error" {
		t.Fatalf("expected server_error, got %q", oauthErr.Error)
	}
	if oauthErr.ErrorDescription != "id token verification failed" {
		t.Fatalf("expected human-readable description, got %q", oauthErr.ErrorDescription)
	}
	if oauthErr.ErrorCode != "id_token_verification_failed" {
		t.Fatalf("expected error_code id_token_verification_failed, got %q", oauthErr.ErrorCode)
	}
}

// --- Discovery ---

func TestDiscovery(t *testing.T) {
	baseURL := testBaseURL
	handler := Discovery(baseURL)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var meta map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&meta); err != nil {
		t.Fatalf("decode: %v", err)
	}

	checks := map[string]string{
		"issuer":                 baseURL,
		"authorization_endpoint": baseURL + "/authorize",
		"token_endpoint":         baseURL + "/token",
		"registration_endpoint":  baseURL + "/register",
	}
	for k, want := range checks {
		got, ok := meta[k].(string)
		if !ok || got != want {
			t.Errorf("%s: want %q, got %v", k, want, meta[k])
		}
	}

	for _, k := range []string{"response_types_supported", "response_modes_supported", "grant_types_supported", "code_challenge_methods_supported", "token_endpoint_auth_methods_supported"} {
		if _, ok := meta[k]; !ok {
			t.Errorf("missing field %s", k)
		}
	}

	// RFC 9207 §3 / RFC 9700 §2.1.4: when the AS emits `iss` on
	// authorization responses, it MUST advertise the metadata flag
	// or strict clients will skip the check.
	if got, ok := meta["authorization_response_iss_parameter_supported"].(bool); !ok || !got {
		t.Errorf("authorization_response_iss_parameter_supported: want true, got %v", meta["authorization_response_iss_parameter_supported"])
	}
}

// --- Register ---

func TestRegister_Success(t *testing.T) {
	tm := newTestTokenManager(t)
	body := `{"redirect_uris":["https://app.example.com/callback"],"client_name":"my-app"}`

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	Register(tm, zap.NewNop(), testBaseURL)(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp registerResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// client_id should be a non-empty encrypted blob
	if resp.ClientID == "" {
		t.Error("client_id should not be empty")
	}
	if len(resp.RedirectURIs) != 1 || resp.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Errorf("redirect_uris mismatch: %v", resp.RedirectURIs)
	}
	if resp.TokenEndpointAuthMethod != "none" {
		t.Errorf("expected default auth method 'none', got %q", resp.TokenEndpointAuthMethod)
	}
	if resp.ClientIDIssuedAt == 0 {
		t.Error("client_id_issued_at should be non-zero")
	}
	// RFC 7591 §3.2.1 OPTIONAL `client_id_expires_at` — surfaced so
	// clients know when the sealed handle stops opening (default 24h).
	if resp.ClientIDExpiresAt <= resp.ClientIDIssuedAt {
		t.Errorf("client_id_expires_at=%d must be > client_id_issued_at=%d",
			resp.ClientIDExpiresAt, resp.ClientIDIssuedAt)
	}
	// Must be ~clientTTL (24h) away from issued_at; allow ±1 min slop.
	if delta := resp.ClientIDExpiresAt - resp.ClientIDIssuedAt; delta < int64(clientTTL.Seconds())-60 || delta > int64(clientTTL.Seconds())+60 {
		t.Errorf("client_id_expires_at delta = %ds, want ~%ds", delta, int64(clientTTL.Seconds()))
	}
	// RFC 7591 §3.2.1: registered client_name must be echoed back.
	if resp.ClientName != "my-app" {
		t.Errorf("client_name should be echoed as %q, got %q", "my-app", resp.ClientName)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("expected Cache-Control: no-store, got %q", cc)
	}
	if pr := rr.Header().Get("Pragma"); pr != "no-cache" {
		t.Errorf("expected Pragma: no-cache, got %q", pr)
	}

	// Verify the client_id is a valid encrypted payload
	var sc sealedClient
	if err := tm.OpenJSON(resp.ClientID, &sc, token.PurposeClient); err != nil {
		t.Errorf("client_id is not a valid sealed client: %v", err)
	}
	if sc.ID == "" {
		t.Error("sealed client should have a non-empty internal ID")
	}
}

func TestRegister_UnsupportedAuthMethod(t *testing.T) {
	tm := newTestTokenManager(t)
	// Client requests client_secret_post, but discovery only advertises "none"
	// and /token never authenticates secrets. Must be rejected per RFC 7591 §3.2.2
	// so the client doesn't believe it registered an authentication method.
	body := `{"redirect_uris":["https://app.example.com/callback"],"token_endpoint_auth_method":"client_secret_post"}`

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	Register(tm, zap.NewNop(), testBaseURL)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_client_metadata" {
		t.Errorf("expected invalid_client_metadata, got %q", oauthErr.Error)
	}
}

func TestRegister_ExplicitNoneAuthMethod(t *testing.T) {
	tm := newTestTokenManager(t)
	body := `{"redirect_uris":["https://app.example.com/callback"],"token_endpoint_auth_method":"none"}`

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	Register(tm, zap.NewNop(), testBaseURL)(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp registerResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TokenEndpointAuthMethod != "none" {
		t.Errorf("expected \"none\", got %q", resp.TokenEndpointAuthMethod)
	}
}

func TestRegister_MissingRedirectURIs(t *testing.T) {
	tm := newTestTokenManager(t)
	body := `{"client_name":"my-app"}`

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	Register(tm, zap.NewNop(), testBaseURL)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// RFC 7591 §3.2.2: redirect_uri-shaped defects use the dedicated code.
	if oauthErr.Error != "invalid_redirect_uri" {
		t.Errorf("expected error 'invalid_redirect_uri', got %q", oauthErr.Error)
	}
}

func TestRegister_InvalidJSON(t *testing.T) {
	tm := newTestTokenManager(t)

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("{not-json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	Register(tm, zap.NewNop(), testBaseURL)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_request" {
		t.Errorf("expected error 'invalid_request', got %q", oauthErr.Error)
	}
}

func TestRegister_RejectsTrailingJSON(t *testing.T) {
	tm := newTestTokenManager(t)
	body := `{"redirect_uris":["https://app.example.com/callback"]} {"redirect_uris":["https://evil.example.com/callback"]}`

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	Register(tm, zap.NewNop(), testBaseURL)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_request" {
		t.Errorf("expected error 'invalid_request', got %q", oauthErr.Error)
	}
}

// --- Authorize ---

func TestAuthorize_Success(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})

	challenge := pkceChallenge("test-verifier-string")

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"user-state-123"},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rr.Code, rr.Body.String())
	}

	loc := rr.Header().Get("Location")
	if loc == "" {
		t.Fatal("missing Location header")
	}
	if !strings.HasPrefix(loc, "https://idp.example.com/authorize") {
		t.Errorf("unexpected redirect location: %s", loc)
	}
	if !strings.Contains(loc, "client_id=test-oidc-client") {
		t.Errorf("location missing oidc client_id: %s", loc)
	}
	if !strings.Contains(loc, "redirect_uri=") {
		t.Errorf("location missing redirect_uri: %s", loc)
	}
}

func TestAuthorize_MissingParams(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})
	challenge := pkceChallenge("test-verifier")

	// Per RFC 6749 §4.1.2.1:
	// - errors BEFORE client_id + redirect_uri are validated → JSON 400
	// - errors AFTER both are validated → 302 to redirect_uri with `error=…`
	tests := []struct {
		name       string
		params     url.Values
		wantError  string
		wantStatus int // 400 (JSON) or 302 (redirect)
	}{
		{
			name: "missing response_type",
			params: url.Values{
				"client_id":             {encClientID},
				"redirect_uri":          {redirectURI},
				"code_challenge":        {challenge},
				"code_challenge_method": {"S256"},
			},
			wantError:  "unsupported_response_type",
			wantStatus: http.StatusFound,
		},
		{
			name: "wrong response_type",
			params: url.Values{
				"response_type":         {"token"},
				"client_id":             {encClientID},
				"redirect_uri":          {redirectURI},
				"code_challenge":        {challenge},
				"code_challenge_method": {"S256"},
			},
			wantError:  "unsupported_response_type",
			wantStatus: http.StatusFound,
		},
		{
			name: "missing client_id",
			params: url.Values{
				"response_type":         {"code"},
				"redirect_uri":          {redirectURI},
				"code_challenge":        {challenge},
				"code_challenge_method": {"S256"},
			},
			wantError:  "invalid_request",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing redirect_uri",
			params: url.Values{
				"response_type":         {"code"},
				"client_id":             {encClientID},
				"code_challenge":        {challenge},
				"code_challenge_method": {"S256"},
			},
			wantError:  "invalid_request",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "missing code_challenge",
			params: url.Values{
				"response_type":         {"code"},
				"client_id":             {encClientID},
				"redirect_uri":          {redirectURI},
				"code_challenge_method": {"S256"},
			},
			wantError:  "invalid_request",
			wantStatus: http.StatusFound,
		},
		{
			name: "wrong code_challenge_method",
			params: url.Values{
				"response_type":         {"code"},
				"client_id":             {encClientID},
				"redirect_uri":          {redirectURI},
				"code_challenge":        {challenge},
				"code_challenge_method": {"plain"},
			},
			wantError:  "invalid_request",
			wantStatus: http.StatusFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/authorize?"+tc.params.Encode(), nil)
			rr := httptest.NewRecorder()

			Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tc.wantStatus, rr.Code, rr.Body.String())
			}
			gotError := extractAuthzError(t, rr, redirectURI)
			if gotError != tc.wantError {
				t.Errorf("expected error %q, got %q", tc.wantError, gotError)
			}
		})
	}
}

// extractAuthzError pulls the `error` field from either a JSON 400 body
// (RFC 6749 §4.1.2.1: client/redirect not yet trusted) or the redirect
// `Location` query string (§4.1.2.1: redirect target is trusted).
// Centralizes the test-side dispatch so each /authorize test stays
// concise.
func extractAuthzError(t *testing.T, rr *httptest.ResponseRecorder, expectedRedirectURI string) string {
	t.Helper()
	if rr.Code == http.StatusFound {
		loc := rr.Header().Get("Location")
		u, err := url.Parse(loc)
		if err != nil {
			t.Fatalf("parse Location %q: %v", loc, err)
		}
		if expectedRedirectURI != "" {
			if got := u.Scheme + "://" + u.Host + u.Path; got != expectedRedirectURI {
				t.Errorf("redirect target = %q, want %q", got, expectedRedirectURI)
			}
		}
		// RFC 9207 §2: `iss` MUST be on every authorization response,
		// success and error alike. Lock it here so a future regression
		// drops the param silently.
		if iss := u.Query().Get("iss"); iss == "" {
			t.Errorf("redirect missing iss param: %s", loc)
		}
		return u.Query().Get("error")
	}
	var oe OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oe); err != nil {
		t.Fatalf("decode JSON error: %v (body=%q)", err, rr.Body.String())
	}
	return oe.Error
}

func TestAuthorize_InvalidClient(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {"nonexistent-client-id"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_client" {
		t.Errorf("expected error 'invalid_client', got %q", oauthErr.Error)
	}
}

func TestAuthorize_RejectsMalformedCodeChallenge(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {strings.Repeat("!", 43)},
		"code_challenge_method": {"S256"},
		"state":                 {"s"},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()
	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	// RFC 6749 §4.1.2.1: redirect_uri is validated, so the malformed-
	// challenge error must redirect (302) rather than render JSON.
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := extractAuthzError(t, rr, redirectURI); got != "invalid_request" {
		t.Errorf("expected invalid_request, got %q", got)
	}
}

func TestAuthorize_RejectsRepeatedSingletonParam(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})

	params := url.Values{
		"response_type":         {"code", "token"},
		"client_id":             {encClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")},
		"code_challenge_method": {"S256"},
		"state":                 {"s"},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()
	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_request" {
		t.Errorf("expected invalid_request, got %q", oauthErr.Error)
	}
}

func TestAuthorize_BadRedirectURI(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	encClientID, _ := registerClient(t, tm, []string{"https://app.example.com/callback"})

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {"https://evil.example.com/callback"},
		"code_challenge":        {pkceChallenge("verifier")},
		"code_challenge_method": {"S256"},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_request" {
		t.Errorf("expected error 'invalid_request', got %q", oauthErr.Error)
	}
	if !strings.Contains(oauthErr.ErrorDescription, "redirect_uri") {
		t.Errorf("error_description should mention redirect_uri: %q", oauthErr.ErrorDescription)
	}
}

func TestAuthorize_ExpiredClient(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	// Create an already-expired client
	sc := sealedClient{
		ID:           "expired-client",
		RedirectURIs: []string{"https://app.example.com/callback"},
		ClientName:   "expired",
		Typ:          token.PurposeClient,
		Audience:     testBaseURL,
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
	}
	encClientID, err := tm.SealJSON(sc, token.PurposeClient)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {pkceChallenge("verifier")},
		"code_challenge_method": {"S256"},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_client" {
		t.Errorf("expected error 'invalid_client', got %q", oauthErr.Error)
	}
}

// --- Token: authorization_code grant ---

func TestTokenAuthCodeFlow(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := pkceChallenge(codeVerifier)

	authCode := sealCode(t, tm, internalID, redirectURI, codeChallenge, "user-sub-123", "user@example.com")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {codeVerifier},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// RFC 6749 §5.1: Cache-Control must be no-store, Pragma must be no-cache
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("expected Cache-Control: no-store, got %q", cc)
	}
	if pr := rr.Header().Get("Pragma"); pr != "no-cache" {
		t.Errorf("expected Pragma: no-cache, got %q", pr)
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp["token_type"] != "Bearer" {
		t.Errorf("expected token_type Bearer, got %v", resp["token_type"])
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("access_token should not be empty")
	}
	if resp["refresh_token"] == nil || resp["refresh_token"] == "" {
		t.Error("refresh_token should not be empty")
	}
	if resp["expires_in"] == nil {
		t.Error("expires_in should be present")
	}

	// Validate the issued access token
	accessToken, ok := resp["access_token"].(string)
	if !ok {
		t.Fatal("access_token is not a string")
	}
	claims, err := tm.Validate(accessToken)
	if err != nil {
		t.Fatalf("validate access token: %v", err)
	}
	if claims.Subject != "user-sub-123" {
		t.Errorf("expected subject 'user-sub-123', got %q", claims.Subject)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("expected email 'user@example.com', got %q", claims.Email)
	}
	if claims.ClientID != internalID {
		t.Errorf("expected client_id %q, got %q", internalID, claims.ClientID)
	}
}

func TestTokenAuthCode_InvalidCode(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	encClientID, _ := registerClient(t, tm, []string{"https://app.example.com/callback"})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"nonexistent-code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {encClientID},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_grant" {
		t.Errorf("expected error 'invalid_grant', got %q", oauthErr.Error)
	}
}

func TestTokenAuthCode_ExpiredCode(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	expiredVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// Create an expired code
	sc := sealedCode{
		TokenID:       uuid.New().String(),
		FamilyID:      uuid.New().String(),
		ClientID:      internalID,
		RedirectURI:   redirectURI,
		CodeChallenge: pkceChallenge(expiredVerifier),
		Subject:       "user-sub",
		Email:         "user@example.com",
		Typ:           token.PurposeCode,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(-1 * time.Minute),
	}
	expiredCode, err := tm.SealJSON(sc, token.PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {expiredCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {expiredVerifier},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_grant" {
		t.Errorf("expected error 'invalid_grant', got %q", oauthErr.Error)
	}
}

func TestTokenAuthCode_BadPKCE(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	correctVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	wrongVerifier := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	codeChallenge := pkceChallenge(correctVerifier)
	authCode := sealCode(t, tm, internalID, redirectURI, codeChallenge, "user-sub", "user@example.com")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {wrongVerifier},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_grant" {
		t.Errorf("expected error 'invalid_grant', got %q", oauthErr.Error)
	}
	if !strings.Contains(oauthErr.ErrorDescription, "PKCE") {
		t.Errorf("error_description should mention PKCE: %q", oauthErr.ErrorDescription)
	}
}

func TestTokenAuthCode_ClientMismatch(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	_, internalID := registerClient(t, tm, []string{redirectURI})
	otherClientID, _ := registerClient(t, tm, []string{redirectURI})

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := pkceChallenge(codeVerifier)
	authCode := sealCode(t, tm, internalID, redirectURI, codeChallenge, "user-sub", "user@example.com")

	// Use the OTHER client_id to exchange the code
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {otherClientID},
		"code_verifier": {codeVerifier},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_grant" {
		t.Errorf("expected error 'invalid_grant', got %q", oauthErr.Error)
	}
}

// --- Token: refresh_token grant ---

func TestTokenRefreshFlow(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})
	refreshTokenStr := sealRefresh(t, tm, "user-sub-456", "refresh@example.com", internalID)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshTokenStr},
		"client_id":     {encClientID},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp["token_type"] != "Bearer" {
		t.Errorf("expected token_type Bearer, got %v", resp["token_type"])
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("access_token should not be empty")
	}

	newRefresh, ok := resp["refresh_token"].(string)
	if !ok || newRefresh == "" {
		t.Fatal("new refresh_token should not be empty")
	}
	if newRefresh == refreshTokenStr {
		t.Error("refresh token should differ from input (new nonce)")
	}

	// Validate the new access token
	accessToken, ok := resp["access_token"].(string)
	if !ok {
		t.Fatal("access_token is not a string")
	}
	claims, err := tm.Validate(accessToken)
	if err != nil {
		t.Fatalf("validate new access token: %v", err)
	}
	if claims.Subject != "user-sub-456" {
		t.Errorf("expected subject 'user-sub-456', got %q", claims.Subject)
	}
	if claims.Email != "refresh@example.com" {
		t.Errorf("expected email 'refresh@example.com', got %q", claims.Email)
	}
}

func TestTokenRefresh_ExpiredRefresh(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	sr := sealedRefresh{
		TokenID:   uuid.New().String(),
		FamilyID:  uuid.New().String(),
		Subject:   "user",
		Email:     "user@example.com",
		ClientID:  internalID,
		Typ:       token.PurposeRefresh,
		Audience:  testBaseURL,
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	expiredRefresh, err := tm.SealJSON(sr, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {expiredRefresh},
		"client_id":     {encClientID},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_grant" {
		t.Errorf("expected error 'invalid_grant', got %q", oauthErr.Error)
	}
}

func TestTokenRefresh_ClientMismatch(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	_, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})
	otherClientID, _ := registerClient(t, tm, []string{"https://app.example.com/callback"})

	refreshTokenStr := sealRefresh(t, tm, "user-sub", "user@example.com", internalID)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshTokenStr},
		"client_id":     {otherClientID},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_grant" {
		t.Errorf("expected error 'invalid_grant', got %q", oauthErr.Error)
	}
}

// --- Resource Metadata (RFC 9728) ---

func TestResourceMetadata(t *testing.T) {
	baseURL := "https://mcp-proxy.example.com"

	// Root variant: "/"-suffixed resource for Claude.ai / RFC 8707.
	t.Run("root_slash_resource", func(t *testing.T) {
		handler := ResourceMetadata(baseURL+"/", baseURL, "")
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		rr := httptest.NewRecorder()
		handler(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var meta map[string]any
		if err := json.NewDecoder(rr.Body).Decode(&meta); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if meta["resource"] != baseURL+"/" {
			t.Errorf("expected resource=%q, got %v", baseURL+"/", meta["resource"])
		}
		servers, ok := meta["authorization_servers"].([]any)
		if !ok || len(servers) != 1 || servers[0] != baseURL {
			t.Errorf("expected authorization_servers=[%q], got %v", baseURL, meta["authorization_servers"])
		}
		methods, ok := meta["bearer_methods_supported"].([]any)
		if !ok || len(methods) != 1 || methods[0] != "header" {
			t.Errorf("expected bearer_methods_supported=[\"header\"], got %v", meta["bearer_methods_supported"])
		}
	})

	// Per-resource variant per RFC 9728 §3.1: /mcp-scoped document.
	t.Run("mcp_scoped_resource", func(t *testing.T) {
		handler := ResourceMetadata(baseURL+"/mcp", baseURL, "")
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil)
		rr := httptest.NewRecorder()
		handler(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var meta map[string]any
		if err := json.NewDecoder(rr.Body).Decode(&meta); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if meta["resource"] != baseURL+"/mcp" {
			t.Errorf("expected resource=%q, got %v", baseURL+"/mcp", meta["resource"])
		}
		servers, ok := meta["authorization_servers"].([]any)
		if !ok || len(servers) != 1 || servers[0] != baseURL {
			t.Errorf("expected authorization_servers=[%q], got %v", baseURL, meta["authorization_servers"])
		}
	})
}

// TestResourceMetadata_ResourceName verifies the optional RFC 9728 §2
// "resource_name" field: omitted from the JSON when the config value is
// empty, and advertised verbatim when non-empty.
func TestResourceMetadata_ResourceName(t *testing.T) {
	baseURL := "https://mcp-proxy.example.com"

	t.Run("omitted_when_empty", func(t *testing.T) {
		handler := ResourceMetadata(baseURL+"/mcp", baseURL, "")
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil)
		rr := httptest.NewRecorder()
		handler(rr, req)

		var meta map[string]any
		if err := json.NewDecoder(rr.Body).Decode(&meta); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, present := meta["resource_name"]; present {
			t.Errorf("resource_name must be omitted when unset, got %v", meta["resource_name"])
		}
	})

	t.Run("advertised_when_set", func(t *testing.T) {
		name := "ACME MCP Server"
		handler := ResourceMetadata(baseURL+"/mcp", baseURL, name)
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil)
		rr := httptest.NewRecorder()
		handler(rr, req)

		var meta map[string]any
		if err := json.NewDecoder(rr.Body).Decode(&meta); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if meta["resource_name"] != name {
			t.Errorf("resource_name: want %q, got %v", name, meta["resource_name"])
		}
	})
}

// --- Authorize with resource param (RFC 8707) ---

func TestAuthorize_AcceptsResourceParam(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://claude.ai/api/mcp/auth_callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})

	codeChallenge := pkceChallenge("test-verifier")
	target := "/authorize?response_type=code&client_id=" + url.QueryEscape(encClientID) +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code_challenge=" + codeChallenge +
		"&code_challenge_method=S256" +
		"&state=s" +
		"&resource=" + url.QueryEscape(testBaseURL)

	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAuthorize_AcceptsConfiguredMountResourceParam(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://claude.ai/api/mcp/auth_callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})

	codeChallenge := pkceChallenge("test-verifier")
	mountResource := testBaseURL + "/mcp"
	target := "/authorize?response_type=code&client_id=" + url.QueryEscape(encClientID) +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code_challenge=" + codeChallenge +
		"&code_challenge_method=S256" +
		"&state=s" +
		"&resource=" + url.QueryEscape(mountResource)

	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{
		PKCERequired: true,
		ResourceURIs: []string{mountResource},
	})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 for mount resource, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- VerifyPKCE ---

func TestVerifyPKCE(t *testing.T) {
	tests := []struct {
		name      string
		verifier  string
		challenge string
		want      bool
	}{
		{
			name:      "valid pair",
			verifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			challenge: pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
			want:      true,
		},
		{
			name:      "wrong verifier",
			verifier:  "wrong-verifier",
			challenge: pkceChallenge("correct-verifier"),
			want:      false,
		},
		{
			name:      "empty verifier",
			verifier:  "",
			challenge: pkceChallenge("something"),
			want:      false,
		},
		{
			name:      "empty challenge",
			verifier:  "some-verifier",
			challenge: "",
			want:      false,
		},
		{
			// RFC 7636 Appendix B test vector
			name:     "rfc7636 appendix B",
			verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			challenge: func() string {
				h := sha256.Sum256([]byte("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
				return base64.RawURLEncoding.EncodeToString(h[:])
			}(),
			want: true,
		},
		{
			name:      "standard padded base64 should fail",
			verifier:  "test-verifier",
			challenge: base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte("test-verifier"))),
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := VerifyPKCE(tc.verifier, tc.challenge)
			if got != tc.want {
				t.Errorf("VerifyPKCE(%q, %q) = %v, want %v", tc.verifier, tc.challenge, got, tc.want)
			}
		})
	}
}

// --- Unsupported grant type ---

func TestToken_UnsupportedGrantType(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	form := url.Values{
		"grant_type": {"client_credentials"},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "unsupported_grant_type" {
		t.Errorf("expected error 'unsupported_grant_type', got %q", oauthErr.Error)
	}
}

// --- Callback: IdP error response ---

func TestCallback_OIDCErrorResponse(t *testing.T) {
	tm := newTestTokenManager(t)
	oauth2Cfg := &oauth2.Config{
		ClientID:     "test",
		ClientSecret: "test",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://fake/auth",
			TokenURL: "http://fake/token",
		},
	}
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		panic("verifyFunc must not be called when IdP returns error")
	}

	// State is gibberish here, so the no-session fail-open path
	// fires — error_description is REPLACED with a fixed string,
	// regardless of what the IdP redirect carried. The phishing-
	// surface fix: caller-controlled text never reflects on the
	// proxy's own origin.
	const noSessionDesc = "authorization request could not be matched to a known session"
	tests := []struct {
		name     string
		query    string
		wantCode int
		wantErr  string
		wantDesc string
	}{
		{
			name:     "access_denied with description",
			query:    "/callback?error=access_denied&error_description=user+denied+access&state=some-state",
			wantCode: http.StatusBadRequest,
			wantErr:  "access_denied",
			wantDesc: noSessionDesc,
		},
		{
			name:     "server_error without description",
			query:    "/callback?error=server_error&state=some-state",
			wantCode: http.StatusBadRequest,
			wantErr:  "server_error",
			wantDesc: noSessionDesc,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.query, nil)
			rr := httptest.NewRecorder()

			CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc, CallbackConfig{})(rr, req)

			if rr.Code != tc.wantCode {
				t.Fatalf("expected %d, got %d: %s", tc.wantCode, rr.Code, rr.Body.String())
			}

			var cbErr OAuthError
			if err := json.NewDecoder(rr.Body).Decode(&cbErr); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if cbErr.Error != tc.wantErr {
				t.Errorf("expected error %q, got %q", tc.wantErr, cbErr.Error)
			}
			if cbErr.ErrorDescription != tc.wantDesc {
				t.Errorf("expected error_description %q, got %q", tc.wantDesc, cbErr.ErrorDescription)
			}
		})
	}
}

// L4: IdP-supplied error strings outside the RFC 6749 §4.1.2.1 allowlist
// are rewritten to server_error. error_description is truncated at 200
// chars and stripped of non-ASCII-printable bytes.
//
// The sanitizer fires only on the redirect path (validated session)
// — the no-session JSON path uses a fixed description to avoid
// reflecting attacker-controlled text on the proxy origin. So this
// test seeds a real session, lets the IdP-error redirect-back path
// fire, and asserts the sanitized description lands in the redirect
// query string.
func TestCallback_OIDCError_AllowlistAndSanitize(t *testing.T) {
	tm := newTestTokenManager(t)
	oauth2Cfg := testOAuth2Config()
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		panic("verifyFunc must not be called when IdP returns error")
	}

	redirectURI := "https://app.example.com/cb"
	mintState := func(t *testing.T) string {
		t.Helper()
		s := sealedSession{
			ClientID:      uuid.New().String(),
			RedirectURI:   redirectURI,
			OriginalState: "client-state",
			Nonce:         "n",
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

	longDesc := strings.Repeat("A", 250) + "<will-be-trimmed>"

	tests := []struct {
		name       string
		errorParam string
		descParam  string
		wantErr    string
		wantDescIs func(string) bool
	}{
		{
			name:       "unknown_error_collapsed_to_server_error",
			errorParam: "attacker-controlled_value",
			descParam:  "hi",
			wantErr:    "server_error",
			wantDescIs: func(s string) bool { return s == "hi" },
		},
		{
			name:       "description_truncated_to_200",
			errorParam: "access_denied",
			descParam:  longDesc,
			wantErr:    "access_denied",
			wantDescIs: func(s string) bool { return len(s) == 200 && strings.HasPrefix(s, "AAAA") },
		},
		{
			name:       "crlf_stripped",
			errorParam: "invalid_request",
			descParam:  "line1\r\nline2",
			wantErr:    "invalid_request",
			wantDescIs: func(s string) bool {
				return !strings.ContainsAny(s, "\r\n") && strings.Contains(s, "line1line2")
			},
		},
		{
			name:       "non_ascii_stripped",
			errorParam: "access_denied",
			descParam:  "café naïve",
			wantErr:    "access_denied",
			wantDescIs: func(s string) bool {
				return strings.Contains(s, "caf") && !strings.ContainsRune(s, 'é')
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := mintState(t)
			query := "/callback?error=" + url.QueryEscape(tc.errorParam) +
				"&error_description=" + url.QueryEscape(tc.descParam) +
				"&state=" + url.QueryEscape(state)
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, query, nil)
			rr := httptest.NewRecorder()

			CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc, CallbackConfig{})(rr, req)

			if rr.Code != http.StatusFound {
				t.Fatalf("expected 302 redirect (session validated), got %d: %s", rr.Code, rr.Body.String())
			}
			loc, err := url.Parse(rr.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			gotErr := loc.Query().Get("error")
			gotDesc := loc.Query().Get("error_description")
			if gotErr != tc.wantErr {
				t.Errorf("error = %q, want %q", gotErr, tc.wantErr)
			}
			if !tc.wantDescIs(gotDesc) {
				t.Errorf("unexpected error_description %q", gotDesc)
			}
		})
	}
}

// --- Register: HTTPS redirect_uri validation ---

func TestRegister_RejectsHTTPNonLoopback(t *testing.T) {
	tm := newTestTokenManager(t)

	body := `{"redirect_uris":["http://evil.example.com/callback"],"client_name":"bad"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	Register(tm, zap.NewNop(), testBaseURL)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// RFC 7591 §3.2.2: redirect_uri-shaped defects use the dedicated code.
	if oauthErr.Error != "invalid_redirect_uri" {
		t.Errorf("expected error 'invalid_redirect_uri', got %q", oauthErr.Error)
	}
	if !strings.Contains(oauthErr.ErrorDescription, "HTTPS") {
		t.Errorf("error_description should mention HTTPS: %q", oauthErr.ErrorDescription)
	}
}

func TestRegister_AllowsHTTPLoopback(t *testing.T) {
	tm := newTestTokenManager(t)

	for _, uri := range []string{
		"http://localhost:8080/callback",
		"http://127.0.0.1:3000/callback",
		"http://[::1]:9090/callback",
	} {
		t.Run(uri, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"redirect_uris": []string{uri}, "client_name": "local"})
			req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			Register(tm, zap.NewNop(), testBaseURL)(rr, req)

			if rr.Code != http.StatusCreated {
				t.Fatalf("expected 201 for loopback URI %q, got %d: %s", uri, rr.Code, rr.Body.String())
			}
		})
	}
}

// --- Callback: missing/tampered state ---

func TestCallback_MissingCodeOrState(t *testing.T) {
	tm := newTestTokenManager(t)
	oauth2Cfg := testOAuth2Config()
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		panic("must not be called")
	}

	tests := []struct {
		name  string
		query string
	}{
		{"missing both", "/callback"},
		{"missing code", "/callback?state=something"},
		{"missing state", "/callback?code=something"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.query, nil)
			rr := httptest.NewRecorder()

			CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc, CallbackConfig{})(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
			}

			var oauthErr OAuthError
			json.NewDecoder(rr.Body).Decode(&oauthErr)
			if oauthErr.Error != "invalid_request" {
				t.Errorf("expected error 'invalid_request', got %q", oauthErr.Error)
			}
		})
	}
}

func TestCallback_RejectsRepeatedSingletonParam(t *testing.T) {
	tm := newTestTokenManager(t)
	oauth2Cfg := testOAuth2Config()
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		panic("must not be called")
	}

	req := httptest.NewRequest(http.MethodGet, "/callback?code=a&code=b&state=s", nil)
	rr := httptest.NewRecorder()

	CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc, CallbackConfig{})(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var oauthErr OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_request" {
		t.Errorf("expected error 'invalid_request', got %q", oauthErr.Error)
	}
}

func TestCallback_TamperedState(t *testing.T) {
	tm := newTestTokenManager(t)
	oauth2Cfg := testOAuth2Config()
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		panic("must not be called")
	}

	req := httptest.NewRequest(http.MethodGet, "/callback?code=fake-code&state=garbage-not-encrypted", nil)
	rr := httptest.NewRecorder()

	CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc, CallbackConfig{})(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var oauthErr OAuthError
	json.NewDecoder(rr.Body).Decode(&oauthErr)
	if oauthErr.Error != "invalid_request" {
		t.Errorf("expected error 'invalid_request', got %q", oauthErr.Error)
	}
}

// --- Token: client expiry at exchange time ---

func TestTokenAuthCode_ExpiredClient(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"

	// Create an already-expired client
	sc := sealedClient{
		ID:           "expired-client-id",
		RedirectURIs: []string{redirectURI},
		ClientName:   "expired",
		Typ:          token.PurposeClient,
		Audience:     testBaseURL,
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
	}
	encClientID, err := tm.SealJSON(sc, token.PurposeClient)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := pkceChallenge(codeVerifier)
	authCode := sealCode(t, tm, sc.ID, redirectURI, codeChallenge, "user-sub", "user@example.com")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {codeVerifier},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var oauthErr OAuthError
	json.NewDecoder(rr.Body).Decode(&oauthErr)
	if oauthErr.Error != "invalid_client" {
		t.Errorf("expected error 'invalid_client', got %q", oauthErr.Error)
	}
}

func TestTokenRefresh_ExpiredClient(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	// Create an already-expired client
	sc := sealedClient{
		ID:           "expired-client-id",
		RedirectURIs: []string{"https://app.example.com/callback"},
		ClientName:   "expired",
		Typ:          token.PurposeClient,
		Audience:     testBaseURL,
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
	}
	encClientID, err := tm.SealJSON(sc, token.PurposeClient)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	refreshTokenStr := sealRefresh(t, tm, "user-sub", "user@example.com", sc.ID)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshTokenStr},
		"client_id":     {encClientID},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var oauthErr OAuthError
	json.NewDecoder(rr.Body).Decode(&oauthErr)
	if oauthErr.Error != "invalid_client" {
		t.Errorf("expected error 'invalid_client', got %q", oauthErr.Error)
	}
}

// --- Token: PKCE verifier length validation ---

func TestTokenAuthCode_VerifierTooShort(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	shortVerifier := "too-short" // 9 chars, minimum is 43
	authCode := sealCode(t, tm, internalID, redirectURI, pkceChallenge(shortVerifier), "user", "u@example.com")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {shortVerifier},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var oauthErr OAuthError
	json.NewDecoder(rr.Body).Decode(&oauthErr)
	if oauthErr.Error != "invalid_request" {
		t.Errorf("expected error 'invalid_request', got %q", oauthErr.Error)
	}
}

func TestTokenAuthCode_VerifierTooLong(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	longVerifier := strings.Repeat("a", 129) // 129 chars, maximum is 128
	authCode := sealCode(t, tm, internalID, redirectURI, pkceChallenge(longVerifier), "user", "u@example.com")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {longVerifier},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var oauthErr OAuthError
	json.NewDecoder(rr.Body).Decode(&oauthErr)
	if oauthErr.Error != "invalid_request" {
		t.Errorf("expected error 'invalid_request', got %q", oauthErr.Error)
	}
}

func TestTokenAuthCode_VerifierInvalidCharacters(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	badVerifier := strings.Repeat("A", 42) + "!"
	authCode := sealCode(t, tm, internalID, redirectURI, pkceChallenge(badVerifier), "user", "u@example.com")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {badVerifier},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}

	var oauthErr OAuthError
	json.NewDecoder(rr.Body).Decode(&oauthErr)
	if oauthErr.Error != "invalid_request" {
		t.Errorf("expected error 'invalid_request', got %q", oauthErr.Error)
	}
}

// --- Token: groups preserved through exchange ---

func TestTokenAuthCodeFlow_GroupsPreserved(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := pkceChallenge(codeVerifier)

	sc := sealedCode{
		TokenID:       uuid.New().String(),
		FamilyID:      uuid.New().String(),
		ClientID:      internalID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		Subject:       "user-sub",
		Email:         "user@example.com",
		Groups:        []string{"admin", "dev"},
		Typ:           token.PurposeCode,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	authCode, err := tm.SealJSON(sc, token.PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {codeVerifier},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)

	accessToken := resp["access_token"].(string)
	claims, err := tm.Validate(accessToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(claims.Groups) != 2 || claims.Groups[0] != "admin" || claims.Groups[1] != "dev" {
		t.Errorf("expected groups [admin dev], got %v", claims.Groups)
	}
}

func TestTokenRefreshFlow_GroupsPreserved(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	sr := sealedRefresh{
		TokenID:   uuid.New().String(),
		FamilyID:  uuid.New().String(),
		Subject:   "user-sub",
		Email:     "user@example.com",
		Groups:    []string{"editors"},
		ClientID:  internalID,
		Typ:       token.PurposeRefresh,
		Audience:  testBaseURL,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	refreshTokenStr, err := tm.SealJSON(sr, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshTokenStr},
		"client_id":     {encClientID},
	}

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)

	accessToken := resp["access_token"].(string)
	claims, err := tm.Validate(accessToken)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(claims.Groups) != 1 || claims.Groups[0] != "editors" {
		t.Errorf("expected groups [editors], got %v", claims.Groups)
	}

	// Verify new refresh token also carries groups
	newRefreshStr := resp["refresh_token"].(string)
	var newRefresh sealedRefresh
	if err := tm.OpenJSON(newRefreshStr, &newRefresh, token.PurposeRefresh); err != nil {
		t.Fatalf("OpenJSON refresh: %v", err)
	}
	if len(newRefresh.Groups) != 1 || newRefresh.Groups[0] != "editors" {
		t.Errorf("expected refresh groups [editors], got %v", newRefresh.Groups)
	}
}

// --- hasOverlap ---

func TestHasOverlap(t *testing.T) {
	tests := []struct {
		name    string
		user    []string
		allowed []string
		want    bool
	}{
		{"match", []string{"admin", "dev"}, []string{"dev"}, true},
		{"no match", []string{"dev"}, []string{"admin"}, false},
		{"empty user groups", nil, []string{"admin"}, false},
		{"empty allowed", []string{"dev"}, nil, false},
		{"both empty", nil, nil, false},
		{"multiple overlap", []string{"a", "b"}, []string{"b", "c"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasOverlap(tc.user, tc.allowed); got != tc.want {
				t.Errorf("hasOverlap(%v, %v) = %v, want %v", tc.user, tc.allowed, got, tc.want)
			}
		})
	}
}

// --- Authorize: PKCE optional mode ---

func TestAuthorize_PKCEOptional_NoPKCE(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})

	// No code_challenge or code_challenge_method — should succeed in relaxed mode
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {encClientID},
		"redirect_uri":  {redirectURI},
		"state":         {"user-state"},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: false})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 with PKCE optional, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAuthorize_PKCERequired_NoPKCE(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {encClientID},
		"redirect_uri":  {redirectURI},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	// RFC 6749 §4.1.2.1: PKCE-required without challenge → redirect.
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 with PKCE required, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := extractAuthzError(t, rr, redirectURI); got != "invalid_request" {
		t.Errorf("expected invalid_request, got %q", got)
	}
}

func TestAuthorize_PKCEOptional_RejectsPlain(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {"some-challenge"},
		"code_challenge_method": {"plain"},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: false})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 for plain method even in relaxed mode, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := extractAuthzError(t, rr, redirectURI); got != "invalid_request" {
		t.Errorf("expected invalid_request, got %q", got)
	}
}

func TestAuthorize_PKCEOptional_RejectsChallengeWithoutMethod(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})

	params := url.Values{
		"response_type":  {"code"},
		"client_id":      {encClientID},
		"redirect_uri":   {redirectURI},
		"code_challenge": {pkceChallenge("verifier")},
		"state":          {"s"},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: false})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 for code_challenge without method, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := extractAuthzError(t, rr, redirectURI); got != "invalid_request" {
		t.Errorf("expected invalid_request, got %q", got)
	}
}

// --- Authorize: state handling (H7) ---
//
// Default (strict) mode refuses /authorize when the client omits state —
// a missing state hides a client-side CSRF bug. COMPAT_ALLOW_STATELESS=true
// keeps the legacy Cursor/MCP Inspector behavior of synthesizing one
// server-side. Either way we emit mcp_auth_access_denied_total{reason=
// "state_missing"} so operators can see which clients still rely on it.

func TestAuthorize_RefusesStatelessByDefault(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})
	challenge := pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	// RFC 6749 §4.1.2.1: state_missing comes after redirect_uri is
	// validated → redirect with `error=invalid_request`. The redirect
	// carries no state (the client never sent one), but DOES carry iss.
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 state_missing in strict mode, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := extractAuthzError(t, rr, redirectURI); got != "invalid_request" {
		t.Errorf("expected invalid_request, got %q", got)
	}
}

func TestAuthorize_CompatGeneratesStateWhenMissing(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})
	challenge := pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{
		PKCERequired:         true,
		CompatAllowStateless: true,
	})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 in compat mode, got %d: %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "state=") {
		t.Errorf("redirect should contain server-generated state: %s", loc)
	}
}

// --- H6: server-side PKCE in relaxed mode ---
//
// When PKCE_REQUIRED=false and the client omits code_challenge, the proxy
// mints a downstream PKCE pair itself so the code is still anchored to a
// verifier — /token verifies it internally and the replay store enforces
// single-use. The client sends no code_verifier in this path.

func TestAuthorize_ServerSidePKCE_WhenClientOmits(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {encClientID},
		"redirect_uri":  {redirectURI},
		"state":         {"s"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: false})(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rr.Code, rr.Body.String())
	}

	idpURL, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	internalState := idpURL.Query().Get("state")
	if internalState == "" {
		t.Fatal("expected sealed state in IdP redirect")
	}

	var session sealedSession
	if err := tm.OpenJSON(internalState, &session, token.PurposeSession); err != nil {
		t.Fatalf("OpenJSON session: %v", err)
	}
	if session.SvrVerifier == "" || session.SvrChallenge == "" {
		t.Fatal("expected server-side PKCE pair to be populated on sealedSession")
	}
	if session.CodeChallenge != session.SvrChallenge {
		t.Errorf("CodeChallenge should mirror SvrChallenge when H6 kicks in")
	}
	if ComputePKCEChallenge(session.SvrVerifier) != session.SvrChallenge {
		t.Errorf("SvrChallenge must be S256 of SvrVerifier")
	}
}

func TestAuthorize_ServerSidePKCE_NotSet_WhenClientProvides(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})
	challenge := pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"s"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: false})(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rr.Code, rr.Body.String())
	}

	idpURL, _ := url.Parse(rr.Header().Get("Location"))
	internalState := idpURL.Query().Get("state")
	var session sealedSession
	if err := tm.OpenJSON(internalState, &session, token.PurposeSession); err != nil {
		t.Fatalf("OpenJSON session: %v", err)
	}
	if session.SvrVerifier != "" || session.SvrChallenge != "" {
		t.Errorf("server-side PKCE must stay empty when client supplied its own challenge")
	}
	if session.CodeChallenge != challenge {
		t.Errorf("session CodeChallenge should mirror client-supplied challenge")
	}
}

// TestToken_ServerSidePKCE_ClientOmitsVerifier: when the proxy minted
// the downstream PKCE pair at /authorize (ServerPKCE=true), /token accepts
// the code without the client sending a code_verifier because the code
// carries the matching SvrVerifier internally.
func TestToken_ServerSidePKCE_ClientOmitsVerifier(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	svrVerifier := "server-minted-verifier-that-is-plenty-long-enough-xyz"
	svrChallenge := ComputePKCEChallenge(svrVerifier)

	sc := sealedCode{
		TokenID:       uuid.New().String(),
		FamilyID:      uuid.New().String(),
		ClientID:      internalID,
		RedirectURI:   redirectURI,
		CodeChallenge: svrChallenge,
		Subject:       "user-sub",
		Email:         "u@example.com",
		ServerPKCE:    true,
		SvrVerifier:   svrVerifier,
		Typ:           token.PurposeCode,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	code, err := tm.SealJSON(sc, token.PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {encClientID},
		// no code_verifier on purpose — H6 path
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with H6 server-side PKCE, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestToken_ServerSidePKCE_RejectsWrongClientVerifier: even in H6 mode, a
// client that tries to send its own verifier must not be able to bypass
// the server-minted challenge. This stops a party that captured the code
// from claiming ownership by brute-force supplying any verifier; only the
// empty "client omitted verifier" case is allowed.
func TestToken_ServerSidePKCE_RejectsWrongClientVerifier(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	svrVerifier := "server-minted-verifier-that-is-plenty-long-enough-xyz"
	svrChallenge := ComputePKCEChallenge(svrVerifier)
	sc := sealedCode{
		TokenID:       uuid.New().String(),
		FamilyID:      uuid.New().String(),
		ClientID:      internalID,
		RedirectURI:   redirectURI,
		CodeChallenge: svrChallenge,
		Subject:       "user-sub",
		Email:         "u@example.com",
		ServerPKCE:    true,
		SvrVerifier:   svrVerifier,
		Typ:           token.PurposeCode,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	code, err := tm.SealJSON(sc, token.PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {"attacker-supplied-verifier-that-wont-match-the-svr-pair"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong client-supplied verifier, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- Cross-instance audience replay protection ---

// TestCallback_RejectsForeignSession verifies that a session minted with a
// different audience (e.g. by a sibling proxy sharing the same secret) is
// rejected at /callback before the IdP code exchange ever runs.
func TestCallback_RejectsForeignSession(t *testing.T) {
	tm := newTestTokenManager(t)
	oauth2Cfg := testOAuth2Config()
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		panic("must not be called when audience mismatch is rejected first")
	}

	foreign := sealedSession{
		ClientID:      "client",
		RedirectURI:   "https://app.example.com/callback",
		CodeChallenge: "",
		OriginalState: "abc",
		Typ:           token.PurposeSession,
		Audience:      "https://other-proxy.example.com",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	state, err := tm.SealJSON(foreign, token.PurposeSession)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/callback?code=anything&state="+url.QueryEscape(state), nil)
	rr := httptest.NewRecorder()
	CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc, CallbackConfig{})(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for foreign-audience session, got %d: %s", rr.Code, rr.Body.String())
	}
	var oauthErr OAuthError
	json.NewDecoder(rr.Body).Decode(&oauthErr)
	if oauthErr.Error != "invalid_request" {
		t.Errorf("expected invalid_request, got %q", oauthErr.Error)
	}
	if !strings.Contains(oauthErr.ErrorDescription, "audience") {
		t.Errorf("error_description should mention audience: %q", oauthErr.ErrorDescription)
	}
}

// TestAuthorize_RejectsForeignClient verifies that a client_id minted by a
// sibling proxy (sharing the same TOKEN_SIGNING_SECRET but a different baseURL)
// is rejected by /authorize.
func TestAuthorize_RejectsForeignClient(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"

	// Register the client with a foreign audience.
	foreign := sealedClient{
		ID:           "foreign-client",
		RedirectURIs: []string{redirectURI},
		ClientName:   "from-other-proxy",
		Typ:          token.PurposeClient,
		Audience:     "https://other-proxy.example.com",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	encClientID, err := tm.SealJSON(foreign, token.PurposeClient)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")},
		"code_challenge_method": {"S256"},
	}

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()
	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for foreign-audience client, got %d: %s", rr.Code, rr.Body.String())
	}
	var oauthErr OAuthError
	json.NewDecoder(rr.Body).Decode(&oauthErr)
	if oauthErr.Error != "invalid_client" {
		t.Errorf("expected invalid_client, got %q", oauthErr.Error)
	}
}

// TestTokenAuthCode_RejectsForeignCode verifies that an authorization code minted
// for a different proxy audience is rejected at /token.
func TestTokenAuthCode_RejectsForeignCode(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := pkceChallenge(codeVerifier)

	// Code minted for a different proxy.
	foreignCode := sealedCode{
		TokenID:       uuid.New().String(),
		FamilyID:      uuid.New().String(),
		ClientID:      internalID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		Subject:       "user-sub",
		Email:         "u@example.com",
		Typ:           token.PurposeCode,
		Audience:      "https://other-proxy.example.com",
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	authCode, err := tm.SealJSON(foreignCode, token.PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {codeVerifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for foreign-audience code, got %d: %s", rr.Code, rr.Body.String())
	}
	var oauthErr OAuthError
	json.NewDecoder(rr.Body).Decode(&oauthErr)
	if oauthErr.Error != "invalid_grant" {
		t.Errorf("expected invalid_grant, got %q", oauthErr.Error)
	}
}

// TestTokenRefresh_RejectsForeignRefresh verifies that a refresh token minted
// for a different proxy audience is rejected.
func TestTokenRefresh_RejectsForeignRefresh(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	foreign := sealedRefresh{
		TokenID:   uuid.New().String(),
		FamilyID:  uuid.New().String(),
		Subject:   "user",
		Email:     "u@example.com",
		ClientID:  internalID,
		Typ:       token.PurposeRefresh,
		Audience:  "https://other-proxy.example.com",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	refreshTokenStr, err := tm.SealJSON(foreign, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshTokenStr},
		"client_id":     {encClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for foreign-audience refresh, got %d: %s", rr.Code, rr.Body.String())
	}
	var oauthErr OAuthError
	json.NewDecoder(rr.Body).Decode(&oauthErr)
	if oauthErr.Error != "invalid_grant" {
		t.Errorf("expected invalid_grant, got %q", oauthErr.Error)
	}
}

// --- REVOKE_BEFORE applied to refresh tokens ---

// TestTokenRefresh_RevokedByCutoff verifies that REVOKE_BEFORE rejects refresh
// tokens issued before the cutoff. Without this, a leaked refresh would still
// be usable to mint fresh access tokens past the cutoff.
func TestTokenRefresh_RevokedByCutoff(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	// Refresh token issued 1 hour ago...
	old := sealedRefresh{
		TokenID:   uuid.New().String(),
		FamilyID:  uuid.New().String(),
		Subject:   "user",
		Email:     "u@example.com",
		ClientID:  internalID,
		Typ:       token.PurposeRefresh,
		Audience:  testBaseURL,
		IssuedAt:  time.Now().Add(-1 * time.Hour),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	refreshTokenStr, err := tm.SealJSON(old, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	// ...with a cutoff set to 30 minutes ago. The refresh predates it.
	cutoff := time.Now().Add(-30 * time.Minute)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshTokenStr},
		"client_id":     {encClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, cutoff, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for revoked refresh, got %d: %s", rr.Code, rr.Body.String())
	}
	var oauthErr OAuthError
	json.NewDecoder(rr.Body).Decode(&oauthErr)
	if oauthErr.Error != "invalid_grant" {
		t.Errorf("expected invalid_grant, got %q", oauthErr.Error)
	}
}

// TestTokenRefresh_NotRevokedAfterCutoff verifies that a refresh token issued
// after the cutoff is still accepted.
func TestTokenRefresh_NotRevokedAfterCutoff(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	cutoff := time.Now().Add(-1 * time.Hour)

	fresh := sealedRefresh{
		TokenID:   uuid.New().String(),
		FamilyID:  uuid.New().String(),
		Subject:   "user",
		Email:     "u@example.com",
		ClientID:  internalID,
		Typ:       token.PurposeRefresh,
		Audience:  testBaseURL,
		IssuedAt:  time.Now(), // after cutoff
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	refreshTokenStr, err := tm.SealJSON(fresh, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshTokenStr},
		"client_id":     {encClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, cutoff, nil)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for refresh after cutoff, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestTokenRefresh_NewTokenCarriesIssuedAt verifies that the rotated
// refresh token has its IssuedAt updated to "now". Per-rotation
// freshness is what the replay-store reuse-detection cares about;
// the bulk REVOKE_BEFORE cutoff is anchored to FamilyIssuedAt
// instead and is exercised by TestTokenRefresh_FamilyIssuedAt_*.
func TestTokenRefresh_NewTokenCarriesIssuedAt(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	old := sealedRefresh{
		TokenID:   uuid.New().String(),
		FamilyID:  uuid.New().String(),
		Subject:   "user",
		Email:     "u@example.com",
		ClientID:  internalID,
		Typ:       token.PurposeRefresh,
		Audience:  testBaseURL,
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	oldRefreshTokenStr, err := tm.SealJSON(old, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {oldRefreshTokenStr},
		"client_id":     {encClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)

	newRefreshStr := resp["refresh_token"].(string)
	var newRefresh sealedRefresh
	if err := tm.OpenJSON(newRefreshStr, &newRefresh, token.PurposeRefresh); err != nil {
		t.Fatalf("OpenJSON: %v", err)
	}
	if newRefresh.IssuedAt.Before(time.Now().Add(-1 * time.Minute)) {
		t.Errorf("rotated refresh IssuedAt should be ~now, got %v", newRefresh.IssuedAt)
	}
	if newRefresh.Audience != testBaseURL {
		t.Errorf("rotated refresh audience: got %q, want %q", newRefresh.Audience, testBaseURL)
	}
}

// TestTokenRefresh_FamilyIssuedAt_Inherited pins C-M3: a rotated
// refresh inherits FamilyIssuedAt from its predecessor, so the
// stamp the bulk REVOKE_BEFORE cutoff is compared against does NOT
// drift forward across rotations. Without this, a quietly rotating
// attacker could outlive an operator's bulk revocation.
func TestTokenRefresh_FamilyIssuedAt_Inherited(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	familyOrigin := time.Now().Add(-3 * time.Hour)
	parent := sealedRefresh{
		TokenID:        uuid.New().String(),
		FamilyID:       uuid.New().String(),
		Subject:        "user",
		Email:          "u@example.com",
		ClientID:       internalID,
		Typ:            token.PurposeRefresh,
		Audience:       testBaseURL,
		IssuedAt:       time.Now().Add(-30 * time.Minute),
		FamilyIssuedAt: familyOrigin,
		ExpiresAt:      time.Now().Add(7 * 24 * time.Hour),
	}
	parentStr, err := tm.SealJSON(parent, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {parentStr},
		"client_id":     {encClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("rotation: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	var rotated sealedRefresh
	if err := tm.OpenJSON(resp["refresh_token"].(string), &rotated, token.PurposeRefresh); err != nil {
		t.Fatalf("OpenJSON rotated: %v", err)
	}
	if !rotated.FamilyIssuedAt.Equal(familyOrigin) {
		t.Errorf("FamilyIssuedAt drifted across rotation: got %v, want %v", rotated.FamilyIssuedAt, familyOrigin)
	}
	if !rotated.IssuedAt.After(parent.IssuedAt) {
		t.Errorf("rotated IssuedAt should advance, got %v (parent %v)", rotated.IssuedAt, parent.IssuedAt)
	}
}

// TestTokenRefresh_RevokeBefore_CatchesRotatedFamily pins C-M3 from
// the operator's perspective: an operator who sets REVOKE_BEFORE to
// a stamp AFTER a session's family origin must invalidate the
// session even when the attacker has already rotated the refresh
// once. Comparing against IssuedAt would let the rotated token
// sneak past; comparing against FamilyIssuedAt catches it.
func TestTokenRefresh_RevokeBefore_CatchesRotatedFamily(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	familyOrigin := time.Now().Add(-3 * time.Hour)
	// Rotated refresh: IssuedAt is "now" (just rotated), but the
	// family was first issued 3h ago. Operator sets REVOKE_BEFORE
	// to 1h ago — the family origin predates it, the rotated stamp
	// does not.
	rotated := sealedRefresh{
		TokenID:        uuid.New().String(),
		FamilyID:       uuid.New().String(),
		Subject:        "user",
		Email:          "u@example.com",
		ClientID:       internalID,
		Typ:            token.PurposeRefresh,
		Audience:       testBaseURL,
		IssuedAt:       time.Now(),
		FamilyIssuedAt: familyOrigin,
		ExpiresAt:      time.Now().Add(7 * 24 * time.Hour),
	}
	rotatedStr, err := tm.SealJSON(rotated, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	cutoff := time.Now().Add(-1 * time.Hour)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rotatedStr},
		"client_id":     {encClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Token(tm, logger, testBaseURL, cutoff, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("REVOKE_BEFORE must catch rotated family; got status %d body %s", rr.Code, rr.Body.String())
	}
	var oauthErr OAuthError
	json.NewDecoder(rr.Body).Decode(&oauthErr)
	if oauthErr.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", oauthErr.Error)
	}
}

// TestTokenRefresh_LegacyZeroFamilyIssuedAt_FallsBackToIssuedAt
// pins the rolling-deploy backstop: a refresh sealed before
// FamilyIssuedAt existed (zero value) is evaluated against
// IssuedAt for REVOKE_BEFORE, and the rotated descendant tightens
// the invariant by adopting the parent's IssuedAt as its
// FamilyIssuedAt seed.
func TestTokenRefresh_LegacyZeroFamilyIssuedAt_FallsBackToIssuedAt(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	parentIssued := time.Now().Add(-2 * time.Hour)
	legacy := sealedRefresh{
		TokenID:   uuid.New().String(),
		FamilyID:  uuid.New().String(),
		Subject:   "user",
		Email:     "u@example.com",
		ClientID:  internalID,
		Typ:       token.PurposeRefresh,
		Audience:  testBaseURL,
		IssuedAt:  parentIssued,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		// FamilyIssuedAt deliberately zero — emulates a refresh
		// sealed by a pre-C-M3 build.
	}
	legacyStr, err := tm.SealJSON(legacy, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	// Rotation succeeds with no cutoff.
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {legacyStr},
		"client_id":     {encClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("legacy rotation: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(rr.Body).Decode(&resp)
	var rotated sealedRefresh
	if err := tm.OpenJSON(resp["refresh_token"].(string), &rotated, token.PurposeRefresh); err != nil {
		t.Fatalf("OpenJSON rotated: %v", err)
	}
	if !rotated.FamilyIssuedAt.Equal(parentIssued) {
		t.Errorf("rotation should seed FamilyIssuedAt from parent IssuedAt; got %v want %v", rotated.FamilyIssuedAt, parentIssued)
	}

	// Now apply REVOKE_BEFORE just after the legacy parent's
	// IssuedAt — the legacy parent (zero FamilyIssuedAt → falls
	// back to IssuedAt) must be rejected.
	cutoff := parentIssued.Add(1 * time.Minute)
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	Token(tm, logger, testBaseURL, cutoff, nil)(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("REVOKE_BEFORE on legacy refresh: want 400, got %d: %s", rr2.Code, rr2.Body.String())
	}
}

// --- Replay protection (single-use authorization codes) ---

// TestTokenAuthCode_ReplayStore_RejectsSecondUse verifies that when a replay
// store is wired, a second attempt to exchange the same authorization code is
// rejected with invalid_grant — the stateless proxy cannot detect this on its
// own and relies on the store for single-use enforcement (RFC 6749 §4.1.2).
func TestTokenAuthCode_ReplayStore_RejectsSecondUse(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	store := replay.NewMemoryStore()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := pkceChallenge(codeVerifier)

	sc := sealedCode{
		TokenID:       uuid.New().String(),
		FamilyID:      uuid.New().String(),
		ClientID:      internalID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		Subject:       "user-sub",
		Email:         "user@example.com",
		Typ:           token.PurposeCode,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(60 * time.Second),
	}
	authCode, err := tm.SealJSON(sc, token.PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	exchange := func() *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authCode},
			"redirect_uri":  {redirectURI},
			"client_id":     {encClientID},
			"code_verifier": {codeVerifier},
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		Token(tm, logger, testBaseURL, time.Time{}, store)(rr, req)
		return rr
	}

	// First exchange: must succeed.
	first := exchange()
	if first.Code != http.StatusOK {
		t.Fatalf("first exchange: want 200, got %d: %s", first.Code, first.Body.String())
	}

	// Second exchange with the same code: must be rejected.
	second := exchange()
	if second.Code != http.StatusBadRequest {
		t.Fatalf("second exchange: want 400, got %d: %s", second.Code, second.Body.String())
	}
	var oauthErr OAuthError
	if err := json.NewDecoder(second.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oauthErr.Error != "invalid_grant" {
		t.Errorf("expected invalid_grant, got %q", oauthErr.Error)
	}
	if oauthErr.ErrorCode != "code_replay" {
		t.Errorf("expected error_code=code_replay, got %q", oauthErr.ErrorCode)
	}
}

// TestRedirectURIMatches_LoopbackPortAgnostic pins RFC 8252 §7.3: when both
// URIs are loopback, any port on the requested URI is accepted. Every other
// URI component must still match. Non-loopback URIs still require exact-string
// equality (OAuth 2.1 §2.3.1).
func TestRedirectURIMatches_LoopbackPortAgnostic(t *testing.T) {
	cases := []struct {
		name       string
		registered string
		requested  string
		want       bool
	}{
		// Loopback, port varies → accept.
		{"ipv4_port_differs", "http://127.0.0.1:8080/cb", "http://127.0.0.1:47521/cb", true},
		{"ipv4_registered_no_port", "http://127.0.0.1/cb", "http://127.0.0.1:47521/cb", true},
		{"ipv6_port_differs", "http://[::1]:8080/cb", "http://[::1]:47521/cb", true},
		{"localhost_port_differs", "http://localhost:8080/cb", "http://localhost:47521/cb", true},
		{"localhost_trailing_dot", "http://localhost./cb", "http://localhost:8080/cb", true},
		{"query_matches", "http://127.0.0.1:8080/cb?client=a", "http://127.0.0.1:47521/cb?client=a", true},
		// Loopback but non-port component differs → reject.
		{"path_differs", "http://127.0.0.1:8080/cb", "http://127.0.0.1:8080/other", false},
		{"path_encoding_differs", "http://127.0.0.1:8080/cb%2Fone", "http://127.0.0.1:47521/cb/one", false},
		{"query_differs", "http://127.0.0.1:8080/cb?client=a", "http://127.0.0.1:47521/cb?client=b", false},
		{"query_added", "http://127.0.0.1:8080/cb", "http://127.0.0.1:47521/cb?client=b", false},
		{"userinfo_added", "http://127.0.0.1:8080/cb", "http://user@127.0.0.1:47521/cb", false},
		{"host_literal_differs", "http://127.0.0.1:8080/cb", "http://localhost:8080/cb", false},
		{"scheme_differs", "http://127.0.0.1:8080/cb", "https://127.0.0.1:8080/cb", false},
		// Non-loopback → strict equality, port must match.
		{"nonloopback_exact_match", "https://app.example.com/cb", "https://app.example.com/cb", true},
		{"nonloopback_port_differs", "https://app.example.com:8080/cb", "https://app.example.com:9090/cb", false},
		// One side loopback, other not → reject (no port relaxation).
		{"loopback_vs_nonloopback", "http://127.0.0.1:8080/cb", "http://evil.example.com:8080/cb", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redirectURIMatches(tc.requested, tc.registered)
			if got != tc.want {
				t.Errorf("redirectURIMatches(%q, %q) = %v, want %v", tc.requested, tc.registered, got, tc.want)
			}
		})
	}
}

// TestAuthorize_LoopbackPortRelaxation_Accepts_DifferentPort verifies
// the RFC 8252 §7.3 relaxation lands end-to-end at /authorize: a
// native client registered with one ephemeral port comes back at
// /authorize with a different port and is accepted (302 to the IdP).
// Strict port equality would force re-registration on every native-app
// launch — exactly what RFC 8252 §7.3 forbids.
func TestAuthorize_LoopbackPortRelaxation_Accepts_DifferentPort(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	registered := "http://127.0.0.1:8080/cb"
	requested := "http://127.0.0.1:47521/cb"
	encClientID, _ := registerClient(t, tm, []string{registered})

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {requested},
		"code_challenge":        {pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")},
		"code_challenge_method": {"S256"},
		"state":                 {"native-app-state"},
	}
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	// Success path: 302 to the IdP authorization endpoint (NOT a
	// redirect-error response — the registered URI is loopback and
	// only the port differs, so the relaxation accepts).
	if rr.Code != http.StatusFound {
		t.Fatalf("want 302 to IdP, got %d: %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, testOAuth2Config().Endpoint.AuthURL) {
		t.Errorf("Location should redirect to IdP authorize endpoint, got %q", loc)
	}
}

// TestAuthorize_LoopbackPortRelaxation_RejectsDifferentHost — the
// relaxation is port-only. A registered loopback URI must NOT match
// a non-loopback requested URI even if every other component lines
// up. Locks the boundary that keeps the relaxation from becoming an
// open-redirect primitive.
func TestAuthorize_LoopbackPortRelaxation_RejectsDifferentHost(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	registered := "http://127.0.0.1:8080/cb"
	encClientID, _ := registerClient(t, tm, []string{registered})

	// Non-loopback host with otherwise identical shape — must be
	// rejected with JSON 400 (this is a redirect_uri-trust failure,
	// so RFC 6749 §4.1.2.1 says render on the AS, not redirect).
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {"http://evil.example.com:8080/cb"},
		"code_challenge":        {pkceChallenge("v")},
		"code_challenge_method": {"S256"},
		"state":                 {"s"},
	}
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 (untrusted redirect target), got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestTokenAuthCode_LoopbackPortMustEcho — at /token, RFC 6749 §4.1.3
// requires byte equality between the redirect_uri sent to /authorize
// and the redirect_uri sent to /token. The loopback-port relaxation
// at /authorize does NOT carry into /token: a native client must echo
// the exact ephemeral port it used at /authorize, not its registered
// value or a different ephemeral one. This is RFC-correct and
// asymmetric with the /authorize relaxation; the test pins the
// asymmetry so a future "let's relax this too" change is loud.
func TestTokenAuthCode_LoopbackPortMustEcho(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	authorizeURI := "http://127.0.0.1:47521/cb" // captured into the sealed code
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	encClientID, internalID := registerClient(t, tm, []string{"http://127.0.0.1:8080/cb"})

	sc := sealedCode{
		TokenID:       uuid.New().String(),
		FamilyID:      uuid.New().String(),
		ClientID:      internalID,
		RedirectURI:   authorizeURI, // what the client sent to /authorize
		CodeChallenge: pkceChallenge(codeVerifier),
		Subject:       "user-sub",
		Email:         "user@example.com",
		Typ:           token.PurposeCode,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(60 * time.Second),
	}
	authCode, err := tm.SealJSON(sc, token.PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	// Echo a DIFFERENT port at /token. Even though both are loopback
	// and the registered URI also uses a different port, /token must
	// reject — what counts is what the client sent to /authorize.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {"http://127.0.0.1:99999/cb"},
		"client_id":     {encClientID},
		"code_verifier": {codeVerifier},
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 (redirect_uri mismatch at /token), got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestTokenAuthCode_PKCEDowngradeReject pins RFC 9700 §4.8.2: a /token
// request that supplies a code_verifier against a code minted with no
// code_challenge must be rejected explicitly. This closes the silent-accept
// path that would otherwise exist when PKCE_REQUIRED=false let a code
// through without a challenge.
func TestTokenAuthCode_PKCEDowngradeReject(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	// Code minted WITHOUT a code_challenge — e.g. relaxed mode with
	// server-side PKCE disabled (hypothetical; current server-PKCE
	// code path always sets CodeChallenge).
	sc := sealedCode{
		TokenID:     uuid.New().String(),
		FamilyID:    uuid.New().String(),
		ClientID:    internalID,
		RedirectURI: redirectURI,
		Subject:     "user-sub",
		Email:       "user@example.com",
		Typ:         token.PurposeCode,
		Audience:    testBaseURL,
		ExpiresAt:   time.Now().Add(60 * time.Second),
	}
	authCode, err := tm.SealJSON(sc, token.PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	// Client supplies code_verifier anyway — attempt to paper over a
	// downgrade. Must be rejected.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var oe OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oe); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oe.Error != "invalid_request" {
		t.Errorf("want error=invalid_request, got %q", oe.Error)
	}
}

// TestTokenAuthCode_Replay_RevokesRefreshFamily verifies RFC 6749 §4.1.2
// "SHOULD revoke previously issued tokens on code reuse". After a legitimate
// code redemption returns a refresh token, a replay of the same code must
// (a) be rejected AND (b) mark the refresh family as revoked so the refresh
// token minted from the first redemption can no longer rotate.
func TestTokenAuthCode_Replay_RevokesRefreshFamily(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	store := replay.NewMemoryStore()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	sc := sealedCode{
		TokenID:       uuid.New().String(),
		FamilyID:      uuid.New().String(),
		ClientID:      internalID,
		RedirectURI:   redirectURI,
		CodeChallenge: pkceChallenge(codeVerifier),
		Subject:       "user-sub",
		Email:         "user@example.com",
		Typ:           token.PurposeCode,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(60 * time.Second),
	}
	authCode, err := tm.SealJSON(sc, token.PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	exchangeCode := func() *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authCode},
			"redirect_uri":  {redirectURI},
			"client_id":     {encClientID},
			"code_verifier": {codeVerifier},
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		Token(tm, logger, testBaseURL, time.Time{}, store)(rr, req)
		return rr
	}

	// 1. First redemption succeeds and returns a refresh token.
	first := exchangeCode()
	if first.Code != http.StatusOK {
		t.Fatalf("first exchange: want 200, got %d: %s", first.Code, first.Body.String())
	}
	var firstTok struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(first.Body).Decode(&firstTok); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if firstTok.RefreshToken == "" {
		t.Fatalf("first exchange did not return a refresh_token")
	}

	// 2. Replay the SAME code. Must reject with code_replay.
	second := exchangeCode()
	if second.Code != http.StatusBadRequest {
		t.Fatalf("replay: want 400, got %d: %s", second.Code, second.Body.String())
	}

	// 3. Now attempt to rotate the refresh token issued in step 1. The
	//    family must be revoked (marker set by the replay detector),
	//    so rotation must be rejected with refresh_family_revoked.
	rotateForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {firstTok.RefreshToken},
		"client_id":     {encClientID},
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(rotateForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Token(tm, logger, testBaseURL, time.Time{}, store)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("rotation after code replay: want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var oe OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oe); err != nil {
		t.Fatalf("decode rotation: %v", err)
	}
	if oe.ErrorCode != "refresh_family_revoked" {
		t.Errorf("want error_code=refresh_family_revoked, got %q (description=%q)", oe.ErrorCode, oe.ErrorDescription)
	}
}

// TestTokenAuthCode_Replay_RevokesRotatedRefresh verifies that the
// family-revoke triggered by a code replay (RFC 6749 §4.1.2) reaches
// every descendant refresh, not just the first-generation one. The
// scenario:
//
//  1. Legitimate redemption mints refresh-A (FamilyID = code.FamilyID)
//  2. Legitimate rotation of refresh-A mints refresh-B (same FamilyID)
//  3. Attacker replays the original code → family revoked
//  4. Legitimate rotation of refresh-B is rejected with
//     refresh_family_revoked
//
// Without family-id inheritance from the code, refresh-B would have a
// fresh family and survive the revoke — the test exists to lock the
// inheritance behavior in handleAuthorizationCode + handleRefreshToken.
func TestTokenAuthCode_Replay_RevokesRotatedRefresh(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	store := replay.NewMemoryStore()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sc := sealedCode{
		TokenID:       uuid.New().String(),
		FamilyID:      uuid.New().String(),
		ClientID:      internalID,
		RedirectURI:   redirectURI,
		CodeChallenge: pkceChallenge(codeVerifier),
		Subject:       "user-sub",
		Email:         "user@example.com",
		Typ:           token.PurposeCode,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(60 * time.Second),
	}
	authCode, err := tm.SealJSON(sc, token.PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	postForm := func(form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		Token(tm, logger, testBaseURL, time.Time{}, store)(rr, req)
		return rr
	}

	// 1. First redemption — refresh-A.
	first := postForm(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {codeVerifier},
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first exchange: want 200, got %d: %s", first.Code, first.Body.String())
	}
	var firstTok struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(first.Body).Decode(&firstTok); err != nil {
		t.Fatalf("decode first: %v", err)
	}

	// 2. Legitimate rotation of refresh-A → refresh-B.
	rotation := postForm(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {firstTok.RefreshToken},
		"client_id":     {encClientID},
	})
	if rotation.Code != http.StatusOK {
		t.Fatalf("legit rotation: want 200, got %d: %s", rotation.Code, rotation.Body.String())
	}
	var rotated struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(rotation.Body).Decode(&rotated); err != nil {
		t.Fatalf("decode rotation: %v", err)
	}
	if rotated.RefreshToken == "" || rotated.RefreshToken == firstTok.RefreshToken {
		t.Fatalf("rotation did not return a new refresh_token (got %q vs prior %q)", rotated.RefreshToken, firstTok.RefreshToken)
	}

	// 3. Attacker replays the original code. (Local var deliberately
	// not named `replay` — would shadow the imported replay package.)
	replayResp := postForm(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {codeVerifier},
	})
	if replayResp.Code != http.StatusBadRequest {
		t.Fatalf("code replay: want 400, got %d: %s", replayResp.Code, replayResp.Body.String())
	}

	// 4. Rotation of refresh-B (the LIVE descendant) must now be
	//    rejected with refresh_family_revoked. This is the bit the
	//    new test adds — the prior test only verified refresh-A.
	rotateB := postForm(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rotated.RefreshToken},
		"client_id":     {encClientID},
	})
	if rotateB.Code != http.StatusBadRequest {
		t.Fatalf("rotation of descendant after code replay: want 400, got %d: %s", rotateB.Code, rotateB.Body.String())
	}
	var oe OAuthError
	if err := json.NewDecoder(rotateB.Body).Decode(&oe); err != nil {
		t.Fatalf("decode descendant rotation: %v", err)
	}
	if oe.ErrorCode != "refresh_family_revoked" {
		t.Errorf("descendant: want error_code=refresh_family_revoked, got %q (description=%q)", oe.ErrorCode, oe.ErrorDescription)
	}
}

// TestTokenRefresh_ReplayStore_ReuseRevokesFamily verifies RFC 6749 §10.4 /
// OAuth 2.1 §6.1 refresh-rotation-with-reuse-detection. Legitimate rotation
// works; replaying an already-rotated refresh is detected and revokes every
// sibling token in the family — including the freshly minted one the
// legitimate client is holding.
func TestTokenRefresh_ReplayStore_ReuseRevokesFamily(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	store := replay.NewMemoryStore()

	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	familyID := uuid.New().String()
	originalRefresh := sealedRefresh{
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
	originalStr, err := tm.SealJSON(originalRefresh, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	refreshExchange := func(refreshStr string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshStr},
			"client_id":     {encClientID},
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		Token(tm, logger, testBaseURL, time.Time{}, store)(rr, req)
		return rr
	}

	// 1. First rotation: succeeds and returns a new refresh token with the
	// same FamilyID.
	first := refreshExchange(originalStr)
	if first.Code != http.StatusOK {
		t.Fatalf("first rotation: want 200, got %d: %s", first.Code, first.Body.String())
	}
	var tok1 map[string]any
	if err := json.NewDecoder(first.Body).Decode(&tok1); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	newRefreshStr := tok1["refresh_token"].(string)

	var rotated sealedRefresh
	if err := tm.OpenJSON(newRefreshStr, &rotated, token.PurposeRefresh); err != nil {
		t.Fatalf("OpenJSON rotated: %v", err)
	}
	if rotated.FamilyID != familyID {
		t.Errorf("rotated FamilyID: got %q, want %q", rotated.FamilyID, familyID)
	}
	if rotated.TokenID == originalRefresh.TokenID {
		t.Error("rotated TokenID should differ from original")
	}

	// 2. Replay the original (already-rotated) refresh token: must be
	// rejected with reuse detection and the family must now be marked
	// revoked.
	replayAttempt := refreshExchange(originalStr)
	if replayAttempt.Code != http.StatusBadRequest {
		t.Fatalf("reuse: want 400, got %d: %s", replayAttempt.Code, replayAttempt.Body.String())
	}
	var reuseErr OAuthError
	if err := json.NewDecoder(replayAttempt.Body).Decode(&reuseErr); err != nil {
		t.Fatalf("decode reuse: %v", err)
	}
	if reuseErr.ErrorCode != "refresh_reuse_detected" {
		t.Errorf("expected error_code=refresh_reuse_detected, got %q", reuseErr.ErrorCode)
	}

	// 3. The legitimate rotated refresh is now invalid too — the family is
	// dead. The client has to re-authenticate via /authorize.
	afterRevoke := refreshExchange(newRefreshStr)
	if afterRevoke.Code != http.StatusBadRequest {
		t.Fatalf("post-revoke rotated use: want 400, got %d: %s", afterRevoke.Code, afterRevoke.Body.String())
	}
	var revokedErr OAuthError
	if err := json.NewDecoder(afterRevoke.Body).Decode(&revokedErr); err != nil {
		t.Fatalf("decode revoked: %v", err)
	}
	if revokedErr.ErrorCode != "refresh_family_revoked" {
		t.Errorf("expected error_code=refresh_family_revoked, got %q", revokedErr.ErrorCode)
	}
}

// TestTokenRefresh_NoReplayStore_RotationStillWorks confirms that without a
// replay store, rotation is non-strict: a refresh token remains usable
// multiple times (pre-existing stateless behavior is preserved).
func TestTokenRefresh_NoReplayStore_RotationStillWorks(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	refreshStr := sealRefresh(t, tm, "user-sub", "user@example.com", internalID)

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshStr},
		"client_id":     {encClientID},
	}

	// Two consecutive exchanges of the SAME refresh must both succeed when
	// no replay store is wired — that is the current stateless contract.
	for i := range 2 {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("iteration %d: want 200, got %d", i, rr.Code)
		}
	}
}

// TestTokenAuthCode_ReplayStore_PKCEFailureDoesNotBurnCode verifies that the
// single-use claim is only recorded after PKCE passes, so that a bad verifier
// (typo, MITM) does not lock the legitimate client out of its own code.
func TestTokenAuthCode_ReplayStore_PKCEFailureDoesNotBurnCode(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	store := replay.NewMemoryStore()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	correctVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	wrongVerifier := strings.Repeat("A", 43)
	codeChallenge := pkceChallenge(correctVerifier)

	sc := sealedCode{
		TokenID:       uuid.New().String(),
		FamilyID:      uuid.New().String(),
		ClientID:      internalID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		Subject:       "user-sub",
		Email:         "user@example.com",
		Typ:           token.PurposeCode,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(60 * time.Second),
	}
	authCode, err := tm.SealJSON(sc, token.PurposeCode)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	// First attempt with wrong verifier: PKCE fails, code must NOT be claimed.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {wrongVerifier},
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Token(tm, logger, testBaseURL, time.Time{}, store)(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("first (bad PKCE): want 400, got %d", rr.Code)
	}

	// Retry with correct verifier: must succeed because the bad PKCE attempt
	// did not consume the code.
	form.Set("code_verifier", correctVerifier)
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	Token(tm, logger, testBaseURL, time.Time{}, store)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("retry with correct PKCE: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- RFC 8707 resource parameter validation ---

func TestMatchResource(t *testing.T) {
	base := "https://auth.example.com"
	cases := []struct {
		name     string
		resource string
		want     bool
	}{
		{"exact_match", "https://auth.example.com", true},
		{"trailing_slash", "https://auth.example.com/", true},
		{"scheme_case", "HTTPS://auth.example.com", true},
		{"host_case", "https://AUTH.example.com", true},
		{"default_port_443", "https://auth.example.com:443", true},
		{"default_port_443_trailing", "https://auth.example.com:443/", true},
		{"wrong_port", "https://auth.example.com:8443", false},
		{"wrong_host", "https://evil.example.com", false},
		{"wrong_scheme", "http://auth.example.com", false},
		{"subpath", "https://auth.example.com/other", false},
		{"empty", "", false},
		{"malformed", "::not-a-url", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchResource(tc.resource, base); got != tc.want {
				t.Errorf("matchResource(%q,%q)=%v want %v", tc.resource, base, got, tc.want)
			}
		})
	}
}

func TestAuthorize_RejectsMismatchedResource(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})

	target := "/authorize?response_type=code&client_id=" + url.QueryEscape(encClientID) +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code_challenge=" + pkceChallenge("v") +
		"&code_challenge_method=S256" +
		"&state=s" +
		"&resource=" + url.QueryEscape("https://evil.example.com")

	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("want 302, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := extractAuthzError(t, rr, redirectURI); got != "invalid_target" {
		t.Errorf("want error=invalid_target, got %q", got)
	}
}

func TestAuthorize_MultipleResource_AllMustMatch(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})

	target := "/authorize?response_type=code&client_id=" + url.QueryEscape(encClientID) +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code_challenge=" + pkceChallenge("v") +
		"&code_challenge_method=S256" +
		"&state=s" +
		"&resource=" + url.QueryEscape(testBaseURL) +
		"&resource=" + url.QueryEscape("https://evil.example.com")

	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("want 302 (one bad resource in list), got %d: %s", rr.Code, rr.Body.String())
	}
	if got := extractAuthzError(t, rr, redirectURI); got != "invalid_target" {
		t.Errorf("want error=invalid_target, got %q", got)
	}
}

// TestAuthorize_RedirectError_PreservesStateAndIss locks the RFC 6749
// §4.1.2.1 contract: errors that occur after redirect_uri is validated
// must redirect to redirect_uri with `error=…&state=…&iss=…`. Test
// covers the full chain by sending an invalid_target with a real
// client-supplied state and asserting all three parameters land on the
// redirect.
func TestAuthorize_RedirectError_PreservesStateAndIss(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})
	clientState := "client-correlation-token-xyz"

	target := "/authorize?response_type=code&client_id=" + url.QueryEscape(encClientID) +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code_challenge=" + pkceChallenge("v") +
		"&code_challenge_method=S256" +
		"&state=" + url.QueryEscape(clientState) +
		"&resource=" + url.QueryEscape("https://evil.example.com")

	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()
	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("want 302, got %d: %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != redirectURI {
		t.Errorf("redirect target = %q, want %q", u.Scheme+"://"+u.Host+u.Path, redirectURI)
	}
	q := u.Query()
	if q.Get("error") != "invalid_target" {
		t.Errorf("error = %q, want invalid_target", q.Get("error"))
	}
	if q.Get("state") != clientState {
		t.Errorf("state = %q, want %q (client correlation MUST round-trip)", q.Get("state"), clientState)
	}
	if q.Get("iss") != testBaseURL {
		t.Errorf("iss = %q, want %q", q.Get("iss"), testBaseURL)
	}
}

func TestAuthorize_TrailingSlashResource_Accepted(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, _ := registerClient(t, tm, []string{redirectURI})

	target := "/authorize?response_type=code&client_id=" + url.QueryEscape(encClientID) +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code_challenge=" + pkceChallenge("v") +
		"&code_challenge_method=S256" +
		"&state=s" +
		"&resource=" + url.QueryEscape(testBaseURL+"/")

	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()

	Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("want 302, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestToken_RejectsMismatchedResource(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	authCode := sealCode(t, tm, internalID, redirectURI, pkceChallenge(verifier), "sub", "e@e")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {verifier},
		"resource":      {"https://evil.example.com"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var e OAuthError
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if e.Error != "invalid_target" {
		t.Errorf("want error=invalid_target, got %q (body=%s)", e.Error, rr.Body.String())
	}
}

// TestToken_EmptyTokenID_Rejected: a sealedCode missing TokenID must be
// refused upfront with invalid_grant, mirroring the refresh-side C2 check.
// Without this the replay store guard silently no-ops on empty TokenID.
func TestToken_EmptyTokenID_Rejected(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sc := sealedCode{
		// TokenID intentionally empty.
		ClientID:      internalID,
		RedirectURI:   redirectURI,
		CodeChallenge: pkceChallenge(verifier),
		Subject:       "sub",
		Email:         "e@e",
		Typ:           token.PurposeCode,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	authCode, err := tm.SealJSON(sc, token.PurposeCode)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var e OAuthError
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if e.Error != "invalid_grant" {
		t.Errorf("want error=invalid_grant, got %q", e.Error)
	}
}

// TestCallback_IdPError_ForwardsToRedirectURI: when the IdP returns an
// error and the session is still decodable, the callback must redirect
// the error+state back to the registered redirect_uri (RFC 6749
// §4.1.2.1) instead of rendering a proxy-hosted JSON body.
func TestCallback_IdPError_ForwardsToRedirectURI(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/cb"
	// Build a valid session pointing at redirectURI.
	session := sealedSession{
		ClientID:      uuid.New().String(),
		RedirectURI:   redirectURI,
		OriginalState: "client-state",
		Nonce:         "n",
		Typ:           token.PurposeSession,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	state, err := tm.SealJSON(session, token.PurposeSession)
	if err != nil {
		t.Fatalf("seal session: %v", err)
	}

	target := "/callback?error=access_denied&error_description=user+said+no&state=" + url.QueryEscape(state)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()

	Callback(tm, logger, testBaseURL, testOAuth2Config(), nil, CallbackConfig{})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("want 302 redirect, got %d body=%s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != redirectURI {
		t.Errorf("want redirect to %q, got %q", redirectURI, loc)
	}
	q := parsed.Query()
	if q.Get("error") != "access_denied" {
		t.Errorf("want error=access_denied, got %q", q.Get("error"))
	}
	if q.Get("state") != "client-state" {
		t.Errorf("want state=client-state, got %q", q.Get("state"))
	}
	if q.Get("error_description") == "" {
		t.Error("want non-empty error_description")
	}
	// RFC 9207 §2 / RFC 9700 §2.1.4: `iss` MUST be on EVERY authorization
	// response, including error redirects. Strict clients gate the mix-up
	// defense on this — omitting it on the error path lets a forged error
	// from a different AS pass undetected.
	if iss := q.Get("iss"); iss != testBaseURL {
		t.Errorf("want iss=%q on error redirect, got %q", testBaseURL, iss)
	}
}

// TestCallback_IdPError_BadState_FallsBackToJSON: when the state is
// unreachable (tampered / expired / missing), the callback cannot
// redirect anywhere safe and falls back to a proxy-hosted JSON body.
func TestCallback_IdPError_BadState_FallsBackToJSON(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&state=garbage", nil)
	rr := httptest.NewRecorder()

	Callback(tm, logger, testBaseURL, testOAuth2Config(), nil, CallbackConfig{})(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 JSON fallback, got %d: %s", rr.Code, rr.Body.String())
	}
	var e OAuthError
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if e.Error != "access_denied" {
		t.Errorf("want error=access_denied, got %q", e.Error)
	}
}

// TestCallback_IdPError_NoSession_DoesNotReflectAttackerDescription
// pins the phishing-surface fix: when no session decodes, the JSON
// 400 body MUST carry a fixed description, not the attacker-supplied
// `error_description`. Otherwise a phisher who lures a victim to
// /callback?error=phishy&error_description=visit+http://evil renders
// attacker text inside a legit-domain JSON page.
func TestCallback_IdPError_NoSession_DoesNotReflectAttackerDescription(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	target := "/callback?error=access_denied&error_description=" +
		url.QueryEscape("please visit http://evil.example to recover your account") +
		"&state=garbage-no-session"
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()
	Callback(tm, logger, testBaseURL, testOAuth2Config(), nil, CallbackConfig{})(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var e OAuthError
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if e.Error != "access_denied" {
		t.Errorf("error code = %q, want access_denied", e.Error)
	}
	if strings.Contains(e.ErrorDescription, "evil.example") || strings.Contains(e.ErrorDescription, "visit") {
		t.Errorf("error_description leaked attacker text: %q", e.ErrorDescription)
	}
}

// TestCallback_IdPError_WithSession_ForwardsDescription pins the
// other side of the dispatch: when the state DOES decode to a valid
// session, the registered redirect_uri is trusted, so the IdP-
// supplied (sanitized) error_description is forwarded to the
// client — operators of legit clients want to see why the IdP
// refused.
func TestCallback_IdPError_WithSession_ForwardsDescription(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/cb"
	session := sealedSession{
		ClientID:      uuid.New().String(),
		RedirectURI:   redirectURI,
		OriginalState: "client-state",
		Nonce:         "n",
		Typ:           token.PurposeSession,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}
	state, err := tm.SealJSON(session, token.PurposeSession)
	if err != nil {
		t.Fatalf("seal session: %v", err)
	}
	target := "/callback?error=access_denied&error_description=" +
		url.QueryEscape("user denied scope") +
		"&state=" + url.QueryEscape(state)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()
	Callback(tm, logger, testBaseURL, testOAuth2Config(), nil, CallbackConfig{})(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("want 302 redirect, got %d body=%s", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := loc.Query().Get("error_description"); got != "user denied scope" {
		t.Errorf("forwarded error_description = %q, want %q", got, "user denied scope")
	}
}

// TestToken_FamilyRevokeAtomic_SurvivesClientCancel covers the
// 3rd-party M1 finding under the atomic design: when refresh reuse
// is detected, the family revocation is part of the same Lua EVAL as
// the reuse detection (see replay/redis.go claimOrCheckFamilyScript).
// The handler does no separate Mark call, so there is no fail-open
// edge a client cancel could cut through. Verify by cancelling the
// request context before the handler runs and confirming a sibling
// refresh in the same family is still rejected as revoked.
func TestToken_FamilyRevokeAtomic_SurvivesClientCancel(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()
	store := replay.NewMemoryStore()
	defer func() { _ = store.Close() }()

	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	familyID := uuid.New().String()
	mkRefresh := func(tid string) string {
		r := sealedRefresh{
			TokenID:   tid,
			FamilyID:  familyID,
			Subject:   "sub",
			Email:     "e@e",
			ClientID:  internalID,
			Typ:       token.PurposeRefresh,
			Audience:  testBaseURL,
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		}
		s, err := tm.SealJSON(r, token.PurposeRefresh)
		if err != nil {
			t.Fatalf("SealJSON: %v", err)
		}
		return s
	}

	tidA := uuid.New().String()
	tidB := uuid.New().String()
	refreshA := mkRefresh(tidA)
	refreshB := mkRefresh(tidB)

	do := func(ctx context.Context, refreshStr string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshStr},
			"client_id":     {encClientID},
		}
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		Token(tm, logger, testBaseURL, time.Time{}, store)(rr, req)
		return rr
	}

	// 1st use of A: legitimate rotation.
	if rr := do(context.Background(), refreshA); rr.Code != http.StatusOK {
		t.Fatalf("first rotation of A: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// 2nd use of A under a pre-cancelled ctx: reuse detected. Under
	// the pre-atomic design the family Mark could have been skipped
	// via client cancel; under the atomic design the marker is set
	// inside the same EVAL so the cancel cannot skip it.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if rr := do(cancelled, refreshA); rr.Code != http.StatusBadRequest {
		t.Fatalf("reuse of A: want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	// Try a SIBLING refresh (different tid, same family). If family
	// revocation lived in a separate writable step that the cancel
	// skipped, B would still be accepted. Under atomic revoke, B is
	// rejected as family-revoked.
	rr := do(context.Background(), refreshB)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("sibling B after cancelled-reuse of A: want 400 family revoked, got %d: %s", rr.Code, rr.Body.String())
	}
	var e OAuthError
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if e.ErrorCode != "refresh_family_revoked" {
		t.Errorf("want error_code=refresh_family_revoked, got %q", e.ErrorCode)
	}
}

// TestRegister_RejectsHostlessOrOpaque covers the 3rd-party H1
// finding: register.go used to accept `https:foo` (opaque URI, Host
// empty) and `https:///callback` (hostless authority) because the
// scheme switch only verified the scheme letter. A redirect_uri
// without a real authority is not an OAuth callback target — the
// later /callback Location header would be a broken URL.
func TestRegister_RejectsHostlessOrOpaque(t *testing.T) {
	cases := []string{
		"https:foo",         // opaque
		"https:///callback", // hostless
		"https:",            // scheme only
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			tm := newTestTokenManager(t)
			logger := zap.NewNop()

			body := `{"redirect_uris":["` + u + `"]}`
			req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			Register(tm, logger, testBaseURL)(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("redirect_uri=%q: want 400, got %d body=%s", u, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestToken_RejectsURLQueryParams covers the 3rd-party M2 finding:
// RFC 6749 §3.2 requires token-endpoint parameters in the body;
// allowing them via URL query would leak codes / refresh tokens into
// access logs, browser history, and Referer headers.
func TestToken_RejectsURLQueryParams(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	req := httptest.NewRequest(
		http.MethodPost,
		"/token?grant_type=refresh_token&refresh_token=leaky&client_id=c",
		strings.NewReader(""),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 rejection for URL-query params, got %d: %s", rr.Code, rr.Body.String())
	}
	var e OAuthError
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if e.Error != "invalid_request" {
		t.Errorf("want error=invalid_request, got %q", e.Error)
	}
}

func TestToken_RejectsRepeatedSingletonParam(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	form := url.Values{
		"grant_type":    {"authorization_code", "refresh_token"},
		"code":          {"code"},
		"redirect_uri":  {"https://app.example.com/callback"},
		"client_id":     {"client"},
		"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 rejection for duplicate singleton param, got %d: %s", rr.Code, rr.Body.String())
	}
	var e OAuthError
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if e.Error != "invalid_request" {
		t.Errorf("want error=invalid_request, got %q", e.Error)
	}
}

func TestToken_ResourceMatchesAudience_Accepted(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	authCode := sealCode(t, tm, internalID, redirectURI, pkceChallenge(verifier), "sub", "e@e")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {verifier},
		"resource":      {testBaseURL + "/"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestToken_ResourceMatchesConfiguredMount_Accepted(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	redirectURI := "https://app.example.com/callback"
	encClientID, internalID := registerClient(t, tm, []string{redirectURI})

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	authCode := sealCode(t, tm, internalID, redirectURI, pkceChallenge(verifier), "sub", "e@e")
	mountResource := testBaseURL + "/mcp"

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {encClientID},
		"code_verifier": {verifier},
		"resource":      {mountResource},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil, mountResource)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 for mount resource, got %d: %s", rr.Code, rr.Body.String())
	}
}
