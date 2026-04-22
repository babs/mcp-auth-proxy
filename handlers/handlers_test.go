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
	sr := sealedRefresh{
		TokenID:   uuid.New().String(),
		FamilyID:  uuid.New().String(),
		Subject:   subject,
		Email:     email,
		ClientID:  clientUUID,
		Typ:       token.PurposeRefresh,
		Audience:  testBaseURL,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
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

	for _, k := range []string{"response_types_supported", "grant_types_supported", "code_challenge_methods_supported", "token_endpoint_auth_methods_supported"} {
		if _, ok := meta[k]; !ok {
			t.Errorf("missing field %s", k)
		}
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

	// Verify the client_id is a valid encrypted payload
	var sc sealedClient
	if err := tm.OpenJSON(resp.ClientID, &sc, token.PurposeClient); err != nil {
		t.Errorf("client_id is not a valid sealed client: %v", err)
	}
	if sc.ID == "" {
		t.Error("sealed client should have a non-empty internal ID")
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
	if oauthErr.Error != "invalid_request" {
		t.Errorf("expected error 'invalid_request', got %q", oauthErr.Error)
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

	tests := []struct {
		name      string
		params    url.Values
		wantError string
	}{
		{
			name: "missing response_type",
			params: url.Values{
				"client_id":             {encClientID},
				"redirect_uri":          {redirectURI},
				"code_challenge":        {challenge},
				"code_challenge_method": {"S256"},
			},
			wantError: "unsupported_response_type",
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
			wantError: "unsupported_response_type",
		},
		{
			name: "missing client_id",
			params: url.Values{
				"response_type":         {"code"},
				"redirect_uri":          {redirectURI},
				"code_challenge":        {challenge},
				"code_challenge_method": {"S256"},
			},
			wantError: "invalid_request",
		},
		{
			name: "missing redirect_uri",
			params: url.Values{
				"response_type":         {"code"},
				"client_id":             {encClientID},
				"code_challenge":        {challenge},
				"code_challenge_method": {"S256"},
			},
			wantError: "invalid_request",
		},
		{
			name: "missing code_challenge",
			params: url.Values{
				"response_type":         {"code"},
				"client_id":             {encClientID},
				"redirect_uri":          {redirectURI},
				"code_challenge_method": {"S256"},
			},
			wantError: "invalid_request",
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
			wantError: "invalid_request",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/authorize?"+tc.params.Encode(), nil)
			rr := httptest.NewRecorder()

			Authorize(tm, logger, testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
			}

			var oauthErr OAuthError
			if err := json.NewDecoder(rr.Body).Decode(&oauthErr); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if oauthErr.Error != tc.wantError {
				t.Errorf("expected error %q, got %q", tc.wantError, oauthErr.Error)
			}
		})
	}
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

	// RFC 6749 §5.1: Cache-Control must be no-store
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("expected Cache-Control: no-store, got %q", cc)
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
	handler := ResourceMetadata(baseURL)

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

	// Resource URI has trailing slash for Claude.ai compatibility (RFC 8707)
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
			wantDesc: "user denied access",
		},
		{
			name:     "server_error without description",
			query:    "/callback?error=server_error&state=some-state",
			wantCode: http.StatusBadRequest,
			wantErr:  "server_error",
			wantDesc: "authorization denied by identity provider",
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
func TestCallback_OIDCError_AllowlistAndSanitize(t *testing.T) {
	tm := newTestTokenManager(t)
	oauth2Cfg := testOAuth2Config()
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		panic("verifyFunc must not be called when IdP returns error")
	}

	longDesc := strings.Repeat("A", 250) + "<will-be-trimmed>"

	tests := []struct {
		name       string
		query      string
		wantErr    string
		wantDescIs func(string) bool
	}{
		{
			name:    "unknown_error_collapsed_to_server_error",
			query:   "/callback?error=attacker-controlled_value&error_description=hi&state=s",
			wantErr: "server_error",
			wantDescIs: func(s string) bool {
				return s == "hi"
			},
		},
		{
			name:    "description_truncated_to_200",
			query:   "/callback?error=access_denied&error_description=" + url.QueryEscape(longDesc) + "&state=s",
			wantErr: "access_denied",
			wantDescIs: func(s string) bool {
				return len(s) == 200 && strings.HasPrefix(s, "AAAA")
			},
		},
		{
			name:    "crlf_stripped",
			query:   "/callback?error=invalid_request&error_description=" + url.QueryEscape("line1\r\nline2") + "&state=s",
			wantErr: "invalid_request",
			wantDescIs: func(s string) bool {
				return !strings.ContainsAny(s, "\r\n") && strings.Contains(s, "line1line2")
			},
		},
		{
			name:    "non_ascii_stripped",
			query:   "/callback?error=access_denied&error_description=" + url.QueryEscape("café naïve") + "&state=s",
			wantErr: "access_denied",
			wantDescIs: func(s string) bool {
				// é and ï collapse to empty (> 0x7E), so we're left with "caf nave"
				return strings.Contains(s, "caf") && !strings.ContainsRune(s, 'é')
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.query, nil)
			rr := httptest.NewRecorder()

			CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc, CallbackConfig{})(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
			}
			var cbErr OAuthError
			if err := json.NewDecoder(rr.Body).Decode(&cbErr); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if cbErr.Error != tc.wantErr {
				t.Errorf("error = %q, want %q", cbErr.Error, tc.wantErr)
			}
			if !tc.wantDescIs(cbErr.ErrorDescription) {
				t.Errorf("unexpected error_description %q", cbErr.ErrorDescription)
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
	if oauthErr.Error != "invalid_request" {
		t.Errorf("expected error 'invalid_request', got %q", oauthErr.Error)
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

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 with PKCE required, got %d", rr.Code)
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

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for plain method even in relaxed mode, got %d", rr.Code)
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

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 state_missing in strict mode, got %d: %s", rr.Code, rr.Body.String())
	}
	var oe OAuthError
	_ = json.NewDecoder(rr.Body).Decode(&oe)
	if oe.Error != "invalid_request" {
		t.Errorf("expected invalid_request, got %q", oe.Error)
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

// TestTokenRefresh_NewTokenCarriesIssuedAt verifies that the rotated refresh
// token has its IssuedAt updated to "now" so it survives a future REVOKE_BEFORE
// cutoff applied to its predecessor.
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
	for i := 0; i < 2; i++ {
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
