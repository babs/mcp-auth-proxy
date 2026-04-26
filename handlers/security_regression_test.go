package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/babs/mcp-auth-proxy/middleware"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// setIDTokenClaims injects a raw claims JSON into an *oidc.IDToken so
// tests can exercise callback paths that depend on the claims payload
// without also spinning up a signed-JWT test-vector pipeline. The field
// is unexported in go-oidc/v3; reflection + unsafe is the only option
// from outside the package. Production code never does this — see
// handlers/callback.go which receives real, verified id_tokens.
func setIDTokenClaims(t *testing.T, tok *oidc.IDToken, claims []byte) {
	t.Helper()
	v := reflect.ValueOf(tok).Elem().FieldByName("claims")
	// #nosec G103 -- test-only reflection into oidc.IDToken's unexported
	// claims field so callback handlers can be driven with synthetic
	// payloads. Never executed outside *_test.go builds.
	reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().SetBytes(claims)
}

// Integration-level regression tests for sealed-type confusion (C1) and
// upstream OIDC missing PKCE/nonce (H3).
//
// The primary defense for C1 is AAD-binding in token.Manager
// (see TestCrossTypeSubstitution). These tests add end-to-end coverage at
// the HTTP-handler layer so a regression that wires AAD correctly at the
// token layer but loses the purpose at a call site still trips a test.

// --- C1.a — sealedClient blob accepted as access bearer ---
func TestC1a_RegisterBlobRejectedAsBearer(t *testing.T) {
	tm := newTestTokenManager(t)
	// Register a client, then hand its returned client_id to the auth middleware
	// as a Bearer token. Before the fix this was accepted as a 24h credential.
	encClientID, _ := registerClient(t, tm, []string{"https://app.example.com/callback"})

	auth := middleware.NewAuth(tm, zap.NewNop(), testBaseURL, time.Time{})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("middleware must not forward a sealed-client blob as a bearer")
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+encClientID)
	rr := httptest.NewRecorder()
	auth.Validate(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("C1.a: expected 401 for sealedClient as bearer, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- C1.b — sealedSession blob accepted at /token refresh_token ---
func TestC1b_SessionBlobRejectedAtTokenRefresh(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	// Build a sealedSession of the same shape /authorize would emit.
	session := sealedSession{
		ClientID:      internalID,
		RedirectURI:   "https://app.example.com/callback",
		CodeChallenge: "",
		OriginalState: "s",
		Typ:           token.PurposeSession,
		Audience:      testBaseURL,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}
	sessionStr, err := tm.SealJSON(session, token.PurposeSession)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {sessionStr},
		"client_id":     {encClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("C1.b: expected 400 for sealedSession at /token, got %d: %s", rr.Code, rr.Body.String())
	}
	var oe OAuthError
	_ = json.NewDecoder(rr.Body).Decode(&oe)
	if oe.Error != "invalid_grant" {
		t.Errorf("C1.b: expected invalid_grant, got %q", oe.Error)
	}
}

// --- C1.c — sealedCode blob accepted at /token refresh_token ---
func TestC1c_CodeBlobRejectedAtTokenRefresh(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	// An authorization code fed into the refresh_token grant.
	codeStr := sealCode(t, tm, internalID, "https://app.example.com/callback",
		"", "user-sub", "user@example.com")

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {codeStr},
		"client_id":     {encClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("C1.c: expected 400 for sealedCode at /token refresh, got %d: %s", rr.Code, rr.Body.String())
	}
	var oe OAuthError
	_ = json.NewDecoder(rr.Body).Decode(&oe)
	if oe.Error != "invalid_grant" {
		t.Errorf("C1.c: expected invalid_grant, got %q", oe.Error)
	}
}

// --- C1.d — sealedRefresh blob accepted as access bearer ---
func TestC1d_RefreshBlobRejectedAsBearer(t *testing.T) {
	tm := newTestTokenManager(t)
	_, internalID := registerClient(t, tm, []string{"https://app.example.com/callback"})

	refreshStr := sealRefresh(t, tm, "user-sub", "user@example.com", internalID)

	auth := middleware.NewAuth(tm, zap.NewNop(), testBaseURL, time.Time{})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("middleware must not forward a sealedRefresh blob as a bearer")
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+refreshStr)
	rr := httptest.NewRecorder()
	auth.Validate(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("C1.d: expected 401 for sealedRefresh as bearer, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- C1.e — access-token blob accepted at /token refresh_token ---
func TestC1e_AccessBlobRejectedAtTokenRefresh(t *testing.T) {
	tm := newTestTokenManager(t)
	logger := zap.NewNop()

	encClientID, _ := registerClient(t, tm, []string{"https://app.example.com/callback"})

	// A legitimate access token issued by tm.Issue — purpose = "access".
	accessTok, _, err := tm.Issue(testBaseURL, "user-sub", "user@example.com", "some-client", nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {accessTok},
		"client_id":     {encClientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	Token(tm, logger, testBaseURL, time.Time{}, nil)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("C1.e: expected 400 for access-token at /token refresh, got %d: %s", rr.Code, rr.Body.String())
	}
	var oe OAuthError
	_ = json.NewDecoder(rr.Body).Decode(&oe)
	if oe.Error != "invalid_grant" {
		t.Errorf("C1.e: expected invalid_grant, got %q", oe.Error)
	}
}

// --- H3 — /callback rejects id_token whose nonce does not match the session ---
func TestH3_CallbackRejectsNonceMismatch(t *testing.T) {
	tm := newTestTokenManager(t)
	oauth2Cfg := testOAuth2Config()

	// Drive /authorize to produce a session with a real nonce.
	encClientID, _ := registerClient(t, tm, []string{"https://app.example.com/callback"})
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state-abc"},
	}
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()
	Authorize(tm, zap.NewNop(), testBaseURL, oauth2Cfg, AuthorizeConfig{PKCERequired: true})(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d: %s", rr.Code, rr.Body.String())
	}
	idpURL, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse IdP Location: %v", err)
	}
	state := idpURL.Query().Get("state")
	if state == "" {
		t.Fatal("expected state in IdP redirect")
	}
	upstreamNonce := idpURL.Query().Get("nonce")
	if upstreamNonce == "" {
		t.Fatal("expected nonce in IdP redirect (H3 defense)")
	}

	// Mock the upstream /token endpoint: it will be hit by oauth2Cfg.Exchange.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "up",
			"token_type":   "Bearer",
			"id_token":     "dummy",
		})
	}))
	defer upstream.Close()
	oauth2Cfg.Endpoint.TokenURL = upstream.URL + "/token"

	// A verifier that returns an id_token with the wrong nonce.
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		return &oidc.IDToken{Subject: "user-sub", Nonce: "WRONG-NONCE"}, nil
	}

	cbReq := httptest.NewRequest(http.MethodGet,
		"/callback?code=fake&state="+url.QueryEscape(state), nil)
	cbRR := httptest.NewRecorder()
	CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc, CallbackConfig{})(cbRR, cbReq)

	if cbRR.Code != http.StatusForbidden {
		t.Fatalf("H3: expected 403 for nonce mismatch, got %d: %s", cbRR.Code, cbRR.Body.String())
	}
	var oe OAuthError
	_ = json.NewDecoder(cbRR.Body).Decode(&oe)
	if oe.ErrorCode != "id_token_verification_failed" {
		t.Errorf("H3: expected error_code=id_token_verification_failed, got %q", oe.ErrorCode)
	}
}

// Note: the H3 happy-path is covered by TestE2E_FullOAuthMCPFlow, which uses
// a real go-oidc Verifier against a mock JWKS — stubbing an *oidc.IDToken is
// not viable because IDToken.Claims parses its private claims JSON.

// --- M5 — DCR redirect_uris count + length caps ---

// TestRegister_RejectsTooManyRedirectURIs pins the count cap at 5.
func TestRegister_RejectsTooManyRedirectURIs(t *testing.T) {
	tm := newTestTokenManager(t)
	uris := []string{
		"https://a.example.com/cb",
		"https://b.example.com/cb",
		"https://c.example.com/cb",
		"https://d.example.com/cb",
		"https://e.example.com/cb",
		"https://f.example.com/cb",
	}
	body, _ := json.Marshal(map[string]any{"redirect_uris": uris, "client_name": "too-many"})
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	Register(tm, zap.NewNop(), testBaseURL)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("M5 count cap: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var oe OAuthError
	_ = json.NewDecoder(rr.Body).Decode(&oe)
	if oe.Error != "invalid_redirect_uri" {
		t.Errorf("M5 count cap: expected invalid_redirect_uri, got %q", oe.Error)
	}
}

// TestRegister_RejectsOversizeRedirectURI pins the per-URI length cap at 512.
func TestRegister_RejectsOversizeRedirectURI(t *testing.T) {
	tm := newTestTokenManager(t)
	// 513-character URI (scheme+host+long path) — above the 512-char limit.
	long := "https://app.example.com/cb?pad=" + strings.Repeat("x", 513-len("https://app.example.com/cb?pad="))
	body, _ := json.Marshal(map[string]any{"redirect_uris": []string{long}, "client_name": "oversize"})
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	Register(tm, zap.NewNop(), testBaseURL)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("M5 length cap: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var oe OAuthError
	_ = json.NewDecoder(rr.Body).Decode(&oe)
	if oe.Error != "invalid_redirect_uri" {
		t.Errorf("M5 length cap: expected invalid_redirect_uri, got %q", oe.Error)
	}
}

func TestRegister_RejectsOversizeClientName(t *testing.T) {
	tm := newTestTokenManager(t)
	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{"https://app.example.com/cb"},
		"client_name":   strings.Repeat("x", maxClientNameLength+1),
	})
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	Register(tm, zap.NewNop(), testBaseURL)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("client_name cap: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
	var oe OAuthError
	_ = json.NewDecoder(rr.Body).Decode(&oe)
	if oe.Error != "invalid_client_metadata" {
		t.Errorf("client_name cap: expected invalid_client_metadata, got %q", oe.Error)
	}
}

// TestRegister_RejectsClientNameControlBytes pins the control-byte
// gate on client_name. The field is sealed into the returned
// client_id and emitted to logs; control bytes (NUL/CR/LF/TAB) and
// the X-User-Groups delimiter `,` would either smuggle past zap's
// JSON-escaping when unsealed downstream or break log parsers.
// RFC 7591 §3.2.2 prescribes invalid_client_metadata.
func TestRegister_RejectsClientNameControlBytes(t *testing.T) {
	cases := map[string]string{
		"newline":     "foo\nbar",
		"carriage":    "foo\rbar",
		"tab":         "foo\tbar",
		"null":        "foo\x00bar",
		"vtab":        "foo\x0bbar",
		"comma_delim": "team-a,team-b",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			tm := newTestTokenManager(t)
			body, _ := json.Marshal(map[string]any{
				"redirect_uris": []string{"https://app.example.com/cb"},
				"client_name":   value,
			})
			req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			Register(tm, zap.NewNop(), testBaseURL)(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rr.Code)
			}
			var oe OAuthError
			_ = json.NewDecoder(rr.Body).Decode(&oe)
			if oe.Error != "invalid_client_metadata" {
				t.Errorf("error = %q, want invalid_client_metadata", oe.Error)
			}
		})
	}
}

// --- M6 — redirect_uri fragment + userinfo rejection ---

func TestRegister_RejectsFragmentAndUserinfo(t *testing.T) {
	tm := newTestTokenManager(t)

	tests := []struct{ name, uri string }{
		{"fragment", "https://app.example.com/cb#f"},
		{"bare_fragment", "https://app.example.com/cb#"},
		{"userinfo", "https://attacker:pass@legit.example.com/cb"},
		{"userinfo_no_pass", "https://attacker@legit.example.com/cb"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"redirect_uris": []string{tc.uri}, "client_name": "bad"})
			req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			Register(tm, zap.NewNop(), testBaseURL)(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("M6 %s: expected 400, got %d: %s", tc.name, rr.Code, rr.Body.String())
			}
			var oe OAuthError
			_ = json.NewDecoder(rr.Body).Decode(&oe)
			if oe.Error != "invalid_redirect_uri" {
				t.Errorf("M6 %s: expected invalid_redirect_uri, got %q", tc.name, oe.Error)
			}
		})
	}
}

// TestRefreshToken_RejectsMissingFamilyOrTokenID pins the early-guard
// rejection for refresh blobs that lack either FamilyID or TokenID.
// Both are required to drive reuse detection: FamilyID anchors the
// lineage, TokenID is the single-use key within it. The guard is
// defense-in-depth — legitimate refreshes always have both — but the
// check keeps the replay-store branch below from being a silent no-op
// if a future code path ever sealed a partial struct.
func TestRefreshToken_RejectsMissingFamilyOrTokenID(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, internalID := registerClient(t, tm, []string{"https://app.example.com/cb"})

	cases := []struct {
		name              string
		familyID, tokenID string
	}{
		{"missing_family", "", uuid.New().String()},
		{"missing_token_id", uuid.New().String(), ""},
		{"both_missing", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sr := sealedRefresh{
				TokenID:   tc.tokenID,
				FamilyID:  tc.familyID,
				Subject:   "user-sub",
				Email:     "user@example.com",
				ClientID:  internalID,
				Typ:       token.PurposeRefresh,
				Audience:  testBaseURL,
				IssuedAt:  time.Now(),
				ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
			}
			rt, err := tm.SealJSON(sr, token.PurposeRefresh)
			if err != nil {
				t.Fatalf("SealJSON: %v", err)
			}
			form := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {rt},
				"client_id":     {encClientID},
			}
			req := httptest.NewRequestWithContext(context.Background(),
				http.MethodPost, "/token", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			Token(tm, zap.NewNop(), testBaseURL, time.Time{}, nil)(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
			}
			var oe OAuthError
			_ = json.NewDecoder(rr.Body).Decode(&oe)
			if oe.Error != "invalid_grant" {
				t.Errorf("expected invalid_grant, got %q", oe.Error)
			}
		})
	}
}

// TestRegister_RejectsNonHTTPScheme pins the scheme allowlist: only http
// (to loopback) and https are valid OAuth callback schemes. A custom or
// protocol-mismatched URI that happens to point at loopback used to slip
// through because the old check only compared against "https".
func TestRegister_RejectsNonHTTPScheme(t *testing.T) {
	tm := newTestTokenManager(t)

	badSchemes := []string{
		"ftp://127.0.0.1/cb",
		"ldap://127.0.0.1/cb",
		"file:///etc/passwd",
		"customapp://127.0.0.1/cb",
		"javascript:alert(1)",
	}
	for _, uri := range badSchemes {
		t.Run(uri, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{"redirect_uris": []string{uri}, "client_name": "bad"})
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			Register(tm, zap.NewNop(), testBaseURL)(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("scheme %q: expected 400, got %d: %s", uri, rr.Code, rr.Body.String())
			}
		})
	}
}

// --- M7 — isLoopback covers RFC 1122, IPv4-mapped IPv6, trailing dot ---

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"localhost.", true}, // trailing-dot FQDN form
		{"127.0.0.1", true},
		{"127.0.0.2", true}, // full 127/8 is loopback (RFC 1122)
		{"127.255.255.254", true},
		{"::1", true},
		{"::ffff:127.0.0.1", true}, // IPv4-mapped IPv6 loopback
		{"::0.0.0.1", true},        // ::1 in dotted-quad form
		{"example.com", false},
		{"10.0.0.1", false},
		{"2001:db8::1", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			u := &url.URL{Scheme: "http", Host: tc.host}
			if tc.host != "" && strings.Contains(tc.host, ":") && !strings.HasPrefix(tc.host, "[") {
				// IPv6 literals need bracketing inside url.URL so Hostname strips them.
				u.Host = "[" + tc.host + "]"
			}
			got := isLoopback(u)
			if got != tc.want {
				t.Errorf("isLoopback(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

// --- M12 — callback rejects group names with invalid characters ---

func TestCallback_RejectsGroupWithInvalidChars(t *testing.T) {
	tm := newTestTokenManager(t)
	oauth2Cfg := testOAuth2Config()

	// Drive /authorize to mint a valid session with a known upstream nonce.
	encClientID, _ := registerClient(t, tm, []string{"https://app.example.com/callback"})
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state"},
	}
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()
	Authorize(tm, zap.NewNop(), testBaseURL, oauth2Cfg, AuthorizeConfig{PKCERequired: true})(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d: %s", rr.Code, rr.Body.String())
	}
	idpURL, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse IdP Location: %v", err)
	}
	state := idpURL.Query().Get("state")
	upstreamNonce := idpURL.Query().Get("nonce")

	// Mock upstream /token so oauth2Cfg.Exchange succeeds.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "up",
			"token_type":   "Bearer",
			"id_token":     "dummy",
		})
	}))
	defer upstream.Close()
	oauth2Cfg.Endpoint.TokenURL = upstream.URL + "/token"

	tests := []struct{ name, group string }{
		{"comma", "foo,bar"},
		{"cr", "foo\rbar"},
		{"lf", "foo\nbar"},
		{"nul", "foo\x00bar"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Verifier emits an id_token whose groups claim includes an
			// invalid character; go-oidc's IDToken.Claims(&raw) parses
			// the stored JSON — populate it so cb can find a groups claim.
			idTokenJSON, _ := json.Marshal(map[string]any{
				"sub":    "user-sub",
				"groups": []string{"ok-group", tc.group},
				"nonce":  upstreamNonce,
			})
			verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
				tok := &oidc.IDToken{Subject: "user-sub", Nonce: upstreamNonce}
				setIDTokenClaims(t, tok, idTokenJSON)
				return tok, nil
			}

			cbReq := httptest.NewRequest(http.MethodGet,
				"/callback?code=fake&state="+url.QueryEscape(state), nil)
			cbRR := httptest.NewRecorder()
			CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc,
				CallbackConfig{GroupsClaim: "groups"})(cbRR, cbReq)

			if cbRR.Code != http.StatusForbidden {
				t.Fatalf("M12 %s: expected 403, got %d: %s", tc.name, cbRR.Code, cbRR.Body.String())
			}
			var oe OAuthError
			_ = json.NewDecoder(cbRR.Body).Decode(&oe)
			if oe.Error != "access_denied" {
				t.Errorf("M12 %s: expected access_denied, got %q", tc.name, oe.Error)
			}
			if oe.ErrorCode != "group_invalid" {
				t.Errorf("M12 %s: expected error_code=group_invalid, got %q", tc.name, oe.ErrorCode)
			}
		})
	}
}

// Keep the import set honest even if a test above stops using a helper.
var (
	_ = uuid.New
	_ = errors.New
)
