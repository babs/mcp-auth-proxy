package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/babs/mcp-auth-proxy/token"
	"go.uber.org/zap"
)

var (
	testSecret  = []byte("test-secret-that-is-at-least-32-bytes!!")
	testBaseURL = "https://mcp-proxy.example.com"
)

func setupAuth(t *testing.T) (*Auth, *token.Manager) {
	t.Helper()
	tm, err := token.NewManager(testSecret)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	auth := NewAuth(tm, zap.NewNop(), testBaseURL, time.Time{})
	return auth, tm
}

func issueToken(t *testing.T, tm *token.Manager, sub, email string, ttl time.Duration) string {
	t.Helper()
	raw, _, err := tm.Issue(testBaseURL, sub, email, "test-client", nil, ttl)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return raw
}

func TestValidate_ValidToken(t *testing.T) {
	auth, tm := setupAuth(t)
	raw := issueToken(t, tm, "user-123", "user@example.com", 5*time.Minute)

	var capturedSub, capturedEmail string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSub, _ = r.Context().Value(ContextSubject).(string)
		capturedEmail, _ = r.Context().Value(ContextEmail).(string)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := httptest.NewRecorder()

	auth.Validate(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if capturedSub != "user-123" {
		t.Fatalf("expected sub=user-123, got %q", capturedSub)
	}
	if capturedEmail != "user@example.com" {
		t.Fatalf("expected email=user@example.com, got %q", capturedEmail)
	}
}

func TestValidate_MissingHeader(t *testing.T) {
	auth, _ := setupAuth(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rr := httptest.NewRecorder()

	auth.Validate(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	// RFC 6750 §3.1: missing credential → invalid_request (not invalid_token,
	// which is reserved for a presented token that failed validation).
	if body["error"] != "invalid_request" {
		t.Errorf("expected error=invalid_request, got %q", body["error"])
	}
}

func TestValidate_WWWAuthenticateHeader(t *testing.T) {
	auth, _ := setupAuth(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rr := httptest.NewRecorder()

	auth.Validate(next).ServeHTTP(rr, req)

	wwwAuth := rr.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Fatal("expected WWW-Authenticate header on 401 response")
	}

	expected := `Bearer error="invalid_request", resource_metadata="` + testBaseURL + `/.well-known/oauth-protected-resource"`
	if wwwAuth != expected {
		t.Errorf("WWW-Authenticate header mismatch\ngot:  %q\nwant: %q", wwwAuth, expected)
	}
}

func TestValidate_InvalidToken(t *testing.T) {
	auth, _ := setupAuth(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer totally-garbage-token")
	rr := httptest.NewRecorder()

	auth.Validate(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "invalid_token" {
		t.Errorf("expected error=invalid_token, got %q", body["error"])
	}
}

func TestValidate_ExpiredToken(t *testing.T) {
	auth, tm := setupAuth(t)

	// Issue with a negative TTL so the token is already expired.
	raw := issueToken(t, tm, "user-789", "expired@example.com", -1*time.Second)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := httptest.NewRecorder()

	auth.Validate(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestValidate_GroupsInContext(t *testing.T) {
	auth, tm := setupAuth(t)

	groups := []string{"admin", "dev"}
	raw, _, err := tm.Issue(testBaseURL, "user-grp", "grp@example.com", "test-client", groups, 5*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	var capturedGroups []string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedGroups, _ = r.Context().Value(ContextGroups).([]string)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := httptest.NewRecorder()

	auth.Validate(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if len(capturedGroups) != 2 || capturedGroups[0] != "admin" || capturedGroups[1] != "dev" {
		t.Errorf("expected groups [admin dev], got %v", capturedGroups)
	}
}

func TestValidate_RevokedByIat(t *testing.T) {
	tm, err := token.NewManager(testSecret)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Issue a token now
	raw := issueToken(t, tm, "user-revoked", "revoked@example.com", 5*time.Minute)

	// Set cutoff to 1 second in the future — token was issued before it
	cutoff := time.Now().Add(1 * time.Second)
	auth := NewAuth(tm, zap.NewNop(), testBaseURL, cutoff)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := httptest.NewRecorder()

	auth.Validate(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestValidate_RejectsWrongAudience(t *testing.T) {
	tm, err := token.NewManager(testSecret)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Token minted for a sibling instance with the same secret but different baseURL.
	raw, _, err := tm.Issue("https://other-proxy.example.com", "user-x", "x@example.com", "test-client", nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	auth := NewAuth(tm, zap.NewNop(), testBaseURL, time.Time{})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler should not be called for a token with the wrong audience")
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := httptest.NewRecorder()

	auth.Validate(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for cross-audience token, got %d", rr.Code)
	}
}

func TestValidate_NotRevokedAfterCutoff(t *testing.T) {
	tm, err := token.NewManager(testSecret)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Set cutoff to 1 hour ago — token issued now is after the cutoff
	cutoff := time.Now().Add(-1 * time.Hour)
	auth := NewAuth(tm, zap.NewNop(), testBaseURL, cutoff)

	raw := issueToken(t, tm, "user-ok", "ok@example.com", 5*time.Minute)

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rr := httptest.NewRecorder()

	auth.Validate(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !called {
		t.Fatal("next handler should have been called")
	}
}
