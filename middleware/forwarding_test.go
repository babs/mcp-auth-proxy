package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const testIdPAccessToken = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJhcGk6Ly91cHN0cmVhbSJ9.c2ln"

func issueForwardingToken(t *testing.T, tm *token.Manager) string {
	t.Helper()
	raw, _, err := tm.IssueWithIdPToken(testBaseURL, "user-123", "user@example.com", "test-client", nil, 5*time.Minute, "",
		token.IdPToken{AccessToken: testIdPAccessToken, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("IssueWithIdPToken: %v", err)
	}
	return raw
}

func serveWith(auth *Auth, bearer string) (*httptest.ResponseRecorder, string, bool, bool) {
	var got string
	var present, called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		got, present = r.Context().Value(ContextIdPAccessToken).(string)
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	auth.Validate(next).ServeHTTP(rr, req)
	return rr, got, present, called
}

func TestValidate_ForwardingHandsIdPTokenToProxy(t *testing.T) {
	auth, tm := setupAuth(t)
	auth.SetForwardIdPToken(true)

	rr, got, present, _ := serveWith(auth, issueForwardingToken(t, tm))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !present || got != testIdPAccessToken {
		t.Errorf("context IdP token = %q (present=%v), want the sealed IdP token", got, present)
	}
}

// A token minted before forwarding was switched on carries no IdP token:
// 401 with the usual challenge, so the client refreshes or signs in
// instead of reaching the upstream without a credential.
func TestValidate_ForwardingRefusesTokenWithoutIdPToken(t *testing.T) {
	auth, tm := setupAuth(t)
	auth.SetForwardIdPToken(true)
	before := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("idp_token_missing"))

	rr, _, _, called := serveWith(auth, issueToken(t, tm, "user-123", "user@example.com", 5*time.Minute))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if called {
		t.Error("request reached the proxy without an IdP token")
	}
	if wa := rr.Header().Get("WWW-Authenticate"); !strings.Contains(wa, `error="invalid_token"`) || !strings.Contains(wa, "resource_metadata=") {
		t.Errorf("WWW-Authenticate = %q, want the invalid_token challenge", wa)
	}
	if got := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("idp_token_missing")) - before; got != 1 {
		t.Errorf("access_denied{idp_token_missing} grew by %v, want 1", got)
	}
}

// With forwarding off, an IdP token left in a claim (minted while the
// mode was on) must never be handed on.
func TestValidate_DefaultModeNeverHandsOnIdPToken(t *testing.T) {
	auth, tm := setupAuth(t)

	rr, _, present, _ := serveWith(auth, issueForwardingToken(t, tm))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if present {
		t.Error("default mode put an IdP token in the request context")
	}
}
