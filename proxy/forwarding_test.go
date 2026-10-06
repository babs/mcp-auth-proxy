package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/middleware"
)

const fwdIdPAccessToken = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJhcGk6Ly91cHN0cmVhbSJ9.c2lnbmF0dXJl"

// recordingUpstream records the Authorization and identity headers of
// every request it receives; when redirectTo is set, the first request
// is answered with a 307 to that location.
type recordingUpstream struct {
	mu         sync.Mutex
	auth       []string
	sub        []string
	redirectTo func(r *http.Request) string
}

func (u *recordingUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.auth = append(u.auth, r.Header.Get("Authorization"))
	u.sub = append(u.sub, r.Header.Get("X-User-Sub"))
	first := len(u.auth) == 1
	u.mu.Unlock()
	if first && u.redirectTo != nil {
		w.Header().Set("Location", u.redirectTo(r))
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func forwardingRequest(idpToken string) *http.Request {
	ctx := context.WithValue(context.Background(), middleware.ContextSubject, "user-123")
	ctx = context.WithValue(ctx, middleware.ContextEmail, "user@example.com")
	if idpToken != "" {
		ctx = context.WithValue(ctx, middleware.ContextIdPAccessToken, idpToken)
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer proxy-token-MUST-NOT-LEAK")
	return req
}

func TestProxy_ForwardIdPToken_SetsUpstreamBearer(t *testing.T) {
	up := &recordingUpstream{}
	srv := httptest.NewServer(up)
	defer srv.Close()
	h, err := Handler(srv.URL, zap.NewNop(), Config{ForwardIdPToken: true})
	if err != nil {
		t.Fatal(err)
	}
	before := testutil.ToFloat64(metrics.UpstreamIdPTokenForwarded)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, forwardingRequest(fwdIdPAccessToken))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if len(up.auth) != 1 || up.auth[0] != "Bearer "+fwdIdPAccessToken {
		t.Errorf("upstream Authorization = %q, want the IdP token byte-for-byte", up.auth)
	}
	if up.sub[0] != "user-123" {
		t.Errorf("X-User-Sub = %q, identity headers must still be injected", up.sub[0])
	}
	if got := testutil.ToFloat64(metrics.UpstreamIdPTokenForwarded) - before; got != 1 {
		t.Errorf("forwarded counter grew by %v, want 1", got)
	}
}

// Same-origin redirect hops carry the same IdP token; the request is
// counted once, not per hop.
func TestProxy_ForwardIdPToken_SurvivesSameOriginRedirect(t *testing.T) {
	up := &recordingUpstream{redirectTo: func(r *http.Request) string { return r.URL.Path + "/" }}
	srv := httptest.NewServer(up)
	defer srv.Close()
	h, err := Handler(srv.URL, zap.NewNop(), Config{ForwardIdPToken: true})
	if err != nil {
		t.Fatal(err)
	}
	before := testutil.ToFloat64(metrics.UpstreamIdPTokenForwarded)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, forwardingRequest(fwdIdPAccessToken))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if len(up.auth) != 2 {
		t.Fatalf("hops = %d, want 2", len(up.auth))
	}
	for i, a := range up.auth {
		if a != "Bearer "+fwdIdPAccessToken {
			t.Errorf("hop %d Authorization = %q, want the IdP token", i, a)
		}
	}
	if got := testutil.ToFloat64(metrics.UpstreamIdPTokenForwarded) - before; got != 1 {
		t.Errorf("forwarded counter grew by %v, want 1 per request", got)
	}
}

// A cross-origin redirect is not followed, so the IdP token never leaves
// the upstream origin.
func TestProxy_ForwardIdPToken_NotSentCrossOrigin(t *testing.T) {
	other := &recordingUpstream{}
	otherSrv := httptest.NewServer(other)
	defer otherSrv.Close()
	up := &recordingUpstream{redirectTo: func(*http.Request) string { return otherSrv.URL + "/mcp" }}
	srv := httptest.NewServer(up)
	defer srv.Close()
	h, err := Handler(srv.URL, zap.NewNop(), Config{ForwardIdPToken: true})
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, forwardingRequest(fwdIdPAccessToken))
	if rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want the 307 passed back unfollowed", rr.Code)
	}
	if len(other.auth) != 0 {
		t.Errorf("the other origin received %d request(s)", len(other.auth))
	}
}

// Defensive: forwarding on but no token in the context (the middleware
// refuses such requests) must not invent a credential, nor fall back to
// the client's own token.
func TestProxy_ForwardIdPToken_NoContextTokenSendsNoAuthorization(t *testing.T) {
	up := &recordingUpstream{}
	srv := httptest.NewServer(up)
	defer srv.Close()
	h, err := Handler(srv.URL, zap.NewNop(), Config{ForwardIdPToken: true})
	if err != nil {
		t.Fatal(err)
	}
	before := testutil.ToFloat64(metrics.UpstreamIdPTokenForwarded)

	h.ServeHTTP(httptest.NewRecorder(), forwardingRequest(""))
	if len(up.auth) != 1 || up.auth[0] != "" {
		t.Errorf("upstream Authorization = %q, want none", up.auth)
	}
	if got := testutil.ToFloat64(metrics.UpstreamIdPTokenForwarded) - before; got != 0 {
		t.Errorf("forwarded counter grew by %v for a request without a token", got)
	}
}

// With forwarding off, a token found in the context is ignored.
func TestProxy_DefaultModeIgnoresContextIdPToken(t *testing.T) {
	up := &recordingUpstream{}
	srv := httptest.NewServer(up)
	defer srv.Close()
	h, err := Handler(srv.URL, zap.NewNop(), Config{})
	if err != nil {
		t.Fatal(err)
	}

	h.ServeHTTP(httptest.NewRecorder(), forwardingRequest(fwdIdPAccessToken))
	if len(up.auth) != 1 || up.auth[0] != "" {
		t.Errorf("upstream Authorization = %q, want none in default mode", up.auth)
	}
}

// An empty token in the context must not become "Authorization: Bearer ".
func TestProxy_ForwardIdPToken_EmptyContextTokenSendsNoHeader(t *testing.T) {
	up := &recordingUpstream{}
	srv := httptest.NewServer(up)
	defer srv.Close()
	h, err := Handler(srv.URL, zap.NewNop(), Config{ForwardIdPToken: true})
	if err != nil {
		t.Fatal(err)
	}
	req := forwardingRequest("")
	req = req.WithContext(context.WithValue(req.Context(), middleware.ContextIdPAccessToken, ""))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if len(up.auth) != 1 || up.auth[0] != "" {
		t.Errorf("upstream Authorization = %q, want none", up.auth)
	}
}
