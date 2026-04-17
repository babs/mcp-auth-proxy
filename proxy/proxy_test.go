package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babs/mcp-auth-proxy/middleware"
	"go.uber.org/zap"
)

func TestProxy_ForwardsRequest(t *testing.T) {
	var gotSub, gotEmail, gotAuth string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSub = r.Header.Get("X-User-Sub")
		gotEmail = r.Header.Get("X-User-Email")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	handler, err := Handler(upstream.URL, zap.NewNop())
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	// Simulate auth middleware having set context values.
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	ctx := context.WithValue(req.Context(), middleware.ContextSubject, "user-123")
	ctx = context.WithValue(ctx, middleware.ContextEmail, "user@example.com")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if gotSub != "user-123" {
		t.Fatalf("expected X-User-Sub=user-123, got %q", gotSub)
	}
	if gotEmail != "user@example.com" {
		t.Fatalf("expected X-User-Email=user@example.com, got %q", gotEmail)
	}
	if gotAuth != "" {
		t.Fatalf("expected Authorization header to be stripped, got %q", gotAuth)
	}
}

func TestProxy_SSEStreaming(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("upstream ResponseWriter does not implement http.Flusher")
		}

		for i := 0; i < 3; i++ {
			fmt.Fprintf(w, "data: event-%d\n\n", i)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	handler, err := Handler(upstream.URL, zap.NewNop())
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	ctx := context.WithValue(req.Context(), middleware.ContextSubject, "sse-user")
	ctx = context.WithValue(ctx, middleware.ContextEmail, "sse@example.com")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	resp := rr.Result()
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("expected Content-Type text/event-stream, got %q", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	for i := 0; i < 3; i++ {
		expected := fmt.Sprintf("data: event-%d", i)
		if !strings.Contains(string(body), expected) {
			t.Fatalf("body missing %q; got:\n%s", expected, body)
		}
	}
}

func TestProxy_ForwardsGroups(t *testing.T) {
	var gotGroups string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotGroups = r.Header.Get("X-User-Groups")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler, err := Handler(upstream.URL, zap.NewNop())
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	ctx := context.WithValue(req.Context(), middleware.ContextSubject, "user-1")
	ctx = context.WithValue(ctx, middleware.ContextEmail, "u@example.com")
	ctx = context.WithValue(ctx, middleware.ContextGroups, []string{"admin", "dev"})
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if gotGroups != "admin,dev" {
		t.Fatalf("expected X-User-Groups=admin,dev, got %q", gotGroups)
	}
}

func TestProxy_NoGroupsHeader(t *testing.T) {
	var gotGroups string
	var hasHeader bool

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotGroups = r.Header.Get("X-User-Groups")
		_, hasHeader = r.Header["X-User-Groups"]
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler, err := Handler(upstream.URL, zap.NewNop())
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	ctx := context.WithValue(req.Context(), middleware.ContextSubject, "user-1")
	ctx = context.WithValue(ctx, middleware.ContextEmail, "u@example.com")
	// No groups in context
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if hasHeader {
		t.Fatalf("expected no X-User-Groups header, got %q", gotGroups)
	}
}

func TestProxy_StripsSpoofedIdentityHeaders(t *testing.T) {
	var gotSub, gotEmail, gotGroups string
	var hasGroups bool

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSub = r.Header.Get("X-User-Sub")
		gotEmail = r.Header.Get("X-User-Email")
		gotGroups = r.Header.Get("X-User-Groups")
		_, hasGroups = r.Header["X-User-Groups"]
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler, err := Handler(upstream.URL, zap.NewNop())
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	ctx := context.WithValue(context.Background(), middleware.ContextSubject, "real-sub")
	ctx = context.WithValue(ctx, middleware.ContextEmail, "real@example.com")
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/mcp", nil)
	req.Header.Set("X-User-Sub", "spoofed-sub")
	req.Header.Set("X-User-Email", "spoofed@example.com")
	req.Header.Set("X-User-Groups", "admin,root")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if gotSub != "real-sub" {
		t.Fatalf("expected X-User-Sub=real-sub, got %q", gotSub)
	}
	if gotEmail != "real@example.com" {
		t.Fatalf("expected X-User-Email=real@example.com, got %q", gotEmail)
	}
	if hasGroups {
		t.Fatalf("expected spoofed X-User-Groups to be removed, got %q", gotGroups)
	}
}

func TestSingleJoiningSlash(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"/api", "/mcp", "/api/mcp"},
		{"/api/", "/mcp", "/api/mcp"},
		{"/api", "mcp", "/api/mcp"},
		{"/api/", "mcp", "/api/mcp"},
		{"", "/mcp", "/mcp"},
		{"", "mcp", "/mcp"},
		{"/api", "/", "/api/"},
		{"/api/", "/", "/api/"},
	}
	for _, tc := range tests {
		got := singleJoiningSlash(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("singleJoiningSlash(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestProxy_Follows307Redirect(t *testing.T) {
	// Simulate a Python backend that redirects /mcp → /mcp/ with 307
	var finalPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			w.Header().Set("Location", "/mcp/")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		finalPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	handler, err := Handler(upstream.URL, zap.NewNop())
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), middleware.ContextSubject, "user-1")
	ctx = context.WithValue(ctx, middleware.ContextEmail, "u@example.com")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should follow the 307 and reach /mcp/
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 after following 307, got %d", rr.Code)
	}
	if finalPath != "/mcp/" {
		t.Errorf("expected final path /mcp/, got %q", finalPath)
	}
}
