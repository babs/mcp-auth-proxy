package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/babs/mcp-auth-proxy/middleware"
	"go.uber.org/zap"
)

// roundTripFunc adapts a plain function to http.RoundTripper for unit tests.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

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

// TestDirector_StripsForwardingHeaders verifies H2: the Director removes all
// inbound forwarding/IP headers and arbitrary X-User-* headers before they
// reach the upstream, while still injecting the proxy-owned identity headers.
func TestDirector_StripsForwardingHeaders(t *testing.T) {
	var gotHeader http.Header

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler, err := Handler(upstream.URL, zap.NewNop())
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("Cookie", "session=secret")
	req.Header.Set("Proxy-Authorization", "Basic abc123")
	req.Header.Set("X-Real-IP", "5.6.7.8")
	req.Header.Set("Forwarded", "for=1.2.3.4")
	req.Header.Set("True-Client-IP", "9.10.11.12")
	req.Header.Set("X-User-Admin", "true") // non-standard X-User-* must be stripped

	ctx := context.WithValue(req.Context(), middleware.ContextSubject, "real-sub")
	ctx = context.WithValue(ctx, middleware.ContextEmail, "real@example.com")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Every one of these must be absent at the upstream.
	for _, h := range []string{
		"X-Forwarded-For", "Cookie", "Proxy-Authorization",
		"X-Real-IP", "Forwarded", "True-Client-IP", "X-User-Admin",
	} {
		if v := gotHeader.Get(h); v != "" {
			t.Errorf("header %q must be stripped, but upstream received %q", h, v)
		}
	}

	// Proxy-owned identity headers must still arrive correctly.
	if got := gotHeader.Get("X-User-Sub"); got != "real-sub" {
		t.Errorf("X-User-Sub: want %q, got %q", "real-sub", got)
	}
	if got := gotHeader.Get("X-User-Email"); got != "real@example.com" {
		t.Errorf("X-User-Email: want %q, got %q", "real@example.com", got)
	}
}

// TestSameHost verifies M8: the redirect-follow transport treats
// host vs host:default-port as the same origin under the request's
// scheme, and applies case-folding so an upper-cased host matches
// too. Anything with a different hostname or explicit non-default
// port returns false.
func TestSameHost(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"https://example.com/x", "https://example.com:443/x", true},
		{"http://example.com/x", "http://example.com:80/x", true},
		{"https://Example.COM/x", "https://example.com/x", true},
		{"https://example.com/x", "https://example.com:8443/x", false},
		{"https://example.com/x", "https://other.example.com/x", false},
		{"http://example.com:80/x", "https://example.com:443/x", false}, // default ports differ by scheme; scheme mismatch is also caught by the separate H1 check
	}
	for _, tc := range tests {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			a, err := url.Parse(tc.a)
			if err != nil {
				t.Fatalf("parse a: %v", err)
			}
			b, err := url.Parse(tc.b)
			if err != nil {
				t.Fatalf("parse b: %v", err)
			}
			if got := sameHost(a, b); got != tc.want {
				t.Errorf("sameHost(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestRedirectFollow_SameHostPortNormalization verifies M8 in situ: a
// 307 whose Location carries the explicit default port is recognized
// as same-host and followed, where the previous raw-string compare
// treated "host" and "host:443" as different hosts.
func TestRedirectFollow_SameHostPortNormalization(t *testing.T) {
	calls := 0
	mock := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		switch calls {
		case 1:
			// First hit — redirect to the same host with explicit :443.
			return &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header:     http.Header{"Location": []string{"https://backend.example.com:443/next"}},
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		default:
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}
	})

	transport := &redirectFollowingTransport{base: mock}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://backend.example.com/original", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after following same-host :443 redirect, got %d", resp.StatusCode)
	}
	if calls != 2 {
		t.Errorf("expected 2 upstream calls (follow), got %d", calls)
	}
}

// TestRedirectFollow_FirstHopStreamsBody verifies H10: on the first
// hop the transport passes the request body straight to the base
// round-tripper without a prior io.ReadAll. The test uses an io.Pipe
// so the client side cannot complete writing until the base starts
// reading — a buffering implementation would deadlock because the
// pipe reader would never be drained.
func TestRedirectFollow_FirstHopStreamsBody(t *testing.T) {
	pr, pw := io.Pipe()
	readStarted := make(chan struct{})
	writeDone := make(chan struct{})

	mock := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Read one byte to prove the base transport is active BEFORE
		// the writer is unblocked. With a pre-buffering implementation
		// we would never reach this point (body read via ReadAll would
		// block waiting for the pipe writer, which is waiting on us).
		buf := make([]byte, 1)
		if _, err := io.ReadFull(req.Body, buf); err != nil {
			return nil, err
		}
		close(readStarted)
		// Drain the rest.
		rest, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(string(buf) + string(rest))),
		}, nil
	})

	go func() {
		defer close(writeDone)
		if _, err := pw.Write([]byte("a")); err != nil {
			t.Errorf("pipe write 1: %v", err)
			return
		}
		select {
		case <-readStarted:
		case <-time.After(2 * time.Second):
			t.Errorf("base transport did not start reading before writer stalled — proxy is pre-buffering")
			_ = pw.CloseWithError(fmt.Errorf("streaming deadline"))
			return
		}
		if _, err := pw.Write([]byte("bcde")); err != nil {
			t.Errorf("pipe write 2: %v", err)
			return
		}
		_ = pw.Close()
	}()

	transport := &redirectFollowingTransport{base: mock}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://backend.example.com/mcp", pr)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read resp body: %v", err)
	}
	if string(body) != "abcde" {
		t.Errorf("body: want %q, got %q", "abcde", body)
	}

	select {
	case <-writeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("pipe writer did not complete")
	}
}

// TestRedirectFollow_BufferedForReplayOnRedirect verifies the other
// half of H10: once a 307/308 comes back, the body is materialized
// (from the tee'd buffer) and replayed to the next hop. The body is
// only buffered when we actually need to replay.
func TestRedirectFollow_BufferedForReplayOnRedirect(t *testing.T) {
	var hops []string

	mock := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		hops = append(hops, string(body))
		if req.URL.Path == "/mcp" {
			return &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header:     http.Header{"Location": []string{"/mcp/"}},
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader("done:" + string(body))),
		}, nil
	})

	transport := &redirectFollowingTransport{base: mock}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://backend.example.com/mcp", strings.NewReader(`{"m":"tools/list"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read resp body: %v", err)
	}
	want := `done:{"m":"tools/list"}`
	if string(body) != want {
		t.Errorf("final body: want %q, got %q", want, body)
	}
	if len(hops) != 2 || hops[0] != `{"m":"tools/list"}` || hops[1] != `{"m":"tools/list"}` {
		t.Errorf("expected same body on both hops, got %v", hops)
	}
}

// TestRedirectFollow_ExhaustionReturns502 verifies L9: when the redirect
// hop budget is exhausted, the transport synthesizes a 502 Bad Gateway
// with a generic JSON body instead of echoing the last 307/308 verbatim.
// Echoing the redirect would push a Location: pointing into a known-bad
// loop to the MCP client.
func TestRedirectFollow_ExhaustionReturns502(t *testing.T) {
	calls := 0
	// Mock transport: every hop returns a 307 to a sibling path, bouncing
	// forever. The transport should abort after maxRedirects and synthesize
	// a 502.
	mock := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		next := fmt.Sprintf("/loop-%d", calls)
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": []string{next}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})

	transport := &redirectFollowingTransport{base: mock}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://backend.example.com/start", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: unexpected error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), `"error":"bad_gateway"`) {
		t.Errorf("body missing bad_gateway error: %q", body)
	}
	if !strings.Contains(string(body), "too many upstream redirects") {
		t.Errorf("body missing description: %q", body)
	}
	// Location header from the upstream's last 307 must not leak.
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Errorf("Location header should not leak to client, got %q", loc)
	}
}

// TestRedirectFollow_SchemeDowngradeRefused verifies H1: a 307/308 whose
// Location downgrades the scheme (https → http) is returned verbatim to the
// caller instead of being followed, preventing identity headers from leaking
// over cleartext.
func TestRedirectFollow_SchemeDowngradeRefused(t *testing.T) {
	calls := 0
	// Mock transport: always returns a 307 whose Location downgrades to http.
	mock := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": []string{"http://" + req.URL.Host + "/new"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})

	transport := &redirectFollowingTransport{base: mock}

	// Request scheme is https; redirect Location is http (downgrade).
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://backend.example.com/original", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: unexpected error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("expected 307 returned verbatim, got %d", resp.StatusCode)
	}
	// Transport must NOT have followed the redirect — exactly one upstream call.
	if calls != 1 {
		t.Errorf("expected 1 upstream call (redirect not followed), got %d", calls)
	}
}
