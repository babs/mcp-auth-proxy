package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/babs/mcp-auth-proxy/middleware"
)

// TestCIDRAwareKey covers P1c: only peers inside a trusted CIDR get
// their XFF honored. Direct-to-pod clients outside the allowlist fall
// back to RemoteAddr-keyed buckets regardless of forwarded headers.
func TestCIDRAwareKey(t *testing.T) {
	_, cidr, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	keyFn := cidrAwareKey([]*net.IPNet{cidr})

	t.Run("trusted_peer_honors_xff", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "10.1.2.3:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.99")
		key, err := keyFn(req)
		if err != nil {
			t.Fatalf("keyFn: %v", err)
		}
		if key != "203.0.113.99" {
			t.Errorf("trusted peer: want key from XFF %q, got %q", "203.0.113.99", key)
		}
	})
	t.Run("untrusted_peer_uses_remote_addr", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "203.0.113.50:443"
		req.Header.Set("X-Forwarded-For", "10.1.2.3")
		key, err := keyFn(req)
		if err != nil {
			t.Fatalf("keyFn: %v", err)
		}
		if key == "10.1.2.3" {
			t.Errorf("untrusted peer must NOT honor XFF; got spoofed key %q", key)
		}
		if key != "203.0.113.50" {
			t.Errorf("want RemoteAddr-derived key %q, got %q", "203.0.113.50", key)
		}
	})
	t.Run("bad_remote_addr_falls_back", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "garbage"
		if _, err := keyFn(req); err != nil {
			t.Errorf("fallback should not error, got %v", err)
		}
	})
}

// TestZapMiddleware_SkipRE verifies ACCESS_LOG_SKIP_RE suppresses the
// access-log line for matching paths while leaving non-matching paths
// and the handler response untouched. A nil regex is the
// log-everything default. The handler MUST always run regardless of
// match — skipping the log line must never skip the handler.
func TestZapMiddleware_SkipRE(t *testing.T) {
	healthz := regexp.MustCompile(`^/healthz$`)
	probes := regexp.MustCompile(`^/(healthz|readyz)$`)

	cases := []struct {
		name     string
		re       *regexp.Regexp
		path     string
		wantLogs int
	}{
		{"nil_logs_healthz", nil, "/healthz", 1},
		{"healthz_re_skips_healthz", healthz, "/healthz", 0},
		{"healthz_re_skips_with_query", healthz, "/healthz?verbose=1", 0},
		{"healthz_re_logs_other", healthz, "/mcp", 1},
		{"healthz_re_logs_trailing_slash", healthz, "/healthz/", 1},
		{"probes_re_skips_readyz", probes, "/readyz", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var called bool
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})
			core, logs := observer.New(zap.InfoLevel)
			h := zapMiddleware(zap.New(core), tc.re, nil)(next) // nil rpcMetrics — RPC observer not under test here
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if !called {
				t.Fatal("next handler was not invoked — skip branch must always call next")
			}
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rec.Code)
			}
			if got := logs.FilterMessage("request").Len(); got != tc.wantLogs {
				t.Errorf("access-log count = %d, want %d", got, tc.wantLogs)
			}
		})
	}
}

// TestZapMiddleware_RPCMetrics_GateAndFanOut pins both axes of the
// rpc-metrics observer:
//
//   - per-tool counter: invoked once per tools/call entry (single
//     request OR per-entry inside a batch). Tool name passes through
//     verbatim (downstream cardinality guard maps "" / overflow).
//   - batch counter: invoked exactly once per HTTP request that
//     decoded as a batch with at least one tools/call entry, AFTER
//     all per-tool fan-outs land. Carries the request's actual bytes.
//
// Skipped cases (no per-tool, no batch invocation): protocol-level
// methods (initialize / notifications/* / tools/list / prompts/*),
// empty requests, batches with zero tools/call entries.
func TestZapMiddleware_RPCMetrics_GateAndFanOut(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		tool        string
		batch       []middleware.RPCCall
		wantTools   []string // perTool invocations in order
		wantBatches int      // batch invocations
	}{
		{name: "tools_call_invokes", method: "tools/call", tool: "weather", wantTools: []string{"weather"}},
		{name: "tools_call_unknown_tool", method: "tools/call", tool: "", wantTools: []string{""}},
		{name: "initialize_skipped", method: "initialize"},
		{name: "notifications_skipped", method: "notifications/initialized"},
		{name: "tools_list_skipped", method: "tools/list"},
		{name: "empty_skipped"},
		{
			name:   "batch_two_tools_calls_fans_out_and_counts_batch",
			method: "tools/call,tools/call",
			batch: []middleware.RPCCall{
				{Method: "tools/call", Tool: "weather"},
				{Method: "tools/call", Tool: "search"},
			},
			wantTools:   []string{"weather", "search"},
			wantBatches: 1,
		},
		{
			name:   "batch_mixed_only_tools_call_counts_and_batch_fires_once",
			method: "tools/call,initialize,tools/call",
			batch: []middleware.RPCCall{
				{Method: "tools/call", Tool: "weather"},
				{Method: "initialize"},
				{Method: "tools/call", Tool: "search"},
			},
			wantTools:   []string{"weather", "search"},
			wantBatches: 1,
		},
		{
			name:   "batch_no_tools_calls_skipped_entirely",
			method: "initialize,tools/list",
			batch: []middleware.RPCCall{
				{Method: "initialize"},
				{Method: "tools/list"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotTools []string
			var gotBatches int
			obs := &rpcMetrics{
				perTool: func(tool string, _ int, _ int64, _ int) {
					gotTools = append(gotTools, tool)
				},
				batch: func(_ int, _ int64, _ int) {
					gotBatches++
				},
			}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if rec := middleware.LogRecordFromContext(r.Context()); rec != nil {
					rec.RPCMethod = tc.method
					rec.RPCTool = tc.tool
					rec.RPCBatch = tc.batch
				}
				w.WriteHeader(http.StatusOK)
			})
			h := zapMiddleware(zap.NewNop(), nil, obs)(next)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/mcp", nil))

			if len(gotTools) != len(tc.wantTools) {
				t.Fatalf("perTool count = %d (%v), want %d (%v)", len(gotTools), gotTools, len(tc.wantTools), tc.wantTools)
			}
			for i, w := range tc.wantTools {
				if gotTools[i] != w {
					t.Errorf("perTool call %d: got tool=%q, want %q", i, gotTools[i], w)
				}
			}
			if gotBatches != tc.wantBatches {
				t.Errorf("batch invocations = %d, want %d", gotBatches, tc.wantBatches)
			}
		})
	}
}

// TestRateLimiter_StripsXRateLimitHeaders verifies the wrapper around
// httprate suppresses the X-RateLimit-Limit / -Remaining / -Reset
// headers on both the success and the 429 paths. Production MCP
// servers don't surface these; we match that posture so an attacker
// cannot pace just-under-the-limit floods.
func TestRateLimiter_StripsXRateLimitHeaders(t *testing.T) {
	mw := rateLimiter(2, time.Minute, "test")
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	h := mw(next)

	probe := func(req *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// First request: should be allowed (200).
	first := probe(httptest.NewRequest(http.MethodGet, "/x", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first request: want 200, got %d", first.Code)
	}
	for _, k := range []string{"X-Ratelimit-Limit", "X-Ratelimit-Remaining", "X-Ratelimit-Reset"} {
		if v := first.Header().Get(k); v != "" {
			t.Errorf("first response leaked %s = %q", k, v)
		}
	}
	// Trip the limit: second + third requests, third should 429.
	for range 2 {
		probe(httptest.NewRequest(http.MethodGet, "/x", nil))
	}
	throttled := probe(httptest.NewRequest(http.MethodGet, "/x", nil))
	if throttled.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled request: want 429, got %d", throttled.Code)
	}
	for _, k := range []string{"X-Ratelimit-Limit", "X-Ratelimit-Remaining", "X-Ratelimit-Reset"} {
		if v := throttled.Header().Get(k); v != "" {
			t.Errorf("429 response leaked %s = %q", k, v)
		}
	}
}

// TestSecurityHeaders pins the public-listener security-headers
// baseline. Every response (regardless of handler outcome — 200, 401,
// 404, 500) MUST carry the five headers. Verified by routing a no-op
// handler, an error handler, and a chain that calls writeOAuthError.
func TestSecurityHeaders(t *testing.T) {
	wantHeaders := map[string]string{
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'",
	}

	cases := []struct {
		name    string
		handler http.HandlerFunc
		status  int
	}{
		{
			name: "ok_200",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			status: http.StatusOK,
		},
		{
			name: "json_400",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
			},
			status: http.StatusBadRequest,
		},
		{
			name: "redirect_302",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "https://example/cb?error=x")
				w.WriteHeader(http.StatusFound)
			},
			status: http.StatusFound,
		},
		{
			name: "panic_recovered",
			handler: func(_ http.ResponseWriter, _ *http.Request) {
				// Recoverer would normally wrap; for this test we
				// just ensure the headers were set BEFORE the panic.
				panic("boom")
			},
			status: http.StatusInternalServerError, // synthesized by deferred recover
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer func() {
					if rec := recover(); rec != nil {
						w.WriteHeader(http.StatusInternalServerError)
					}
				}()
				tc.handler(w, r)
			}))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
			for k, want := range wantHeaders {
				if got := rr.Header().Get(k); got != want {
					t.Errorf("%s: header %q = %q, want %q", tc.name, k, got, want)
				}
			}
		})
	}
}
