package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/babs/mcp-auth-proxy/handlers"
	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/middleware"
)

// TestCIDRAwareKey covers R2-H1: keying walks XFF right-to-left from
// the trusted ingress, stopping at the first hop NOT in the trusted
// CIDR set. That stops a client behind a typical k8s ingress from
// minting an unbounded rate-limit bucket per request by appending
// arbitrary leftmost values.
func TestCIDRAwareKey(t *testing.T) {
	_, podCIDR, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	keyFn := cidrAwareKey([]*net.IPNet{podCIDR}, "")

	t.Run("trusted_peer_uses_rightmost_untrusted_xff_hop", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "10.1.2.3:12345"
		// nginx-ingress style: client IP is rightmost-trusted-1.
		req.Header.Set("X-Forwarded-For", "203.0.113.99, 10.42.0.7")
		key, err := keyFn(req)
		if err != nil {
			t.Fatalf("keyFn: %v", err)
		}
		if key != "203.0.113.99" {
			t.Errorf("want client IP from rightmost-trusted-1, got %q", key)
		}
	})
	t.Run("trusted_peer_ignores_attacker_appended_leftmost_xff", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "10.1.2.3:12345"
		// Attacker behind an ingress that APPENDS XFF: their value
		// is the leftmost entry. With a right-to-left walk we land
		// on the ingress' own view of the immediate peer
		// (203.0.113.99), not on whatever the attacker forged.
		req.Header.Set("X-Forwarded-For", "evil-spoof, 203.0.113.99, 10.42.0.7")
		key, err := keyFn(req)
		if err != nil {
			t.Fatalf("keyFn: %v", err)
		}
		if key == "evil-spoof" {
			t.Errorf("attacker spoof leaked into bucket key: %q", key)
		}
		if key != "203.0.113.99" {
			t.Errorf("want client IP from rightmost-trusted-1, got %q", key)
		}
	})
	t.Run("trusted_peer_ignores_true_client_ip_by_default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "10.1.2.3:12345"
		// Default header is X-Forwarded-For; True-Client-IP must
		// NOT influence the bucket without an explicit opt-in.
		req.Header.Set("True-Client-IP", "evil-spoof")
		key, err := keyFn(req)
		if err != nil {
			t.Fatalf("keyFn: %v", err)
		}
		if key == "evil-spoof" {
			t.Errorf("True-Client-IP leaked into bucket key without TRUSTED_PROXY_HEADER opt-in: %q", key)
		}
	})
	t.Run("trusted_peer_uses_pinned_header_when_opted_in", func(t *testing.T) {
		fn := cidrAwareKey([]*net.IPNet{podCIDR}, "X-Real-Ip")
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "10.1.2.3:12345"
		req.Header.Set("X-Real-Ip", "203.0.113.42")
		// XFF should be ignored when the operator pinned a different header.
		req.Header.Set("X-Forwarded-For", "203.0.113.99")
		key, err := fn(req)
		if err != nil {
			t.Fatalf("keyFn: %v", err)
		}
		if key != "203.0.113.42" {
			t.Errorf("want pinned X-Real-Ip value, got %q", key)
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
	t.Run("trusted_peer_no_xff_falls_back_to_remote_addr", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "10.1.2.3:12345"
		key, err := keyFn(req)
		if err != nil {
			t.Fatalf("keyFn: %v", err)
		}
		if key != "10.1.2.3" {
			t.Errorf("want fallback to RemoteAddr, got %q", key)
		}
	})
	t.Run("trusted_peer_all_hops_trusted_falls_back", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "10.1.2.3:12345"
		// Pathological: every XFF entry is itself a trusted hop.
		// No untrusted origin to bucket on — fall back to RemoteAddr.
		req.Header.Set("X-Forwarded-For", "10.42.0.1, 10.42.0.2, 10.42.0.3")
		key, err := keyFn(req)
		if err != nil {
			t.Fatalf("keyFn: %v", err)
		}
		if key != "10.1.2.3" {
			t.Errorf("want fallback to RemoteAddr when every XFF hop is trusted, got %q", key)
		}
	})
	t.Run("malformed_xff_hop_falls_back", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "10.1.2.3:12345"
		req.Header.Set("X-Forwarded-For", "not-an-ip")
		key, err := keyFn(req)
		if err != nil {
			t.Fatalf("keyFn: %v", err)
		}
		if key != "10.1.2.3" {
			t.Errorf("want fallback to RemoteAddr on malformed hop, got %q", key)
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
				w.Header().Set("Content-Type", "application/json")
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
			// resp_content_type is the runbooks' fingerprint for telling
			// the HTML error page from the JSON body — it must survive
			// refactors.
			if tc.wantLogs == 1 {
				fields := logs.FilterMessage("request").All()[0].ContextMap()
				if got, ok := fields["resp_content_type"]; !ok || got != "application/json" {
					t.Errorf("resp_content_type = %v (present=%v), want application/json", got, ok)
				}
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

// TestRegisterOAuthRoutes_BrowserFacingWiring pins the wiring itself,
// not just the middleware's behaviour: every handler-level test installs
// BrowserFacing by hand, so all of them stay green if the router stops
// installing it. This asserts the routes as mounted.
//
// Each route gets its OWN stub that names itself in a header before
// deferring to the negotiated 429 sink: one shared stub would stay
// green with two handlers swapped between paths, and the sink is what
// reads which representation a route produces.
func TestRegisterOAuthRoutes_BrowserFacingWiring(t *testing.T) {
	stub := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Handler", name)
			handlers.RateLimitExceeded(w, r)
		}
	}
	r := chi.NewRouter()
	registerOAuthRoutes(r, oauthRoutes{
		Register: stub("register"), Authorize: stub("authorize"), Consent: stub("consent"),
		Callback: stub("callback"), Token: stub("token"),
		RegisterLimit: passthrough, AuthorizeLimit: passthrough, ConsentLimit: passthrough,
		CallbackLimit: passthrough, TokenLimit: passthrough,
	})

	cases := []struct {
		method, path, wantHandler, wantCT string
	}{
		// Browser-terminated: the human reads the response.
		{http.MethodGet, "/authorize", "authorize", "text/html; charset=utf-8"},
		{http.MethodPost, "/consent", "consent", "text/html; charset=utf-8"},
		{http.MethodGet, "/callback", "callback", "text/html; charset=utf-8"},
		// Machine endpoints: RFC 6749 §5.2 / RFC 7591 §3.2.2 require JSON
		// whatever the caller asks for.
		{http.MethodPost, "/register", "register", "application/json"},
		{http.MethodPost, "/token", "token", "application/json"},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
			req.Header.Set("Sec-Fetch-Dest", "document")
			rr := httptest.NewRecorder()

			r.ServeHTTP(rr, req)

			if got := rr.Result().Header.Get("X-Handler"); got != tc.wantHandler {
				t.Errorf("%s %s served by handler %q, want %q", tc.method, tc.path, got, tc.wantHandler)
			}
			if got := rr.Result().Header.Get("Content-Type"); got != tc.wantCT {
				t.Errorf("%s %s: Content-Type = %q, want %q", tc.method, tc.path, got, tc.wantCT)
			}
		})
	}
}

// TestRegisterOAuthRoutes_MarkerOutsideLimiter pins the ordering
// constraint on EVERY browser-facing route: BrowserFacing must wrap the
// limiter, not the reverse. Inverted, the throttle response never sees
// the marker and a throttled human is back to the JSON dead end — with
// every other test still green, since they all install the middleware
// by hand instead of going through the router.
func TestRegisterOAuthRoutes_MarkerOutsideLimiter(t *testing.T) {
	reached := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	cases := []struct {
		name, method, path, wantCT string
		limited                    func(*oauthRoutes, func(http.Handler) http.Handler)
	}{
		{"authorize", http.MethodGet, "/authorize", "text/html; charset=utf-8", func(rt *oauthRoutes, l func(http.Handler) http.Handler) { rt.AuthorizeLimit = l }},
		{"consent", http.MethodPost, "/consent", "text/html; charset=utf-8", func(rt *oauthRoutes, l func(http.Handler) http.Handler) { rt.ConsentLimit = l }},
		{"callback", http.MethodGet, "/callback", "text/html; charset=utf-8", func(rt *oauthRoutes, l func(http.Handler) http.Handler) { rt.CallbackLimit = l }},
		// The two machine endpoints carry different budgets from the
		// browser ones: their binding must be pinned too, or the router
		// can swap limiters (and so budgets) with every test green.
		{"register", http.MethodPost, "/register", "application/json", func(rt *oauthRoutes, l func(http.Handler) http.Handler) { rt.RegisterLimit = l }},
		{"token", http.MethodPost, "/token", "application/json", func(rt *oauthRoutes, l func(http.Handler) http.Handler) { rt.TokenLimit = l }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := oauthRoutes{
				Register: reached, Authorize: reached, Consent: reached, Callback: reached, Token: reached,
				RegisterLimit: passthrough, AuthorizeLimit: passthrough, ConsentLimit: passthrough,
				CallbackLimit: passthrough, TokenLimit: passthrough,
			}
			tc.limited(&rt, rateLimiter(1, time.Minute, "wiring-"+tc.name))
			r := chi.NewRouter()
			registerOAuthRoutes(r, rt)

			send := func() *httptest.ResponseRecorder {
				req := httptest.NewRequest(tc.method, tc.path, nil)
				req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
				req.Header.Set("Sec-Fetch-Dest", "document")
				rr := httptest.NewRecorder()
				r.ServeHTTP(rr, req)
				return rr
			}

			if first := send(); first.Result().StatusCode != http.StatusOK {
				t.Fatalf("first request: want 200, got %d", first.Result().StatusCode)
			}
			throttled := send()
			if throttled.Result().StatusCode != http.StatusTooManyRequests {
				t.Fatalf("second request: want 429, got %d", throttled.Result().StatusCode)
			}
			if got := throttled.Result().Header.Get("Content-Type"); got != tc.wantCT {
				t.Errorf("throttled Content-Type = %q, want %q on %s — wrong limiter binding or BrowserFacing inside the limiter", got, tc.wantCT, tc.path)
			}
		})
	}
}

// A nil limiter would leave the route unthrottled. Wiring must fail
// loudly rather than serve it, and the message must name the route.
func TestRegisterOAuthRoutes_NilLimiterPanics(t *testing.T) {
	stub := http.HandlerFunc(handlers.RateLimitExceeded)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("a nil limiter was accepted — the route would serve unthrottled")
		}
		if msg, _ := r.(string); !strings.Contains(msg, "/callback") {
			t.Errorf("panic %q does not name the offending route", r)
		}
	}()

	registerOAuthRoutes(chi.NewRouter(), oauthRoutes{
		Register: stub, Authorize: stub, Consent: stub, Callback: stub, Token: stub,
		RegisterLimit: passthrough, AuthorizeLimit: passthrough, ConsentLimit: passthrough,
		CallbackLimit: nil, TokenLimit: passthrough,
	})
}

// TestRateLimiter_ThrottleNegotiates pins that a throttled human on a
// browser-facing route gets the error page, not a JSON dead end — the
// 429 is the throttle a user is most likely to meet, and it used to be
// the one response that bypassed content negotiation entirely.
func TestRateLimiter_ThrottleNegotiates(t *testing.T) {
	limited := handlers.BrowserFacing(rateLimiter(1, time.Minute, "negotiate-test")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))

	send := func(accept string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/callback", nil)
		req.Header.Set("Accept", accept)
		// A real top-level navigation: the 429 page arm requires the
		// navigation signal on top of Accept (anti-amplification).
		req.Header.Set("Sec-Fetch-Dest", "document")
		rr := httptest.NewRecorder()
		limited.ServeHTTP(rr, req)
		return rr
	}

	browserAccept := "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	if first := send(browserAccept); first.Code != http.StatusOK {
		t.Fatalf("first request: want 200, got %d", first.Code)
	}

	throttled := send(browserAccept)
	if throttled.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: want 429, got %d", throttled.Code)
	}
	if ct := throttled.Result().Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8 (body: %s)", ct, throttled.Body.String())
	}
	if body := throttled.Body.String(); !strings.Contains(body, "Temporarily unavailable") {
		t.Errorf("throttle page missing its title:\n%s", body)
	}
	if got := throttled.Result().Header.Get("Vary"); got != "Accept, Sec-Fetch-Dest" {
		t.Errorf("Vary = %q, want \"Accept, Sec-Fetch-Dest\"", got)
	}
	// The page tells the user to wait and retry; the response has to
	// say how long, and the value has to be the window rather than a
	// default that happens to be non-empty.
	if got := throttled.Result().Header.Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After = %q, want 60 (the limiter window)", got)
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

// TestRateLimiter_AuthorizeAndConsent_IndependentBuckets pins the
// wiring: /authorize and /consent each get their own httprate bucket
// instance, so a flood that exhausts one path does not poison the
// other. A regression that re-shared the limiter (the earlier shape
// before the dedicated consentLimit) is caught by triggering one
// label's 429 and verifying the other label's counter stays flat.
func TestRateLimiter_AuthorizeAndConsent_IndependentBuckets(t *testing.T) {
	authorizeMW := rateLimiter(2, time.Minute, "authorize")
	consentMW := rateLimiter(2, time.Minute, "consent")

	// Sanity — they must be distinct middleware instances (i.e. the
	// caller in main.go must construct two separate rateLimiter calls,
	// not reuse one).
	authorizeBefore := testutil.ToFloat64(metrics.RateLimited.WithLabelValues("authorize"))
	consentBefore := testutil.ToFloat64(metrics.RateLimited.WithLabelValues("consent"))

	noop := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	authH := authorizeMW(noop)
	consentH := consentMW(noop)

	send := func(h http.Handler) int {
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	// Burn /authorize's bucket: 2 allowed, 3rd should 429.
	send(authH)
	send(authH)
	if got := send(authH); got != http.StatusTooManyRequests {
		t.Fatalf("authorize 3rd request: want 429, got %d", got)
	}

	// /consent's bucket should be untouched: 2 allowed, 3rd 429s on
	// its own counter, NOT on the authorize one.
	send(consentH)
	send(consentH)
	if got := send(consentH); got != http.StatusTooManyRequests {
		t.Fatalf("consent 3rd request: want 429, got %d", got)
	}

	// Each label's counter incremented exactly once (the 3rd
	// request on each path).
	if delta := testutil.ToFloat64(metrics.RateLimited.WithLabelValues("authorize")) - authorizeBefore; delta != 1 {
		t.Errorf("authorize RateLimited delta = %v, want 1", delta)
	}
	if delta := testutil.ToFloat64(metrics.RateLimited.WithLabelValues("consent")) - consentBefore; delta != 1 {
		t.Errorf("consent RateLimited delta = %v, want 1 (regression: /consent likely sharing the /authorize bucket)", delta)
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

// Every http.Server this binary builds must cap MaxHeaderBytes: Go's
// 1 MB default lets a single request drag a megabyte of headers through
// the pre-auth path (the Accept negotiation scan among others), which
// the rate limiter by construction does not cover. Asserted over the
// AST because the servers are built inside main() and are not reachable
// from a test.
func TestServers_CapMaxHeaderBytes(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}

	found := 0
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Server" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "http" {
			return true
		}
		found++
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "MaxHeaderBytes" {
				continue
			}
			// Value, not just presence: the field exists to shrink the
			// pre-auth header budget, so 1<<20 (net/http's own default,
			// the value this test exists to reject) must not pass.
			n, err := strconv.Atoi(types.ExprString(kv.Value))
			if err != nil {
				// Shift expressions do not constant-fold in ExprString.
				var base, shift int
				if _, e := fmt.Sscanf(types.ExprString(kv.Value), "%d << %d", &base, &shift); e != nil {
					t.Errorf("main.go:%d: MaxHeaderBytes value %q is not a plain integer or shift — cannot verify the budget",
						fset.Position(kv.Pos()).Line, types.ExprString(kv.Value))
					return true
				}
				n = base << shift
			}
			if n > 64<<10 {
				t.Errorf("main.go:%d: MaxHeaderBytes = %d, want <= %d — the point of the field is a budget smaller than net/http's 1 MB default",
					fset.Position(kv.Pos()).Line, n, 64<<10)
			}
			return true
		}
		t.Errorf("main.go:%d: http.Server literal does not set MaxHeaderBytes — it inherits net/http's 1 MB default",
			fset.Position(lit.Pos()).Line)
		return true
	})
	if found < 2 {
		t.Fatalf("found %d http.Server literals in main.go, want >=2 (public + metrics) — this test went blind", found)
	}
}

// A wrong method on a browser-facing route must answer through the
// error sink, not chi's default empty-bodied 405: /consent is a URL
// users bookmark, and a blank page is exactly what this feature exists
// to remove.
func TestRegisterOAuthRoutes_MethodNotAllowedNegotiates(t *testing.T) {
	r := routerWith405(t)

	// GET /consent — the bookmark case. POST-only route, so 405.
	// Sec-Fetch-Dest marks it a real top-level navigation, which the
	// unbounded 405 path requires before it will ship the page.
	req := httptest.NewRequest(http.MethodGet, "/consent", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	req.Header.Set("Sec-Fetch-Dest", "document")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Result().StatusCode)
	}
	if ct := rr.Result().Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want the negotiated page", ct)
	}
	if body := rr.Body.String(); !strings.Contains(body, "method_not_allowed") {
		t.Errorf("405 page carries no support code:\n%s", body)
	}

	// A machine caller on the same wrong method stays on JSON.
	jsonReq := httptest.NewRequest(http.MethodGet, "/consent", nil)
	jsonRR := httptest.NewRecorder()
	r.ServeHTTP(jsonRR, jsonReq)
	if ct := jsonRR.Result().Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("machine caller Content-Type = %q, want application/json", ct)
	}
}

// routerWith405 builds the production route shape plus the 405
// responder, which main installs only once every route is registered.
func routerWith405(t *testing.T) chi.Router {
	t.Helper()
	stub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r := chi.NewRouter()
	r.Get("/healthz", stub)
	// Production route shapes the OAuth five do not cover, and which
	// allowedMethods has a branch for each of: a multi-method route
	// (sorting + ", " joining), an all-methods Handle route (chi's "*"
	// pseudo-method), and a wildcard pattern (skipped entirely).
	r.Get("/multi", stub)
	r.Put("/multi", stub)
	r.Post("/multi", stub)
	r.Handle("/mcp", stub)
	r.Handle("/mcp/*", stub)
	registerOAuthRoutes(r, oauthRoutes{
		Register: stub, Authorize: stub, Consent: stub, Callback: stub, Token: stub,
		RegisterLimit: passthrough, AuthorizeLimit: passthrough, ConsentLimit: passthrough,
		CallbackLimit: passthrough, TokenLimit: passthrough,
	})
	installMethodNotAllowed(r)
	installNotFound(r)
	return r
}

// The 405 responder is router-wide, so its negotiation has to be scoped
// per path or it re-opens on /token and /register the HTML arm the
// BrowserFacing marker exists to keep shut (RFC 6749 §5.2, RFC 7591
// §3.2.2). Every non-browser-facing route on the router is checked, not
// just the OAuth ones — the handler answers for all of them.
func TestMethodNotAllowed_NegotiatesOnlyOnBrowserRoutes(t *testing.T) {
	r := routerWith405(t)
	for _, tc := range []struct {
		method, path, wantCT string
	}{
		{http.MethodPost, "/authorize", "text/html; charset=utf-8"},
		{http.MethodGet, "/consent", "text/html; charset=utf-8"},
		{http.MethodPost, "/callback", "text/html; charset=utf-8"},
		{http.MethodGet, "/token", "application/json"},
		{http.MethodGet, "/register", "application/json"},
		{http.MethodPost, "/healthz", "application/json"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
		req.Header.Set("Sec-Fetch-Dest", "document")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Result().StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: status = %d, want 405", tc.method, tc.path, rr.Result().StatusCode)
			continue
		}
		if ct := rr.Result().Header.Get("Content-Type"); ct != tc.wantCT {
			t.Errorf("%s %s: Content-Type = %q, want %q", tc.method, tc.path, ct, tc.wantCT)
		}
	}
}

// RFC 9110 §15.5.6 makes Allow a MUST on 405. chi's default responder
// sets it; a replacement that forgets to drops a mandatory header on
// every route at once.
func TestMethodNotAllowed_SetsAllow(t *testing.T) {
	r := routerWith405(t)
	for _, tc := range []struct{ method, path, want string }{
		{http.MethodGet, "/consent", "POST"},
		{http.MethodPost, "/callback", "GET"},
		{http.MethodGet, "/token", "POST"},
		{http.MethodPost, "/healthz", "GET"},
		// Multi-method: pins both the sort (map iteration is random, so
		// an unsorted Allow differs across restarts) and the ", " join.
		{http.MethodDelete, "/multi", "GET, POST, PUT"},
	} {
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
		if got := rr.Result().Header.Get("Allow"); got != tc.want {
			t.Errorf("%s %s: Allow = %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

// The proxy-rendered pages allow their inline <style> by sha256 hash,
// never by 'unsafe-inline' (handlers/pages.go). Two documents kept
// describing the pre-hash policy long after the code changed, so the
// class of defect — prose asserting a CSP directive the code does not
// emit — gets a guard instead of a promise to remember. Matches the
// directive form only: naming 'unsafe-inline' to say it is NOT used is
// exactly what several of these documents legitimately do.
func TestDocs_DoNotClaimUnsafeInlineStyles(t *testing.T) {
	// Regexp, not a fixed substring: a real CSP names a source before
	// the keyword (`style-src 'self' 'unsafe-inline'`), and the fixed
	// form saw none of those.
	banned := regexp.MustCompile(`style-src[^;\n]*'unsafe-inline'`)
	negated := regexp.MustCompile(`(?i)\b(not|never|rather than|instead of|no longer|without|must NOT)\b`)
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	scanned := 0
	seen := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		// .go too: the claim also rots in code comments, and one did —
		// handlers/consent.go described the pre-hash policy for a whole
		// review round with this guard green.
		switch filepath.Ext(path) {
		case ".md", ".go":
		default:
			return nil
		}
		// This file states the pattern in order to search for it.
		if strings.HasSuffix(path, "main_test.go") {
			return nil
		}
		scanned++
		if rel, e := filepath.Rel(root, path); e == nil {
			seen[rel] = true
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Whitespace-normalised over a two-line window: every doc here
		// is hard-wrapped at ~70 columns and the claim is 24 chars, so
		// a reflow splitting it across lines is the likely shape, not a
		// contrived one.
		inFence, fenceLine := false, 0
		lines := strings.Split(string(body), "\n")
		joined := func(i int) string {
			if i+1 < len(lines) {
				return strings.Join(strings.Fields(lines[i]+" "+lines[i+1]), " ")
			}
			return strings.Join(strings.Fields(lines[i]), " ")
		}
		for i, line := range lines {
			// Fenced blocks quote code, including code as it stood at
			// the time of a dated incident note — that is a record, not
			// a claim about today. Prose is the claim.
			if strings.HasPrefix(strings.TrimSpace(line), "```") {
				inFence = !inFence
				fenceLine = i + 1
				continue
			}
			// A negated mention is the correct thing to write — every
			// doc here explains what the CSP uses *instead of*
			// 'unsafe-inline'. Only an assertion that it IS used is a
			// defect.
			text := joined(i)
			if !inFence && banned.MatchString(text) && !negated.MatchString(text) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s:%d claims style-src 'unsafe-inline', but every proxy-rendered page allows its style by sha256 hash:\n\t%s",
					rel, i+1, strings.TrimSpace(joined(i)))
			}
		}
		// An unbalanced fence would latch inFence true to EOF and blind
		// the rest of the file — itself a doc defect, so fail on it.
		if inFence {
			rel, _ := filepath.Rel(root, path)
			t.Errorf("%s:%d opens a code fence that is never closed — everything after it escapes this guard", rel, fenceLine)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// A walk that reaches nothing must fail loudly rather than pass.
	// A count alone does not prove the files that make CSP claims were
	// among those scanned; name them.
	for _, must := range []string{"README.md", "specs.md", "docs/threat-model.md", "manifests/overlays/production/README.md", "handlers/pages.go"} {
		if !seen[must] {
			t.Errorf("%s was never scanned — the walk missed a file that makes CSP claims", must)
		}
	}
	if scanned < 30 {
		t.Fatalf("scanned only %d files, want >=30 — the walk went blind", scanned)
	}
}

// browserFacingPaths and the BrowserFacing wiring in
// registerOAuthRoutes are two statements of the same fact, and the 405
// responder trusts the list. Derive the marked set from the live router
// rather than restating it: markedness is observed through
// RateLimitExceeded, whose arm choice IS the marker the responder
// reads, so a route marked on the handler and missing from the list
// fails here instead of silently answering JSON on its 405.
func TestBrowserFacingPaths_MatchesTheWiring(t *testing.T) {
	stub := http.HandlerFunc(handlers.RateLimitExceeded)
	r := chi.NewRouter()
	registerOAuthRoutes(r, oauthRoutes{
		Register: stub, Authorize: stub, Consent: stub, Callback: stub, Token: stub,
		RegisterLimit: passthrough, AuthorizeLimit: passthrough, ConsentLimit: passthrough,
		CallbackLimit: passthrough, TokenLimit: passthrough,
	})

	var marked []string
	probed := 0
	for _, route := range r.Routes() {
		for method := range route.Handlers {
			if method == "*" {
				continue
			}
			req := httptest.NewRequest(method, route.Pattern, nil)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("Sec-Fetch-Dest", "document")
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			probed++
			if strings.HasPrefix(rr.Result().Header.Get("Content-Type"), "text/html") {
				marked = append(marked, route.Pattern)
			}
		}
	}
	if probed < 5 {
		t.Fatalf("probed only %d routes, want >=5 — the walk went blind", probed)
	}

	want := slices.Clone(browserFacingPaths)
	slices.Sort(want)
	slices.Sort(marked)
	if !slices.Equal(marked, want) {
		t.Errorf("routes wired with BrowserFacing = %v, browserFacingPaths = %v — installMethodNotAllowed reads the list, so the two must agree", marked, want)
	}
}

// The Allow table is built on the first 405, not at wiring time, so a
// route registered after installMethodNotAllowed still gets its header.
// Without this the eager form is indistinguishable: every other harness
// registers all its routes first, which is exactly the ordering the
// lazy build exists to survive.
func TestMethodNotAllowed_AllowSurvivesLateRouteRegistration(t *testing.T) {
	stub := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r := chi.NewRouter()
	installMethodNotAllowed(r) // deliberately BEFORE the route
	r.Post("/late", stub)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/late", nil))
	if rr.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Result().StatusCode)
	}
	if got := rr.Result().Header.Get("Allow"); got != "POST" {
		t.Errorf("Allow = %q, want POST — the table was snapshotted before the route existed", got)
	}
}

// The PROD_MODE rejected-flag list is restated in four documents, and
// this diff's own edits to three of them left OIDC_ALLOW_INSECURE_HTTP
// out of all three. Derive the flag set from config.go's violations
// block rather than restating it a fifth time here, and require every
// enumeration to name every flag.
func TestDocs_ProdModeEnumerationsAreComplete(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(root, "config", "config.go"))
	if err != nil {
		t.Fatalf("read config.go: %v", err)
	}
	// The env var named in each violation message.
	flagRE := regexp.MustCompile(`violations = append\(violations, "([A-Z_]+)`)
	flags := map[string]bool{}
	for _, m := range flagRE.FindAllStringSubmatch(string(src), -1) {
		flags[m[1]] = true
	}
	if len(flags) < 6 {
		t.Fatalf("found %d PROD_MODE violation flags in config.go (%v), want >=6 — the extraction went blind", len(flags), flags)
	}

	// Per ENUMERATION, not per file: specs.md carries two, and a
	// whole-file check passes as long as a flag survives in either one.
	// Each enumeration is the window around a "PKCE_REQUIRED=false"
	// mention, whitespace-normalised because several are hard-wrapped.
	files := []string{
		"docs/configuration.md",
		"specs.md",
		"docs/conformance.md",
		"manifests/k8s/configmap.yaml",
	}
	const window = 700
	checked := 0
	for _, rel := range files {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := strings.Join(strings.Fields(string(body)), " ")
		anchor := "PKCE_REQUIRED=false"
		for at := 0; ; {
			i := strings.Index(text[at:], anchor)
			if i < 0 {
				break
			}
			i += at
			lo := max(i-window/3, 0)
			hi := min(i+window, len(text))
			enum := text[lo:hi]
			checked++
			for flag := range flags {
				if !strings.Contains(enum, flag) {
					t.Errorf("%s: the PROD_MODE enumeration at offset %d omits %s, which config.go rejects\n\t%s",
						rel, i, flag, enum)
				}
			}
			at = i + len(anchor)
		}
	}
	if checked < 5 {
		t.Fatalf("checked %d PROD_MODE enumerations, want >=5 — the guard went blind", checked)
	}
}

// Every wire error_code must have a row in the specs.md table: that
// table is what an operator reads when a user quotes a code, and a code
// absent from it is a support dead end. Table ROWS specifically — a
// mention in surrounding prose is not a definition, and checking for
// the string anywhere in the file is how `not_found` shipped
// undocumented while a looser check stayed green.
func TestDocs_EveryErrorCodeHasASpecsTableRow(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(root, "handlers", "helpers.go"))
	if err != nil {
		t.Fatalf("read helpers.go: %v", err)
	}
	constRE := regexp.MustCompile(`(?m)^\tcode[A-Za-z]+\s+=\s+"([a-z_0-9]+)"`)
	var codes []string
	for _, m := range constRE.FindAllStringSubmatch(string(src), -1) {
		codes = append(codes, m[1])
	}
	if len(codes) < 40 {
		t.Fatalf("extracted %d error_code constants, want >=40 — the walk went blind", len(codes))
	}

	spec, err := os.ReadFile(filepath.Join(root, "specs.md"))
	if err != nil {
		t.Fatalf("read specs.md: %v", err)
	}
	// A row defines a code at the start of a table cell; several rows
	// define more than one, separated by " / ".
	documented := map[string]bool{}
	rowRE := regexp.MustCompile("(?m)^\\| ((?:`[a-z_0-9]+`(?: / )?)+) \\|")
	cellRE := regexp.MustCompile("`([a-z_0-9]+)`")
	for _, row := range rowRE.FindAllStringSubmatch(string(spec), -1) {
		for _, c := range cellRE.FindAllStringSubmatch(row[1], -1) {
			documented[c[1]] = true
		}
	}
	if len(documented) < 30 {
		t.Fatalf("found %d documented codes in the specs.md table, want >=30 — the row parser went blind", len(documented))
	}
	for _, code := range codes {
		if !documented[code] {
			t.Errorf("error_code %q has no row in the specs.md error-code table — a user quoting it has nothing to look up", code)
		}
	}
}

// The 404 responder splits on the same list as the 405: a mistyped or
// trailing-slash bookmark on a browser route renders, every other
// unrouted path keeps the discovery-shaped machine body. Both arms
// asserted — a fix that routed everything through the page would turn
// every stray probe into a 1.3 kB render.
func TestInstallNotFound_SplitsBrowserAndMachinePaths(t *testing.T) {
	r := chi.NewRouter()
	r.Get("/healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	installNotFound(r)

	cases := []struct {
		name, path string
		nav        bool
		wantCT     string
	}{
		{"browser_route_trailing_slash", "/authorize/", true, "text/html; charset=utf-8"},
		{"browser_route_exact_unrouted", "/consent", true, "text/html; charset=utf-8"},
		{"browser_route_without_navigation", "/authorize/", false, "application/json"},
		{"unrelated_path_stays_machine", "/nope", true, "application/json"},
		{"discovery_probe_stays_machine", "/.well-known/oauth-x", true, "application/json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Accept", "text/html")
			if tc.nav {
				req.Header.Set("Sec-Fetch-Dest", "document")
			}
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if rr.Result().StatusCode != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rr.Result().StatusCode)
			}
			if ct := rr.Result().Header.Get("Content-Type"); ct != tc.wantCT {
				t.Errorf("Content-Type = %q, want %q", ct, tc.wantCT)
			}
			// Whichever arm answered, it must never be chi's bare
			// text/plain body — that is the defect this closed.
			if strings.Contains(rr.Body.String(), "404 page not found") {
				t.Errorf("chi's default body leaked through:\n%s", rr.Body.String())
			}
		})
	}
}

// A metric nobody documented is a metric nobody alerts on. Names are
// extracted from the declarations, so a new counter must be written up
// before it can ship. docs/configuration.md is the canonical
// observability reference (specs.md points operators at it), so that is
// the file required to name every series.
func TestDocs_EveryMetricIsDocumented(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(root, "metrics", "metrics.go"))
	if err != nil {
		t.Fatalf("read metrics.go: %v", err)
	}
	nameRE := regexp.MustCompile(`Name:\s+"(mcp_auth_[a-z_]+)"`)
	var names []string
	for _, m := range nameRE.FindAllStringSubmatch(string(src), -1) {
		names = append(names, m[1])
	}
	if len(names) < 10 {
		t.Fatalf("extracted %d metric names, want >=10 — the walk went blind", len(names))
	}
	docs, err := os.ReadFile(filepath.Join(root, "docs", "configuration.md"))
	if err != nil {
		t.Fatalf("read configuration.md: %v", err)
	}
	for _, name := range names {
		if !strings.Contains(string(docs), name) {
			t.Errorf("metric %s is declared but never named in docs/configuration.md — nothing tells an operator it exists", name)
		}
	}
}

// An environment variable nobody documented is a variable nobody can
// use. Names are extracted from the os.Getenv call sites, so a new knob
// must be written up before it can ship — the third guard of this shape
// (metrics, error codes, now env vars), because that is the class that
// keeps slipping through.
func TestDocs_EveryEnvVarIsDocumented(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(root, "config", "config.go"))
	if err != nil {
		t.Fatalf("read config.go: %v", err)
	}
	// Screaming-snake only: os.Getenv is also used for lowercase probes
	// (HOME, PATH) that are not this proxy's configuration surface.
	envRE := regexp.MustCompile(`os\.Getenv\("([A-Z][A-Z0-9_]{2,})"\)`)
	seen := map[string]bool{}
	var names []string
	for _, m := range envRE.FindAllStringSubmatch(string(src), -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			names = append(names, m[1])
		}
	}
	if len(names) < 20 {
		t.Fatalf("extracted %d env vars from config.go, want >=20 — the walk went blind", len(names))
	}

	docs, err := os.ReadFile(filepath.Join(root, "docs", "configuration.md"))
	if err != nil {
		t.Fatalf("read configuration.md: %v", err)
	}
	// A table row defines it; a passing mention in prose does not.
	rows := regexp.MustCompile("(?m)^\\| `([A-Z][A-Z0-9_]+)`").FindAllStringSubmatch(string(docs), -1)
	documented := map[string]bool{}
	for _, r := range rows {
		documented[r[1]] = true
	}
	if len(documented) < 20 {
		t.Fatalf("found %d env-var rows in docs/configuration.md, want >=20 — the row parser went blind", len(documented))
	}
	for _, name := range names {
		if !documented[name] {
			t.Errorf("%s is read by config.go but has no row in docs/configuration.md — an operator has no way to learn it exists", name)
		}
	}
}
