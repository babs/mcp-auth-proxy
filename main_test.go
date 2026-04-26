package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
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
			h := zapMiddleware(zap.New(core), tc.re)(next)
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
