package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
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
