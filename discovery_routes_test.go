package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestRegisterDiscoveryRoutes locks in the intended status for every
// well-known probe path. The whole point of the discovery carve-outs
// is to prevent the /mcp/* auth-gated catch-all from swallowing these
// probes into 401 — so the test also wires a fake 401 catch-all to
// prove the carve-outs win the chi routing trie.
func TestRegisterDiscoveryRoutes(t *testing.T) {
	baseURL := "https://proxy.example.test"

	r := chi.NewRouter()
	registerDiscoveryRoutes(r, baseURL, "/mcp", "")
	// Simulate the production auth-gated catch-all. If any discovery
	// path falls through to this, the assertion on the status will
	// flag it (it writes 401 instead of the expected value).
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			})
		})
		r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// auth middleware short-circuits before this is reached
		}))
	})

	cases := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"prm_root", http.MethodGet, "/.well-known/oauth-protected-resource", http.StatusOK},
		{"prm_mcp", http.MethodGet, "/.well-known/oauth-protected-resource/mcp", http.StatusOK},
		{"as_root", http.MethodGet, "/.well-known/oauth-authorization-server", http.StatusOK},
		{"as_mcp_compat", http.MethodGet, "/.well-known/oauth-authorization-server/mcp", http.StatusOK},
		{"openid_root_404", http.MethodGet, "/.well-known/openid-configuration", http.StatusNotFound},
		{"openid_mcp_404", http.MethodGet, "/.well-known/openid-configuration/mcp", http.StatusNotFound},
		{"mcp_wellknown_as_404", http.MethodGet, "/mcp/.well-known/oauth-authorization-server", http.StatusNotFound},
		{"mcp_wellknown_openid_404", http.MethodGet, "/mcp/.well-known/openid-configuration", http.StatusNotFound},
		// HEAD and POST on the 404 carve-outs must also return 404, not
		// fall through to the auth-gated catch-all (M1 regression guard).
		{"openid_head_404", http.MethodHead, "/.well-known/openid-configuration", http.StatusNotFound},
		{"mcp_wellknown_head_404", http.MethodHead, "/mcp/.well-known/foo", http.StatusNotFound},
		{"mcp_wellknown_post_404", http.MethodPost, "/mcp/.well-known/bar", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("%s %s: want %d, got %d (body=%q)",
					tc.method, tc.path, tc.want, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestRegisterDiscoveryRoutes_CustomMount exercises the full
// parameterization for a non-default mount (e.g. /api/v1/mcp): the
// per-resource PRM variant, the AS-meta compat variant, the openid
// 404 variant, and the <mount>/.well-known/* under-resource carve-out
// must all track the mount verbatim. The default "/mcp" paths must
// NOT be served (they'd confuse clients about the canonical resource).
func TestRegisterDiscoveryRoutes_CustomMount(t *testing.T) {
	baseURL := "https://proxy.example.test"
	mount := "/api/v1/mcp"
	r := chi.NewRouter()
	registerDiscoveryRoutes(r, baseURL, mount, "")
	r.Group(func(r chi.Router) {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			})
		})
		r.Handle("/*", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	})

	cases := []struct {
		name string
		path string
		want int
	}{
		{"prm_custom", "/.well-known/oauth-protected-resource/api/v1/mcp", http.StatusOK},
		{"as_custom", "/.well-known/oauth-authorization-server/api/v1/mcp", http.StatusOK},
		{"openid_custom_404", "/.well-known/openid-configuration/api/v1/mcp", http.StatusNotFound},
		{"under_mount_wellknown_404", "/api/v1/mcp/.well-known/oauth-authorization-server", http.StatusNotFound},
		// Default /mcp paths must NOT be served for a non-default
		// mount — they fall through to the simulated auth catch-all.
		{"prm_default_not_served", "/.well-known/oauth-protected-resource/mcp", http.StatusUnauthorized},
		{"under_default_not_served", "/mcp/.well-known/oauth-authorization-server", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("%s: want %d, got %d (body=%q)", tc.path, tc.want, rr.Code, rr.Body.String())
			}
		})
	}

	// PRM "resource" field for the custom mount must be baseURL+mount.
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource"+mount, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	var meta map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&meta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if want := baseURL + mount; meta["resource"] != want {
		t.Errorf("resource: want %q, got %v", want, meta["resource"])
	}
}

// TestWellKnownNotFound_JSONShape verifies the JSON-envelope 404 body
// so clients that only parse JSON errors do not trip on a text/plain
// "404 page not found" from net/http's default (M2).
func TestWellKnownNotFound_JSONShape(t *testing.T) {
	r := chi.NewRouter()
	registerDiscoveryRoutes(r, "https://proxy.example.test", "/mcp", "")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status: want 404, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}
	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "not_found" {
		t.Errorf("error field: want \"not_found\", got %v", body["error"])
	}
}

// TestRegisterDiscoveryRoutes_ResourceFields verifies the two PRM
// variants advertise distinct "resource" fields (root "/"-suffixed vs
// /mcp-scoped). Catches regressions where both routes accidentally
// point at the same handler.
func TestRegisterDiscoveryRoutes_ResourceFields(t *testing.T) {
	baseURL := "https://proxy.example.test"
	r := chi.NewRouter()
	registerDiscoveryRoutes(r, baseURL, "/mcp", "")

	cases := []struct {
		path         string
		wantResource string
	}{
		{"/.well-known/oauth-protected-resource", baseURL + "/"},
		{"/.well-known/oauth-protected-resource/mcp", baseURL + "/mcp"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status: want 200, got %d", rr.Code)
			}
			var meta map[string]any
			if err := json.NewDecoder(rr.Body).Decode(&meta); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if meta["resource"] != tc.wantResource {
				t.Errorf("resource: want %q, got %v", tc.wantResource, meta["resource"])
			}
		})
	}
}
