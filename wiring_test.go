package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"

	"github.com/babs/mcp-auth-proxy/config"
	"github.com/babs/mcp-auth-proxy/replay"
	"github.com/babs/mcp-auth-proxy/token"
)

// TestForwardingWiring pins what main builds for UPSTREAM_FORWARD_IDP_TOKEN
// and the sign-in policy. Every field here fails open when dropped: no
// group re-check on refresh, no IdP throttle, no extra scope, tokens
// that cannot be opened, or an upstream reached without a credential.
func TestForwardingWiring(t *testing.T) {
	cfg := &config.Config{
		OIDCClientID:            "proxy",
		OIDCClientSecret:        "secret",
		ProxyBaseURL:            "https://proxy.example.com",
		UpstreamMCPMountPath:    "/mcp",
		GroupsClaim:             "groups",
		AllowedGroups:           []string{"staff"},
		RefreshRaceGrace:        2 * time.Second,
		OIDCExtraScopes:         []string{"api://upstream/access"},
		UpstreamForwardIdPToken: true,
	}
	tm, err := token.NewManager([]byte("wiring-test-secret-that-is-at-least-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}

	oauth2Cfg := newOAuth2Config(cfg, oauth2.Endpoint{TokenURL: "https://idp.example.com/token"})
	if want := []string{"openid", "email", "profile", "api://upstream/access"}; !slices.Equal(oauth2Cfg.Scopes, want) {
		t.Errorf("IdP scopes = %v, want %v", oauth2Cfg.Scopes, want)
	}
	if oauth2Cfg.ClientID != "proxy" || oauth2Cfg.ClientSecret != "secret" || oauth2Cfg.RedirectURL != "https://proxy.example.com/callback" {
		t.Errorf("oauth2 config = %q %q %q", oauth2Cfg.ClientID, oauth2Cfg.ClientSecret, oauth2Cfg.RedirectURL)
	}
	if pc := newProxyConfig(cfg); !pc.ForwardIdPToken || pc.UpstreamAuthorization != "" {
		t.Errorf("proxy config = %+v", pc)
	}

	big := strings.Repeat("a", 20<<10) // over the 16 KB default cap
	if tm.FitsOpenCap(big, token.PurposeAccess) {
		t.Fatal("default cap already admits 20 KB; the probe proves nothing")
	}
	refresher := enableForwarding(cfg, tm, oauth2Cfg)
	if refresher == nil {
		t.Fatal("enableForwarding returned no refresher with the mode on")
	}
	for _, purpose := range []string{token.PurposeCode, token.PurposeAccess, token.PurposeRefresh} {
		if !tm.FitsOpenCap(big, purpose) {
			t.Errorf("open() cap not raised for %q", purpose)
		}
	}

	limiter := rate.NewLimiter(1, 1)
	store := replay.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })
	verified := false
	verify := func(context.Context, string) (*oidc.IDToken, error) { verified = true; return nil, nil }

	tc := newTokenConfig(cfg, refresher, limiter, verify)
	if _, _ = tc.VerifyIDToken(t.Context(), ""); !verified {
		t.Error("token config does not carry the verifier it was given")
	}
	if !tc.ForwardIdPToken || tc.IdPRefresher != refresher || tc.IdPExchangeLimiter != limiter ||
		tc.GroupsClaim != "groups" || !slices.Equal(tc.AllowedGroups, cfg.AllowedGroups) || tc.RefreshRaceGrace != cfg.RefreshRaceGrace {
		t.Errorf("token config = %+v", tc)
	}
	cc := newCallbackConfig(cfg, store, limiter)
	if !cc.ForwardIdPToken || cc.IdPExchangeLimiter != limiter || cc.ReplayStore != replay.Store(store) ||
		cc.GroupsClaim != "groups" || !slices.Equal(cc.AllowedGroups, cfg.AllowedGroups) {
		t.Errorf("callback config = %+v", cc)
	}

	// The middleware must refuse a token that carries no IdP token.
	plain, _, err := tm.Issue(cfg.ProxyBaseURL, "sub", "u@example.com", "cid", nil, time.Hour, cfg.ProxyBaseURL+cfg.UpstreamMCPMountPath)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	rr := httptest.NewRecorder()
	reached := false
	newAuthMiddleware(cfg, tm, zap.NewNop()).Validate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(rr, req)
	if reached || rr.Code != http.StatusUnauthorized {
		t.Errorf("token without an IdP token: status %d, reached upstream = %v; want 401, false", rr.Code, reached)
	}

	// REVOKE_BEFORE reaches the middleware: a token issued before it is refused.
	revoked := *cfg
	revoked.UpstreamForwardIdPToken = false
	revoked.RevokeBefore = time.Now().Add(time.Hour)
	for cutoff, wantReached := range map[*config.Config]bool{&revoked: false, {ProxyBaseURL: cfg.ProxyBaseURL, UpstreamMCPMountPath: "/mcp"}: true} {
		reached = false
		newAuthMiddleware(cutoff, tm, zap.NewNop()).Validate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).ServeHTTP(httptest.NewRecorder(), req)
		if reached != wantReached {
			t.Errorf("RevokeBefore=%v: reached upstream = %v, want %v", cutoff.RevokeBefore, reached, wantReached)
		}
	}
	static := newProxyConfig(&config.Config{UpstreamAuthorization: "Bearer static"})
	if static.ForwardIdPToken || static.UpstreamAuthorization != "Bearer static" {
		t.Errorf("proxy config (static header) = %+v", static)
	}

	off := *cfg
	off.UpstreamForwardIdPToken = false
	offTM, _ := token.NewManager([]byte("wiring-test-secret-that-is-at-least-32-bytes"))
	if enableForwarding(&off, offTM, oauth2Cfg) != nil || offTM.FitsOpenCap(big, token.PurposeAccess) {
		t.Error("mode off still built a refresher or raised the cap")
	}
}

// Forwarding never runs without a replay store: without REDIS_URL it
// gets the in-memory one, and says it is single-instance. Default mode
// without REDIS_URL stays stateless, and REDIS_URL always means Redis.
func TestNewReplayStore(t *testing.T) {
	t.Run("forwarding_without_redis", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		store, err := newReplayStore(&config.Config{UpstreamForwardIdPToken: true}, zap.New(core))
		if err != nil || store == nil {
			t.Fatalf("store = %v, err = %v; want the in-memory store", store, err)
		}
		t.Cleanup(func() { _ = store.Close() })
		warn := logs.FilterMessage("replay_store_in_memory").FilterLevelExact(zap.WarnLevel)
		if warn.Len() != 1 || !strings.Contains(warn.All()[0].ContextMap()["hint"].(string), "single instance") {
			t.Errorf("want one replay_store_in_memory warning saying single instance, got %v", logs.All())
		}
		// It really is single-use.
		if err := store.ClaimOnce(t.Context(), "k", time.Minute); err != nil {
			t.Fatal(err)
		}
		if err := store.ClaimOnce(t.Context(), "k", time.Minute); err == nil {
			t.Error("second claim of the same key succeeded")
		}
	})
	t.Run("default_mode_stays_stateless", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		store, err := newReplayStore(&config.Config{}, zap.New(core))
		if err != nil || store != nil {
			t.Fatalf("store = %v, err = %v; want none", store, err)
		}
		if logs.FilterMessage("replay_store_disabled").Len() != 1 || logs.FilterMessage("replay_store_in_memory").Len() != 0 {
			t.Errorf("logs = %v", logs.All())
		}
	})
	t.Run("redis_url_means_redis", func(t *testing.T) {
		// Nothing listens there: an error proves the Redis branch was
		// taken instead of quietly falling back to memory.
		store, err := newReplayStore(&config.Config{UpstreamForwardIdPToken: true, RedisURL: "redis://127.0.0.1:1/0"}, zap.NewNop())
		if err == nil || store != nil {
			t.Fatalf("store = %v, err = %v; want a Redis connection error and no store", store, err)
		}
	})
}
