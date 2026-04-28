package config

import (
	"strings"
	"testing"
	"time"
)

// setAllRequired sets every mandatory env var to a valid value.
// REDIS_URL is set too so the default PROD_MODE=true posture does
// not reject these test loads on the "no replay store" check.
func setAllRequired(t *testing.T) {
	t.Helper()
	t.Setenv("OIDC_ISSUER_URL", "https://issuer.example.com")
	t.Setenv("OIDC_CLIENT_ID", "client-id")
	t.Setenv("OIDC_CLIENT_SECRET", "client-secret")
	t.Setenv("PROXY_BASE_URL", "https://proxy.example.com")
	t.Setenv("UPSTREAM_MCP_URL", "http://localhost:3000/mcp")
	// 32 bytes, hex-encoded -> 16 distinct ASCII chars; clears the
	// PROD_MODE entropy gate (>=16 distinct bytes).
	t.Setenv("TOKEN_SIGNING_SECRET", "0123456789abcdef0123456789abcdef")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
}

func TestLoad_AllVarsSet(t *testing.T) {
	setAllRequired(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.OIDCIssuerURL != "https://issuer.example.com" {
		t.Errorf("OIDCIssuerURL = %q, want %q", cfg.OIDCIssuerURL, "https://issuer.example.com")
	}
	if cfg.OIDCClientID != "client-id" {
		t.Errorf("OIDCClientID = %q, want %q", cfg.OIDCClientID, "client-id")
	}
	if cfg.OIDCClientSecret != "client-secret" {
		t.Errorf("OIDCClientSecret = %q, want %q", cfg.OIDCClientSecret, "client-secret")
	}
	if cfg.ProxyBaseURL != "https://proxy.example.com" {
		t.Errorf("ProxyBaseURL = %q, want %q", cfg.ProxyBaseURL, "https://proxy.example.com")
	}
	if cfg.UpstreamMCPURL != "http://localhost:3000/mcp" {
		t.Errorf("UpstreamMCPURL = %q, want %q", cfg.UpstreamMCPURL, "http://localhost:3000/mcp")
	}
	if string(cfg.TokenSigningSecret) != "0123456789abcdef0123456789abcdef" {
		t.Errorf("TokenSigningSecret = %q, want fixture value", cfg.TokenSigningSecret)
	}
}

func TestLoad_MissingVars(t *testing.T) {
	required := []string{
		"OIDC_ISSUER_URL",
		"OIDC_CLIENT_ID",
		"OIDC_CLIENT_SECRET",
		"PROXY_BASE_URL",
		"UPSTREAM_MCP_URL",
		"TOKEN_SIGNING_SECRET",
	}

	for _, skip := range required {
		t.Run(skip, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv(skip, "") // clear the one we want missing

			_, err := Load()
			if err == nil {
				t.Fatalf("expected error when %s is missing, got nil", skip)
			}
			if !strings.Contains(err.Error(), skip) {
				t.Errorf("error %q should mention %q", err, skip)
			}
		})
	}
}

func TestLoad_ShortSecret(t *testing.T) {
	setAllRequired(t)
	t.Setenv("TOKEN_SIGNING_SECRET", "short-10ch")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for short secret, got nil")
	}
	if !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Errorf("error %q should mention 'at least 32 bytes'", err)
	}
}

func TestLoad_Defaults(t *testing.T) {
	setAllRequired(t)
	t.Setenv("LISTEN_ADDR", "")
	t.Setenv("METRICS_ADDR", "")
	t.Setenv("LOG_LEVEL", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":8080")
	}
	if cfg.MetricsAddr != "127.0.0.1:9090" {
		t.Errorf("MetricsAddr = %q, want %q", cfg.MetricsAddr, "127.0.0.1:9090")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
}

func TestLoad_TrailingSlashTrimmed(t *testing.T) {
	setAllRequired(t)
	t.Setenv("OIDC_ISSUER_URL", "https://issuer.example.com/")
	t.Setenv("PROXY_BASE_URL", "https://proxy.example.com/")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.OIDCIssuerURL != "https://issuer.example.com" {
		t.Errorf("OIDCIssuerURL = %q, want trailing slash trimmed", cfg.OIDCIssuerURL)
	}
	if cfg.ProxyBaseURL != "https://proxy.example.com" {
		t.Errorf("ProxyBaseURL = %q, want trailing slash trimmed", cfg.ProxyBaseURL)
	}
}

func TestEnvOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		envVal   string
		wantAddr string
	}{
		{name: "uses_default_when_unset", envVal: "", wantAddr: ":8080"},
		{name: "uses_env_when_set", envVal: ":9999", wantAddr: ":9999"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("LISTEN_ADDR", tc.envVal)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.ListenAddr != tc.wantAddr {
				t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, tc.wantAddr)
			}
		})
	}
}

func TestLoad_GroupsClaim_Default(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.GroupsClaim != "groups" {
		t.Errorf("GroupsClaim = %q, want %q", cfg.GroupsClaim, "groups")
	}
}

func TestLoad_GroupsClaim_Custom(t *testing.T) {
	setAllRequired(t)
	t.Setenv("GROUPS_CLAIM", "roles")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.GroupsClaim != "roles" {
		t.Errorf("GroupsClaim = %q, want %q", cfg.GroupsClaim, "roles")
	}
}

func TestLoad_AllowedGroups(t *testing.T) {
	setAllRequired(t)
	t.Setenv("ALLOWED_GROUPS", " admin , editors , ")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.AllowedGroups) != 2 || cfg.AllowedGroups[0] != "admin" || cfg.AllowedGroups[1] != "editors" {
		t.Errorf("AllowedGroups = %v, want [admin editors]", cfg.AllowedGroups)
	}
}

func TestLoad_AllowedGroups_Empty(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AllowedGroups != nil {
		t.Errorf("AllowedGroups = %v, want nil", cfg.AllowedGroups)
	}
}

func TestLoad_RevokeBefore(t *testing.T) {
	setAllRequired(t)
	t.Setenv("REVOKE_BEFORE", "2026-03-28T12:00:00Z")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RevokeBefore.IsZero() {
		t.Fatal("RevokeBefore should not be zero")
	}
	if cfg.RevokeBefore.Year() != 2026 || cfg.RevokeBefore.Month() != 3 || cfg.RevokeBefore.Day() != 28 {
		t.Errorf("RevokeBefore = %v, want 2026-03-28", cfg.RevokeBefore)
	}
}

func TestLoad_RevokeBefore_Invalid(t *testing.T) {
	setAllRequired(t)
	t.Setenv("REVOKE_BEFORE", "not-a-date")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid REVOKE_BEFORE")
	}
	if !strings.Contains(err.Error(), "REVOKE_BEFORE") {
		t.Errorf("error %q should mention REVOKE_BEFORE", err)
	}
}

func TestLoad_RevokeBefore_Unset(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.RevokeBefore.IsZero() {
		t.Errorf("RevokeBefore should be zero when unset, got %v", cfg.RevokeBefore)
	}
}

func TestLoad_RefreshRaceGrace_Default(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RefreshRaceGrace != 2*time.Second {
		t.Errorf("RefreshRaceGrace default = %v, want 2s", cfg.RefreshRaceGrace)
	}
}

func TestLoad_RefreshRaceGrace_ZeroDisables(t *testing.T) {
	setAllRequired(t)
	t.Setenv("REFRESH_RACE_GRACE_SEC", "0")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RefreshRaceGrace != 0 {
		t.Errorf("RefreshRaceGrace = %v, want 0 (disabled)", cfg.RefreshRaceGrace)
	}
}

func TestLoad_RefreshRaceGrace_Custom(t *testing.T) {
	setAllRequired(t)
	t.Setenv("REFRESH_RACE_GRACE_SEC", "5")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RefreshRaceGrace != 5*time.Second {
		t.Errorf("RefreshRaceGrace = %v, want 5s", cfg.RefreshRaceGrace)
	}
}

func TestLoad_RefreshRaceGrace_RejectsNonInt(t *testing.T) {
	setAllRequired(t)
	t.Setenv("REFRESH_RACE_GRACE_SEC", "two")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "REFRESH_RACE_GRACE_SEC") {
		t.Fatalf("want error mentioning REFRESH_RACE_GRACE_SEC, got %v", err)
	}
}

func TestLoad_RefreshRaceGrace_RejectsNegative(t *testing.T) {
	setAllRequired(t)
	t.Setenv("REFRESH_RACE_GRACE_SEC", "-1")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), ">= 0") {
		t.Fatalf("want error mentioning >= 0, got %v", err)
	}
}

// TestLoad_RefreshRaceGrace_RejectsAboveCeiling pins the 10-second
// security cap. Wider windows are rejected at startup so the
// operator cannot quietly extend the attacker's ride window.
func TestLoad_RefreshRaceGrace_RejectsAboveCeiling(t *testing.T) {
	setAllRequired(t)
	t.Setenv("REFRESH_RACE_GRACE_SEC", "11")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "<= 10") {
		t.Fatalf("want error mentioning <= 10, got %v", err)
	}
}

func TestLoad_IdPExchangeRate_DefaultDisabled(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.IdPExchangeRatePerSec != 0 {
		t.Errorf("IdPExchangeRatePerSec default = %v, want 0 (disabled)", cfg.IdPExchangeRatePerSec)
	}
	if cfg.IdPExchangeBurst != 50 {
		t.Errorf("IdPExchangeBurst default = %d, want 50", cfg.IdPExchangeBurst)
	}
}

func TestLoad_IdPExchangeRate_Custom(t *testing.T) {
	setAllRequired(t)
	t.Setenv("IDP_EXCHANGE_RATE_PER_SEC", "20")
	t.Setenv("IDP_EXCHANGE_BURST", "100")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.IdPExchangeRatePerSec != 20 {
		t.Errorf("IdPExchangeRatePerSec = %v, want 20", cfg.IdPExchangeRatePerSec)
	}
	if cfg.IdPExchangeBurst != 100 {
		t.Errorf("IdPExchangeBurst = %d, want 100", cfg.IdPExchangeBurst)
	}
}

func TestLoad_IdPExchangeRate_RejectsNegative(t *testing.T) {
	setAllRequired(t)
	t.Setenv("IDP_EXCHANGE_RATE_PER_SEC", "-1")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "IDP_EXCHANGE_RATE_PER_SEC") {
		t.Fatalf("want error mentioning IDP_EXCHANGE_RATE_PER_SEC, got %v", err)
	}
}

func TestLoad_IdPExchangeRate_RejectsNonNumber(t *testing.T) {
	setAllRequired(t)
	t.Setenv("IDP_EXCHANGE_RATE_PER_SEC", "fast")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "must be a number") {
		t.Fatalf("want parse error, got %v", err)
	}
}

func TestLoad_IdPExchangeBurst_RejectsZero(t *testing.T) {
	setAllRequired(t)
	t.Setenv("IDP_EXCHANGE_BURST", "0")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), ">= 1") {
		t.Fatalf("want >= 1 rejection, got %v", err)
	}
}

func TestLoad_ClientRegistrationTTL_Default(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientRegistrationTTL != 7*24*time.Hour {
		t.Errorf("ClientRegistrationTTL default = %v, want 168h (7d)", cfg.ClientRegistrationTTL)
	}
}

func TestLoad_ClientRegistrationTTL_Custom(t *testing.T) {
	setAllRequired(t)
	t.Setenv("CLIENT_REGISTRATION_TTL", "720h")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientRegistrationTTL != 720*time.Hour {
		t.Errorf("ClientRegistrationTTL = %v, want 720h", cfg.ClientRegistrationTTL)
	}
}

func TestLoad_ClientRegistrationTTL_RejectsNonPositive(t *testing.T) {
	setAllRequired(t)
	t.Setenv("CLIENT_REGISTRATION_TTL", "0s")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "positive") {
		t.Fatalf("want positive rejection, got %v", err)
	}
}

func TestLoad_ClientRegistrationTTL_RejectsAboveCap(t *testing.T) {
	setAllRequired(t)
	t.Setenv("CLIENT_REGISTRATION_TTL", "2400h") // 100 days, > 90d cap
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "90d cap") {
		t.Fatalf("want 90d-cap rejection, got %v", err)
	}
}

func TestLoad_ClientRegistrationTTL_RejectsBadFormat(t *testing.T) {
	setAllRequired(t)
	t.Setenv("CLIENT_REGISTRATION_TTL", "7d") // time.ParseDuration doesn't accept "d"
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "Go duration") {
		t.Fatalf("want format-error, got %v", err)
	}
}

func TestLoad_PKCERequired_Default(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.PKCERequired {
		t.Error("PKCERequired should default to true")
	}
}

func TestLoad_PKCERequired_False(t *testing.T) {
	setAllRequired(t)
	t.Setenv("PROD_MODE", "false") // toggle being tested is a prod-mode violation
	t.Setenv("PKCE_REQUIRED", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PKCERequired {
		t.Error("PKCERequired should be false when PKCE_REQUIRED=false")
	}
}

func TestLoad_ShutdownTimeout_Default(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ShutdownTimeout != 120*time.Second {
		t.Errorf("ShutdownTimeout default = %v, want 120s", cfg.ShutdownTimeout)
	}
}

func TestLoad_ShutdownTimeout_Custom(t *testing.T) {
	setAllRequired(t)
	t.Setenv("SHUTDOWN_TIMEOUT", "5m")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ShutdownTimeout != 5*time.Minute {
		t.Errorf("ShutdownTimeout = %v, want 5m", cfg.ShutdownTimeout)
	}
}

func TestLoad_ShutdownTimeout_Invalid(t *testing.T) {
	setAllRequired(t)
	t.Setenv("SHUTDOWN_TIMEOUT", "not-a-duration")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid SHUTDOWN_TIMEOUT")
	}
	if !strings.Contains(err.Error(), "SHUTDOWN_TIMEOUT") {
		t.Errorf("error %q should mention SHUTDOWN_TIMEOUT", err)
	}
}

func TestLoad_ShutdownTimeout_Negative(t *testing.T) {
	setAllRequired(t)
	t.Setenv("SHUTDOWN_TIMEOUT", "-1s")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for negative SHUTDOWN_TIMEOUT")
	}
	if !strings.Contains(err.Error(), "positive") {
		t.Errorf("error %q should mention positive requirement", err)
	}
}

func TestLoad_RedisKeyPrefix_Default(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RedisKeyPrefix != "mcp-auth-proxy:" {
		t.Errorf("RedisKeyPrefix default = %q, want %q", cfg.RedisKeyPrefix, "mcp-auth-proxy:")
	}
}

func TestLoad_RedisKeyPrefix_Custom(t *testing.T) {
	setAllRequired(t)
	t.Setenv("REDIS_KEY_PREFIX", "tenant-42:")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RedisKeyPrefix != "tenant-42:" {
		t.Errorf("RedisKeyPrefix = %q, want %q", cfg.RedisKeyPrefix, "tenant-42:")
	}
}

// TestLoad_RedisKeyPrefix_ExplicitEmpty verifies that setting REDIS_KEY_PREFIX
// to the empty string is respected — operators can opt out of namespacing
// without being overridden back to the default.
func TestLoad_RedisKeyPrefix_ExplicitEmpty(t *testing.T) {
	setAllRequired(t)
	t.Setenv("REDIS_KEY_PREFIX", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RedisKeyPrefix != "" {
		t.Errorf("RedisKeyPrefix = %q, want empty (explicit opt-out)", cfg.RedisKeyPrefix)
	}
}

// REDIS_REQUIRED defaults to true so the safe (replay-protected) mode is
// the default. main.go refuses to start when REDIS_URL is unset and this
// flag is true.
func TestLoad_RedisRequired_Default(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.RedisRequired {
		t.Error("RedisRequired should default to true")
	}
}

func TestLoad_RedisRequired_False(t *testing.T) {
	setAllRequired(t)
	t.Setenv("PROD_MODE", "false") // toggle being tested is a prod-mode violation
	t.Setenv("REDIS_REQUIRED", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RedisRequired {
		t.Error("RedisRequired should be false when REDIS_REQUIRED=false")
	}
}

// COMPAT_ALLOW_STATELESS defaults to false — strict mode refuses /authorize
// requests that omit state. Explicit opt-in restores the legacy behavior
// for MCP Inspector / Cursor compatibility.
func TestLoad_CompatAllowStateless_Default(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CompatAllowStateless {
		t.Error("CompatAllowStateless should default to false (strict)")
	}
}

func TestLoad_CompatAllowStateless_True(t *testing.T) {
	setAllRequired(t)
	t.Setenv("PROD_MODE", "false") // toggle being tested is a prod-mode violation
	t.Setenv("COMPAT_ALLOW_STATELESS", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.CompatAllowStateless {
		t.Error("CompatAllowStateless should be true when COMPAT_ALLOW_STATELESS=true")
	}
}

func TestLoad_RenderConsentPage_Default(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.RenderConsentPage {
		t.Error("RenderConsentPage should default to true (consent page on by default)")
	}
}

func TestLoad_RenderConsentPage_False(t *testing.T) {
	setAllRequired(t)
	t.Setenv("RENDER_CONSENT_PAGE", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RenderConsentPage {
		t.Error("RenderConsentPage should be false when RENDER_CONSENT_PAGE=false")
	}
}

// TestLoad_RenderConsentPage_NonStrictBoolean pins the env-parser
// shape: only the literal "false" (case-insensitive) opts out;
// every other value keeps the secure default true. Mirrors
// PKCE_REQUIRED / REDIS_REQUIRED / RATE_LIMIT_ENABLED so an
// operator copy-pasting "0" / "no" / "off" from a different config
// schema does not silently disable the consent page.
func TestLoad_RenderConsentPage_NonStrictBoolean(t *testing.T) {
	cases := map[string]bool{
		"FALSE": false,
		"False": false,
		"false": false,
		"true":  true,
		"":      true,
		"0":     true,
		"no":    true,
		"off":   true,
	}
	for value, want := range cases {
		t.Run("value="+value, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("RENDER_CONSENT_PAGE", value)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.RenderConsentPage != want {
				t.Errorf("RenderConsentPage = %v for env %q, want %v", cfg.RenderConsentPage, value, want)
			}
		})
	}
}

func TestLoad_MCPLogBodyMax_Default(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MCPLogBodyMax != 65536 {
		t.Errorf("MCPLogBodyMax default = %d, want 65536", cfg.MCPLogBodyMax)
	}
}

func TestLoad_MCPLogBodyMax_Zero(t *testing.T) {
	setAllRequired(t)
	t.Setenv("MCP_LOG_BODY_MAX", "0")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MCPLogBodyMax != 0 {
		t.Errorf("MCPLogBodyMax = %d, want 0", cfg.MCPLogBodyMax)
	}
}

func TestLoad_MCPLogBodyMax_Custom(t *testing.T) {
	setAllRequired(t)
	t.Setenv("MCP_LOG_BODY_MAX", "32768")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MCPLogBodyMax != 32768 {
		t.Errorf("MCPLogBodyMax = %d, want 32768", cfg.MCPLogBodyMax)
	}
}

func TestLoad_MCPLogBodyMax_Invalid(t *testing.T) {
	setAllRequired(t)
	t.Setenv("MCP_LOG_BODY_MAX", "not-a-number")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid MCP_LOG_BODY_MAX")
	}
	if !strings.Contains(err.Error(), "MCP_LOG_BODY_MAX") {
		t.Errorf("error %q should mention MCP_LOG_BODY_MAX", err)
	}
}

func TestLoad_AccessLogSkipRE_Default(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AccessLogSkipRE != nil {
		t.Errorf("AccessLogSkipRE should default to nil, got %q", cfg.AccessLogSkipRE.String())
	}
}

func TestLoad_AccessLogSkipRE_Compiled(t *testing.T) {
	setAllRequired(t)
	t.Setenv("ACCESS_LOG_SKIP_RE", `^/healthz$|^/readyz$`)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AccessLogSkipRE == nil {
		t.Fatal("AccessLogSkipRE should be compiled when ACCESS_LOG_SKIP_RE is set")
	}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/healthz", true},
		{"/readyz", true},
		{"/healthz/", false},
		{"/mcp", false},
	} {
		if got := cfg.AccessLogSkipRE.MatchString(tc.path); got != tc.want {
			t.Errorf("MatchString(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestLoad_AccessLogSkipRE_Invalid(t *testing.T) {
	setAllRequired(t)
	t.Setenv("ACCESS_LOG_SKIP_RE", "(")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid ACCESS_LOG_SKIP_RE")
	}
	if !strings.Contains(err.Error(), "ACCESS_LOG_SKIP_RE") {
		t.Errorf("error %q should mention ACCESS_LOG_SKIP_RE", err)
	}
}

func TestLoad_AccessLogSkipRE_WhitespaceTreatedAsUnset(t *testing.T) {
	setAllRequired(t)
	t.Setenv("ACCESS_LOG_SKIP_RE", "  \n\t")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AccessLogSkipRE != nil {
		t.Errorf("whitespace-only ACCESS_LOG_SKIP_RE should be treated as unset, got %q", cfg.AccessLogSkipRE.String())
	}
}

func TestLoad_ToolMetrics_DefaultsOff(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ToolMetricsEnabled {
		t.Error("ToolMetricsEnabled should default to false (cardinality + privacy trade)")
	}
	if cfg.ToolMetricsMaxCardinality != 256 {
		t.Errorf("ToolMetricsMaxCardinality default = %d, want 256", cfg.ToolMetricsMaxCardinality)
	}
}

func TestLoad_ToolMetrics_Enabled(t *testing.T) {
	setAllRequired(t)
	t.Setenv("MCP_TOOL_METRICS", "true")
	t.Setenv("MCP_TOOL_METRICS_MAX_CARDINALITY", "32")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.ToolMetricsEnabled {
		t.Error("ToolMetricsEnabled should be true when MCP_TOOL_METRICS=true")
	}
	if cfg.ToolMetricsMaxCardinality != 32 {
		t.Errorf("ToolMetricsMaxCardinality = %d, want 32", cfg.ToolMetricsMaxCardinality)
	}
}

func TestLoad_ToolMetrics_InvalidCardinality(t *testing.T) {
	cases := []string{"-1", "not-a-number"}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("MCP_TOOL_METRICS_MAX_CARDINALITY", in)
			_, err := Load()
			if err == nil {
				t.Fatalf("expected error for %q", in)
			}
			if !strings.Contains(err.Error(), "MCP_TOOL_METRICS_MAX_CARDINALITY") {
				t.Errorf("error should mention the env var, got %q", err)
			}
		})
	}
}

// TestLoad_ToolMetrics_ZeroDisablesCap pins the documented contract:
// MCP_TOOL_METRICS_MAX_CARDINALITY=0 means "no cap" (the consumer at
// metrics.ToolCardinality.ToolLabel reads MaxCardinality > 0 before
// applying the cap). Operators following the docs were previously
// rejected by the config validator — fixed.
func TestLoad_ToolMetrics_ZeroDisablesCap(t *testing.T) {
	setAllRequired(t)
	t.Setenv("MCP_TOOL_METRICS_MAX_CARDINALITY", "0")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("0 should be accepted (disables the cap), got %v", err)
	}
	if cfg.ToolMetricsMaxCardinality != 0 {
		t.Errorf("ToolMetricsMaxCardinality = %d, want 0 (disabled)", cfg.ToolMetricsMaxCardinality)
	}
}

func TestLoad_MCPLogBodyMax_Negative(t *testing.T) {
	setAllRequired(t)
	t.Setenv("MCP_LOG_BODY_MAX", "-1")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for negative MCP_LOG_BODY_MAX")
	}
	if !strings.Contains(err.Error(), "MCP_LOG_BODY_MAX") {
		t.Errorf("error %q should mention MCP_LOG_BODY_MAX", err)
	}
}

// TRUST_PROXY_HEADERS defaults to false. Enabling it opts in to keying the
// rate limiter by XFF/X-Real-IP — only safe behind a trusted frontend.
func TestLoad_TrustProxyHeaders_Default(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TrustProxyHeaders {
		t.Error("TrustProxyHeaders should default to false")
	}
}

func TestLoad_TrustProxyHeaders_True(t *testing.T) {
	setAllRequired(t)
	t.Setenv("PROD_MODE", "false") // toggle being tested is a prod-mode violation
	t.Setenv("TRUST_PROXY_HEADERS", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.TrustProxyHeaders {
		t.Error("TrustProxyHeaders should be true when TRUST_PROXY_HEADERS=true")
	}
}

func TestLoad_PerSubjectConcurrency_Default(t *testing.T) {
	setAllRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PerSubjectConcurrency != 16 {
		t.Errorf("PerSubjectConcurrency default = %d, want 16", cfg.PerSubjectConcurrency)
	}
}

func TestLoad_PerSubjectConcurrency_Custom(t *testing.T) {
	setAllRequired(t)
	t.Setenv("MCP_PER_SUBJECT_CONCURRENCY", "64")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PerSubjectConcurrency != 64 {
		t.Errorf("PerSubjectConcurrency = %d, want 64", cfg.PerSubjectConcurrency)
	}
}

func TestLoad_PerSubjectConcurrency_Zero(t *testing.T) {
	setAllRequired(t)
	t.Setenv("MCP_PER_SUBJECT_CONCURRENCY", "0")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PerSubjectConcurrency != 0 {
		t.Errorf("PerSubjectConcurrency = %d, want 0 (disabled)", cfg.PerSubjectConcurrency)
	}
}

func TestLoad_PerSubjectConcurrency_Invalid(t *testing.T) {
	setAllRequired(t)
	t.Setenv("MCP_PER_SUBJECT_CONCURRENCY", "not-a-number")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid MCP_PER_SUBJECT_CONCURRENCY")
	}
	if !strings.Contains(err.Error(), "MCP_PER_SUBJECT_CONCURRENCY") {
		t.Errorf("error %q should mention MCP_PER_SUBJECT_CONCURRENCY", err)
	}
}

func TestLoad_PerSubjectConcurrency_Negative(t *testing.T) {
	setAllRequired(t)
	t.Setenv("MCP_PER_SUBJECT_CONCURRENCY", "-1")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for negative MCP_PER_SUBJECT_CONCURRENCY")
	}
}

// L1: TOKEN_SIGNING_SECRET with fewer than 16 distinct bytes surfaces a
// non-fatal weakness warning that main.go logs at startup under
// PROD_MODE=false. PROD_MODE=true promotes this to a hard error
// (covered by TestLoad_ProdMode_BlocksLowEntropySecret).
func TestLoad_SecretWeaknessWarning_LowEntropy(t *testing.T) {
	setAllRequired(t)
	// PROD_MODE=false to keep the warning path observable; under
	// PROD_MODE=true the same secret would fail Load() outright.
	t.Setenv("PROD_MODE", "false")
	t.Setenv("REDIS_REQUIRED", "false")
	// 32 bytes but only one distinct byte → 1 < 16.
	t.Setenv("TOKEN_SIGNING_SECRET", strings.Repeat("a", 32))
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	w := cfg.SecretWeaknessWarning()
	if w == "" {
		t.Fatal("expected non-empty weakness warning for 1-distinct-byte secret")
	}
	if !strings.Contains(w, "distinct bytes") {
		t.Errorf("warning %q should explain the distinct-byte count", w)
	}
}

func TestLoad_SecretWeaknessWarning_HighEntropy(t *testing.T) {
	setAllRequired(t)
	// 32 distinct chars → ≥16.
	t.Setenv("TOKEN_SIGNING_SECRET", "abcdefghijklmnopqrstuvwxyz012345")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if w := cfg.SecretWeaknessWarning(); w != "" {
		t.Errorf("unexpected weakness warning for high-entropy secret: %q", w)
	}
}

// L2: SHUTDOWN_TIMEOUT above 15m is fatal.
func TestLoad_ShutdownTimeout_Over15mFatal(t *testing.T) {
	setAllRequired(t)
	t.Setenv("SHUTDOWN_TIMEOUT", "16m")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for SHUTDOWN_TIMEOUT >15m")
	}
	if !strings.Contains(err.Error(), "15m") {
		t.Errorf("error %q should mention the 15m cap", err)
	}
}

func TestLoad_ShutdownTimeout_AtBoundary(t *testing.T) {
	setAllRequired(t)
	t.Setenv("SHUTDOWN_TIMEOUT", "15m")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("15m should be accepted, got %v", err)
	}
	if cfg.ShutdownTimeout != 15*time.Minute {
		t.Errorf("ShutdownTimeout = %v, want 15m", cfg.ShutdownTimeout)
	}
}

// L3: REDIS_KEY_PREFIX rejects cluster-hash tags and control bytes.
// (setenv refuses NUL, so the NUL case is covered by
// TestValidateRedisKeyPrefix_DirectNUL below.)
func TestLoad_RedisKeyPrefix_ForbiddenBytes(t *testing.T) {
	bad := []string{
		"tenant-{42}:",
		"tenant{:",
		"tenant}:",
		"tenant\r:",
		"tenant\n:",
		"tenant\t:",
		"tenant\x7f:", // DEL
		"tenanté:",    // non-ASCII
	}
	for _, p := range bad {
		t.Run(p, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("REDIS_KEY_PREFIX", p)
			_, err := Load()
			if err == nil {
				t.Fatalf("expected error for REDIS_KEY_PREFIX=%q", p)
			}
			if !strings.Contains(err.Error(), "REDIS_KEY_PREFIX") {
				t.Errorf("error %q should mention REDIS_KEY_PREFIX", err)
			}
		})
	}
}

// The setenv path refuses NUL in env values on most OSes; hit the
// validator directly so the NUL byte is still covered.
func TestValidateRedisKeyPrefix_DirectNUL(t *testing.T) {
	if err := validateRedisKeyPrefix("tenant\x00:"); err == nil {
		t.Fatal("validateRedisKeyPrefix should reject NUL")
	}
}

func TestLoad_RedisKeyPrefix_AllowsPrintable(t *testing.T) {
	setAllRequired(t)
	t.Setenv("REDIS_KEY_PREFIX", "prod-mcp-v2:")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected printable prefix to be accepted: %v", err)
	}
	if cfg.RedisKeyPrefix != "prod-mcp-v2:" {
		t.Errorf("RedisKeyPrefix = %q, want %q", cfg.RedisKeyPrefix, "prod-mcp-v2:")
	}
}

// L8: PROXY_BASE_URL validation — https required, or http+loopback; no
// userinfo, no fragment, no non-root path.
func TestLoad_ProxyBaseURL_RejectsInvalid(t *testing.T) {
	cases := []struct {
		name, url string
	}{
		{"http_non_loopback", "http://example.com"},
		{"ftp_scheme", "ftp://example.com"},
		{"with_userinfo", "https://user:pass@example.com"},
		{"with_fragment", "https://example.com/#frag"},
		{"with_path", "https://example.com/base"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("PROXY_BASE_URL", tc.url)
			_, err := Load()
			if err == nil {
				t.Fatalf("expected error for PROXY_BASE_URL=%q", tc.url)
			}
			if !strings.Contains(err.Error(), "PROXY_BASE_URL") {
				t.Errorf("error %q should mention PROXY_BASE_URL", err)
			}
		})
	}
}

func TestLoad_ProxyBaseURL_AllowsValid(t *testing.T) {
	cases := []string{
		"https://proxy.example.com",
		"https://proxy.example.com/", // trailing slash trimmed
		"http://localhost:8080",
		"http://127.0.0.1:9090",
		"http://[::1]:8080",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("PROXY_BASE_URL", u)
			if _, err := Load(); err != nil {
				t.Fatalf("PROXY_BASE_URL=%q should be accepted: %v", u, err)
			}
		})
	}
}

// TestLoad_ProxyBaseURL_RejectsOpaqueOrQuery covers the 3rd-party M3
// finding: validateProxyBaseURL used to accept "https:foo" (opaque
// URL) and "https://x?y=1" (query string). Both pollute downstream
// issuer metadata / WWW-Authenticate headers, so both are now
// rejected at startup.
func TestLoad_ProxyBaseURL_RejectsOpaqueOrQuery(t *testing.T) {
	bad := []string{
		"https:foo",               // opaque URL, Host=""
		"https:///callback",       // hostless authority
		"https://x?y=1",           // query string
		"https://proxy.example/?", // empty query (still RawQuery != "")
	}
	for _, u := range bad {
		t.Run(u, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("PROXY_BASE_URL", u)
			if _, err := Load(); err == nil {
				t.Fatalf("PROXY_BASE_URL=%q should be rejected", u)
			}
		})
	}
}

// TestLoad_UpstreamMCPURL_Validation covers the validator: absolute
// http(s) URL with host, no userinfo/query/fragment/opaque. A path IS
// allowed and becomes the proxy mount (verbatim both sides). A path
// that collides with a control-plane route owned by the proxy is
// rejected at startup.
func TestLoad_UpstreamMCPURL_Validation(t *testing.T) {
	cases := []struct {
		url string
		ok  bool
	}{
		{"http://mcp-backend:8080/mcp", true},
		{"http://mcp-backend:8080/api", true},
		{"https://mcp.internal.example/mcp", true},
		{"https://mcp.internal.example/api/v1/mcp", true},
		{"http://mcp-backend:8080", false},        // origin-only, no path
		{"http://mcp-backend:8080/", false},       // lone "/" is not a mount
		{"http://backend/token", false},           // collides with /token
		{"http://backend/.well-known/foo", false}, // under reserved
		{"ftp://mcp-backend/mcp", false},
		{"http:foo", false},                 // opaque
		{"http:///api", false},              // hostless
		{"https://backend/mcp?x=1", false},  // query
		{"https://u:p@backend/mcp", false},  // userinfo
		{"https://backend/mcp#frag", false}, // fragment
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("UPSTREAM_MCP_URL", tc.url)
			_, err := Load()
			if tc.ok && err != nil {
				t.Fatalf("UPSTREAM_MCP_URL=%q should be accepted: %v", tc.url, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("UPSTREAM_MCP_URL=%q should be rejected", tc.url)
			}
		})
	}
}

// TestLoad_UpstreamMCPURL_OriginOnlyHint verifies the error message
// on an origin-only URL includes a clean suggestion (no double slash
// when the user supplied a trailing "/").
func TestLoad_UpstreamMCPURL_OriginOnlyHint(t *testing.T) {
	cases := []struct {
		in         string
		wantInHint string
	}{
		{"http://backend", `"http://backend/mcp"`},
		{"http://backend/", `"http://backend/mcp"`},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("UPSTREAM_MCP_URL", tc.in)
			_, err := Load()
			if err == nil {
				t.Fatalf("UPSTREAM_MCP_URL=%q should be rejected", tc.in)
			}
			if !strings.Contains(err.Error(), tc.wantInHint) {
				t.Errorf("error hint should contain %s, got %q", tc.wantInHint, err)
			}
			if strings.Contains(err.Error(), "//mcp") {
				t.Errorf("error hint contains double slash: %q", err)
			}
		})
	}
}

// TestLoad_UpstreamMCPURL_MountPath verifies the derived MCP mount
// path: the path component drives both the public proxy mount and the
// per-resource discovery variants, with trailing-slash normalization.
func TestLoad_UpstreamMCPURL_MountPath(t *testing.T) {
	cases := []struct {
		in        string
		wantURL   string
		wantMount string
	}{
		{"http://backend:8080/mcp", "http://backend:8080/mcp", "/mcp"},
		{"http://backend:8080/mcp/", "http://backend:8080/mcp", "/mcp"},
		{"http://backend:8080/api/v1/mcp", "http://backend:8080/api/v1/mcp", "/api/v1/mcp"},
		{"http://backend:8080/api/v1/mcp/", "http://backend:8080/api/v1/mcp", "/api/v1/mcp"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("UPSTREAM_MCP_URL", tc.in)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.UpstreamMCPURL != tc.wantURL {
				t.Errorf("UpstreamMCPURL = %q, want %q", cfg.UpstreamMCPURL, tc.wantURL)
			}
			if cfg.UpstreamMCPMountPath != tc.wantMount {
				t.Errorf("UpstreamMCPMountPath = %q, want %q", cfg.UpstreamMCPMountPath, tc.wantMount)
			}
		})
	}
}

// TestLoad_UpstreamMCPURL_RejectsRouterPatternChars pins the
// chi-pattern guard: `:`, `*`, `{`, `}` in the mount path would
// silently register router patterns instead of literal segments.
// Reject at startup so an operator's typo doesn't turn /api/:v/mcp
// into a path-parameter route.
func TestLoad_UpstreamMCPURL_RejectsRouterPatternChars(t *testing.T) {
	cases := []string{
		"http://backend:8080/api/:v/mcp",
		"http://backend:8080/api/*/mcp",
		"http://backend:8080/api/{v}/mcp",
		"http://backend:8080/mcp@1",
		"http://backend:8080/mcp+sub",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("UPSTREAM_MCP_URL", in)
			_, err := Load()
			if err == nil {
				t.Fatalf("expected error for %q", in)
			}
			if !strings.Contains(err.Error(), "unreserved characters") {
				t.Errorf("error %q should mention unreserved characters", err)
			}
		})
	}
}

// TestLoad_UpstreamMCPURL_ReservedPrefix_NotShadowed pins the
// reserved-route collision check. The validator rejects exact match
// (`/healthz`) and a slash-bounded prefix (`/healthz/x`) but
// deliberately allows close-but-not-reserved siblings
// (`/healthzfoo`, `/registerx`) — chi mounts those as distinct routes
// from the control plane. This test locks the boundary so a future
// reserved-list addition (e.g. `/healthcheck`) is forced to think
// about the prefix-collision implication.
func TestLoad_UpstreamMCPURL_ReservedPrefix_NotShadowed(t *testing.T) {
	cases := []struct {
		path    string
		wantErr bool
	}{
		// Exact reserved route: rejected.
		{"/healthz", true},
		{"/register", true},
		{"/authorize", true},
		{"/callback", true},
		{"/token", true},
		// Slash-bounded prefix: rejected.
		{"/healthz/x", true},
		{"/.well-known/x", true},
		// Close-but-not-reserved sibling: ALLOWED. Mount is a
		// literal route, no shadowing risk.
		{"/healthzfoo", false},
		{"/registerx", false},
		{"/tokenize", false},
		{"/callbacks", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("UPSTREAM_MCP_URL", "http://backend:8080"+tc.path)
			_, err := Load()
			if tc.wantErr && err == nil {
				t.Fatalf("expected reserved-route error for %q, got nil", tc.path)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected %q to be allowed (non-reserved sibling), got error: %v", tc.path, err)
			}
		})
	}
}

// TestLoad_ProdMode_BlocksUnsafeFlags covers P1a: PROD_MODE=true must
// fail startup when any compatibility flag that relaxes a security
// control is set. Each violation is tested independently so the
// error message clearly names which one tripped the gate.
func TestLoad_ProdMode_BlocksUnsafeFlags(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T)
	}{
		{"pkce_disabled", func(t *testing.T) { t.Setenv("PKCE_REQUIRED", "false") }},
		{"compat_stateless", func(t *testing.T) { t.Setenv("COMPAT_ALLOW_STATELESS", "true") }},
		{"redis_not_required", func(t *testing.T) { t.Setenv("REDIS_REQUIRED", "false") }},
		{"redis_url_unset", func(t *testing.T) {
			// setAllRequired seeds a default REDIS_URL for PROD_MODE
			// compatibility; clear it explicitly for this case.
			t.Setenv("REDIS_URL", "")
		}},
		{"legacy_trust_proxy_headers", func(t *testing.T) {
			t.Setenv("TRUST_PROXY_HEADERS", "true")
		}},
		{"insecure_oidc_http", func(t *testing.T) {
			t.Setenv("OIDC_ALLOW_INSECURE_HTTP", "true")
			t.Setenv("OIDC_ISSUER_URL", "http://keycloak:8080/realms/mcp-demo")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("PROD_MODE", "true")
			tc.setup(t)
			_, err := Load()
			if err == nil {
				t.Fatalf("PROD_MODE=true with %s should fail startup", tc.name)
			}
			if !strings.Contains(err.Error(), "PROD_MODE") {
				t.Errorf("error should mention PROD_MODE, got %q", err)
			}
		})
	}
}

func TestLoad_ProdMode_AllowsTrustProxyHeadersWithCIDRs(t *testing.T) {
	setAllRequired(t)
	t.Setenv("PROD_MODE", "true")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	t.Setenv("TRUST_PROXY_HEADERS", "true")
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("PROD_MODE with CIDR-scoped proxy trust should pass: %v", err)
	}
	if !cfg.TrustProxyHeaders {
		t.Error("TrustProxyHeaders should still reflect the configured legacy flag")
	}
	if len(cfg.TrustedProxyCIDRs) != 1 {
		t.Fatalf("TrustedProxyCIDRs len = %d, want 1", len(cfg.TrustedProxyCIDRs))
	}
}

// TestLoad_ProdMode_BlocksLowEntropySecret pins the entropy gate:
// PROD_MODE=true rejects a TOKEN_SIGNING_SECRET with <16 distinct
// bytes (patterned / human-typed). Same secret accepted with a
// warning when PROD_MODE=false.
func TestLoad_ProdMode_BlocksLowEntropySecret(t *testing.T) {
	patterned := strings.Repeat("a", 32) // 1 distinct byte, 32 bytes long

	t.Run("prod_mode_rejects", func(t *testing.T) {
		setAllRequired(t)
		t.Setenv("PROD_MODE", "true")
		t.Setenv("REDIS_URL", "redis://localhost:6379/0")
		t.Setenv("TOKEN_SIGNING_SECRET", patterned)
		_, err := Load()
		if err == nil {
			t.Fatal("expected error for patterned secret under PROD_MODE=true")
		}
		if !strings.Contains(err.Error(), "TOKEN_SIGNING_SECRET") || !strings.Contains(err.Error(), "distinct bytes") {
			t.Errorf("error %q should mention TOKEN_SIGNING_SECRET + distinct bytes", err)
		}
	})

	t.Run("dev_mode_warns", func(t *testing.T) {
		setAllRequired(t)
		t.Setenv("PROD_MODE", "false")
		t.Setenv("REDIS_REQUIRED", "false")
		t.Setenv("TOKEN_SIGNING_SECRET", patterned)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("dev mode should accept patterned secret with a warning, got error: %v", err)
		}
		if cfg.SecretWeaknessWarning() == "" {
			t.Error("SecretWeaknessWarning should be non-empty for a patterned secret")
		}
	})
}

// TestLoad_ProdMode_BlocksLowEntropyPreviousSecret pins the same gate
// on rolling-rotation entries so a cutover cannot regress the entropy
// floor by carrying an old patterned secret in
// TOKEN_SIGNING_SECRETS_PREVIOUS.
func TestLoad_ProdMode_BlocksLowEntropyPreviousSecret(t *testing.T) {
	setAllRequired(t)
	t.Setenv("PROD_MODE", "true")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	// Strong primary, weak previous.
	t.Setenv("TOKEN_SIGNING_SECRETS_PREVIOUS", strings.Repeat("b", 32))
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for patterned previous secret under PROD_MODE=true")
	}
	if !strings.Contains(err.Error(), "TOKEN_SIGNING_SECRETS_PREVIOUS") {
		t.Errorf("error %q should mention TOKEN_SIGNING_SECRETS_PREVIOUS", err)
	}
}

// TestLoad_ProdMode_PassesWithSafeDefaults ensures PROD_MODE=true does
// NOT fail when every safety flag is in its default (secure) state
// and REDIS_URL is configured.
func TestLoad_ProdMode_PassesWithSafeDefaults(t *testing.T) {
	setAllRequired(t)
	t.Setenv("PROD_MODE", "true")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("PROD_MODE with safe defaults should pass: %v", err)
	}
	if !cfg.ProdMode {
		t.Error("ProdMode should be true after PROD_MODE=true")
	}
}

// TestLoad_TokenSigningSecretsPrevious covers G4.1: env-var parsing
// for rolling key rotation. Whitespace-separated so operators can
// paste multi-line blocks from a secret manager; each entry must
// clear the 32-byte floor.
func TestLoad_TokenSigningSecretsPrevious(t *testing.T) {
	// Use 32-byte fixtures with 16+ distinct bytes so the PROD_MODE
	// entropy gate doesn't trip — this test covers parsing /
	// whitespace-splitting / length-floor, not the entropy floor
	// (covered separately).
	longA := "0123456789abcdef0123456789abcdee"
	longB := "fedcba9876543210fedcba9876543211"
	t.Run("single_previous", func(t *testing.T) {
		setAllRequired(t)
		t.Setenv("TOKEN_SIGNING_SECRETS_PREVIOUS", longA)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(cfg.TokenSigningSecretsPrevious) != 1 {
			t.Errorf("want 1 previous key, got %d", len(cfg.TokenSigningSecretsPrevious))
		}
	})
	t.Run("multiple_whitespace_separated", func(t *testing.T) {
		setAllRequired(t)
		t.Setenv("TOKEN_SIGNING_SECRETS_PREVIOUS", longA+" \t\n"+longB)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(cfg.TokenSigningSecretsPrevious) != 2 {
			t.Errorf("want 2 previous keys, got %d", len(cfg.TokenSigningSecretsPrevious))
		}
	})
	t.Run("short_secret_fails", func(t *testing.T) {
		setAllRequired(t)
		t.Setenv("TOKEN_SIGNING_SECRETS_PREVIOUS", "too-short")
		if _, err := Load(); err == nil {
			t.Fatal("short previous secret must fail startup")
		}
	})
	t.Run("unset_empty", func(t *testing.T) {
		setAllRequired(t)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.TokenSigningSecretsPrevious != nil {
			t.Errorf("unset should yield nil, got %v", cfg.TokenSigningSecretsPrevious)
		}
	})
}

// TestLoad_TrustedProxyCIDRs covers P1c: parse a comma-separated CIDR
// list, reject typos, take precedence over the legacy bool.
func TestLoad_TrustedProxyCIDRs(t *testing.T) {
	t.Run("parses_multiple", func(t *testing.T) {
		setAllRequired(t)
		t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 172.16.0.0/12 ,192.168.0.0/16")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(cfg.TrustedProxyCIDRs) != 3 {
			t.Errorf("want 3 CIDRs, got %d", len(cfg.TrustedProxyCIDRs))
		}
	})
	t.Run("rejects_typo", func(t *testing.T) {
		setAllRequired(t)
		t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/80")
		if _, err := Load(); err == nil {
			t.Fatal("invalid CIDR should fail startup")
		}
	})
	t.Run("unset_empty", func(t *testing.T) {
		setAllRequired(t)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.TrustedProxyCIDRs != nil {
			t.Errorf("unset should yield nil, got %v", cfg.TrustedProxyCIDRs)
		}
	})
}

// TestLoad_TrustedProxyHeader covers R2-H1 wiring: optional opt-in
// header pin, allowlisted to the three forms operators realistically
// use, typo rejected at startup.
func TestLoad_TrustedProxyHeader(t *testing.T) {
	t.Run("default_unset_yields_empty", func(t *testing.T) {
		setAllRequired(t)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.TrustedProxyHeader != "" {
			t.Errorf("want empty default, got %q", cfg.TrustedProxyHeader)
		}
	})
	t.Run("accepts_x_real_ip", func(t *testing.T) {
		setAllRequired(t)
		t.Setenv("TRUSTED_PROXY_HEADER", "X-Real-IP")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.TrustedProxyHeader != "X-Real-Ip" {
			t.Errorf("want canonical X-Real-Ip, got %q", cfg.TrustedProxyHeader)
		}
	})
	t.Run("accepts_true_client_ip_lowercase", func(t *testing.T) {
		setAllRequired(t)
		t.Setenv("TRUSTED_PROXY_HEADER", "true-client-ip")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.TrustedProxyHeader != "True-Client-Ip" {
			t.Errorf("want canonical True-Client-Ip, got %q", cfg.TrustedProxyHeader)
		}
	})
	t.Run("rejects_unknown", func(t *testing.T) {
		setAllRequired(t)
		t.Setenv("TRUSTED_PROXY_HEADER", "X-Custom-Forwarded")
		if _, err := Load(); err == nil {
			t.Fatal("unknown header value should fail startup")
		}
	})
}

// TestLoad_UpstreamAuthorizationHeader covers the
// UPSTREAM_AUTHORIZATION_HEADER feature: operator supplies the full
// header value (scheme + credentials); Config captures it verbatim.
func TestLoad_UpstreamAuthorizationHeader(t *testing.T) {
	t.Run("unset_empty", func(t *testing.T) {
		setAllRequired(t)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.UpstreamAuthorization != "" {
			t.Errorf("want empty, got %q", cfg.UpstreamAuthorization)
		}
	})
	t.Run("full_header_value", func(t *testing.T) {
		setAllRequired(t)
		t.Setenv("UPSTREAM_AUTHORIZATION_HEADER", "Bearer upstream-xyz")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.UpstreamAuthorization != "Bearer upstream-xyz" {
			t.Errorf("want %q, got %q", "Bearer upstream-xyz", cfg.UpstreamAuthorization)
		}
	})
}

func TestLoad_OIDCIssuerURL_AllowsExplicitDevCleartext(t *testing.T) {
	setAllRequired(t)
	t.Setenv("PROD_MODE", "false")
	t.Setenv("OIDC_ALLOW_INSECURE_HTTP", "true")
	t.Setenv("OIDC_ISSUER_URL", "http://keycloak:8080/realms/mcp-demo")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected explicit dev cleartext issuer to be accepted: %v", err)
	}
	if cfg.OIDCIssuerURL != "http://keycloak:8080/realms/mcp-demo" {
		t.Errorf("OIDCIssuerURL = %q", cfg.OIDCIssuerURL)
	}
}

// TestLoad_OIDCIssuerURL_RejectsCleartextAndHostless covers the
// 3rd-party H2 finding: OIDC_ISSUER_URL used to accept any non-empty
// string. Cleartext http:// to a real IdP exposes the client secret
// during discovery and the authorization-code exchange.
func TestLoad_OIDCIssuerURL_RejectsCleartextAndHostless(t *testing.T) {
	cases := []struct {
		issuer string
		ok     bool
	}{
		{"https://idp.example.com", true},
		{"https://idp.example.com/realms/x", true},
		{"http://localhost:8080", true}, // loopback dev
		{"http://127.0.0.1/realms/dev", true},
		{"http://idp.example.com", false}, // cleartext external
		{"ftp://idp.example.com", false},  // unsupported scheme
		{"https:idp.example.com", false},  // opaque, Host=""
		{"https:///realms/x", false},      // hostless
		{"not a url at all %%%", false},   // parse error
	}
	for _, tc := range cases {
		t.Run(tc.issuer, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("OIDC_ISSUER_URL", tc.issuer)
			_, err := Load()
			if tc.ok && err != nil {
				t.Fatalf("OIDC_ISSUER_URL=%q should be accepted: %v", tc.issuer, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("OIDC_ISSUER_URL=%q should be rejected", tc.issuer)
			}
		})
	}
}
