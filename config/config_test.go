package config

import (
	"strings"
	"testing"
	"time"
)

// setAllRequired sets every mandatory env var to a valid value.
func setAllRequired(t *testing.T) {
	t.Helper()
	t.Setenv("OIDC_ISSUER_URL", "https://issuer.example.com")
	t.Setenv("OIDC_CLIENT_ID", "client-id")
	t.Setenv("OIDC_CLIENT_SECRET", "client-secret")
	t.Setenv("PROXY_BASE_URL", "https://proxy.example.com")
	t.Setenv("UPSTREAM_MCP_URL", "http://localhost:3000")
	t.Setenv("TOKEN_SIGNING_SECRET", "this-secret-is-at-least-32-bytes!")
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
	if cfg.UpstreamMCPURL != "http://localhost:3000" {
		t.Errorf("UpstreamMCPURL = %q, want %q", cfg.UpstreamMCPURL, "http://localhost:3000")
	}
	if string(cfg.TokenSigningSecret) != "this-secret-is-at-least-32-bytes!" {
		t.Errorf("TokenSigningSecret = %q, want %q", cfg.TokenSigningSecret, "this-secret-is-at-least-32-bytes!")
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
	t.Setenv("COMPAT_ALLOW_STATELESS", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.CompatAllowStateless {
		t.Error("CompatAllowStateless should be true when COMPAT_ALLOW_STATELESS=true")
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
// non-fatal weakness warning that main.go logs at startup. High-entropy
// secrets yield no warning.
func TestLoad_SecretWeaknessWarning_LowEntropy(t *testing.T) {
	setAllRequired(t)
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
