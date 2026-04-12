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
	if cfg.MetricsAddr != ":9090" {
		t.Errorf("MetricsAddr = %q, want %q", cfg.MetricsAddr, ":9090")
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
