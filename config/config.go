package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	OIDCIssuerURL      string
	OIDCClientID       string
	OIDCClientSecret   string
	ProxyBaseURL       string
	UpstreamMCPURL     string
	ListenAddr         string
	MetricsAddr        string
	TokenSigningSecret []byte
	LogLevel           string
	GroupsClaim        string        // flat claim name in id_token (default "groups")
	AllowedGroups      []string      // empty = allow all authenticated users
	RevokeBefore       time.Time     // tokens issued before this time are rejected (zero = disabled)
	PKCERequired       bool          // require PKCE on /authorize (default true, set false for Cursor/MCP Inspector)
	ShutdownTimeout    time.Duration // graceful shutdown deadline; raise to drain long-lived SSE streams
}

func Load() (*Config, error) {
	c := &Config{
		ListenAddr:  envOrDefault("LISTEN_ADDR", ":8080"),
		MetricsAddr: envOrDefault("METRICS_ADDR", ":9090"),
		LogLevel:    envOrDefault("LOG_LEVEL", "info"),
		GroupsClaim: envOrDefault("GROUPS_CLAIM", "groups"),
	}

	var missing []string

	c.OIDCIssuerURL = strings.TrimRight(os.Getenv("OIDC_ISSUER_URL"), "/")
	if c.OIDCIssuerURL == "" {
		missing = append(missing, "OIDC_ISSUER_URL")
	}

	c.OIDCClientID = os.Getenv("OIDC_CLIENT_ID")
	if c.OIDCClientID == "" {
		missing = append(missing, "OIDC_CLIENT_ID")
	}

	c.OIDCClientSecret = os.Getenv("OIDC_CLIENT_SECRET")
	if c.OIDCClientSecret == "" {
		missing = append(missing, "OIDC_CLIENT_SECRET")
	}

	c.ProxyBaseURL = strings.TrimRight(os.Getenv("PROXY_BASE_URL"), "/")
	if c.ProxyBaseURL == "" {
		missing = append(missing, "PROXY_BASE_URL")
	}

	c.UpstreamMCPURL = os.Getenv("UPSTREAM_MCP_URL")
	if c.UpstreamMCPURL == "" {
		missing = append(missing, "UPSTREAM_MCP_URL")
	}

	secret := os.Getenv("TOKEN_SIGNING_SECRET")
	if secret == "" {
		missing = append(missing, "TOKEN_SIGNING_SECRET")
	} else if len(secret) < 32 {
		return nil, fmt.Errorf("TOKEN_SIGNING_SECRET must be at least 32 bytes")
	} else {
		c.TokenSigningSecret = []byte(secret)
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}

	c.PKCERequired = strings.ToLower(os.Getenv("PKCE_REQUIRED")) != "false"

	c.ShutdownTimeout = 120 * time.Second
	if st := os.Getenv("SHUTDOWN_TIMEOUT"); st != "" {
		d, err := time.ParseDuration(st)
		if err != nil {
			return nil, fmt.Errorf("SHUTDOWN_TIMEOUT must be a duration (e.g. 120s, 2m): %w", err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("SHUTDOWN_TIMEOUT must be positive, got %s", d)
		}
		c.ShutdownTimeout = d
	}

	if rb := os.Getenv("REVOKE_BEFORE"); rb != "" {
		t, err := time.Parse(time.RFC3339, rb)
		if err != nil {
			return nil, fmt.Errorf("REVOKE_BEFORE must be RFC3339 (e.g. 2026-03-28T12:00:00Z): %w", err)
		}
		c.RevokeBefore = t
	}

	if ag := os.Getenv("ALLOWED_GROUPS"); ag != "" {
		for _, g := range strings.Split(ag, ",") {
			if g = strings.TrimSpace(g); g != "" {
				c.AllowedGroups = append(c.AllowedGroups, g)
			}
		}
	}

	return c, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
