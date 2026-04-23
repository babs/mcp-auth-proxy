package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
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
	RedisURL           string        // optional; when set, enables single-use authorization codes (replay protection)
	RedisKeyPrefix     string        // prefix applied to every Redis key (for shared-Redis deployments); default "mcp-auth-proxy:"
	RateLimitEnabled   bool          // enable per-IP rate limiting on pre-auth endpoints (default true)
	// RedisRequired fails startup when REDIS_URL is unset. Default true —
	// stateless codes/refresh tokens are replayable within TTL (C3/C4); the
	// safe default is Redis-enforced single-use. Set REDIS_REQUIRED=false
	// only for dev / single-replica deployments that accept the trade-off.
	RedisRequired bool
	// CompatAllowStateless keeps the legacy Cursor/MCP Inspector behavior of
	// accepting /authorize requests without a client-supplied state. Default
	// false — strict mode refuses stateless requests so the client cannot
	// silently lose its CSRF protection. Set COMPAT_ALLOW_STATELESS=true to
	// opt into the compat mode (emits mcp_auth_access_denied_total{reason=
	// "state_missing"} as a denial counter either way for visibility).
	CompatAllowStateless bool
	// MCPLogBodyMax is the max bytes buffered per request for JSON-RPC method
	// extraction into access logs. 0 disables buffering entirely (no method
	// logging). Default 65536 (64 KiB).
	MCPLogBodyMax int64 // env: MCP_LOG_BODY_MAX
	// TrustProxyHeaders controls whether X-Forwarded-For / X-Real-IP /
	// True-Client-IP are honored when keying the rate limiter. Default false —
	// the limiter keys on the stripped r.RemoteAddr so a client behind an
	// untrusted frontend cannot spoof a header to evade the bucket. Flip to
	// true only when the proxy runs behind a trusted L4/L7 load balancer that
	// already sanitizes these headers (otherwise every request trivially picks
	// its own rate-limit key). env: TRUST_PROXY_HEADERS.
	TrustProxyHeaders bool
	// PerSubjectConcurrency caps the number of in-flight requests per
	// authenticated subject on the MCP route group. Default 16. A single
	// runaway or compromised client identity cannot saturate the proxy's
	// goroutine / upstream pool at the expense of others. env:
	// MCP_PER_SUBJECT_CONCURRENCY (0 disables the limit).
	PerSubjectConcurrency int64
	// UpstreamAuthorization, when non-empty, is set verbatim as the
	// Authorization header on every request forwarded to the upstream
	// MCP backend. Full header value including the scheme, e.g.
	// "Bearer s3cr3t" or "Basic dXNlcjpwYXNz". Empty = no header
	// (upstream sees the proxy-injected X-User-* headers only).
	// env: UPSTREAM_AUTHORIZATION_HEADER. Treat as a secret in
	// deployment (mount from a Secret, not a ConfigMap).
	UpstreamAuthorization string
	// secretWeakWarning is non-empty when TOKEN_SIGNING_SECRET has low
	// byte-entropy (fewer than 16 distinct bytes). Exposed via
	// SecretWeaknessWarning() so the caller can emit a structured log
	// event at startup without Load() taking a *zap.Logger dependency.
	secretWeakWarning string
}

func Load() (*Config, error) {
	c := &Config{
		ListenAddr: envOrDefault("LISTEN_ADDR", ":8080"),
		// MetricsAddr binds to loopback by default so /metrics and /readyz are
		// not exposed on the public interface of a host. Operators who front
		// the pod with a Prometheus sidecar on another interface must opt in
		// explicitly (e.g. METRICS_ADDR=:9090 or 0.0.0.0:9090).
		MetricsAddr: envOrDefault("METRICS_ADDR", "127.0.0.1:9090"),
		LogLevel:    envOrDefault("LOG_LEVEL", "info"),
		GroupsClaim: envOrDefault("GROUPS_CLAIM", "groups"),
	}

	var missing []string

	c.OIDCIssuerURL = strings.TrimRight(os.Getenv("OIDC_ISSUER_URL"), "/")
	if c.OIDCIssuerURL == "" {
		missing = append(missing, "OIDC_ISSUER_URL")
	} else if err := validateOIDCIssuerURL(c.OIDCIssuerURL); err != nil {
		return nil, err
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
	} else if err := validateProxyBaseURL(c.ProxyBaseURL); err != nil {
		return nil, err
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
		// L1: count distinct bytes in the secret. A 32-byte string with <16
		// unique byte values signals a human-picked or repeating pattern
		// (e.g. "aaaaaaaa..."): the AES-GCM key derived from SHA-256 is
		// still 256 bits wide, but the secret itself has far less effective
		// entropy than its length suggests. Warn only — rejecting at
		// startup would break deployments whose secrets happen to land just
		// under the threshold by chance.
		if distinct := distinctByteCount(c.TokenSigningSecret); distinct < 16 {
			c.secretWeakWarning = fmt.Sprintf(
				"TOKEN_SIGNING_SECRET has only %d distinct bytes (<16); effective entropy is much lower than its length suggests",
				distinct,
			)
		}
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
		// L2: cap at 15 minutes. A larger value keeps a crashed/stuck pod
		// lingering past the K8s terminationGracePeriodSeconds sweet spot,
		// masking upstream bugs behind an apparently healthy rollout.
		if d > 15*time.Minute {
			return nil, fmt.Errorf("SHUTDOWN_TIMEOUT exceeds 15m cap, got %s", d)
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

	c.RedisURL = os.Getenv("REDIS_URL")
	// LookupEnv so operators can opt into an empty prefix explicitly
	// (REDIS_KEY_PREFIX="") without tripping the default.
	if v, ok := os.LookupEnv("REDIS_KEY_PREFIX"); ok {
		// L3: redis-cluster hash-tag syntax "{...}" forces all keys into
		// one slot, and CR/LF / non-printable bytes turn the prefix into a
		// RESP-injection or log-injection foothold. ASCII-printable only.
		if err := validateRedisKeyPrefix(v); err != nil {
			return nil, err
		}
		c.RedisKeyPrefix = v
	} else {
		c.RedisKeyPrefix = "mcp-auth-proxy:"
	}
	c.RateLimitEnabled = strings.ToLower(os.Getenv("RATE_LIMIT_ENABLED")) != "false"

	// REDIS_REQUIRED defaults to true. Stateless defaults are too lenient on
	// replay (C3/C4); require a conscious opt-out for dev deployments.
	c.RedisRequired = strings.ToLower(os.Getenv("REDIS_REQUIRED")) != "false"

	// COMPAT_ALLOW_STATELESS defaults to false. H7: a server-synthesized
	// state hides a client-side CSRF bug; strict mode refuses the request.
	c.CompatAllowStateless = strings.ToLower(os.Getenv("COMPAT_ALLOW_STATELESS")) == "true"

	c.MCPLogBodyMax = 65536
	if v := os.Getenv("MCP_LOG_BODY_MAX"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("MCP_LOG_BODY_MAX must be a non-negative integer, got %q", v)
		}
		c.MCPLogBodyMax = n
	}

	// TRUST_PROXY_HEADERS defaults to false. Honoring XFF/X-Real-IP behind an
	// untrusted frontend lets any client mint its own rate-limit bucket key.
	c.TrustProxyHeaders = strings.ToLower(os.Getenv("TRUST_PROXY_HEADERS")) == "true"

	c.UpstreamAuthorization = os.Getenv("UPSTREAM_AUTHORIZATION_HEADER")

	c.PerSubjectConcurrency = 16
	if v := os.Getenv("MCP_PER_SUBJECT_CONCURRENCY"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("MCP_PER_SUBJECT_CONCURRENCY must be a non-negative integer, got %q", v)
		}
		c.PerSubjectConcurrency = n
	}

	return c, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// SecretWeaknessWarning returns a non-empty human-readable message when
// TOKEN_SIGNING_SECRET has low byte-entropy, or "" when the secret looks
// sane. Caller logs it at startup (main.go) so Load() stays logger-free.
func (c *Config) SecretWeaknessWarning() string {
	return c.secretWeakWarning
}

// distinctByteCount returns the number of unique byte values in b.
func distinctByteCount(b []byte) int {
	var seen [256]bool
	n := 0
	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			n++
		}
	}
	return n
}

// validateRedisKeyPrefix enforces ASCII-printable only (no cluster-hash
// tags {}, no CR/LF, no control bytes). See L3 in PLAN notes.
func validateRedisKeyPrefix(p string) error {
	for i := 0; i < len(p); i++ {
		b := p[i]
		if b < 0x20 || b > 0x7E || b == '{' || b == '}' {
			return fmt.Errorf("REDIS_KEY_PREFIX contains forbidden byte 0x%02x at offset %d; ASCII-printable only (no { } CR LF control)", b, i)
		}
	}
	return nil
}

// validateOIDCIssuerURL enforces https:// (or http:// to a loopback host
// for dev, mirroring the PROXY_BASE_URL posture). Without this an
// operator who sets OIDC_ISSUER_URL=http://idp.example.com sends OIDC
// discovery, the authorization-code exchange, and the confidential
// client secret over cleartext HTTP. go-oidc does not enforce TLS
// itself.
func validateOIDCIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("OIDC_ISSUER_URL is not a valid URL: %w", err)
	}
	if u.Opaque != "" || u.Host == "" {
		return fmt.Errorf("OIDC_ISSUER_URL must include a host, got %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := strings.TrimSuffix(u.Hostname(), ".")
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("OIDC_ISSUER_URL uses http:// but host %q is not loopback; https required (cleartext OIDC exposes the client secret)", host)
	default:
		return fmt.Errorf("OIDC_ISSUER_URL must use https:// (or http:// to a loopback host), got scheme %q", u.Scheme)
	}
}

// validateProxyBaseURL enforces the invariants downstream code relies on:
// https (or http+loopback for dev), no userinfo, no fragment, empty path
// (already trim-slashed by the caller). A violation here would surface as
// a subtle bug in redirect handling or OIDC metadata rather than a clear
// startup failure.
func validateProxyBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("PROXY_BASE_URL is not a valid URL: %w", err)
	}
	// Reject opaque (scheme:path without "//") and hostless URLs. Both
	// pass url.Parse but poison downstream issuer/resource metadata
	// and the WWW-Authenticate resource_metadata link.
	if u.Opaque != "" {
		return fmt.Errorf("PROXY_BASE_URL must be an absolute URL with authority (no opaque form), got %q", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("PROXY_BASE_URL must include a host, got %q", raw)
	}
	switch u.Scheme {
	case "https":
		// ok
	case "http":
		host := strings.TrimSuffix(u.Hostname(), ".")
		if host != "localhost" {
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				return fmt.Errorf("PROXY_BASE_URL uses http:// but host %q is not loopback; https required", host)
			}
		}
	default:
		return fmt.Errorf("PROXY_BASE_URL must use https:// (or http:// to a loopback host), got scheme %q", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("PROXY_BASE_URL must not contain userinfo")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("PROXY_BASE_URL must not contain a fragment")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("PROXY_BASE_URL must not contain a query string")
	}
	// TrimRight already stripped one trailing slash; anything left is a path.
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("PROXY_BASE_URL must not contain a path, got %q", u.Path)
	}
	return nil
}
