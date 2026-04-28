package config

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
	ProxyBaseURL     string
	UpstreamMCPURL   string
	// UpstreamMCPMountPath is the path component extracted from
	// UPSTREAM_MCP_URL. It is always non-empty (the validator rejects
	// origin-only URLs) and is used as both the public mount on this
	// proxy and — verbatim — as the path forwarded upstream.
	UpstreamMCPMountPath string
	// ResourceName is an optional human-readable name for this
	// protected resource. When non-empty it's advertised under
	// "resource_name" in the RFC 9728 PRM (§2 — OPTIONAL field).
	// Clients use it for UI display (e.g. consent prompts that list
	// the resource by name). env: MCP_RESOURCE_NAME.
	ResourceName       string
	ListenAddr         string
	MetricsAddr        string
	TokenSigningSecret []byte
	// TokenSigningSecretsPrevious carries zero or more retired signing
	// secrets that must still open existing (not-yet-expired) sealed
	// payloads during a rolling key rotation. New payloads are always
	// sealed with TokenSigningSecret (the primary); Open tries primary
	// first, then each previous secret in order. See
	// docs/runbooks/key-rotation.md for the rollout procedure. env:
	// TOKEN_SIGNING_SECRETS_PREVIOUS (whitespace-separated list).
	TokenSigningSecretsPrevious [][]byte
	LogLevel                    string
	GroupsClaim                 string        // flat claim name in id_token (default "groups")
	AllowedGroups               []string      // empty = allow all authenticated users
	RevokeBefore                time.Time     // tokens issued before this time are rejected (zero = disabled)
	PKCERequired                bool          // require PKCE on /authorize (default true, set false for Cursor/MCP Inspector)
	ShutdownTimeout             time.Duration // graceful shutdown deadline; raise to drain long-lived SSE streams
	RedisURL                    string        // optional; when set, enables single-use authorization codes (replay protection)
	RedisKeyPrefix              string        // prefix applied to every Redis key (for shared-Redis deployments); default "mcp-auth-proxy:"
	RateLimitEnabled            bool          // enable per-IP rate limiting on pre-auth endpoints (default true)
	// RedisRequired fails startup when REDIS_URL is unset. Default true —
	// stateless codes/refresh tokens are replayable within TTL (C3/C4); the
	// safe default is Redis-enforced single-use. Set REDIS_REQUIRED=false
	// only for dev / single-replica deployments that accept the trade-off.
	RedisRequired bool
	// RefreshRaceGrace is the window inside which a refresh-rotation
	// claim collision is treated as a benign concurrent submit
	// (parallel-tab refresh, slow-network double-submit) and surfaces
	// as 429 `refresh_concurrent_submit` without revoking the family.
	// Outside the window the strict "every collision revokes" behavior
	// applies. Default 2s; clamped to [0, 10s] at Load. Set to 0 to
	// keep the strict pre-grace behavior. env: REFRESH_RACE_GRACE_SEC.
	RefreshRaceGrace time.Duration
	// IdPExchangeRatePerSec caps the proxy → IdP token-endpoint
	// fan-out at /callback. Defense in depth: a flood of /callback
	// hits that slips past the per-IP limiter (distributed sources,
	// permissive XFF trust matrix) is bounded by this token-bucket
	// before reaching the IdP. 0 disables (no outbound throttling).
	// env: IDP_EXCHANGE_RATE_PER_SEC.
	IdPExchangeRatePerSec float64
	// IdPExchangeBurst is the burst size for the IdP-exchange limiter
	// when IdPExchangeRatePerSec > 0. env: IDP_EXCHANGE_BURST.
	IdPExchangeBurst int
	// ClientRegistrationTTL is the lifetime of a sealed client_id
	// minted by POST /register. Defaults to 7 days so the envelope
	// always covers a full refresh-token cycle — a shorter value
	// would silently kill long-running MCP clients (which treat DCR
	// as one-shot at startup) the moment their access token first
	// expired. env: CLIENT_REGISTRATION_TTL (Go duration: 168h, 7d-
	// equivalent values like 168h0m0s, etc.; "d" suffix not supported
	// by time.ParseDuration).
	ClientRegistrationTTL time.Duration
	// CompatAllowStateless keeps the legacy Cursor/MCP Inspector behavior of
	// accepting /authorize requests without a client-supplied state. Default
	// false — strict mode refuses stateless requests so the client cannot
	// silently lose its CSRF protection. Set COMPAT_ALLOW_STATELESS=true to
	// opt into the compat mode (emits mcp_auth_access_denied_total{reason=
	// "state_missing"} as a denial counter either way for visibility).
	CompatAllowStateless bool
	// RenderConsentPage gates the proxy-rendered consent screen on
	// /authorize. Default true: /authorize stops after parameter
	// validation and renders an HTML page that requires an explicit
	// user click before the upstream IdP redirect — closes the
	// silent-issuance phishing path where a malicious DCR client +
	// an active IdP session = a token issued without the user ever
	// seeing the proxy. Set RENDER_CONSENT_PAGE=false to fall back
	// to the legacy silent-redirect path; only do that when every
	// caller is non-interactive and known-trusted.
	// env: RENDER_CONSENT_PAGE.
	RenderConsentPage bool
	// MCPLogBodyMax is the max bytes buffered per request for JSON-RPC method
	// extraction into access logs. 0 disables buffering entirely (no method
	// logging). Default 65536 (64 KiB).
	MCPLogBodyMax int64 // env: MCP_LOG_BODY_MAX
	// AccessLogSkipRE, when non-nil, suppresses access-log lines whose
	// request path matches. Typical use: quiet liveness-probe noise with
	// "^/healthz$" (probes on every replica, every periodSeconds, bury
	// real requests otherwise). Metrics, rate-limit counters, and the
	// handler response are unaffected — only the zap "request" log line
	// is skipped. Go regexp is RE2 → linear-time, no ReDoS. Invalid
	// pattern fails startup. Default nil (log everything).
	// env: ACCESS_LOG_SKIP_RE.
	AccessLogSkipRE *regexp.Regexp
	// ToolMetricsEnabled gates per-tool Prometheus counters
	// (mcp_auth_rpc_calls_total{tool}, …). Off by default — the
	// `tool` label increases series cardinality and may reveal
	// which workflows tenants invoke. Enable when the visibility
	// is worth the cardinality + privacy trade. env: MCP_TOOL_METRICS.
	ToolMetricsEnabled bool
	// ToolMetricsMaxCardinality caps the number of distinct tool
	// labels the proxy will mint. Names past the cap collapse into
	// the `_overflow` bucket so a malicious client that probes
	// thousands of fictional tool names cannot blow up Prometheus
	// memory. Default 256 — comfortably above any real upstream's
	// tool count, low enough to detect runaways. env:
	// MCP_TOOL_METRICS_MAX_CARDINALITY.
	ToolMetricsMaxCardinality int
	// TrustProxyHeaders is the legacy "trust every peer's XFF" switch.
	// Kept for backward compatibility; prefer TrustedProxyCIDRs in new
	// deployments. When true AND TrustedProxyCIDRs is empty, every
	// inbound request is treated as if it came from a trusted proxy —
	// which is correct only if the pod literally cannot be reached
	// except through one. env: TRUST_PROXY_HEADERS.
	TrustProxyHeaders bool
	// TrustedProxyCIDRs scopes the XFF/X-Real-IP/True-Client-IP trust
	// to peers whose immediate RemoteAddr falls inside one of the
	// listed networks. Typical value for a k8s deployment:
	// "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" (RFC1918) or the
	// specific pod-CIDR of the ingress controller. When this is set
	// it takes precedence over TRUST_PROXY_HEADERS. env:
	// TRUSTED_PROXY_CIDRS (comma-separated list of CIDRs).
	TrustedProxyCIDRs []*net.IPNet
	// TrustedProxyHeader names the forwarding header the rate-limit
	// keying walks right-to-left when the immediate peer is inside
	// TrustedProxyCIDRs. Default "X-Forwarded-For" — that is the
	// only header most ingresses actually OVERWRITE rather than
	// pass through verbatim. Operators whose ingress is known to
	// emit a single trusted hop in `X-Real-IP` or `True-Client-IP`
	// can pin those instead. The legacy
	// `httprate.KeyByRealIP`-style behaviour (read True-Client-IP,
	// X-Real-IP, leftmost-XFF in that order, no validation) is
	// gone — it bucketed per attacker-spoofed value because none
	// of those headers are gated on the peer being trusted. env:
	// TRUSTED_PROXY_HEADER.
	TrustedProxyHeader string
	// PerSubjectConcurrency caps the number of in-flight requests per
	// authenticated subject on the MCP route group. Default 16. A single
	// runaway or compromised client identity cannot saturate the proxy's
	// goroutine / upstream pool at the expense of others. env:
	// MCP_PER_SUBJECT_CONCURRENCY (0 disables the limit).
	PerSubjectConcurrency int64
	// ProdMode, when true, fails startup if any compatibility flag
	// that weakens a security control is set (PKCE_REQUIRED=false,
	// COMPAT_ALLOW_STATELESS=true, REDIS_REQUIRED=false, REDIS_URL
	// empty, or legacy TRUST_PROXY_HEADERS=true without
	// TRUSTED_PROXY_CIDRS).
	//
	// Default true — the strict OAuth 2.1 / MCP posture that the
	// published metadata already advertises, so operators cannot
	// silently ship a laxer runtime than what clients expect. Set
	// PROD_MODE=false explicitly for dev / single-replica work that
	// needs one of the compatibility toggles.
	// env: PROD_MODE.
	ProdMode bool
	// UpstreamAuthorization, when non-empty, is set verbatim as the
	// Authorization header on every request forwarded to the upstream
	// MCP backend. Full header value including the scheme, e.g.
	// "Bearer s3cr3t" or "Basic dXNlcjpwYXNz". Empty = no header
	// (upstream sees the proxy-injected X-User-* headers only).
	// env: UPSTREAM_AUTHORIZATION_HEADER. Treat as a secret in
	// deployment (mount from a Secret, not a ConfigMap).
	UpstreamAuthorization string
	// secretWeakWarning is non-empty when TOKEN_SIGNING_SECRET matches
	// an obvious-weakness pattern (all-same byte, or short repeating
	// period). Exposed via
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
		ProdMode:    strings.ToLower(os.Getenv("PROD_MODE")) != "false",
	}
	allowInsecureOIDCHTTP := strings.ToLower(os.Getenv("OIDC_ALLOW_INSECURE_HTTP")) == "true"

	var missing []string

	c.OIDCIssuerURL = strings.TrimRight(os.Getenv("OIDC_ISSUER_URL"), "/")
	if c.OIDCIssuerURL == "" {
		missing = append(missing, "OIDC_ISSUER_URL")
	} else if err := validateOIDCIssuerURL(c.OIDCIssuerURL, allowInsecureOIDCHTTP); err != nil {
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
	} else {
		normalized, mount, err := validateUpstreamMCPURL(c.UpstreamMCPURL)
		if err != nil {
			return nil, err
		}
		c.UpstreamMCPURL = normalized
		c.UpstreamMCPMountPath = mount
	}

	secret := os.Getenv("TOKEN_SIGNING_SECRET")
	switch {
	case secret == "":
		missing = append(missing, "TOKEN_SIGNING_SECRET")
	case len(secret) < 32:
		return nil, fmt.Errorf("TOKEN_SIGNING_SECRET must be at least 32 bytes")
	default:
		c.TokenSigningSecret = []byte(secret)
		// Detect obvious-weakness patterns (all-same byte, or short
		// repeating period). The AES-GCM key derived via SHA-256 is
		// still 256 bits wide, but the secret itself has near-zero
		// effective entropy when it's `aaaa…` or `abcabc…`. Warn
		// unconditionally; the PROD_MODE violations block below
		// promotes it to a hard error when strict mode is on, so dev
		// / single-replica work that knowingly uses a patterned
		// secret keeps working under PROD_MODE=false. Use
		// `manifests/scripts/generate-signing-secret.sh` to produce
		// a known-good 64-char base64 value.
		if reason := weakSecretReason(c.TokenSigningSecret); reason != "" {
			c.secretWeakWarning = "TOKEN_SIGNING_SECRET " + reason
		}
	}

	// G4.1: previous signing secrets for rolling rotation. Whitespace-
	// separated so operators can paste multi-line blocks from a
	// secret manager. Each entry must be ≥32 bytes, same floor as the
	// primary. A mid-rotation deploy carries the NEW secret as
	// TOKEN_SIGNING_SECRET and the OLD one(s) here; after every
	// cached token expires (1h access / 7d refresh), the operator
	// redeploys with this var emptied.
	if raw := os.Getenv("TOKEN_SIGNING_SECRETS_PREVIOUS"); raw != "" {
		for _, s := range strings.Fields(raw) {
			if len(s) < 32 {
				return nil, fmt.Errorf("TOKEN_SIGNING_SECRETS_PREVIOUS: each secret must be at least 32 bytes")
			}
			c.TokenSigningSecretsPrevious = append(c.TokenSigningSecretsPrevious, []byte(s))
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

	// REFRESH_RACE_GRACE_SEC: integer seconds, default 2, clamped to
	// [0, 10]. The 10s ceiling is a security cap — any collision wider
	// than 10s is statistically attacker-shaped (real parallel-tab
	// races complete sub-second; HTTP clients retry at single-digit
	// seconds). 0 disables the grace window (every collision revokes
	// the family — pre-grace behavior).
	c.RefreshRaceGrace = 2 * time.Second
	if raw := os.Getenv("REFRESH_RACE_GRACE_SEC"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("REFRESH_RACE_GRACE_SEC must be an integer: %w", err)
		}
		if n < 0 {
			return nil, fmt.Errorf("REFRESH_RACE_GRACE_SEC must be >= 0; got %d", n)
		}
		if n > 10 {
			return nil, fmt.Errorf("REFRESH_RACE_GRACE_SEC must be <= 10; got %d (wider windows are statistically attacker-shaped)", n)
		}
		c.RefreshRaceGrace = time.Duration(n) * time.Second
	}

	// IDP_EXCHANGE_RATE_PER_SEC + IDP_EXCHANGE_BURST tune the
	// outbound rate-limit bucket on the proxy → IdP /token leg.
	// 0 disables. Default off — operators behind a permissive XFF
	// trust matrix or facing distributed flood patterns opt in
	// explicitly.
	if raw := os.Getenv("IDP_EXCHANGE_RATE_PER_SEC"); raw != "" {
		f, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil, fmt.Errorf("IDP_EXCHANGE_RATE_PER_SEC must be a number: %w", err)
		}
		if f < 0 {
			return nil, fmt.Errorf("IDP_EXCHANGE_RATE_PER_SEC must be >= 0; got %v", f)
		}
		c.IdPExchangeRatePerSec = f
	}
	c.IdPExchangeBurst = 50
	if raw := os.Getenv("IDP_EXCHANGE_BURST"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("IDP_EXCHANGE_BURST must be an integer: %w", err)
		}
		if n < 1 {
			return nil, fmt.Errorf("IDP_EXCHANGE_BURST must be >= 1; got %d", n)
		}
		c.IdPExchangeBurst = n
	}

	// CLIENT_REGISTRATION_TTL: how long a sealed client_id stays
	// openable. Default 7d so a client holding a still-valid
	// refresh token (refreshTokenTTL = 7d) can always exchange it.
	// Hard cap at 90d — a longer envelope materially extends the
	// window an exfiltrated client_id (which is unauthenticated
	// metadata) can be reused.
	c.ClientRegistrationTTL = 7 * 24 * time.Hour
	if raw := os.Getenv("CLIENT_REGISTRATION_TTL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("CLIENT_REGISTRATION_TTL must be a Go duration (e.g. 168h, 24h, 720h): %w", err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("CLIENT_REGISTRATION_TTL must be positive, got %s", d)
		}
		if d > 90*24*time.Hour {
			return nil, fmt.Errorf("CLIENT_REGISTRATION_TTL exceeds 90d cap, got %s", d)
		}
		c.ClientRegistrationTTL = d
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

	// Default true: only an explicit "false" opts out. Mirrors the
	// PKCE_REQUIRED / REDIS_REQUIRED / RATE_LIMIT_ENABLED shape so
	// every "secure-by-default" toggle behaves the same way.
	c.RenderConsentPage = strings.ToLower(os.Getenv("RENDER_CONSENT_PAGE")) != "false"

	c.ResourceName = os.Getenv("MCP_RESOURCE_NAME")

	c.MCPLogBodyMax = 65536
	if v := os.Getenv("MCP_LOG_BODY_MAX"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("MCP_LOG_BODY_MAX must be a non-negative integer, got %q", v)
		}
		c.MCPLogBodyMax = n
	}

	// TrimSpace so a stray space or trailing newline (common with .env
	// loaders / heredocs) is treated as "unset" instead of compiling
	// into a regex that quietly matches paths containing that whitespace.
	if v := strings.TrimSpace(os.Getenv("ACCESS_LOG_SKIP_RE")); v != "" {
		re, err := regexp.Compile(v)
		if err != nil {
			return nil, fmt.Errorf("ACCESS_LOG_SKIP_RE is not a valid regexp: %w", err)
		}
		c.AccessLogSkipRE = re
	}

	c.ToolMetricsEnabled = strings.ToLower(os.Getenv("MCP_TOOL_METRICS")) == "true"
	c.ToolMetricsMaxCardinality = 256
	if v := os.Getenv("MCP_TOOL_METRICS_MAX_CARDINALITY"); v != "" {
		n, err := strconv.Atoi(v)
		// 0 is a documented sentinel meaning "disable the cap entirely"
		// — only safe when the upstream enforces a tool allowlist.
		// Negative values stay rejected (no semantic).
		if err != nil || n < 0 {
			return nil, fmt.Errorf("MCP_TOOL_METRICS_MAX_CARDINALITY must be a non-negative integer (0 disables the cap), got %q", v)
		}
		c.ToolMetricsMaxCardinality = n
	}

	// TRUST_PROXY_HEADERS defaults to false. Honoring XFF/X-Real-IP behind an
	// untrusted frontend lets any client mint its own rate-limit bucket key.
	c.TrustProxyHeaders = strings.ToLower(os.Getenv("TRUST_PROXY_HEADERS")) == "true"

	// TRUSTED_PROXY_CIDRS: comma-separated CIDR list of peers whose
	// forwarding headers may be trusted. Takes precedence over the
	// legacy TRUST_PROXY_HEADERS bool. Parsing failure is fatal so a
	// typo ("10.0.0.0/80") does not silently disable header-based
	// keying (which would then fall back to the less-discerning
	// default).
	if raw := os.Getenv("TRUSTED_PROXY_CIDRS"); raw != "" {
		for _, s := range strings.Split(raw, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS contains invalid CIDR %q: %w", s, err)
			}
			c.TrustedProxyCIDRs = append(c.TrustedProxyCIDRs, n)
		}
	}

	// Pin the forwarding header the rate-limit keying walks
	// right-to-left when the immediate peer is in
	// TRUSTED_PROXY_CIDRS. Allowlist three forms operators
	// realistically use; reject everything else so a typo cannot
	// silently fall back to "no header keying".
	if raw := strings.TrimSpace(os.Getenv("TRUSTED_PROXY_HEADER")); raw != "" {
		switch http.CanonicalHeaderKey(raw) {
		case "X-Forwarded-For", "X-Real-Ip", "True-Client-Ip":
			c.TrustedProxyHeader = http.CanonicalHeaderKey(raw)
		default:
			return nil, fmt.Errorf("TRUSTED_PROXY_HEADER must be one of X-Forwarded-For, X-Real-IP, True-Client-IP, got %q", raw)
		}
	}

	c.UpstreamAuthorization = os.Getenv("UPSTREAM_AUTHORIZATION_HEADER")

	c.PerSubjectConcurrency = 16
	if v := os.Getenv("MCP_PER_SUBJECT_CONCURRENCY"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("MCP_PER_SUBJECT_CONCURRENCY must be a non-negative integer, got %q", v)
		}
		c.PerSubjectConcurrency = n
	}

	// PROD_MODE fails closed on every compatibility flag that relaxes
	// a security control. None of these flags are exploitable when
	// used intentionally (dev, legacy clients, stateless dev
	// replicas), but leaving them set in a production pod is usually
	// a paste-error from a dev config. Failing startup turns a quiet
	// misconfiguration into a loud crash — the whole point of a
	// hardened-mode gate.
	if c.ProdMode {
		var violations []string
		if !c.PKCERequired {
			violations = append(violations, "PKCE_REQUIRED=false (PKCE downgrade risk)")
		}
		if c.CompatAllowStateless {
			violations = append(violations, "COMPAT_ALLOW_STATELESS=true (hides client-side CSRF bugs)")
		}
		if !c.RedisRequired {
			violations = append(violations, "REDIS_REQUIRED=false (authorization codes + refresh tokens become replayable within TTL)")
		}
		if c.RedisURL == "" {
			violations = append(violations, "REDIS_URL unset (no replay store → no single-use codes, no refresh-rotation reuse detection)")
		}
		if c.TrustProxyHeaders && len(c.TrustedProxyCIDRs) == 0 {
			violations = append(violations, "TRUST_PROXY_HEADERS=true without TRUSTED_PROXY_CIDRS (forwarded-header spoofing can bypass per-IP limits)")
		}
		if allowInsecureOIDCHTTP {
			violations = append(violations, "OIDC_ALLOW_INSECURE_HTTP=true (cleartext OIDC exposes the client secret)")
		}
		// Promote the obvious-weakness warning to a hard fail under
		// PROD_MODE. A patterned secret (all-same byte, or short
		// repeating period) leaves the AES-GCM key derived from
		// SHA-256 trivially recoverable. Dev / single-replica work
		// that intentionally uses a patterned secret should set
		// PROD_MODE=false.
		if reason := weakSecretReason(c.TokenSigningSecret); reason != "" {
			violations = append(violations, "TOKEN_SIGNING_SECRET "+reason)
		}
		for i, prev := range c.TokenSigningSecretsPrevious {
			if reason := weakSecretReason(prev); reason != "" {
				violations = append(violations, fmt.Sprintf("TOKEN_SIGNING_SECRETS_PREVIOUS[%d] %s", i, reason))
			}
		}
		if len(violations) > 0 {
			return nil, fmt.Errorf("PROD_MODE=true rejects unsafe settings: %s", strings.Join(violations, "; "))
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

// SecretWeaknessWarning returns a non-empty human-readable message when
// TOKEN_SIGNING_SECRET has low byte-entropy, or "" when the secret looks
// sane. Caller logs it at startup (main.go) so Load() stays logger-free.
func (c *Config) SecretWeaknessWarning() string {
	return c.secretWeakWarning
}

// weakSecretReason returns a non-empty human-readable reason when b
// matches an obvious-weakness pattern, or "" when b looks sane.
// Catches three classes:
//
//  1. All-same byte (period 1).
//  2. Repeating period < len(b) — e.g. `abcabc…`,
//     `0123456789abcdef0123456789abcdef`.
//  3. Tiny alphabet (< 8 distinct bytes). Closes shapes that
//     defeat the period check by having uneven run-lengths
//     (`aaaa…b`, `aaaaabbbbbcccccddddd…`) but obviously cluster
//     around a small symbol set.
//
// Threshold choice for class 3: 8 is the most defensive floor
// that still has zero practical false-positive rate on real
// random output. A 32-char hex secret over a 16-symbol alphabet
// has expected ~14 distinct chars (P(<8 distinct in 64 chars) is
// essentially zero); base64 (64 symbols) and raw bytes (256)
// cluster even higher. 4 was the prior choice and accepted
// shapes like 5-symbol clustered runs; 8 closes that and stays
// well below the random-hex distribution.
func weakSecretReason(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	for period := 1; period*2 <= len(b); period++ {
		repeats := true
		for i := period; i < len(b); i++ {
			if b[i] != b[i%period] {
				repeats = false
				break
			}
		}
		if repeats {
			if period == 1 {
				return fmt.Sprintf("is %d copies of a single byte (effectively zero entropy)", len(b))
			}
			return fmt.Sprintf("repeats with period %d (truly random secrets are non-periodic; use manifests/scripts/generate-signing-secret.sh)", period)
		}
	}
	const minDistinct = 8
	var seen [256]bool
	distinct := 0
	for _, v := range b {
		if !seen[v] {
			seen[v] = true
			distinct++
			if distinct >= minDistinct {
				return ""
			}
		}
	}
	return fmt.Sprintf("uses only %d distinct byte values (use manifests/scripts/generate-signing-secret.sh)", distinct)
}

// validateRedisKeyPrefix enforces ASCII-printable only (no cluster-hash
// tags {}, no CR/LF, no control bytes). See L3 in PLAN notes.
func validateRedisKeyPrefix(p string) error {
	for i := range len(p) {
		b := p[i]
		if b < 0x20 || b > 0x7E || b == '{' || b == '}' {
			return fmt.Errorf("REDIS_KEY_PREFIX contains forbidden byte 0x%02x at offset %d; ASCII-printable only (no { } CR LF control)", b, i)
		}
	}
	return nil
}

// validateOIDCIssuerURL enforces https:// (or http:// to a loopback host
// for dev, mirroring the PROXY_BASE_URL posture). The explicit
// allowInsecureHTTP escape hatch exists for the Docker Compose demo,
// where Keycloak is reached over a single-host bridge network. PROD_MODE
// rejects that escape hatch so production cannot silently ship cleartext
// OIDC. Without this, go-oidc would allow discovery, code exchange, and
// the confidential client secret over HTTP.
func validateOIDCIssuerURL(raw string, allowInsecureHTTP bool) error {
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
		if allowInsecureHTTP {
			return nil
		}
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

// validateUpstreamMCPURL enforces the shape the reverse-proxy relies
// on: absolute URL with a real authority, http(s) scheme, no
// userinfo/fragment/query, no opaque form, and a non-empty path
// component. The path is the MCP mount on this proxy (public) and
// simultaneously the upstream path — they match verbatim, no rewrite.
// Requiring a path up-front keeps discovery metadata unambiguous and
// turns typo/bogus paths into a 404 at the router instead of opaque
// upstream errors. A path that collides with a control-plane route
// owned by the proxy is rejected so the MCP reverse-proxy cannot
// silently shadow /token, /authorize, etc.
//
// Returns the normalized URL and the mount path. The trailing "/" on
// a multi-segment path is stripped ("/api/" → "/api") so downstream
// comparisons are canonical.
func validateUpstreamMCPURL(raw string) (string, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("UPSTREAM_MCP_URL is not a valid URL: %w", err)
	}
	if u.Opaque != "" || u.Host == "" {
		return "", "", fmt.Errorf("UPSTREAM_MCP_URL must be an absolute URL with a host, got %q", raw)
	}
	switch u.Scheme {
	case "http", "https":
		// both ok — operator picks in-cluster transport
	default:
		return "", "", fmt.Errorf("UPSTREAM_MCP_URL must use http:// or https://, got scheme %q", u.Scheme)
	}
	if u.User != nil {
		return "", "", fmt.Errorf("UPSTREAM_MCP_URL must not contain userinfo")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return "", "", fmt.Errorf("UPSTREAM_MCP_URL must not contain a fragment")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", "", fmt.Errorf("UPSTREAM_MCP_URL must not contain a query string")
	}
	if len(u.Path) > 1 && strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimRight(u.Path, "/")
	}
	if u.Path == "" || u.Path == "/" {
		return "", "", fmt.Errorf("UPSTREAM_MCP_URL must include an explicit path (e.g. %q), got origin-only %q", strings.TrimRight(raw, "/")+"/mcp", raw)
	}
	if strings.Contains(u.Path, "//") {
		return "", "", fmt.Errorf("UPSTREAM_MCP_URL path must not contain empty segments, got %q", u.Path)
	}
	// The mount path is treated as opaque: no normalization, no
	// dot-segment resolution, no case folding. Whatever the operator
	// types is what chi mounts and what the upstream sees.
	//
	// Restrict to RFC 3986 unreserved + "/". RFC 3986 also allows
	// pct-encoded and sub-delims (`:`, `*`, `{`, `}`, `!`, `$`, `&`,
	// `'`, `(`, `)`, `,`, `;`, `=`, `@`, `+`) in paths, but several of
	// those have meaning to chi's router (`:` = path param, `*` =
	// catchall, `{` / `}` = regex param) and the rest have no
	// established use in MCP mounts. The conservative allowlist keeps
	// the literal/pattern boundary unambiguous; expand only with a
	// concrete operator need (none today).
	for i := range len(u.Path) {
		c := u.Path[i]
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~', c == '/':
			continue
		default:
			return "", "", fmt.Errorf("UPSTREAM_MCP_URL path may only contain unreserved characters and '/', got %q", u.Path)
		}
	}
	reserved := []string{"/healthz", "/register", "/authorize", "/callback", "/token", "/.well-known"}
	for _, r := range reserved {
		if u.Path == r || strings.HasPrefix(u.Path, r+"/") {
			return "", "", fmt.Errorf("UPSTREAM_MCP_URL path %q collides with reserved route %q", u.Path, r)
		}
	}
	return u.String(), u.Path, nil
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
