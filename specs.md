# SPEC — mcp-auth-proxy

## Objective

Reverse proxy in Go acting as an OAuth 2.1 Authorization Server compatible with the MCP auth spec, federating authentication to any OIDC Identity Provider (Keycloak, Microsoft Entra ID, Auth0, Okta, Google...) via auto-discovery. It lets MCP clients (claude.ai, Claude Code) access a private MCP server through a standard PKCE flow.

---

## Standards Conformance

This proxy MUST conform to the following specifications:

| Spec | Usage |
|---|---|
| [OAuth 2.1 (draft-ietf-oauth-v2-1-13)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13) | Authorization code + PKCE flow, token handling, security requirements |
| [RFC 8414 — OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414) | `GET /.well-known/oauth-authorization-server` discovery endpoint |
| [RFC 7591 — OAuth 2.0 Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591) | `POST /register` — automatic client registration for MCP clients |
| [RFC 9728 — OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728) | `GET /.well-known/oauth-protected-resource` — MCP clients discover the AS through this endpoint; `WWW-Authenticate` header on 401 responses MUST include `resource_metadata` URL |
| [RFC 8707 — Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html) | `resource` parameter accepted in `/authorize` and `/token` requests |
| [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636) | `code_verifier` must be 43-128 characters, `code_challenge_method` must be `S256` |
| [MCP Authorization Spec (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) | End-to-end MCP auth flow combining the above RFCs |

### Claude-specific requirements

- Claude's OAuth callback URL: `https://claude.ai/api/mcp/auth_callback` (may migrate to `https://claude.com/api/mcp/auth_callback`)
- Claude's OAuth client name: `Claude`
- Claude supports Dynamic Client Registration (DCR)
- Claude supports both SSE and Streamable HTTP transports (SSE may be deprecated)
- Claude supports token expiry and refresh

---

## Architecture

```
MCP Client (claude.ai / Claude Code)
    │
    │  0. MCP request → 401 + WWW-Authenticate header
    │  1. GET /.well-known/oauth-protected-resource  (RFC 9728)
    │  2. GET /.well-known/oauth-authorization-server (RFC 8414)
    │  3. POST /register  (RFC 7591 Dynamic Client Registration)
    │  4. GET /authorize  (PKCE + resource param)
    │  5. POST /token     (+ resource param)
    │  6. MCP requests with Bearer token
    ▼
mcp-auth-proxy  (this service)
    │
    │  Federates auth → OIDC IdP (Keycloak, Entra, Auth0...)
    │  Validates incoming Bearer tokens
    │  Forwards requests to upstream MCP server
    ▼
Upstream MCP Server (target, unmodified)
```

### Stateless design

All transient OAuth state (client registrations, authorize sessions, authorization codes, refresh tokens) is AES-GCM encrypted into the tokens and URL parameters themselves. Any instance sharing the same `TOKEN_SIGNING_SECRET` can handle any request — no shared storage, no sticky sessions.

| Flow state | Encrypted into | Carries audience? |
|---|---|---|
| Client registration | `client_id` (encrypted blob, 24h TTL) | yes |
| Authorize session | IdP `state` parameter (encrypted blob, 10min TTL) | yes |
| Authorization code | `code` parameter (encrypted blob, 60s TTL) | yes |
| Access token | Opaque token (encrypted claims, 1h TTL) | yes |
| Refresh token | Opaque token (encrypted claims + `iat`, 7d TTL) | yes |

#### Audience binding (cross-instance replay protection)

Every sealed payload carries the proxy's `PROXY_BASE_URL` as an `audience` field, populated at creation time and verified on every open. Two deployments accidentally sharing the same `TOKEN_SIGNING_SECRET` (e.g. by copy-pasted Helm values, mirrored DR configs, or a shared `Secret`) cannot replay each other's tokens — the receiving instance rejects any payload whose audience does not match its own `PROXY_BASE_URL`.

The check is enforced in:
- `middleware/auth.go:Validate` — access token bearer check
- `handlers/authorize.go` — `sealedClient` open
- `handlers/callback.go` — `sealedSession` open (before the IdP exchange runs)
- `handlers/token.go:handleAuthorizationCode` — `sealedCode` and `sealedClient` open
- `handlers/token.go:handleRefreshToken` — `sealedRefresh` and `sealedClient` open

Within a single deployment this is invisible: the audience always matches and nothing changes for clients. The cost is one string comparison per check.

Trade-offs:
- **No per-token revocation** without a shared store. Mitigated by short access token TTL (1h), PKCE preventing code replay, and `REVOKE_BEFORE` for bulk revocation.
- **Authorization codes are replayable** within their 60-second TTL when no replay store is configured. Mitigated by PKCE (the attacker also needs the `code_verifier`) and the short window. Set `REDIS_URL` to make codes strictly single-use across replicas (RFC 6749 §4.1.2).
- **Bulk revocation** via `REVOKE_BEFORE`: set to the current timestamp and redeploy — all existing access tokens AND refresh tokens with `iat` before the cutoff are rejected. Refresh tokens carry their own `iat` so an attacker holding a leaked refresh cannot keep minting fresh access tokens past the cutoff. Incident response: rotate `REVOKE_BEFORE` and watch a `kubectl rollout status` complete before assuming the cutoff is enforced fleet-wide.

### Replay protection (optional)

Set `REDIS_URL` (e.g. `redis://redis:6379/0`, or `rediss://` for TLS) to enable two layered protections backed by Redis `SET NX` / `EXISTS`. All Redis keys are namespaced with `REDIS_KEY_PREFIX` (default `mcp-auth-proxy:`) so multiple proxy deployments can safely share a single Redis DB without key collisions:

- **Single-use authorization codes.** Each code carries a unique `tid` (UUID); `/token` claims the key atomically, so a second exchange attempt is rejected with `invalid_grant` + `error_code: code_replay`. Claim TTL matches the remaining code lifetime.
- **Refresh rotation with reuse detection** (RFC 6749 §10.4 / OAuth 2.1 §6.1). Each refresh carries a unique `tid` and a `fam` (family ID shared by all rotations in the lineage). On rotation the old `tid` is claimed; replaying an already-rotated token is detected as reuse, revokes the whole family (`refresh_family_revoked:<fam>` marker, 7-day TTL), and any subsequent use of any sibling refresh is rejected with `error_code: refresh_family_revoked`. This kills the attacker and the legitimate holder simultaneously — both are forced back through `/authorize`, but the compromised lineage stops minting tokens.

On Redis failure the handler fails closed (503 `server_error` / `error_code: replay_store_unavailable`) rather than issuing tokens against an unknown replay state. When `REDIS_URL` is unset the proxy stays fully stateless: codes remain replayable within the 60s TTL (mitigated by PKCE), and refresh tokens rotate without reuse detection.

---

## Configuration

All configuration is via environment variables.

| Variable | Description | Example |
|---|---|---|
| `OIDC_ISSUER_URL` | OIDC Issuer URL (auto-discovery via `/.well-known/openid-configuration`) | `https://keycloak.example.com/realms/myrealm` or `https://login.microsoftonline.com/{tenant}/v2.0` |
| `OIDC_CLIENT_ID` | OIDC client ID registered with the IdP | `xxxxxxxx-...` |
| `OIDC_CLIENT_SECRET` | OIDC client secret | `...` |
| `PROXY_BASE_URL` | Public URL of this proxy | `https://mcp-proxy.example.com` |
| `UPSTREAM_MCP_URL` | Origin of the upstream MCP server (scheme+host+port, no path). Proxy forwards the client `/mcp` path verbatim. If upstream mounts MCP elsewhere (`/api/v1/mcp`, `/sse`, …), put a rewrite layer in front and point this URL at the rewrite layer. Path, query, fragment, userinfo rejected at startup. | `http://mcp-server:8080` |
| `LISTEN_ADDR` | Bind address | `:8080` |
| `METRICS_ADDR` | Prometheus metrics bind address. Default `127.0.0.1:9090` — loopback only so `/metrics` and `/readyz` are never exposed on the public interface. Override to `:9090` or a specific interface when a Prometheus scraper must reach the pod over the network | `127.0.0.1:9090` (default) |
| `TOKEN_SIGNING_SECRET` | Secret for AES-GCM opaque tokens (min 32 bytes, shared across all instances) | `...` |
| `LOG_LEVEL` | `debug`, `info`, `warn` | `info` |
| `GROUPS_CLAIM` | Flat claim name in the OIDC id_token containing user groups | `groups` (default) |
| `ALLOWED_GROUPS` | Comma-separated group allowlist. Empty = allow all authenticated users | `admin,mcp-users` |
| `REVOKE_BEFORE` | RFC3339 timestamp — both access tokens AND refresh tokens with `iat` before this are rejected (bulk revocation). Empty = disabled | `2026-03-28T12:00:00Z` |
| `PKCE_REQUIRED` | Require PKCE on /authorize (default `true`). Set `false` for Cursor, MCP Inspector, ChatGPT compat | `true` |
| `SHUTDOWN_TIMEOUT` | Graceful shutdown deadline. Raise above the longest expected SSE stream so rolling deploys do not cut MCP sessions mid-stream. Match `terminationGracePeriodSeconds` in K8s | `120s` (default) |
| `REDIS_URL` | Enables single-use authorization codes and refresh rotation with reuse detection (OAuth 2.1 §6.1) across replicas. `rediss://` for TLS. On Redis failure the proxy fails closed (503) | `redis://redis:6379/0` |
| `REDIS_REQUIRED` | Fail startup (`logger.Fatal`) when `REDIS_URL` is unset. Default `true` — stateless mode leaves authorization codes / refresh tokens replayable within their TTL (findings C3/C4). Set `false` only for dev or single-replica deployments that accept the trade-off | `true` (default) |
| `REDIS_KEY_PREFIX` | Prefix applied to every Redis key (default `mcp-auth-proxy:`). Override when sharing a Redis DB between multiple proxy deployments to avoid key collisions. Set explicitly to empty (`REDIS_KEY_PREFIX=`) to opt out of namespacing | `prod-mcp:` |
| `RATE_LIMIT_ENABLED` | Per-IP rate limiting on pre-auth endpoints and on the authenticated MCP route (default `true`). Keyed on the stripped `RemoteAddr` by default; set `TRUST_PROXY_HEADERS=true` to honor `X-Forwarded-For`/`X-Real-IP`/`True-Client-IP` behind a trusted frontend | `true` |
| `TRUST_PROXY_HEADERS` | Honor `X-Forwarded-For`/`X-Real-IP`/`True-Client-IP` when keying the rate limiter (default `false`). Enable **only** behind a trusted L4/L7 that sanitizes these headers — otherwise a client can trivially mint its own rate-limit key and bypass the limiter | `false` (default) |
| `MCP_PER_SUBJECT_CONCURRENCY` | Per-subject in-flight request cap on the authenticated MCP route (default `16`). A runaway or compromised client identity cannot saturate the proxy / upstream pool at the expense of others. Entries for subjects with no in-flight work are reclaimed by a background pruner after ≥5 min idle so map memory stays proportional to active principals, not the lifetime set of ever-seen subjects. `0` disables the limit. Excess requests return 503 `temporarily_unavailable` with `Retry-After: 1` and increment `mcp_auth_access_denied_total{reason="subject_concurrency_exceeded"}` | `16` (default) |
| `COMPAT_ALLOW_STATELESS` | When `true`, `/authorize` synthesizes a `state` server-side if the client omits it (legacy MCP Inspector / Cursor). Default `false` — strict mode refuses with 400 `invalid_request` because a silent server-synth hides client-side CSRF bugs. `mcp_auth_access_denied_total{reason="state_missing"}` is incremented either way so operators can see how many clients still rely on the compat path | `false` (default) |
| `MCP_LOG_BODY_MAX` | Max bytes buffered per authenticated request for JSON-RPC method extraction into access logs (default `65536`). `0` disables buffering — no `rpc_method`/`rpc_tool`/`rpc_id` fields are emitted. Only triggered when `Content-Type: application/json` and `Content-Length` is set and within the limit; SSE / chunked uploads pass through untouched | `65536` (default) |

---

## Project structure

```
mcp-auth-proxy/
├── main.go
├── go.mod
├── go.sum
├── config/
│   └── config.go              # env parsing, validation
├── handlers/
│   ├── helpers.go             # OAuthError, sealed types, writeJSON, isLoopback
│   ├── resource_metadata.go   # GET /.well-known/oauth-protected-resource (RFC 9728)
│   ├── discovery.go           # GET /.well-known/oauth-authorization-server (RFC 8414)
│   ├── register.go            # POST /register  (RFC 7591 DCR)
│   ├── authorize.go           # GET /authorize  (+ resource param, RFC 8707)
│   ├── callback.go            # GET /callback  (OIDC IdP return)
│   └── token.go               # POST /token    (+ resource param, RFC 8707)
├── middleware/
│   └── auth.go                # Bearer token validation on MCP routes
├── proxy/
│   └── proxy.go               # reverse proxy to upstream MCP server
├── token/
│   └── token.go               # AES-GCM seal/open, access token issue/validate
├── replay/
│   ├── replay.go              # Store interface + ErrAlreadyClaimed
│   ├── redis.go               # Redis-backed Store (SET NX, SET, EXISTS with prefix)
│   └── memory.go              # In-process Store (tests / single replica)
├── metrics/
│   └── metrics.go             # Prometheus counters for security events
└── Dockerfile
```

---

## Go dependencies

```go
// go.mod
module github.com/babs/mcp-auth-proxy

go 1.26

require (
    github.com/coreos/go-oidc/v3             // OIDC discovery + id_token verification (any IdP)
    golang.org/x/oauth2                      // OAuth2 flow
    github.com/go-chi/chi/v5                 // HTTP router
    github.com/go-chi/httprate               // per-IP rate limiter
    github.com/google/uuid                   // ID generation
    github.com/prometheus/client_golang      // Prometheus metrics
    github.com/redis/go-redis/v9             // optional replay store
    go.uber.org/zap                          // structured logging
    golang.org/x/term                        // TTY detection for log format
)
```

---

## Endpoints

### GET `/.well-known/oauth-protected-resource` — Protected Resource Metadata (RFC 9728)

Response 200 JSON:

```json
{
  "resource": "{PROXY_BASE_URL}/",
  "authorization_servers": ["{PROXY_BASE_URL}"],
  "bearer_methods_supported": ["header"]
}
```

MCP clients use this endpoint to discover which authorization server protects this resource.
No authentication required. The `resource` field is `"/"`-terminated so it matches the RFC 8707 canonicalisation Claude.ai applies to resource indicators.

### GET `/.well-known/oauth-protected-resource/mcp` — per-resource PRM (RFC 9728 §3.1)

Same shape, `resource` = `{PROXY_BASE_URL}/mcp`. MCP clients that scope discovery to the `/mcp` resource path (per RFC 9728 §3.1) fetch this variant instead of the root one.

---

### GET `/.well-known/oauth-authorization-server` — Authorization Server Metadata (RFC 8414)

Also served at `/.well-known/oauth-authorization-server/mcp` (non-spec compat for MCP clients that probe the per-resource suffix). Both paths return the same document.


Response 200 JSON:

```json
{
  "issuer": "{PROXY_BASE_URL}",
  "authorization_endpoint": "{PROXY_BASE_URL}/authorize",
  "token_endpoint": "{PROXY_BASE_URL}/token",
  "registration_endpoint": "{PROXY_BASE_URL}/register",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"]
}
```

PKCE-only proxy: no client secrets are validated.
No authentication required on this endpoint.

---

### POST `/register` — Dynamic Client Registration (RFC 7591)

**Request body (JSON):**
```json
{
  "redirect_uris": ["https://claude.ai/..."],
  "client_name": "Claude",
  "token_endpoint_auth_method": "none"
}
```

**Behavior:**
- Validate that `redirect_uris` is present and non-empty
- OAuth 2.1 §2.3.1: each `redirect_uri` must use HTTPS, or HTTP when pointing at a loopback host. Loopback is recognized via `net.ParseIP().IsLoopback()` (covers the full 127/8 range, `::1`, `::ffff:127.0.0.1`, `::0.0.0.1`) plus the literal `localhost` / `localhost.`. Non-http(s) schemes (e.g. `ftp://`, `ldap://`, `file://`, custom app schemes) are rejected unconditionally even when the host is loopback
- Generate an internal UUID for the client
- Encrypt the whole `{ id, redirect_uris, client_name, expires_at }` with AES-GCM → this is the returned `client_id`
- TTL embedded in the encrypted blob: 24h (clients re-register)
- Request body limited to 1 MB (`MaxBytesReader`)

**Response 201 JSON:**
```json
{
  "client_id": "<encrypted blob>",
  "client_id_issued_at": 1234567890,
  "redirect_uris": ["..."],
  "token_endpoint_auth_method": "none"
}
```

---

### GET `/authorize`

**Query params:**
- `response_type=code` (required, reject otherwise)
- `client_id` (required, decrypt and validate not expired)
- `redirect_uri` (required, must match a registered URI — exact match)
- `code_challenge` (required if `PKCE_REQUIRED=true`, optional otherwise)
- `code_challenge_method=S256` (required if `code_challenge` present)
- `state` (optional — if absent, a random state is generated server-side for Cursor/MCP Inspector compatibility)
- `resource` (optional, RFC 8707 — accepted, identifies the target MCP server)

**Behavior:**
1. Validate all params
2. Decrypt the `client_id` → verify not expired, `redirect_uri` matched
3. Encrypt the session with AES-GCM (10min TTL):
   ```
   {
     client_id (internal UUID),
     redirect_uri, code_challenge,
     original_state,
     expires_at
   }
   ```
4. Use the encrypted blob as the `state` parameter sent to the IdP
5. Build the authorization URL from endpoints discovered via OIDC auto-discovery:
   ```
   {discovered_authorization_endpoint}
     ?client_id={OIDC_CLIENT_ID}
     &response_type=code
     &redirect_uri={PROXY_BASE_URL}/callback
     &scope=openid email profile
     &state={encrypted_session}
     &response_mode=query
   ```
6. Redirect 302 to the IdP

---

### GET `/callback`

**Query params:** `code`, `state` (from the IdP)

**Behavior:**
1. If the IdP returns an `error` (RFC 6749 §4.1.2.1), propagate it to the client
2. Decrypt the `state` → retrieve the session, verify not expired
3. Exchange the code with the IdP (POST token endpoint, 10s timeout) to obtain `id_token` + `access_token`
4. Validate the `id_token` via go-oidc (JWKS signature auto-discovery, issuer, audience)
5. Extract claims: `sub`, `email`, `email_verified`, `name`
6. If `email_verified` is present and false, reject with 403 `access_denied` + `error_code: email_not_verified` (absent claim is accepted — not all IdPs emit it)
7. Extract groups from the configured claim (`GROUPS_CLAIM`, default `groups`)
8. If `ALLOWED_GROUPS` is configured, verify the user belongs to at least one allowed group → 403 otherwise
9. Encrypt an internal authorization code with AES-GCM (60s TTL):
   ```
   {
     token_id (UUID, used for single-use replay check),
     client_id (internal UUID),
     redirect_uri, code_challenge,
     subject, email, name, groups,
     expires_at
   }
   ```
10. Redirect 302 to `redirect_uri?code={encrypted_code}&state={original_state}`
    - Built via `url.Parse` + merged query params (safe even if redirect_uri already contains query params)

---

### POST `/token`

**Request body (application/x-www-form-urlencoded, max 1 MB):**

For `grant_type=authorization_code`:
```
grant_type=authorization_code
&code=<encrypted internal code>
&redirect_uri=<must match>
&client_id=<must match>
&code_verifier=<PKCE verifier, 43-128 chars per RFC 7636 §4.1>
```

For `grant_type=refresh_token`:
```
grant_type=refresh_token
&refresh_token=<encrypted token>
&client_id=<must match>
```

**Behavior — authorization_code:**
1. Validate `code_verifier` length (43-128 chars, RFC 7636 §4.1)
2. Decrypt the code, verify not expired
3. Decrypt the `client_id`, verify not expired
4. Verify `client_id` (internal UUID) and `redirect_uri` match the code
5. Validate PKCE: base64url-encoded `SHA256(code_verifier)` == stored `code_challenge` (constant-time comparison)
6. If `REDIS_URL` is configured, atomically claim the code's `token_id` via `SET NX`. A second attempt is rejected with `invalid_grant` + `error_code: code_replay`; Redis failures fail closed with 503
7. Issue an opaque access token (AES-GCM, 1h TTL) and a refresh token (AES-GCM, 7d TTL)

**Behavior — refresh_token:**
1. Decrypt the refresh token, verify its `audience` matches `PROXY_BASE_URL`
2. If `REVOKE_BEFORE` is configured, reject if refresh `iat` < cutoff (bulk revocation applies to refresh tokens too, not only access tokens)
3. Verify the refresh is not expired
4. Decrypt the `client_id`, verify audience + not expired + UUID matches the refresh
5. If `REDIS_URL` is configured:
   a. Reject if `refresh_family_revoked:<fam>` is set (prior reuse killed the family)
   b. Atomically claim `refresh:<tid>` via `SET NX`. If already claimed → reuse detected: mark the family revoked for 7 days, reject with `error_code: refresh_reuse_detected`. Any subsequent sibling refresh also gets rejected in step 5a
6. Issue new access + refresh tokens. The new refresh inherits the original `fam` (so reuse detection spans the lineage) and gets a fresh `tid`. `iat` is set to `now` so it survives the next `REVOKE_BEFORE` application

**Response 200 JSON:**
```json
{
  "access_token": "<opaque token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque refresh token>"
}
```

Headers `Cache-Control: no-store` and `Pragma: no-cache` required (RFC 6749 §5.1).

**Standard OAuth2 errors:**
```json
{ "error": "invalid_grant", "error_description": "...", "error_code": "..." }
```

`error_code` is an optional extension field for machine-readable internal
error identifiers. Clients must treat it as advisory and rely on the
standard `error` field for OAuth behavior.

---

## Internal token

Opaque format: JSON → AES-GCM encryption with `TOKEN_SIGNING_SECRET` → base64url.

**Access token payload:**

```go
type Claims struct {
    TokenID   string    // UUID
    Audience  string    // PROXY_BASE_URL — bound at issuance, verified on every Validate
    Subject   string    // IdP sub
    Email     string
    Groups    []string  // from GROUPS_CLAIM in id_token
    ClientID  string
    IssuedAt  time.Time
    ExpiresAt time.Time
}
```

**Refresh token payload** (sealed identically; `TokenID` and `FamilyID` drive the optional Redis-backed reuse detection):

```go
type sealedRefresh struct {
    TokenID   string    // UUID, unique per refresh (single-use key when Redis is wired)
    FamilyID  string    // UUID, constant across rotations — shared by every sibling in the lineage
    Subject   string
    Email     string
    Groups    []string
    ClientID  string
    Audience  string
    IssuedAt  time.Time // used by REVOKE_BEFORE bulk revocation
    ExpiresAt time.Time
}
```

No JWT exposed — opaque token only on the MCP client side. Validated by AES-GCM decryption + audience check + expiry. No store required.

---

## Auth middleware (MCP routes)

All MCP routes (`/*` except OAuth endpoints):

1. Extract `Authorization: Bearer <token>`
2. Decode and validate the opaque token (AES-GCM decryption, expiry check)
3. Verify `claims.Audience == PROXY_BASE_URL` — rejects tokens minted by a sibling instance sharing the same secret but with a different baseURL
4. If `REVOKE_BEFORE` is configured, reject if `iat` < cutoff (bulk revocation)
5. Inject into context: `sub`, `email`, `groups`
6. On failure, return `401` per RFC 6750 §3.1:
   - Missing or malformed `Authorization` header → `{ "error": "invalid_request" }`
   - Token decrypt/expiry/audience/iat failures → `{ "error": "invalid_token" }`
   Both responses include `WWW-Authenticate: Bearer error="<code>", resource_metadata="{PROXY_BASE_URL}/.well-known/oauth-protected-resource"` (RFC 9728 §5.1).

---

## MCP proxy

After auth middleware passes:

```go
// Forward to upstream MCP server
// Client request path forwarded verbatim; UPSTREAM_MCP_URL is origin-only
// Added headers:
r.Header.Set("X-User-Sub", claims.Subject)
r.Header.Set("X-User-Email", claims.Email)
r.Header.Set("X-User-Groups", "group1,group2")  // comma-separated, omitted if empty
r.Header.Del("Authorization")  // do not leak the internal token

// Support SSE (text/event-stream): no response buffering
// Support Streamable HTTP (chunked): immediate flush
```

Use `httputil.ReverseProxy` with `FlushInterval: -1` (immediate flush) to support SSE and streaming. The underlying `*http.Transport` sets `ResponseHeaderTimeout: 30s` so a wedged upstream fails fast during header negotiation — stream bodies themselves remain uncapped. The transport follows 307/308 redirects server-side (Python FastAPI/Starlette backends), same-host only, body replayed, max 10 hops. On exhaustion the proxy responds **502 Bad Gateway** with `{"error":"bad_gateway","error_description":"too many upstream redirects"}` rather than echoing the last 307/308 (which would leak a broken upstream `Location:` to the MCP client). Proxied request bodies are capped at 16 MiB via `http.MaxBytesReader` to bound the memory the redirect-follow buffer can hold.

### Upstream path handling

`UPSTREAM_MCP_URL` is origin-only (scheme + host + port). The client request path is forwarded verbatim — no join, no strip, no rewrite. The proxy exposes `/mcp` on the client side, so the upstream receives `/mcp` on the same origin.

Real-world MCP endpoints use many paths:

| Product | Path |
|---|---|
| FastMCP (Python) default | `/mcp` |
| GitHub Copilot (`api.githubcopilot.com`) | `/mcp` |
| Cloudflare (`mcp.cloudflare.com`) | `/mcp` |
| Atlassian Rovo | `/v1/mcp` |
| GitLab | `/api/v4/mcp` |

When the upstream mounts MCP anywhere other than `/mcp`, put a rewrite layer between this proxy and the upstream (Ingress rule, k8s Service middleware, nginx/envoy sidecar) and point `UPSTREAM_MCP_URL` at that layer. This proxy does not rewrite paths.

Path, query, fragment, and userinfo on `UPSTREAM_MCP_URL` are rejected at startup.

---

## Routing (chi)

```go
r := chi.NewRouter()

// Global middlewares
r.Use(chimw.RequestID)
r.Use(zapMiddleware(logger))
r.Use(chimw.Recoverer)

// OAuth endpoints (no auth). /register, /authorize, /callback, /token are
// wrapped in per-IP rate limiters (httprate.LimitByIP) when
// cfg.RateLimitEnabled is true — otherwise a passthrough middleware is used
// so the router composition stays identical in both modes. replayStore is
// optional (nil when REDIS_URL is unset); when non-nil, /token enforces
// single-use authorization codes and refresh rotation with reuse detection.
registerDiscoveryRoutes(r, cfg.ProxyBaseURL) // PRM + AS metadata (root & /mcp) + 404 carve-outs
r.With(registerLimit).Post("/register", handlers.Register(tm, logger, cfg.ProxyBaseURL))
r.With(authorizeLimit).Get("/authorize", handlers.Authorize(tm, logger, cfg.ProxyBaseURL, oauth2Cfg, handlers.AuthorizeConfig{
    PKCERequired: cfg.PKCERequired,
}))
r.With(callbackLimit).Get("/callback", handlers.Callback(tm, logger, cfg.ProxyBaseURL, oauth2Cfg, idTokenVerifier, handlers.CallbackConfig{
    AllowedGroups: cfg.AllowedGroups,
    GroupsClaim:   cfg.GroupsClaim,
}))
r.With(tokenLimit).Post("/token", handlers.Token(tm, logger, cfg.ProxyBaseURL, cfg.RevokeBefore, replayStore))

// Liveness: 200 as long as the process is up.
r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
})

// Readiness: probes Redis (1s timeout) when REDIS_URL is set, so a
// degraded pod drops out of a K8s Service until Redis recovers.
r.Get("/readyz", readyzHandler(replayStore, logger))

// MCP proxy (auth required). Mounted at /mcp only — any non-/mcp
// path on the proxy is 404 by the router. UPSTREAM_MCP_URL is
// origin-only (scheme+host+port); the proxy forwards the client
// request path verbatim so upstream and client share the same
// namespace. Upstream must serve MCP at /mcp.
r.Group(func(r chi.Router) {
    r.Use(authMW.Validate)
    r.Handle("/mcp", proxyHandler)
    r.Handle("/mcp/*", proxyHandler)
})
```

---

## OAuth2 error handling

Always return errors conforming to RFC 6749:

```go
type OAuthError struct {
    Error            string `json:"error"`
    ErrorDescription string `json:"error_description,omitempty"`
    ErrorCode        string `json:"error_code,omitempty"`
}
```

**Standard `error` values** (RFC 6749 §5.2): `invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`, `server_error`, `access_denied`, `temporarily_unavailable`.

**Extension `error_code` values** (proxy-specific, advisory — clients MUST rely on `error` for OAuth behavior):

| `error_code` | When | Paired `error` |
|---|---|---|
| `code_replay` | Authorization code reused (requires Redis) | `invalid_grant` |
| `refresh_reuse_detected` | Refresh token replayed after rotation → family revoked (requires Redis) | `invalid_grant` |
| `refresh_family_revoked` | Refresh token whose family was previously revoked | `invalid_grant` |
| `email_not_verified` | id_token `email_verified` is `false` | `access_denied` |
| `subject_missing` | IdP returned a verified id_token without a `sub` claim (L5) | `access_denied` |
| `group_invalid` | IdP group name contains `,` `\r` `\n` `\x00` | `access_denied` |
| `replay_store_unavailable` | Redis unreachable; handler fails closed | `server_error` |
| `id_token_verification_failed` | go-oidc rejected the IdP id_token | `server_error` |
| `token_issue_failed` | AES-GCM seal error when minting an access token | `server_error` |

IdP-supplied `error` values on `/callback` are allowlisted against the
RFC 6749 §4.1.2.1 set (`invalid_request`, `invalid_client`,
`unauthorized_client`, `access_denied`, `unsupported_response_type`,
`invalid_scope`, `server_error`, `temporarily_unavailable`); anything
outside that set is rewritten to `server_error` before being echoed to
the MCP client. `error_description` is truncated at 200 bytes and
stripped of non-ASCII-printable bytes to defeat log / header injection.

---

## Dockerfile

```dockerfile
FROM golang:1.26-alpine AS builder

ARG VERSION="v0.0.0"
ARG COMMIT_HASH="00000000-dirty"
ARG BUILD_TIMESTAMP="1970-01-01T00:00:00+00:00"
ARG BUILDER="unknown"
ARG PROJECT_URL="https://github.com/babs/mcp-auth-proxy"

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
      -X 'main.Version=${VERSION}' \
      -X 'main.CommitHash=${COMMIT_HASH}' \
      -X 'main.BuildTimestamp=${BUILD_TIMESTAMP}' \
      -X 'main.Builder=${BUILDER}' \
      -X 'main.ProjectURL=${PROJECT_URL}'" \
    -o mcp-auth-proxy ./main.go

# distroless/static-debian13:nonroot ships ca-certificates and runs as UID
# 65532 by default — no shell, no apt, minimal attack surface. The static
# Go binary (CGO_ENABLED=0) needs nothing else.
FROM gcr.io/distroless/static-debian13:nonroot

ARG BUILD_TIMESTAMP="1970-01-01T00:00:00+00:00"
ARG COMMIT_HASH="00000000-dirty"
ARG PROJECT_URL="https://github.com/babs/mcp-auth-proxy"
ARG VERSION="v0.0.0"

LABEL org.opencontainers.image.source=${PROJECT_URL}
LABEL org.opencontainers.image.created=${BUILD_TIMESTAMP}
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.revision=${COMMIT_HASH}

COPY --from=builder /app/mcp-auth-proxy /usr/local/bin/mcp-auth-proxy

USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/mcp-auth-proxy"]
```

---

## Constraints and implementation notes

- **Stateless**: no shared store required — all transient state is encrypted in tokens/params
- **Scalable**: any instance sharing the same `TOKEN_SIGNING_SECRET` can handle any request
- **No client-side state**: no cookies, everything in query params / headers
- **PKCE**: `S256` only (if provided). Strict by default (`PKCE_REQUIRED=true`). Set `false` for clients that omit PKCE (Cursor, MCP Inspector, ChatGPT). `code_verifier` must be 43-128 chars when present
- **Audience binding**: every sealed payload (client_id, session, code, refresh, access token) carries `PROXY_BASE_URL` as `audience` and is rejected if a sibling instance with a different baseURL receives it. Defends against accidental cross-deployment secret reuse
- **Refresh-token bulk revocation**: `REVOKE_BEFORE` applies to refresh tokens too — a leaked refresh cannot mint fresh access tokens past the cutoff. Refresh tokens carry their own `iat` for this check
- **redirect_uri**: exact match; `http://` allowed only to a loopback host (full 127/8 range, `::1`, `::ffff:127.0.0.1`, `::0.0.0.1`, `localhost`, `localhost.`); non-http(s) schemes rejected even on loopback; fragments and userinfo rejected; length capped at 512 chars; at most 5 entries per client registration
- **Structured logs**: zap, JSON format, include `request_id` in each log. Inbound `X-Request-Id` is stripped before chi mints one, to prevent log-forgery via client-controlled IDs. Authenticated requests additionally carry `sub` and `email` from the bearer token. JSON-RPC requests to the upstream MCP server also carry `rpc_method` (e.g. `tools/call`), `rpc_tool` (the `params.name` field), and `rpc_id`. `rpc_method` and `rpc_tool` are capped at 128 characters, `rpc_id` at 64; all three pass through a narrow allowlist (ASCII alphanumerics plus `._:/-+`), so arbitrary attacker-supplied strings cannot bloat or smuggle into log lines. Set `MCP_LOG_BODY_MAX=0` to suppress the `rpc_*` fields entirely
- **Business metrics**: alongside the Prometheus Go runtime counters, the `metrics` package emits `mcp_auth_tokens_issued_total{grant_type}`, `mcp_auth_access_denied_total{reason}`, `mcp_auth_replay_detected_total{kind}`, `mcp_auth_rate_limited_total{endpoint}`, and `mcp_auth_clients_registered_total` so security-relevant events are alertable
- **Graceful shutdown**: context with SIGINT/SIGTERM signals, deadline configurable via `SHUTDOWN_TIMEOUT` (default 120s) — calibrate to the expected SSE stream duration to avoid cutting ongoing MCP sessions during a rolling deploy. The K8s `terminationGracePeriodSeconds` must be ≥ `SHUTDOWN_TIMEOUT`
- **Timeouts**: `ReadTimeout: 30s`, `WriteTimeout: 0` (SSE), `IdleTimeout: 120s`
- **Proxy must support SSE**: do not buffer `text/event-stream` responses, immediate flush required
- **Body size limit**: POST endpoints limited to 1 MB (`MaxBytesReader`)
- **Rate limiting**: per-IP rate limits on `/register` (10/min), `/authorize` (30/min), `/callback` (30/min), `/token` (60/min). Enabled by default; disable via `RATE_LIMIT_ENABLED=false`. The limiter keys on `X-Forwarded-For`/`X-Real-IP`/`RemoteAddr`, so deployments must terminate behind a trusted L4/L7 frontend — otherwise the headers can be spoofed
- **Email verification**: `email_verified=false` in the id_token is rejected at `/callback` with 403 `access_denied` + `error_code: email_not_verified`. Missing claim is accepted — not all IdPs emit it
- **Replay protection (optional, Redis-gated)**: set `REDIS_URL` to enable two layered controls — (1) single-use authorization codes via `SET NX` on the code's `tid`, and (2) refresh rotation with reuse detection per OAuth 2.1 §6.1: each refresh carries a `tid` + `fam` (family id, shared across rotations); replaying an already-rotated refresh revokes the whole family for 7 days, forcing the lineage back through `/authorize`. On Redis failure the handler fails closed with 503. Without Redis, codes are replayable within the 60s TTL (mitigated by PKCE + audience) and refresh tokens rotate without reuse detection
- **Group filtering**: optional via `ALLOWED_GROUPS` — enforced at callback time (403 before code issuance). Groups propagated through sealed chain to upstream `X-User-Groups` header
- **State parameter**: if client omits `state` (MCP Inspector, Cursor), a random 32-char hex value is generated server-side
- **307/308 redirect following**: proxy follows 307/308 redirects server-side for Python MCP backends (FastAPI/Starlette redirect `/mcp` → `/mcp/`). Same-host only, body replayed, max 10 hops
- **Resource URI**: `/.well-known/oauth-protected-resource` returns `resource` with trailing slash for Claude.ai compatibility (RFC 8707)
- **Tests**: unit tests on PKCE validation, token issue/validate, `/register`, `/authorize`, `/token` handlers, group filtering, audience-rejection across all sealed types, `REVOKE_BEFORE` on refresh tokens, authorization-code single-use (with an in-memory replay store), PKCE failure not burning a code, refresh rotation with reuse detection revoking the whole family, miniredis-backed tests for Redis prefixing and cross-deployment isolation, Go 1.22 fuzz targets on the AES-GCM open path (`FuzzOpenJSON`, `FuzzValidate`), and a full E2E flow against a mock OIDC provider including `email_verified=false` rejection and `email_verified=true` acceptance

---

## Multi-instance deployment (K8s)

The stateless design supports horizontal scaling without sticky sessions. Required configuration symmetry across replicas:

1. **`TOKEN_SIGNING_SECRET`** — must be byte-identical (mount from a `Secret`, not generated per-pod). The single most important invariant: a mismatch breaks every cross-pod token validation.
2. **`PROXY_BASE_URL`** — must be the public DNS name reached by clients, not a per-pod hostname. Audience binding enforces this — a pod with a wrong `PROXY_BASE_URL` will reject every token minted by its siblings.
3. **`OIDC_*`** — same registration on the same IdP.
4. **`UPSTREAM_MCP_URL`** — same in-cluster service URL.
5. **`PKCE_REQUIRED`, `ALLOWED_GROUPS`, `GROUPS_CLAIM`, `REVOKE_BEFORE`, `REDIS_URL`, `REDIS_KEY_PREFIX`, `RATE_LIMIT_ENABLED`** — any asymmetry produces "works on some pods, not others" bugs. `REDIS_URL` + `REDIS_KEY_PREFIX` in particular must match across all replicas, otherwise single-use and reuse-detection guarantees only hold within each pod's local set of clients.

Recommended Deployment shape:

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  replicas: 3
  strategy:
    rollingUpdate:
      maxUnavailable: 0
      maxSurge: 1
  template:
    spec:
      terminationGracePeriodSeconds: 120  # match SHUTDOWN_TIMEOUT
      containers:
      - name: mcp-auth-proxy
        envFrom:
        - secretRef:
            name: mcp-auth-proxy-secret
        - configMapRef:
            name: mcp-auth-proxy-config
        readinessProbe:
          httpGet:
            path: /healthz
            port: 8080
        ports:
        - { name: http,    containerPort: 8080 }
        - { name: metrics, containerPort: 9090 }
---
apiVersion: v1
kind: Service
spec:
  sessionAffinity: None  # explicit; no stickiness needed
  selector: { app: mcp-auth-proxy }
  ports:
  - { name: http, port: 80, targetPort: 8080 }
```

Ship a `PodDisruptionBudget` with `minAvailable: 1` (or 2 for ≥3 replicas) so node drains do not take out the whole auth plane at once.

The `manifests/` folder ships a turn-key demo: a Docker Compose stack (Keycloak + Redis + fake MCP upstream + proxy) for local exploration and a Kubernetes reference set (`Deployment`, `Service`, `Ingress`, `PodDisruptionBudget`, plus `scripts/generate-signing-secret.sh`).

### Bulk revocation rollout caveat

`REVOKE_BEFORE` is read at startup. Updating it requires a rolling restart, and during the rollout window some pods enforce the new cutoff while others still use the old one. Wait for `kubectl rollout status` to converge before assuming the cutoff is fleet-wide enforced.

---

## Startup validation

`config.Load()` fails closed on the following config mistakes (fatal at startup):

- `TOKEN_SIGNING_SECRET` shorter than 32 bytes.
- `SHUTDOWN_TIMEOUT` non-positive or greater than 15 minutes (L2).
- `REDIS_KEY_PREFIX` containing `{`, `}`, `\r`, `\n`, or any byte outside the 0x20..0x7E ASCII-printable range (L3).
- `PROXY_BASE_URL` with a scheme other than `https://` (or `http://` to a loopback host), a non-empty userinfo, a fragment, or a path beyond `/` (L8).
- `MCP_LOG_BODY_MAX` / `MCP_PER_SUBJECT_CONCURRENCY` not parseable as non-negative integers.
- `SHUTDOWN_TIMEOUT` / `REVOKE_BEFORE` unparseable as duration / RFC3339.

Non-fatal startup warnings:

- `token_signing_secret_weak` fires when the 32-byte secret has fewer than 16 distinct byte values — signals a human-typed / patterned secret whose effective entropy is well below its length (L1).
- `token_seal_rotation_threshold` fires once after 2^28 successful seals per Manager, suggesting `TOKEN_SIGNING_SECRET` rotation before AES-GCM nonce-collision bounds matter (L6).
