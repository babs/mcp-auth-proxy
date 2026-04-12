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
| Authorization code | `code` parameter (encrypted blob, 5min TTL) | yes |
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
- **Authorization codes are replayable** within their 5-minute TTL. Mitigated by PKCE — the attacker also needs the `code_verifier`.
- **Bulk revocation** via `REVOKE_BEFORE`: set to the current timestamp and redeploy — all existing access tokens AND refresh tokens with `iat` before the cutoff are rejected. Refresh tokens carry their own `iat` so an attacker holding a leaked refresh cannot keep minting fresh access tokens past the cutoff. Incident response: rotate `REVOKE_BEFORE` and watch a `kubectl rollout status` complete before assuming the cutoff is enforced fleet-wide.

---

## Configuration

All configuration is via environment variables.

| Variable | Description | Example |
|---|---|---|
| `OIDC_ISSUER_URL` | OIDC Issuer URL (auto-discovery via `/.well-known/openid-configuration`) | `https://keycloak.example.com/realms/myrealm` or `https://login.microsoftonline.com/{tenant}/v2.0` |
| `OIDC_CLIENT_ID` | OIDC client ID registered with the IdP | `xxxxxxxx-...` |
| `OIDC_CLIENT_SECRET` | OIDC client secret | `...` |
| `PROXY_BASE_URL` | Public URL of this proxy | `https://mcp-proxy.example.com` |
| `UPSTREAM_MCP_URL` | URL of the target MCP server (path prefix preserved) | `http://mcp-server:8080` or `http://mcp-server:8080/api` |
| `LISTEN_ADDR` | Bind address | `:8080` |
| `METRICS_ADDR` | Prometheus metrics bind address | `:9090` |
| `TOKEN_SIGNING_SECRET` | Secret for AES-GCM opaque tokens (min 32 bytes, shared across all instances) | `...` |
| `LOG_LEVEL` | `debug`, `info`, `warn` | `info` |
| `GROUPS_CLAIM` | Flat claim name in the OIDC id_token containing user groups | `groups` (default) |
| `ALLOWED_GROUPS` | Comma-separated group allowlist. Empty = allow all authenticated users | `admin,mcp-users` |
| `REVOKE_BEFORE` | RFC3339 timestamp — both access tokens AND refresh tokens with `iat` before this are rejected (bulk revocation). Empty = disabled | `2026-03-28T12:00:00Z` |
| `PKCE_REQUIRED` | Require PKCE on /authorize (default `true`). Set `false` for Cursor, MCP Inspector, ChatGPT compat | `true` |
| `SHUTDOWN_TIMEOUT` | Graceful shutdown deadline. Raise above the longest expected SSE stream so rolling deploys do not cut MCP sessions mid-stream. Match `terminationGracePeriodSeconds` in K8s | `120s` (default) |

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
    github.com/google/uuid                   // ID generation
    github.com/prometheus/client_golang      // Prometheus metrics
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
  "resource": "{PROXY_BASE_URL}",
  "authorization_servers": ["{PROXY_BASE_URL}"],
  "bearer_methods_supported": ["header"]
}
```

MCP clients use this endpoint to discover which authorization server protects this resource.
No authentication required.

---

### GET `/.well-known/oauth-authorization-server`

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
- OAuth 2.1 §2.3.1: each `redirect_uri` must use HTTPS (except loopback: `localhost`, `127.0.0.1`, `::1`)
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
5. Extract claims: `sub`, `email`, `name`
6. Extract groups from the configured claim (`GROUPS_CLAIM`, default `groups`)
7. If `ALLOWED_GROUPS` is configured, verify the user belongs to at least one allowed group → 403 otherwise
8. Encrypt an internal authorization code with AES-GCM (5min TTL):
   ```
   {
     client_id (internal UUID),
     redirect_uri, code_challenge,
     subject, email, name, groups,
     expires_at
   }
   ```
9. Redirect 302 to `redirect_uri?code={encrypted_code}&state={original_state}`
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
6. Issue an opaque access token (AES-GCM, 1h TTL) and a refresh token (AES-GCM, 7d TTL)

**Behavior — refresh_token:**
1. Decrypt the refresh token, verify its `audience` matches `PROXY_BASE_URL`
2. If `REVOKE_BEFORE` is configured, reject if refresh `iat` < cutoff (bulk revocation applies to refresh tokens too, not only access tokens)
3. Verify the refresh is not expired
4. Decrypt the `client_id`, verify audience + not expired + UUID matches the refresh
5. Issue new access + refresh tokens (the new refresh carries an `iat` set to `now`, so it survives the next `REVOKE_BEFORE` application)

**Response 200 JSON:**
```json
{
  "access_token": "<opaque token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque refresh token>"
}
```

Header `Cache-Control: no-store` required (RFC 6749 §5.1).

**Standard OAuth2 errors:**
```json
{ "error": "invalid_grant", "error_description": "..." }
```

---

## Internal token

Opaque format: JSON → AES-GCM encryption with `TOKEN_SIGNING_SECRET` → base64url.

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

No JWT exposed — opaque token only on the MCP client side. Validated by AES-GCM decryption + audience check + expiry. No store required.

---

## Auth middleware (MCP routes)

All MCP routes (`/*` except OAuth endpoints):

1. Extract `Authorization: Bearer <token>`
2. Decode and validate the opaque token (AES-GCM decryption, expiry check)
3. Verify `claims.Audience == PROXY_BASE_URL` — rejects tokens minted by a sibling instance sharing the same secret but with a different baseURL
4. If `REVOKE_BEFORE` is configured, reject if `iat` < cutoff (bulk revocation)
5. Inject into context: `sub`, `email`, `groups`
6. If invalid: `401 { "error": "invalid_token" }` with header `WWW-Authenticate: Bearer resource_metadata="{PROXY_BASE_URL}/.well-known/oauth-protected-resource"` (RFC 9728 §5.1)

---

## MCP proxy

After auth middleware passes:

```go
// Forward to upstream MCP server
// Path prefix from UPSTREAM_MCP_URL is preserved (e.g. /api)
// Added headers:
r.Header.Set("X-User-Sub", claims.Subject)
r.Header.Set("X-User-Email", claims.Email)
r.Header.Set("X-User-Groups", "group1,group2")  // comma-separated, omitted if empty
r.Header.Del("Authorization")  // do not leak the internal token

// Support SSE (text/event-stream): no response buffering
// Support Streamable HTTP (chunked): immediate flush
```

Use `httputil.ReverseProxy` with `FlushInterval: -1` (immediate flush) to support SSE and streaming. The transport follows 307/308 redirects server-side (Python FastAPI/Starlette backends), same-host only, body replayed, max 10 hops.

---

## Routing (chi)

```go
r := chi.NewRouter()

// Global middlewares
r.Use(chimw.RequestID)
r.Use(zapMiddleware(logger))
r.Use(chimw.Recoverer)

// OAuth endpoints (no auth)
r.Get("/.well-known/oauth-protected-resource", handlers.ResourceMetadata(cfg.ProxyBaseURL))
r.Get("/.well-known/oauth-authorization-server", handlers.Discovery(cfg.ProxyBaseURL))
r.Post("/register", handlers.Register(tm, logger, cfg.ProxyBaseURL))
r.Get("/authorize", handlers.Authorize(tm, logger, cfg.ProxyBaseURL, oauth2Cfg, handlers.AuthorizeConfig{
    PKCERequired: cfg.PKCERequired,
}))
r.Get("/callback", handlers.Callback(tm, logger, cfg.ProxyBaseURL, oauth2Cfg, idTokenVerifier, handlers.CallbackConfig{
    AllowedGroups: cfg.AllowedGroups,
    GroupsClaim:   cfg.GroupsClaim,
}))
r.Post("/token", handlers.Token(tm, logger, cfg.ProxyBaseURL, cfg.RevokeBefore))

// Health
r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
})

// MCP proxy (auth required)
r.Group(func(r chi.Router) {
    r.Use(authMW.Validate)
    r.Handle("/*", proxyHandler)
})
```

---

## OAuth2 error handling

Always return errors conforming to RFC 6749:

```go
type OAuthError struct {
    Error            string `json:"error"`
    ErrorDescription string `json:"error_description,omitempty"`
}

// Error codes to use:
// invalid_request, invalid_client, invalid_grant,
// unauthorized_client, unsupported_grant_type,
// invalid_scope, server_error
```

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

FROM debian:bookworm-slim

ARG BUILD_TIMESTAMP="1970-01-01T00:00:00+00:00"
ARG COMMIT_HASH="00000000-dirty"
ARG PROJECT_URL="https://github.com/babs/mcp-auth-proxy"
ARG VERSION="v0.0.0"

LABEL org.opencontainers.image.source=${PROJECT_URL}
LABEL org.opencontainers.image.created=${BUILD_TIMESTAMP}
LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.revision=${COMMIT_HASH}

# Security: install CA certs for TLS, then run as non-root
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r app && useradd -r -g app -s /usr/sbin/nologin app

COPY --from=builder /app/mcp-auth-proxy /usr/local/bin/mcp-auth-proxy

USER app:app
EXPOSE 8080
ENTRYPOINT ["mcp-auth-proxy"]
```

---

## Constraints and implementation notes

- **Stateless**: no shared store required — all transient state is encrypted in tokens/params
- **Scalable**: any instance sharing the same `TOKEN_SIGNING_SECRET` can handle any request
- **No client-side state**: no cookies, everything in query params / headers
- **PKCE**: `S256` only (if provided). Strict by default (`PKCE_REQUIRED=true`). Set `false` for clients that omit PKCE (Cursor, MCP Inspector, ChatGPT). `code_verifier` must be 43-128 chars when present
- **Audience binding**: every sealed payload (client_id, session, code, refresh, access token) carries `PROXY_BASE_URL` as `audience` and is rejected if a sibling instance with a different baseURL receives it. Defends against accidental cross-deployment secret reuse
- **Refresh-token bulk revocation**: `REVOKE_BEFORE` applies to refresh tokens too — a leaked refresh cannot mint fresh access tokens past the cutoff. Refresh tokens carry their own `iat` for this check
- **redirect_uri**: exact match, HTTPS required except loopback (`localhost`, `127.0.0.1`, `::1`)
- **Structured logs**: zap, JSON format, include `request_id` in each log
- **Graceful shutdown**: context with SIGINT/SIGTERM signals, deadline configurable via `SHUTDOWN_TIMEOUT` (default 120s) — calibrate to the expected SSE stream duration to avoid cutting ongoing MCP sessions during a rolling deploy. The K8s `terminationGracePeriodSeconds` must be ≥ `SHUTDOWN_TIMEOUT`
- **Timeouts**: `ReadTimeout: 30s`, `WriteTimeout: 0` (SSE), `IdleTimeout: 120s`
- **Proxy must support SSE**: do not buffer `text/event-stream` responses, immediate flush required
- **Body size limit**: POST endpoints limited to 1 MB (`MaxBytesReader`)
- **Group filtering**: optional via `ALLOWED_GROUPS` — enforced at callback time (403 before code issuance). Groups propagated through sealed chain to upstream `X-User-Groups` header
- **State parameter**: if client omits `state` (MCP Inspector, Cursor), a random 32-char hex value is generated server-side
- **307/308 redirect following**: proxy follows 307/308 redirects server-side for Python MCP backends (FastAPI/Starlette redirect `/mcp` → `/mcp/`). Same-host only, body replayed, max 10 hops
- **Resource URI**: `/.well-known/oauth-protected-resource` returns `resource` with trailing slash for Claude.ai compatibility (RFC 8707)
- **Tests**: unit tests on PKCE validation, token issue/validate, `/register`, `/authorize`, `/token` handlers, group filtering, audience-rejection across all sealed types, REVOKE_BEFORE on refresh tokens, plus a full E2E test with a mock OIDC provider

---

## Multi-instance deployment (K8s)

The stateless design supports horizontal scaling without sticky sessions. Required configuration symmetry across replicas:

1. **`TOKEN_SIGNING_SECRET`** — must be byte-identical (mount from a `Secret`, not generated per-pod). The single most important invariant: a mismatch breaks every cross-pod token validation.
2. **`PROXY_BASE_URL`** — must be the public DNS name reached by clients, not a per-pod hostname. Audience binding enforces this — a pod with a wrong `PROXY_BASE_URL` will reject every token minted by its siblings.
3. **`OIDC_*`** — same registration on the same IdP.
4. **`UPSTREAM_MCP_URL`** — same in-cluster service URL.
5. **`PKCE_REQUIRED`, `ALLOWED_GROUPS`, `GROUPS_CLAIM`, `REVOKE_BEFORE`** — any asymmetry produces "works on some pods, not others" bugs.

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

### Bulk revocation rollout caveat

`REVOKE_BEFORE` is read at startup. Updating it requires a rolling restart, and during the rollout window some pods enforce the new cutoff while others still use the old one. Wait for `kubectl rollout status` to converge before assuming the cutoff is fleet-wide enforced.
