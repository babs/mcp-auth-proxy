# mcp-auth-proxy

> OAuth 2.1 authorization server that fronts any OIDC IdP, so MCP clients
> can speak to your private MCP server without you writing a single line
> of auth code.

[![Build](https://github.com/babs/mcp-auth-proxy/actions/workflows/release.yml/badge.svg)](https://github.com/babs/mcp-auth-proxy/actions/workflows/release.yml)
[![Go](https://img.shields.io/badge/go-1.26-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Container](https://img.shields.io/badge/ghcr.io-babs%2Fmcp--auth--proxy-181717?logo=github)](https://github.com/babs/mcp-auth-proxy/pkgs/container/mcp-auth-proxy)

---

## What it does

```
┌──────────────────┐      ┌────────────────────┐      ┌─────────────────┐
│ Claude / Cursor  │ ───► │  mcp-auth-proxy    │ ───► │ private MCP     │
│ Claude Code      │      │  OAuth 2.1 AS      │      │ server          │
│ MCP Inspector    │ ◄─── │  (this project)    │ ◄─── │ (unchanged)     │
└──────────────────┘      └────────┬───────────┘      └─────────────────┘
                                   │
                                   ▼
                          ┌────────────────────┐
                          │  your OIDC IdP     │
                          │  Keycloak · Entra  │
                          │  Auth0 · Okta · …  │
                          └────────────────────┘
```

- Speaks **OAuth 2.1 + PKCE** to MCP clients (claude.ai, Claude Code,
  Cursor, MCP Inspector, ChatGPT…)
- Federates authentication to **any OIDC-compliant IdP** via auto-discovery
  (no vendor lock-in, zero IdP-specific code)
- Reverse-proxies to your **unmodified** upstream MCP server
- **Stateless by default** — no database, no sticky sessions; scale
  horizontally by sharing one secret
- **Optional Redis** unlocks strict single-use authorization codes and
  refresh-rotation reuse detection (OAuth 2.1 §6.1) across replicas
- Per-IP **rate limiting** on every pre-auth endpoint, `email_verified`
  enforcement on the IdP id_token, and **Prometheus metrics** for every
  security-relevant event

---

## Why

The MCP spec requires an OAuth 2.1 Authorization Server in front of
protected MCP servers. You probably do not want to:

- implement RFC 8414 / 7591 / 9728 / 7636 / 8707 yourself,
- glue a session store in front of every replica,
- or rewrite your MCP backend to understand OIDC.

Drop this in front, point it at your existing IdP, done.

---

## Standards conformance

| RFC / Spec | What we implement |
|---|---|
| [OAuth 2.1 draft-13](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13) | Authorization code + PKCE, hardened defaults |
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | `/.well-known/oauth-authorization-server` |
| [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) | `/.well-known/oauth-protected-resource` + `WWW-Authenticate` |
| [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) | Dynamic Client Registration on `POST /register` |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE S256, 43-128 char verifier |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | `resource` indicator on `/authorize` and `/token` |
| [MCP Authorization 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) | End-to-end MCP auth flow |

Full design notes live in [`specs.md`](./specs.md).

---

## Quick start

### Docker

```bash
docker run --rm -p 8080:8080 -p 9090:9090 \
  -e OIDC_ISSUER_URL=https://keycloak.example.com/realms/myrealm \
  -e OIDC_CLIENT_ID=mcp-proxy \
  -e OIDC_CLIENT_SECRET=**** \
  -e PROXY_BASE_URL=https://mcp.example.com \
  -e UPSTREAM_MCP_URL=http://mcp-server:8080 \
  -e TOKEN_SIGNING_SECRET=$(openssl rand -hex 32) \
  ghcr.io/babs/mcp-auth-proxy:latest
```

### From source

```bash
git clone https://github.com/babs/mcp-auth-proxy.git
cd mcp-auth-proxy
./build.sh local        # builds ./mcp-auth-proxy with ldflags injected
./mcp-auth-proxy
```

Then point your MCP client at `https://mcp.example.com` — it'll
auto-discover the AS, register itself, and walk through PKCE.

---

## Configuration

All configuration via **environment variables**. Bold = required.

| Variable | Default | Description |
|---|---|---|
| **`OIDC_ISSUER_URL`** | — | OIDC issuer (auto-discovered via `/.well-known/openid-configuration`) |
| **`OIDC_CLIENT_ID`** | — | Client registered on the IdP |
| **`OIDC_CLIENT_SECRET`** | — | IdP client secret |
| **`PROXY_BASE_URL`** | — | Public URL of this proxy (audience-bound into every sealed token) |
| **`UPSTREAM_MCP_URL`** | — | Target MCP server (path prefix preserved) |
| **`TOKEN_SIGNING_SECRET`** | — | ≥ 32 bytes, AES-GCM key; must be byte-identical across replicas |
| `LISTEN_ADDR` | `:8080` | Public bind address |
| `METRICS_ADDR` | `:9090` | Prometheus bind address (separate listener) |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `GROUPS_CLAIM` | `groups` | Flat claim holding user groups |
| `ALLOWED_GROUPS` | (empty) | CSV allowlist; empty = allow all authenticated users |
| `REVOKE_BEFORE` | (empty) | RFC3339 cutoff for bulk revocation (applies to access *and* refresh tokens) |
| `PKCE_REQUIRED` | `true` | Set `false` for clients that omit PKCE (Cursor, MCP Inspector, ChatGPT) |
| `SHUTDOWN_TIMEOUT` | `120s` | Graceful shutdown; must be ≥ longest expected SSE stream |
| `REDIS_URL` | (empty) | Optional. Enables single-use authz codes + refresh-rotation reuse detection. `rediss://` for TLS |
| `REDIS_KEY_PREFIX` | `mcp-auth-proxy:` | Key prefix for shared Redis; set to empty to opt out of namespacing |
| `RATE_LIMIT_ENABLED` | `true` | Per-IP rate limiting on pre-auth endpoints. Disable only behind a WAF that already enforces it |

---

## Architecture at a glance

**Everything transient is sealed, not stored.**

Client registrations, authorize sessions, authorization codes, access
tokens, refresh tokens — each one is an AES-GCM blob carrying its own
TTL and an `audience` matching `PROXY_BASE_URL`. No database is
required to operate this service.

| Flow state | Encrypted into | TTL |
|---|---|---|
| Client registration | `client_id` | 24h |
| Authorize session | IdP `state` parameter | 10min |
| Authorization code | `code` parameter | 60s |
| Access token | Opaque bearer | 1h |
| Refresh token | Opaque bearer | 7d |

Every payload verifies its audience on open. Two deployments that
accidentally share a `TOKEN_SIGNING_SECRET` but differ on
`PROXY_BASE_URL` **cannot replay each other's tokens** — tested across
every sealed type.

See [`specs.md`](./specs.md) for the full trade-off table, revocation
rollout notes, and K8s deployment shape.

---

## Endpoints

| Path | Purpose |
|---|---|
| `GET /.well-known/oauth-protected-resource` | RFC 9728 resource metadata |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 AS metadata |
| `POST /register` | RFC 7591 dynamic client registration |
| `GET  /authorize` | PKCE authorization endpoint |
| `GET  /callback` | OIDC callback from the IdP |
| `POST /token` | `authorization_code` + `refresh_token` grants |
| `GET  /healthz` | Liveness probe (always 200 while the process is up) |
| `GET  /readyz` | Readiness probe (503 when Redis is configured but unreachable) |
| `*` (any other path) | Reverse-proxied to `UPSTREAM_MCP_URL` after Bearer check |
| `GET /metrics` (port 9090) | Prometheus metrics |

---

## Observability

- **Structured logs** — zap, JSON in production, console when run on a TTY.
  Every request carries a `request_id` in the log and in the
  `X-Request-Id` response header. Inbound `X-Request-Id` is stripped to
  prevent log-forgery.
- **Metrics** — Prometheus on a dedicated port (`:9090`, separate listener,
  not exposed through the public router). Alongside the default Go
  runtime counters, the proxy emits:
  - `mcp_auth_tokens_issued_total{grant_type}` — access tokens minted
  - `mcp_auth_access_denied_total{reason}` — group / `email_unverified`
    / `refresh_family_revoked` rejections
  - `mcp_auth_replay_detected_total{kind}` — `code` or `refresh` replays
    caught by the Redis-backed store
  - `mcp_auth_rate_limited_total{endpoint}` — httprate 429s by endpoint
  - `mcp_auth_clients_registered_total` — RFC 7591 registrations
- **Health** — `GET /healthz` (liveness) and `GET /readyz` (reflects
  Redis reachability when `REDIS_URL` is set).

---

## Building

```bash
./build.sh local        # local binary only
./build.sh docker       # docker image only
./build.sh              # both
```

`build.sh` injects `Version`, `CommitHash`, `BuildTimestamp`, `Builder`,
and `ProjectURL` via `-ldflags -X`. CI (`.github/workflows/release.yml`)
does the same on tag pushes — native multi-arch builders for
`linux/amd64` and `linux/arm64`, per-platform tags merged into a
manifest list, GitHub Release auto-created.

Release a new version:

```bash
git tag v1.2.3 && git push origin v1.2.3
```

---

## Deploying on Kubernetes

Stateless → plain `Deployment` + `Service`. Required invariants across
replicas:

1. Identical `TOKEN_SIGNING_SECRET` (mount from a `Secret`, do not
   generate per-pod).
2. Identical `PROXY_BASE_URL` (public DNS, not a per-pod hostname).
3. `terminationGracePeriodSeconds ≥ SHUTDOWN_TIMEOUT` so rolling
   deploys don't chop SSE streams mid-flight.

A ready-to-adapt manifest shape sits at the bottom of
[`specs.md`](./specs.md#multi-instance-deployment-k8s).

---

## Testing

```bash
go test ./...                           # unit + e2e (mock OIDC provider)
go test -race ./...                     # with the race detector
go test -cover ./...                    # with coverage
```

The E2E test (`e2e_test.go`) spins up a full mock OIDC provider and
exercises registration → authorize → callback → token → refresh →
bearer-protected proxy in one go.

---

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
