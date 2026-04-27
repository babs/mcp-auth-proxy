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
- **Stateless design** — all transient state (registrations, codes,
  tokens) is AEAD-sealed into opaque strings; scale horizontally by
  sharing one secret
- **Redis required by default** for strict single-use authorization
  codes and refresh-rotation reuse detection (OAuth 2.1 §6.1) across
  replicas. Set `REDIS_REQUIRED=false` only for single-replica dev
- Per-IP **rate limiting** on every pre-auth endpoint, **per-subject
  concurrency caps** on the authenticated route, `email_verified`
  enforcement on the IdP id_token, and **Prometheus metrics** for every
  security-relevant event
- Turn-key **demo stack** in [`manifests/`](./manifests) — Docker
  Compose with Keycloak + Redis + a fake MCP backend, and a reference
  Kubernetes `Deployment` + `Ingress` + `PodDisruptionBudget` set

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
| [OAuth 2.1 draft-13](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13) | Authorization code + PKCE, hardened defaults. Tracks the draft pinned by MCP Authorization 2025-06-18; later drafts (currently `draft-15`) not yet adopted |
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | `/.well-known/oauth-authorization-server` |
| [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) | `/.well-known/oauth-protected-resource` + `WWW-Authenticate` |
| [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) | Dynamic Client Registration on `POST /register` |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE S256, 43-128 char verifier |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | `resource` indicator on `/authorize` and `/token` |
| [MCP Authorization 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) | End-to-end MCP auth flow |

Full design notes live in [`specs.md`](./specs.md). The implementation
claim matrix, compatibility notes, and current IdP evidence live in
[`docs/conformance.md`](./docs/conformance.md).

---

## Quick start

### Docker

```bash
docker run --rm -p 8080:8080 -p 9090:9090 \
  -e OIDC_ISSUER_URL=https://keycloak.example.com/realms/myrealm \
  -e OIDC_CLIENT_ID=mcp-proxy \
  -e OIDC_CLIENT_SECRET=**** \
  -e PROXY_BASE_URL=https://mcp.example.com \
  -e UPSTREAM_MCP_URL=http://mcp-server:8080/mcp \
  -e TOKEN_SIGNING_SECRET=$(openssl rand -hex 32) \
  -e REDIS_URL=redis://redis:6379/0 \
  ghcr.io/babs/mcp-auth-proxy:latest
```

`PROD_MODE` defaults to `true` — the proxy fails startup unless `REDIS_URL` is set (single-use codes + refresh-rotation reuse detection). For a single-replica dev run without Redis, add `-e PROD_MODE=false -e REDIS_REQUIRED=false` instead.

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
| `OIDC_ALLOW_INSECURE_HTTP` | `false` | Dev-only escape hatch for cleartext `http://` OIDC issuers, used by the Docker Compose Keycloak demo. Rejected when `PROD_MODE=true`; production should use `https://` |
| **`OIDC_CLIENT_ID`** | — | Client registered on the IdP |
| **`OIDC_CLIENT_SECRET`** | — | IdP client secret |
| **`PROXY_BASE_URL`** | — | Public URL of this proxy (audience-bound into every sealed token) |
| **`UPSTREAM_MCP_URL`** | — | Upstream MCP URL. Must include an explicit path — origin-only (`http://backend`) and lone-`/` (`http://backend/`) are rejected at startup. The path is used verbatim on both sides: it's the proxy's public mount *and* the path forwarded to the upstream. `http://mcp:8000/api/v1/mcp` → proxy exposes `/api/v1/mcp`, upstream sees `/api/v1/mcp`, client points at `{PROXY_BASE_URL}/api/v1/mcp`. Query, fragment, userinfo, and paths that collide with a control-plane route (`/healthz`, `/register`, `/authorize`, `/callback`, `/token`, `/.well-known`) are rejected too. |
| **`TOKEN_SIGNING_SECRET`** | — | ≥ 32 bytes, AES-GCM key; must be byte-identical across replicas. `PROD_MODE=true` additionally rejects secrets with < 16 distinct bytes (patterned / human-typed values like `aaaa…` or `0123…`). Generate with `openssl rand -hex 32` or `manifests/scripts/generate-signing-secret.sh` |
| `LISTEN_ADDR` | `:8080` | Public bind address |
| `METRICS_ADDR` | `127.0.0.1:9090` | Prometheus bind address (separate listener). Loopback-only by default so `/metrics` and `/readyz` are never exposed on the public interface; override to `:9090` or an explicit interface when a scraper must reach the pod |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `GROUPS_CLAIM` | `groups` | Flat claim holding user groups |
| `ALLOWED_GROUPS` | (empty) | CSV allowlist; empty = allow all authenticated users |
| `REVOKE_BEFORE` | (empty) | RFC3339 cutoff for bulk revocation (applies to access *and* refresh tokens) |
| `MCP_RESOURCE_NAME` | (empty) | Human-readable name advertised under `resource_name` in the RFC 9728 PRM (e.g. `"ACME MCP"`). Used by MCP clients for display/consent UI. Optional; field is omitted when unset |
| `PKCE_REQUIRED` | `true` | Set `false` for clients that omit PKCE (Cursor, MCP Inspector, ChatGPT) |
| `SHUTDOWN_TIMEOUT` | `120s` | Graceful shutdown; must be ≥ longest expected SSE stream |
| `REDIS_URL` | (empty) | Enables single-use authz codes + refresh-rotation reuse detection. `rediss://` for TLS |
| `REDIS_REQUIRED` | `true` | Fail startup when `REDIS_URL` is unset. Set `false` only for dev / single-replica; stateless mode leaves codes/refresh replayable within TTL |
| `REDIS_KEY_PREFIX` | `mcp-auth-proxy:` | Key prefix for shared Redis; set to empty to opt out of namespacing |
| `RATE_LIMIT_ENABLED` | `true` | Per-IP rate limiting on pre-auth endpoints and on the authenticated MCP route. Disable only behind a WAF that already enforces it |
| `TOKEN_SIGNING_SECRETS_PREVIOUS` | _(empty)_ | Whitespace-separated retired signing secrets accepted on Open during a rolling rotation. New seals always use `TOKEN_SIGNING_SECRET` (primary); Open tries primary first, then each previous. See [`docs/runbooks/key-rotation.md`](./docs/runbooks/key-rotation.md) |
| `TRUSTED_PROXY_CIDRS` | _(empty)_ | Comma-separated CIDRs of peers whose forwarding header (default `X-Forwarded-For`) is walked right-to-left for rate-limit keying. The first hop NOT in the trusted set is the bucket key; everything left of it (typically appended by the client) is ignored. Other peers fall back to RemoteAddr. Preferred over the legacy `TRUST_PROXY_HEADERS` bool |
| `TRUSTED_PROXY_HEADER` | `X-Forwarded-For` | Pin which forwarding header carries the hop list. Allowlist: `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`. Pin `X-Real-IP` / `True-Client-IP` only when the trusted ingress is known to OVERWRITE (not append) that header — otherwise a client behind a passthrough ingress can spoof an unbounded rate-limit bucket per request |
| `TRUST_PROXY_HEADERS` | `false` | **Legacy.** Blanket trust of every peer's forwarded headers (delegates to `httprate.KeyByRealIP`, which honours leftmost-XFF / `True-Client-IP` / `X-Real-IP` without validation). Superseded by `TRUSTED_PROXY_CIDRS` when both are set; rejected entirely under `PROD_MODE=true` without `TRUSTED_PROXY_CIDRS` because the bucket key becomes attacker-spoofable |
| `PROD_MODE` | `true` | Fails startup if any compatibility flag that weakens a security control is set (`PKCE_REQUIRED=false`, `COMPAT_ALLOW_STATELESS=true`, `REDIS_REQUIRED=false`, `REDIS_URL` empty, or legacy `TRUST_PROXY_HEADERS=true` without `TRUSTED_PROXY_CIDRS`). Default **on** so the runtime posture matches the OAuth 2.1 / MCP guarantees the published metadata advertises. Set `PROD_MODE=false` explicitly for dev / single-replica work that needs one of the relaxation toggles |
| `UPSTREAM_AUTHORIZATION_HEADER` | _(empty)_ | When set, sent verbatim as the `Authorization` header on every request to the upstream MCP backend. Full header value incl. scheme, e.g. `Bearer xyz`. Treat as a secret |
| `MCP_PER_SUBJECT_CONCURRENCY` | `16` | Per-subject in-flight cap on the authenticated MCP route. Excess requests get 503 `temporarily_unavailable` + `Retry-After: 1`. Idle subjects (no in-flight work for ≥5 min) are reclaimed by a background pruner so map memory stays proportional to active principals. `0` disables |
| `COMPAT_ALLOW_STATELESS` | `false` | Synthesize a server-side `state` on `/authorize` when the client omits it (legacy Cursor / MCP Inspector). Strict mode refuses the request; counter `mcp_auth_access_denied_total{reason="state_missing"}` fires either way |
| `RENDER_CONSENT_PAGE` | `true` | Render an explicit proxy-side consent page on `/authorize` so the user sees who's asking and where they'll be redirected before the IdP login. Closes the silent-token-issuance path where a malicious DCR client + an active IdP session = tokens issued without any user interaction with the proxy. Plain HTML, no JavaScript; the form's submit POSTs to `/consent` with an Approve / Deny choice. Set `RENDER_CONSENT_PAGE=false` to fall back to the legacy silent-redirect — only do that when every caller is non-interactive and known-trusted |
| `MCP_LOG_BODY_MAX` | `65536` | Max bytes buffered per request for JSON-RPC method extraction into access logs. `0` disables buffering (no `rpc_method`/`rpc_tool`/`rpc_id` fields). Raise for large batches; lower or zero when tool names must stay out of logs |
| `ACCESS_LOG_SKIP_RE` | _(empty)_ | **Go [RE2](https://pkg.go.dev/regexp/syntax) regexp** matched against `r.URL.Path` on the **public listener only**. When a request path matches, the access-log line is suppressed; the handler response, Prometheus counters, and panic recovery are unaffected. Invalid pattern fails startup. RE2 is linear-time — no ReDoS. Typical value: `ACCESS_LOG_SKIP_RE=^/healthz$` (liveness-probe noise). **Always anchor with `^…$`** unless you intentionally want substring matching — `healthz` (no anchors) also matches `/mcp/healthz-tool` if an upstream tool carries that substring; `.*` silences the entire access log. `/readyz` and `/metrics` live on `METRICS_ADDR` by default and do not reach this middleware — no need to match them unless you've deliberately moved them onto the public listener |
| `MCP_TOOL_METRICS` | `false` | When `true`, emits per-tool Prometheus counters: `mcp_auth_rpc_calls_total{tool}`, `mcp_auth_rpc_calls_failed_total{tool}` (status ≥ 400), `mcp_auth_rpc_request_bytes_total{tool}`, `mcp_auth_rpc_response_bytes_total{tool}`. Counters fire only on JSON-RPC `tools/call` requests; protocol-level methods (`initialize`, `notifications/*`, `tools/list`, `prompts/*`, …) do not contribute. Tool name comes from `params.name`; calls with unparseable params land in `_unknown`. Disabled by default — the `tool` label increases series cardinality and reveals workflow patterns; flip on when the visibility is worth the trade |
| `MCP_TOOL_METRICS_MAX_CARDINALITY` | `256` | Cap on distinct `tool` label values. Names past the cap collapse into the `_overflow` bucket, so an adversarial client probing fictional tool names cannot inflate Prometheus memory. Empty / unparsed tool names land in `_unknown`. Set to `0` to disable the cap (only safe when the upstream enforces a tool allowlist). Only meaningful when `MCP_TOOL_METRICS=true` |

---

## Architecture at a glance

**Everything transient is sealed, not stored.**

Client registrations, authorize sessions, authorization codes, access
tokens, refresh tokens — each one is an AES-GCM blob carrying its own
TTL and an `audience` matching `PROXY_BASE_URL`. No application database
is required. Redis is still required by default (`REDIS_REQUIRED=true`)
for replay protection — single-use authorization codes and
refresh-rotation reuse detection (OAuth 2.1 §6.1) — because the sealed
payloads alone remain replayable within their TTL.

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
| `GET /.well-known/oauth-protected-resource` | RFC 9728 resource metadata (`resource` is `/`-terminated for RFC 8707 / Claude.ai compat) |
| `GET /.well-known/oauth-protected-resource<mount>` | RFC 9728 §3.1 per-resource variant (`resource` = `{PROXY_BASE_URL}<mount>`, where `<mount>` is the path from `UPSTREAM_MCP_URL`) |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 AS metadata |
| `GET /.well-known/oauth-authorization-server<mount>` | Same document as above — non-spec compat for MCP clients that probe the per-resource suffix |
| `POST /register` | RFC 7591 dynamic client registration |
| `GET  /authorize` | PKCE authorization endpoint. Returns 200 HTML with a consent form by default; setting `RENDER_CONSENT_PAGE=false` reverts to the legacy 302 straight to the IdP |
| `POST /consent` | Consent-page Approve / Deny submission. Approve → 302 to IdP. Deny → 302 to the client's registered `redirect_uri` with `error=access_denied`. Always registered; no-op when `RENDER_CONSENT_PAGE=false` because nothing mints a valid `consent_token` in that mode |
| `GET  /callback` | OIDC callback from the IdP |
| `POST /token` | `authorization_code` + `refresh_token` grants |
| `GET  /healthz` | Liveness probe (always 200 while the process is up) |
| `GET  /readyz` | Readiness probe (503 when Redis is configured but unreachable) |
| MCP mount (path from `UPSTREAM_MCP_URL`) and sub-paths | Reverse-proxied to `UPSTREAM_MCP_URL` after Bearer check, path forwarded verbatim. Any request outside the mount returns 404. |
| `GET /metrics` (port 9090) | Prometheus metrics |

---

## Observability

- **Structured logs** — zap, JSON in production, console when run on a TTY.
  Every request carries a `request_id` in the log and in the
  `X-Request-Id` response header. Inbound `X-Request-Id` is stripped to
  prevent log-forgery. Authenticated requests also carry `sub` and `email`
  from the bearer token. JSON-RPC requests to the upstream MCP server
  additionally carry `rpc_method` (e.g. `tools/call`), `rpc_tool` (the
  `params.name` field, e.g. `shell`), and `rpc_id`. `rpc_method` and
  `rpc_tool` are capped at 128 characters; `rpc_id` at 64. All three pass
  through a narrow allowlist (ASCII alphanumerics plus `._:/-+`) so
  arbitrary attacker-supplied strings cannot bloat or smuggle into log
  lines. Set `MCP_LOG_BODY_MAX=0` to suppress all three.
- **Metrics** — Prometheus on a dedicated port (`:9090`, loopback-only
  by default via `METRICS_ADDR=127.0.0.1:9090`, separate listener, never
  exposed through the public router). Alongside the default Go runtime
  counters, the proxy emits:
  - `mcp_auth_tokens_issued_total{grant_type}` — access tokens minted
  - `mcp_auth_access_denied_total{reason}` — `group` / `group_invalid` /
    `email_unverified` / `refresh_family_revoked` / `state_missing` /
    `subject_missing` / `subject_concurrency_exceeded` /
    `invalid_token` (forged / malformed / signature / AAD failures —
    attack signal) / `token_expired` (benign aging) /
    `audience_mismatch` / `resource_mismatch` /
    `token_revoked_iat_cutoff` / `id_token_verification_failed` /
    `replay_store_unavailable` rejections. Note: `token_expired` is
    a separate bucket from `invalid_token` so a spike on the latter
    is unambiguously the attack-signal channel
  - `mcp_auth_consent_decisions_total{decision}` — `approved` /
    `denied` clicks on the proxy-rendered consent page. Distinct
    from `access_denied_total`: a user clicking Deny is a normal
    expected interaction, not a policy rejection. Pair with
    `mcp_auth_tokens_issued_total{grant_type="authorization_code"}`
    to derive abandoned-after-approve as a funnel signal
  - `mcp_auth_replay_detected_total{kind}` — `code` or `refresh` replays
    caught by the Redis-backed store
  - `mcp_auth_rate_limited_total{endpoint}` — httprate 429s by endpoint
  - `mcp_auth_clients_registered_total` — RFC 7591 registrations
  - `mcp_auth_groups_claim_shape_mismatch_total` — id_token `groups`
    claim failed to decode as `[]string`; user is admitted with empty
    groups. Distinct from `access_denied` because no denial occurs —
    surfaces an IdP schema regression before it cascades into a
    `group` denial spike
  - `mcp_auth_token_seals_total{purpose}` — successful AES-GCM seal
    operations, labelled by purpose (`client` / `session` / `code` /
    `access` / `refresh`). Aggregate across replicas to track
    cumulative seals per signing key — alert on
    `sum(increase(mcp_auth_token_seals_total[7d])) > 2**28` and rotate
    `TOKEN_SIGNING_SECRET` before the per-key 2^32 nonce-collision
    bound becomes a concern
  - `mcp_auth_rpc_calls_total{tool}`,
    `mcp_auth_rpc_calls_failed_total{tool}`,
    `mcp_auth_rpc_request_bytes_total{tool}`,
    `mcp_auth_rpc_response_bytes_total{tool}` — per-tool RPC traffic
    visibility. **Opt-in via `MCP_TOOL_METRICS=true`** because the
    `tool` label increases cardinality and reveals workflow patterns.
    Counters fire only on JSON-RPC `tools/call` requests — protocol-
    level methods (`initialize`, `notifications/*`, `tools/list`,
    `prompts/*`, …) do not contribute, so an alert on `_unknown`
    flags malformed `tools/call` payloads, not background chatter.
    JSON-RPC batches fan out into one `rpc_calls_total` increment per
    `tools/call` entry, each carrying its own tool label; the byte
    counters stay scoped to single-call requests because per-call
    Content-Length / response bytes cannot be honestly attributed
    inside a batch. Cap distinct labels via
    `MCP_TOOL_METRICS_MAX_CARDINALITY` (default 256); over-cap names
    fold into `_overflow`, unparseable tool names into `_unknown`
  - `mcp_auth_rpc_batches_total`, `mcp_auth_rpc_batches_failed_total`,
    `mcp_auth_rpc_batch_bytes_total{direction}` — batch-shape
    counters, disjoint from the per-tool family above so the `tool`
    label stays clean. One increment per JSON-RPC HTTP request whose
    body decoded as a top-level array AND contained at least one
    `tools/call` entry. Use `rate(rpc_batches_total) / sum(rate(rpc_calls_total{tool!~"^_.*"}))`
    for "fraction of tool calls that came via batch", and
    `rate(rpc_batch_bytes_total{direction="request"})` /
    `…{direction="response"}` for batch bandwidth. Same opt-in toggle
    as the per-tool family
- **Health** — `GET /healthz` (liveness, public router) and
  `GET /readyz` (on the metrics port; reflects Redis reachability when
  `REDIS_URL` is set, cached ~1s to resist probe-flood amplification).

---

## Demo stack

[`manifests/`](./manifests) ships a turn-key local stack: Docker Compose
with Keycloak (pre-seeded realm + admin user), Redis, a minimal MCP
server, and the proxy itself wired end-to-end. The `manifests/k8s/` set
is split between reference YAML templates and a production-oriented
kustomize overlay at `manifests/overlays/production`.
`scripts/generate-signing-secret.sh` emits a 32-byte random hex string
suitable for `TOKEN_SIGNING_SECRET`.

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

Production posture guides:

- [`docs/redis-production.md`](./docs/redis-production.md) — what
  "production Redis" means for this proxy (auth, TLS, HA, sizing).
- [`docs/conformance.md`](./docs/conformance.md) — spec claim matrix,
  compatibility notes, and current IdP evidence.
- [`docs/release-checklist.md`](./docs/release-checklist.md) — checks
  to run before and after publishing a release image.
- [`docs/runbooks/`](./docs/runbooks/) — key rotation, bulk
  revocation via `REVOKE_BEFORE`, Redis outage, IdP outage.

---

## Testing

```bash
go test ./...                           # unit + e2e (mock OIDC provider)
go test -tags=keycloak_e2e -run TestKeycloakE2EFullOAuthFlow -count=1 .
go test -race ./...                     # with the race detector
go test -cover ./...                    # with coverage
```

The E2E test (`e2e_test.go`) spins up a full mock OIDC provider and
exercises registration → authorize → callback → token → refresh →
bearer-protected proxy in one go.

The `keycloak_e2e` test runs against the Docker Compose demo stack with
real Keycloak. Generate `manifests/docker-compose/.env`, start the stack,
then run the tagged test above. CI runs this path automatically.

---

## Verifying published images

Tagged releases are built by [`release.yml`](./.github/workflows/release.yml) with:

- **SLSA provenance** (`mode=max`) and **SBOM** attestations embedded in the OCI image index
- **Keyless cosign signatures** over both the per-platform image digests and the merged multi-arch index digest, using a short-lived Fulcio certificate minted from the GitHub Actions OIDC token and anchored in the Rekor transparency log

Note the image tag convention: published tags strip the `v` prefix (`ghcr.io/babs/mcp-auth-proxy:1.0.0`), while the git tag itself is `v1.0.0`. The identity regex below matches the git tag (`refs/tags/v…`); the image reference uses the stripped form.

To verify a signature before pulling:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/babs/mcp-auth-proxy/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/babs/mcp-auth-proxy:1.0.0
```

The regex binds the signature to *this repo's release workflow* on a version tag; both identity and issuer must match or verification fails.

Inspect provenance and SBOM:

```bash
# SLSA provenance (buildinfo, source revision, builder identity)
docker buildx imagetools inspect ghcr.io/babs/mcp-auth-proxy:1.0.0 \
  --format '{{json .Provenance}}' | jq

# SBOM (Software Bill of Materials, SPDX format)
docker buildx imagetools inspect ghcr.io/babs/mcp-auth-proxy:1.0.0 \
  --format '{{json .SBOM}}' | jq
```

A policy controller (Kyverno, cosigned, Sigstore policy-controller) can enforce these checks on every pull in a cluster — see each tool's docs for the exact policy syntax.

---

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
