# mcp-auth-proxy

> OAuth 2.1 authorization server that fronts any OIDC IdP, so MCP clients
> can speak to your private MCP server without you writing a single line
> of auth code.

[![Build](https://github.com/babs/mcp-auth-proxy/actions/workflows/release.yml/badge.svg)](https://github.com/babs/mcp-auth-proxy/actions/workflows/release.yml)
[![Go](https://img.shields.io/badge/go-1.26-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Container](https://img.shields.io/badge/ghcr.io-babs%2Fmcp--auth--proxy-181717?logo=github)](https://github.com/babs/mcp-auth-proxy/pkgs/container/mcp-auth-proxy)

---

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

## TL;DR — deploy

```bash
docker run --rm -p 8080:8080 \
  -e OIDC_ISSUER_URL=https://idp.example.com \
  -e OIDC_CLIENT_ID=mcp-auth-proxy \
  -e OIDC_CLIENT_SECRET='<your-idp-secret>' \
  -e PROXY_BASE_URL=https://mcp.example.com \
  -e UPSTREAM_MCP_URL=http://mcp-backend:8000/mcp \
  -e TOKEN_SIGNING_SECRET="$(openssl rand -hex 32)" \
  -e REDIS_URL=redis://your-redis-host:6379/0 \
  ghcr.io/babs/mcp-auth-proxy:latest
```

Substitute the angle-bracketed placeholder with your real IdP
credential and pick a Redis URL that's reachable from the container
(host networking, an explicit `--network`, or the demo stack below
all work). Point your MCP client at `https://mcp.example.com/mcp`
and the proxy walks RFC 7591 → 8414 → 6749 → 8707 → OIDC → your
protected backend on its own.

For a full local stack with Keycloak + Redis + a sample MCP server
already wired up, see [Demo stack](#demo-stack).

## Requirements

- **OIDC IdP** with discovery (`/.well-known/openid-configuration`)
  reachable from the proxy. Tested with Keycloak, Microsoft Entra ID;
  any OIDC-compliant IdP works (Auth0, Okta, Google, …).
- **Redis** ≥ 7 (or compatible) for production. Required by default
  (`REDIS_REQUIRED=true`) so single-use authorization codes and
  refresh-rotation reuse detection work across replicas. See
  [`docs/redis-production.md`](./docs/redis-production.md) for sizing.
- **Public HTTPS** terminating at an ingress that reaches the proxy's
  `LISTEN_ADDR` (`:8080` by default). The IdP and the MCP clients both
  see `PROXY_BASE_URL` over the public network.
- **Go 1.26+** if building from source. Container images are static
  (`CGO_ENABLED=0`).
- **Kubernetes**: any conformant cluster. Sample manifests under
  [`manifests/`](./manifests). Production overlay enforces the safe
  posture; see [Deploying](#deploying-on-kubernetes).

---

## What it does

- Speaks **OAuth 2.1 + PKCE** to MCP clients (claude.ai, Claude Code,
  Cursor, MCP Inspector, ChatGPT…).
- Federates authentication to **any OIDC-compliant IdP** via
  auto-discovery (no vendor lock-in, zero IdP-specific code).
- Reverse-proxies to your **unmodified** upstream MCP server.
- **Stateless design** — every transient state (registrations, codes,
  tokens) is AEAD-sealed into opaque strings; scale horizontally by
  sharing one secret.
- **Redis-backed replay defense** — single-use authorization codes,
  refresh-rotation reuse detection (OAuth 2.1 §6.1), single-use
  consent and callback-state tokens.
- **Per-IP rate limiting** on every pre-auth endpoint, **per-subject
  concurrency caps** on the authenticated route, `email_verified`
  enforcement on the IdP id_token, **Prometheus metrics** for every
  security-relevant event, and a **proxy-rendered consent page** on
  by default.

The MCP spec requires an OAuth 2.1 Authorization Server in front of
protected MCP servers. You probably do not want to implement RFC 8414
/ 7591 / 9728 / 7636 / 8707 yourself, glue a session store in front of
every replica, or rewrite your MCP backend to understand OIDC. Drop
this in front, point it at your existing IdP, done.

---

## Standards conformance

| RFC / Spec | Implements |
|---|---|
| [OAuth 2.1 draft-13](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13) | Authorization code + PKCE, hardened defaults |
| [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) | `/.well-known/oauth-authorization-server` |
| [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) | `/.well-known/oauth-protected-resource` + `WWW-Authenticate` |
| [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) | Dynamic Client Registration on `POST /register` |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) | PKCE S256, 43-128 char verifier |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) | `resource` indicator on `/authorize` and `/token` |
| [MCP Authorization 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) | End-to-end MCP auth flow |

Companion docs:
- [`specs.md`](./specs.md) — design + flow rationale.
- [`docs/conformance.md`](./docs/conformance.md) — claim matrix +
  compatibility notes + IdP evidence.
- [`docs/threat-model.md`](./docs/threat-model.md) — STRIDE coverage
  with code + test + runbook links.
- [`docs/configuration.md`](./docs/configuration.md) — full env-var
  reference with rationale per knob.

---

## Configuration

All configuration via **environment variables**. The five required
vars are below; everything else is optional and defaults to the safe
production posture.

| Variable | Description |
|---|---|
| **`OIDC_ISSUER_URL`** | OIDC issuer (auto-discovered via `/.well-known/openid-configuration`) |
| **`OIDC_CLIENT_ID`** | Client registered on the IdP |
| **`OIDC_CLIENT_SECRET`** | IdP client secret |
| **`PROXY_BASE_URL`** | Public URL of this proxy (audience-bound into every sealed token) |
| **`UPSTREAM_MCP_URL`** | Upstream MCP URL with explicit path (`http://mcp:8000/mcp`); the path is the proxy's mount AND forwarded verbatim. Origin-only, fragment-bearing, or control-plane-colliding paths are rejected at startup |
| **`TOKEN_SIGNING_SECRET`** | ≥ 32 bytes, AES-GCM key; byte-identical across replicas. **Generate with `manifests/scripts/generate-signing-secret.sh`** (64-char base64). The startup validator rejects three weak-secret shapes: all-same-byte, short-repeating-period, and tiny alphabet (< 8 distinct values). Under `PROD_MODE=true` weak secrets fail fast. Rotation procedure (with `TOKEN_SIGNING_SECRETS_PREVIOUS` for zero-downtime rollover) in [`docs/runbooks/key-rotation.md`](./docs/runbooks/key-rotation.md) |

Optional knobs (rate limits, replay store tuning, header trust,
observability, dev/compat) are documented in
[`docs/configuration.md`](./docs/configuration.md).

### Production posture

`PROD_MODE=true` by default — the proxy fails startup if any
compatibility flag that weakens a security control is set. The
shipped defaults give you, with no extra effort:

- **Redis required** — `REDIS_REQUIRED=true` blocks startup without
  `REDIS_URL`. Stateless mode (codes/refresh replayable within TTL)
  is dev-only.
- **PKCE required** — `PKCE_REQUIRED=true`. Clients without PKCE
  (Cursor, MCP Inspector) need an explicit operator override.
- **Consent page on** — `RENDER_CONSENT_PAGE=true`. Closes the
  silent-token-issuance phishing path.
- **Per-IP rate limiting on** — every pre-auth endpoint plus the
  authenticated MCP route. **Per-replica scope:** the limiter is
  in-process; an `N`-replica deployment admits up to `N ×` the
  documented per-endpoint rate. Size `TRUSTED_PROXY_CIDRS` and any
  upstream WAF accordingly.
- **Strict state on `/authorize`** — `COMPAT_ALLOW_STATELESS=false`.
  The proxy refuses requests without a client-supplied state.
- **Forwarded-header allowlist enforced** — `TRUSTED_PROXY_CIDRS`
  must be set if you want the rate limiter to honour `X-Forwarded-*`.
  Wildcard trust (`TRUST_PROXY_HEADERS=true` without a CIDR list)
  fails startup.

Set `PROD_MODE=false` only for single-replica dev / debugging that
needs one of the relaxation toggles. The CI manifest gate
(`manifest-prod` job) enforces this posture on the shipped overlay.

---

## Architecture at a glance

**Everything transient is sealed, not stored.** Client registrations,
authorize sessions, authorization codes, access tokens, refresh
tokens — each one is an AES-GCM blob carrying its own TTL and an
audience matching `PROXY_BASE_URL`. No application database is
required. Redis is required by default for replay protection
(single-use authorization codes, refresh-rotation reuse detection,
single-use consent + callback-state tokens) — the sealed payloads
alone remain replayable within their TTL.

| Flow state | Encrypted into | TTL |
|---|---|---|
| Client registration | `client_id` | 7d (configurable via `CLIENT_REGISTRATION_TTL`) |
| Authorize session | IdP `state` parameter | 10min |
| Authorization code | `code` parameter | 60s |
| Access token | Opaque bearer | 1h |
| Refresh token | Opaque bearer | 7d |

Every payload verifies its audience on open. Two deployments that
accidentally share a `TOKEN_SIGNING_SECRET` but differ on
`PROXY_BASE_URL` **cannot replay each other's tokens** — tested
across every sealed type.

See [`specs.md`](./specs.md) for the full trade-off table,
revocation rollout notes, and the K8s deployment shape.

---

## Endpoints

| Path | Purpose |
|---|---|
| `GET /.well-known/oauth-protected-resource` | RFC 9728 resource metadata |
| `GET /.well-known/oauth-protected-resource<mount>` | RFC 9728 §3.1 per-resource variant |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 AS metadata |
| `POST /register` | RFC 7591 dynamic client registration |
| `GET  /authorize` | PKCE authorization endpoint (renders consent page by default) |
| `POST /consent` | Consent-page Approve / Deny submission |
| `GET  /callback` | OIDC callback from the IdP |
| `POST /token` | `authorization_code` + `refresh_token` grants |
| `GET  /healthz` | Liveness probe (always 200 while the process is up) |
| `GET  /readyz` (port 9090) | Readiness probe on the metrics listener (NOT the public router); reflects Redis reachability |
| MCP mount + sub-paths | Reverse-proxied to `UPSTREAM_MCP_URL` after Bearer check |
| `GET /metrics` (port 9090) | Prometheus metrics |

Per-endpoint contract details (params, error shapes, replay-claim
ordering) live in [`specs.md`](./specs.md).

---

## Observability

- **Structured logs** — zap, JSON in production, console on a TTY.
  Every request carries a `request_id` (in the log AND the
  `X-Request-Id` response header — inbound is stripped). Authenticated
  requests carry `sub` and `email`.
- **Metrics** — Prometheus on a dedicated port (`:9090`, loopback-only
  by default). Series families:
  - `mcp_auth_tokens_issued_total{grant_type}`
  - `mcp_auth_authorize_initiated_total{path}` — funnel entry
  - `mcp_auth_consent_decisions_total{decision}` — funnel approve/deny
  - `mcp_auth_access_denied_total{reason}` — every denial bucket
  - `mcp_auth_replay_detected_total{kind}` — `code` / `refresh` /
    `consent` / `callback_state`
  - `mcp_auth_rate_limited_total{endpoint}` — pre-auth httprate 429s
  - `mcp_auth_idp_exchange_throttled_total` — outbound bucket denials
  - `mcp_auth_clients_registered_total`, `mcp_auth_token_seals_total{purpose}`,
    `mcp_auth_groups_claim_shape_mismatch_total`
  - `mcp_auth_rpc_calls_total{tool}` and friends — opt-in via
    `MCP_TOOL_METRICS=true` (per-tool RPC traffic)
- **Health** — `GET /healthz` (liveness, public router) and
  `GET /readyz` (metrics port; reflects Redis when `REDIS_URL` is set,
  cached ~1s to resist probe-flood amplification).

Full alerting playbook + PromQL recipes (consent funnel rate, seal
counter rotation alert, etc.) in
[`docs/configuration.md`](./docs/configuration.md#observability).

---

## Demo stack

[`manifests/`](./manifests) ships a turn-key local stack: Docker
Compose with Keycloak (pre-seeded realm + admin user), Redis, a
minimal MCP server, and the proxy itself wired end-to-end. The
`manifests/k8s/` set is split between reference YAML templates and a
production-oriented kustomize overlay at
`manifests/overlays/production`. `manifests/scripts/generate-signing-secret.sh`
emits a 64-character cryptographically-random base64 string suitable
for `TOKEN_SIGNING_SECRET`.

---

## Building

```bash
./build.sh local        # local binary only
./build.sh docker       # docker image only
./build.sh              # both
```

`build.sh` injects `Version`, `CommitHash`, `BuildTimestamp`,
`Builder`, and `ProjectURL` via `-ldflags -X`. CI
([`release.yml`](./.github/workflows/release.yml)) does the same on
tag pushes — native multi-arch builders for `linux/amd64` and
`linux/arm64`, per-platform tags merged into a manifest list, GitHub
Release auto-created.

Release a new version:

```bash
git tag v1.2.3 && git push origin v1.2.3
```

---

## Deploying on Kubernetes

Stateless → plain `Deployment` + `Service`. Required invariants
across replicas:

1. Identical `TOKEN_SIGNING_SECRET` (mount from a `Secret`, do not
   generate per-pod).
2. Identical `PROXY_BASE_URL` (public DNS, not a per-pod hostname).
3. `terminationGracePeriodSeconds ≥ SHUTDOWN_TIMEOUT` so rolling
   deploys don't chop SSE streams mid-flight.

A ready-to-adapt manifest shape sits at
[`manifests/overlays/production/`](./manifests/overlays/production)
and at the bottom of
[`specs.md`](./specs.md#multi-instance-deployment-k8s).

Production posture guides:

- [`docs/redis-production.md`](./docs/redis-production.md) — what
  "production Redis" means for this proxy (auth, TLS, HA, sizing).
- [`docs/conformance.md`](./docs/conformance.md) — spec claim matrix,
  compatibility notes, current IdP evidence.
- [`docs/threat-model.md`](./docs/threat-model.md) — STRIDE coverage
  matrix.
- [`docs/release-checklist.md`](./docs/release-checklist.md) — checks
  to run before and after publishing a release image.
- [`docs/runbooks/`](./docs/runbooks/) — key rotation, bulk
  revocation, Redis outage, IdP outage, consent denials, client
  registration expired.

---

## Testing

```bash
go test ./...                           # unit + e2e (mock OIDC)
go test -tags=keycloak_e2e -run "^TestKeycloakE2E" -count=1 .
go test -race ./...                     # race detector
go test -cover ./...                    # coverage
```

The mock-IdP e2e (`e2e_test.go`) exercises registration → authorize →
callback → token → refresh → bearer-protected proxy. The
`keycloak_e2e` build tag runs the same flows + four negative-path
tests against the Docker Compose demo stack with real Keycloak. CI
runs both paths automatically on every PR.

---

## Verifying published images

Tagged releases are built by
[`release.yml`](./.github/workflows/release.yml) with **SLSA
provenance** (`mode=max`) + **SBOM** attestations embedded in the OCI
image index, and **keyless cosign signatures** over both the
per-platform image digests and the merged multi-arch index, anchored
in the Rekor transparency log.

Image tags strip the `v` prefix (`ghcr.io/babs/mcp-auth-proxy:1.0.0`)
while git tags carry it (`v1.0.0`). The identity regex below matches
the git tag form.

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/babs/mcp-auth-proxy/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/babs/mcp-auth-proxy:1.0.0
```

Inspect provenance and SBOM:

```bash
docker buildx imagetools inspect ghcr.io/babs/mcp-auth-proxy:1.0.0 \
  --format '{{json .Provenance}}' | jq

docker buildx imagetools inspect ghcr.io/babs/mcp-auth-proxy:1.0.0 \
  --format '{{json .SBOM}}' | jq
```

A policy controller (Kyverno, Sigstore policy-controller, …) can
enforce these checks on every pull in a cluster — see each tool's
docs for the exact policy syntax.

---

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE) and
[`NOTICE`](./NOTICE).
