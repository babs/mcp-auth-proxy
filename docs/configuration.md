# Configuration reference

Companion to the [README](../README.md). The README lists the five
required environment variables and the production-posture
guarantees; this doc is the full reference for every knob, grouped
by what they affect.

All configuration is via environment variables. Defaults match the
secure production posture (`PROD_MODE=true`); flags listed here as
"loosens X" are rejected by the startup validator unless
`PROD_MODE=false` is set explicitly.

## Required (no defaults)

| Variable | Description |
|---|---|
| `OIDC_ISSUER_URL` | OIDC issuer auto-discovered via `/.well-known/openid-configuration`. |
| `OIDC_CLIENT_ID` | Client registered on the IdP. |
| `OIDC_CLIENT_SECRET` | IdP client secret. |
| `PROXY_BASE_URL` | Public URL of this proxy. Audience-bound into every sealed token — two deployments accidentally sharing `TOKEN_SIGNING_SECRET` but differing on `PROXY_BASE_URL` cannot replay each other's tokens. |
| `UPSTREAM_MCP_URL` | Upstream MCP URL with explicit path, e.g. `http://mcp:8000/api/v1/mcp`. The path is the proxy's mount AND forwarded verbatim to the upstream. Origin-only (`http://backend`), lone-`/`, query, fragment, userinfo, and paths colliding with control-plane routes (`/healthz`, `/register`, `/authorize`, `/callback`, `/token`, `/.well-known`) are rejected at startup. |
| `TOKEN_SIGNING_SECRET` | ≥ 32 bytes AES-GCM key. Byte-identical across replicas. **Generate with `manifests/scripts/generate-signing-secret.sh`** (a 64-char base64 value, no padding) — that's the canonical path. The validator runs an obvious-weakness check on every secret with three rejection classes: (1) all-same byte (`aaaa…`); (2) short repeating period (`abcabc…`, `0123456789abcdef0123456789abcdef`); (3) tiny alphabet — fewer than 8 distinct byte values, which catches uneven-run-length shapes (`aaaa…b`, `aaaaabbbbbcccccddddd…`) that defeat both period and all-same checks. Real random output of any encoding (raw, hex, base64) is non-periodic AND has well over 8 distinct values in 32+ bytes, so it passes. Under `PROD_MODE=true` a weak secret fails startup; under `PROD_MODE=false` it produces a startup warning instead. |

## Listeners and logging

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | Public bind address. |
| `METRICS_ADDR` | `127.0.0.1:9090` | Prometheus + readiness bind address (separate listener). Loopback-only by default so `/metrics` and `/readyz` are never exposed on the public interface. Override (`:9090` / explicit interface) when a scraper must reach the pod. |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error`. |
| `SHUTDOWN_TIMEOUT` | `120s` | Graceful shutdown deadline. Must be ≥ longest expected SSE stream so rolling deploys don't chop streams mid-flight. Capped at 15 minutes — a longer value keeps a stuck pod lingering past the K8s `terminationGracePeriodSeconds` sweet spot, masking upstream bugs behind an apparently healthy rollout. |

## Identity and authorization

| Variable | Default | Description |
|---|---|---|
| `GROUPS_CLAIM` | `groups` | Flat claim name in the IdP id_token holding user groups. |
| `ALLOWED_GROUPS` | (empty) | Comma-separated allowlist; empty = allow all authenticated users. |
| `MCP_RESOURCE_NAME` | (empty) | Human-readable name advertised under `resource_name` in the RFC 9728 PRM (e.g. `"ACME MCP"`). Used by MCP clients for display / consent UI. Optional; field is omitted when unset. |
| `UPSTREAM_AUTHORIZATION_HEADER` | (empty) | When set, sent verbatim as the `Authorization` header on every request to the upstream MCP backend. Full header value incl. scheme, e.g. `Bearer xyz`. Treat as a secret. |

## Token signing and rotation

| Variable | Default | Description |
|---|---|---|
| `TOKEN_SIGNING_SECRETS_PREVIOUS` | (empty) | Whitespace-separated retired signing secrets accepted on Open during a rolling rotation. New seals always use the primary `TOKEN_SIGNING_SECRET`; Open tries primary first, then each previous. See [`runbooks/key-rotation.md`](./runbooks/key-rotation.md). |
| `REVOKE_BEFORE` | (empty) | RFC3339 timestamp. Bulk revocation cutoff: tokens with `iat` before this are rejected. Applies to access AND refresh tokens. |
| `CLIENT_REGISTRATION_TTL` | `168h` (7d) | Lifetime of a sealed `client_id` minted by `POST /register`. Default matches the 7-day refresh-token TTL so a client holding a still-valid refresh can always exchange it; a shorter value silently kills long-running MCP clients (which treat DCR as one-shot at startup) the moment their access token first expires. Go duration syntax (`168h`, `720h`, …); capped at 90d. **Rolling-deploy note:** the TTL is sealed into each `client_id` at registration time, so bumping this env var only affects newly-issued client_ids — existing registrations stay on whatever TTL was in effect when they were minted. See [`runbooks/client-registration-expired.md`](./runbooks/client-registration-expired.md). |

## Replay store (Redis)

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | (empty) | Enables single-use authz codes + refresh-rotation reuse detection + single-use consent / callback-state tokens. `rediss://` for TLS. See [`redis-production.md`](./redis-production.md). |
| `REDIS_REQUIRED` | `true` | Fail startup when `REDIS_URL` is unset. Set `false` only for dev / single-replica; stateless mode leaves codes / refresh tokens replayable within their TTL. Rejected by `PROD_MODE`. |
| `REDIS_KEY_PREFIX` | `mcp-auth-proxy:` | Key prefix for shared Redis. Set to empty to opt out of namespacing. |
| `REFRESH_RACE_GRACE_SEC` | `2` | Grace window in seconds during which a refresh-rotation collision is treated as a benign concurrent submit (parallel-tab refresh, slow-network double-submit) and returns 429 `refresh_concurrent_submit` without revoking the family. Outside the window every collision still revokes. Range `[0, 10]`; `0` disables. The 10s ceiling is a security cap — wider windows are statistically attacker-shaped. |
| `IDP_EXCHANGE_RATE_PER_SEC` | (disabled) | Cap on outbound proxy → IdP token-endpoint requests at `/callback`. Defense in depth: a flood of `/callback` hits that slips past the per-IP limiter (distributed sources, permissive XFF trust matrix) is bounded by this token bucket before reaching the IdP. Denied requests get 503 `temporarily_unavailable` + `error_code=idp_exchange_throttled` + `Retry-After: 1`. Set to a positive number (e.g. `20`) to enable. **Per-replica scope:** an `N`-replica deployment admits up to `N × IDP_EXCHANGE_RATE_PER_SEC` to the IdP — divide your IdP-side ceiling by replica count. |
| `IDP_EXCHANGE_BURST` | `50` | Burst size for the IdP-exchange limiter when `IDP_EXCHANGE_RATE_PER_SEC > 0`. Higher burst absorbs a short spike (e.g. a deploy-time reconnect storm) without 503s; lower burst keeps the ceiling tighter. Ignored when `IDP_EXCHANGE_RATE_PER_SEC` is unset/zero. |

## Rate limiting and proxy headers

| Variable | Default | Description |
|---|---|---|
| `RATE_LIMIT_ENABLED` | `true` | Per-IP rate limiting on pre-auth endpoints and on the authenticated MCP route. Disable only behind a WAF that already enforces it. |
| `TRUSTED_PROXY_CIDRS` | (empty) | Comma-separated CIDRs of peers whose forwarding header (default `X-Forwarded-For`) is walked right-to-left for rate-limit keying. The first hop NOT in the trusted set is the bucket key; everything left of it (typically appended by the client) is ignored. Other peers fall back to RemoteAddr. **Preferred over the legacy `TRUST_PROXY_HEADERS` bool.** |
| `TRUSTED_PROXY_HEADER` | `X-Forwarded-For` | Pin which forwarding header carries the hop list. Allowlist: `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`. Pin `X-Real-IP` / `True-Client-IP` only when the trusted ingress is known to OVERWRITE (not append) that header — otherwise a client behind a passthrough ingress can spoof an unbounded rate-limit bucket per request. |
| `TRUST_PROXY_HEADERS` | `false` | **Legacy.** Blanket trust of every peer's forwarded headers. Superseded by `TRUSTED_PROXY_CIDRS` when both are set; rejected entirely under `PROD_MODE=true` without `TRUSTED_PROXY_CIDRS` because the bucket key becomes attacker-spoofable. |

**Per-replica scope:** the rate limiter is in-process. An `N`-replica
deployment admits up to `N × <per-endpoint rate>` per IP; size your
upstream WAF or external limiter accordingly. The optional outbound
`IDP_EXCHANGE_RATE_PER_SEC` bucket has the same per-replica scope —
divide your IdP-side ceiling by replica count when sizing it.

## Resource management

| Variable | Default | Description |
|---|---|---|
| `MCP_PER_SUBJECT_CONCURRENCY` | `16` | Per-subject in-flight cap on the authenticated MCP route. Excess requests get 503 `temporarily_unavailable` + `Retry-After: 1`. Idle subjects (no in-flight work for ≥5 min) are reclaimed by a background pruner. `0` disables. |

## Production posture toggles

`PROD_MODE=true` rejects unsafe combinations at startup. The
relaxation toggles below are offered for dev / legacy-client paths;
flipping any of them in production silently weakens a security
control.

| Variable | Default | Description |
|---|---|---|
| `PROD_MODE` | `true` | Fails startup if any compatibility flag that weakens a security control is set (`PKCE_REQUIRED=false`, `COMPAT_ALLOW_STATELESS=true`, `REDIS_REQUIRED=false`, `REDIS_URL` empty, `OIDC_ALLOW_INSECURE_HTTP=true`, or legacy `TRUST_PROXY_HEADERS=true` without `TRUSTED_PROXY_CIDRS`). Set `false` explicitly only for dev / single-replica work that needs one of the relaxation toggles. |
| `PKCE_REQUIRED` | `true` | Set `false` for legacy clients that omit PKCE (Cursor, MCP Inspector, ChatGPT). Rejected by `PROD_MODE`. |
| `COMPAT_ALLOW_STATELESS` | `false` | Synthesize a server-side `state` on `/authorize` when the client omits it. Strict mode refuses the request; counter `mcp_auth_access_denied_total{reason="state_missing"}` fires either way. Rejected by `PROD_MODE`. |
| `RENDER_CONSENT_PAGE` | `true` | Render an explicit proxy-side consent page on `/authorize` so the user sees who's asking and where they'll be redirected before the IdP login. Closes the silent-token-issuance path where a malicious DCR client + an active IdP session = tokens issued without any user interaction. Plain HTML, no JavaScript. Set `false` to fall back to the legacy silent-redirect — only when every caller is non-interactive and known-trusted. |
| `CSP_FORM_ACTION_EXTRA` | (empty) | **Deprecated, ignored.** `POST /consent` is now answered with a same-origin navigation interstitial (200 + meta refresh) instead of a 302, which terminates Chromium's form-action redirect-chain enforcement at the proxy — the consent page's `form-action` is `'self'`-only and no IdP / client origin needs to be enumerated. Still parsed and validated so existing deployments keep starting; a `csp_form_action_extra_deprecated` startup warning fires when set. Remove it from your deployment. |
| `OIDC_ALLOW_INSECURE_HTTP` | `false` | Dev-only escape hatch for cleartext `http://` OIDC issuers (Docker Compose Keycloak demo). Rejected when `PROD_MODE=true`. |

## Logging and observability

| Variable | Default | Description |
|---|---|---|
| `MCP_LOG_BODY_MAX` | `65536` | Max bytes buffered per request for JSON-RPC method extraction into access logs. `0` disables buffering (no `rpc_method` / `rpc_tool` / `rpc_id` fields). Raise for large batches; lower or zero when tool names must stay out of logs. |
| `ACCESS_LOG_SKIP_RE` | (empty) | **Go [RE2](https://pkg.go.dev/regexp/syntax) regexp** matched against `r.URL.Path` on the **public listener only**. Matching paths suppress the access-log line; handler response, Prometheus counters, and panic recovery are unaffected. Invalid pattern fails startup. RE2 is linear-time — no ReDoS. Typical: `^/healthz$` (liveness probe noise). **Always anchor with `^…$`** unless intentionally substring-matching: `healthz` (no anchors) also matches `/mcp/healthz-tool`. |
| `MCP_TOOL_METRICS` | `false` | Emit per-tool Prometheus counters (`mcp_auth_rpc_calls_total{tool}`, etc.) on JSON-RPC `tools/call` requests. Disabled by default — the `tool` label increases series cardinality and reveals workflow patterns. |
| `MCP_TOOL_METRICS_MAX_CARDINALITY` | `256` | Cap on distinct `tool` label values. Names past the cap collapse into `_overflow`; unparsed names land in `_unknown`. `0` disables the cap (only safe when the upstream enforces a tool allowlist). Only meaningful when `MCP_TOOL_METRICS=true`. |

---

## Observability

Every series the proxy emits, with the alerting playbook for the
ones operators most often want to wire up.

### Token funnel

- `mcp_auth_authorize_initiated_total{path}` — validated `/authorize`
  requests entering the consent (`path="consent"`) or silent-redirect
  (`path="silent"`) fork. Closes the GET-side of the funnel.
- `mcp_auth_consent_decisions_total{decision}` — `approved` /
  `denied` clicks on the proxy-rendered consent page. Distinct from
  `access_denied_total`: a user clicking Deny is a normal interaction.
- `mcp_auth_tokens_issued_total{grant_type}` — access tokens minted,
  by `authorization_code` / `refresh_token`.
- `mcp_auth_clients_registered_total` — RFC 7591 registrations.

PromQL recipes:

```promql
# Fraction of /authorize traffic taking the consent fork:
mcp_auth_authorize_initiated_total{path="consent"}
  / sum(mcp_auth_authorize_initiated_total)

# Consent abandonment (started but didn't click approve OR deny):
1 - sum(mcp_auth_consent_decisions_total)
  / mcp_auth_authorize_initiated_total{path="consent"}

# Approve-but-no-token (consent flow that died at the IdP or callback):
sum(mcp_auth_consent_decisions_total{decision="approved"})
  - mcp_auth_tokens_issued_total{grant_type="authorization_code"}
```

### Denials

- `mcp_auth_access_denied_total{reason}` — buckets:
  - `group` / `group_invalid` — user not in `ALLOWED_GROUPS`, or
    group name contained header-smuggling chars.
  - `email_unverified` — `email_verified=false` from the IdP.
  - `subject_missing` / `subject_concurrency_exceeded`.
  - `invalid_token` — forged / malformed / signature / AAD failures
    (**attack signal**).
  - `token_expired` — benign aging (separate bucket from
    `invalid_token` so the latter is unambiguously the attack channel).
  - `audience_mismatch` / `resource_mismatch`.
  - `token_revoked_iat_cutoff` — `REVOKE_BEFORE` rejection.
  - `id_token_verification_failed` — IdP signature / nonce / claim
    parse.
  - `replay_store_unavailable` — Redis down (fail-closed).
  - `state_missing` — `/authorize` without state in strict mode.
  - `refresh_family_revoked` / `refresh_concurrent_submit` —
    refresh-rotation outcomes.
- `mcp_auth_replay_detected_total{kind}` — `code` / `refresh` /
  `consent` / `callback_state` replays caught by the Redis-backed
  store.
- `mcp_auth_groups_claim_shape_mismatch_total` — id_token `groups`
  claim failed to decode as `[]string`. **No denial occurs** — user
  is admitted with empty groups; the counter surfaces an IdP schema
  regression before it cascades into a `group` denial spike.

### Throttling

- `mcp_auth_rate_limited_total{endpoint}` — httprate 429s by
  endpoint (`register` / `authorize` / `consent` / `callback` /
  `token` / `mcp` / `discovery`).
- `mcp_auth_idp_exchange_throttled_total` — outbound proxy → IdP
  token-endpoint exchanges denied by the rate-limit bucket
  (`IDP_EXCHANGE_RATE_PER_SEC`). A spike under steady inbound
  traffic usually means a distributed flood is slipping past the
  per-IP limiter, or the IdP is slow enough that the bucket fills
  faster than it drains.

### Crypto bookkeeping

- `mcp_auth_token_seals_total{purpose}` — successful AES-GCM seal
  operations, by purpose (`client` / `session` / `code` / `access` /
  `refresh`). Aggregate across replicas to track cumulative seals
  per signing key.

  Alert before nonce-collision matters:

  ```promql
  sum(increase(mcp_auth_token_seals_total[7d])) > 2**28
  ```

  At `2^28` seals/key, rotate `TOKEN_SIGNING_SECRET` via
  `TOKEN_SIGNING_SECRETS_PREVIOUS` (see
  [`runbooks/key-rotation.md`](./runbooks/key-rotation.md)). The
  AES-GCM 96-bit nonce is random, so the practical wall is the
  birthday bound at `2^32`.

### MCP RPC traffic (opt-in)

When `MCP_TOOL_METRICS=true`, additional counters fire only on
JSON-RPC `tools/call` requests — protocol-level methods
(`initialize`, `notifications/*`, `tools/list`, `prompts/*`) do not
contribute, so an alert on `_unknown` flags malformed `tools/call`
payloads, not background chatter.

- `mcp_auth_rpc_calls_total{tool}`
- `mcp_auth_rpc_calls_failed_total{tool}` — status ≥ 400.
- `mcp_auth_rpc_request_bytes_total{tool}` /
  `mcp_auth_rpc_response_bytes_total{tool}` — single-call only;
  per-call attribution is honest only outside batches.
- `mcp_auth_rpc_batches_total`,
  `mcp_auth_rpc_batches_failed_total`,
  `mcp_auth_rpc_batch_bytes_total{direction}` — batch-shape
  counters, disjoint from the per-tool family above so the `tool`
  label stays clean.

JSON-RPC batches fan out into one `rpc_calls_total` increment per
`tools/call` entry, each carrying its own tool label. Cap distinct
labels via `MCP_TOOL_METRICS_MAX_CARDINALITY` (default 256).

### Health probes

- `GET /healthz` (public listener) — liveness; 200 while the process
  is up.
- `GET /readyz` (metrics port only) — readiness. Reflects Redis
  reachability when `REDIS_URL` is set, cached ~1s to resist
  probe-flood amplification.
