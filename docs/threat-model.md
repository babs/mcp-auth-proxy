# Threat model

Auditable mapping from identified threats to the code, tests, and
runbooks that mitigate them. Companion to [`specs.md`](../specs.md)
(what the proxy implements) and [`conformance.md`](conformance.md)
(which RFCs it claims). Goal: when a reviewer asks *"what's the
worst case here?"*, the answer is on a row in this document with a
file path, a test name, and an operational runbook.

Categories use STRIDE: **S**poofing, **T**ampering, **R**epudiation,
**I**nformation disclosure, **D**enial of service, **E**levation of
privilege.

## Coverage matrix

| # | STRIDE | Threat | Mitigation | Code | Test | Runbook |
|---|---|---|---|---|---|---|
| 1 | T / I | **DCR abuse** — mass client registration to exhaust quota or phish via attacker-controlled `client_name` | Per-IP rate limit on `/register` (10/min default); control-byte strip on `client_name` at registration; `mcp_auth_clients_registered_total` for trend monitoring | `handlers/register.go`, `main.go` (`registerLimit`) | `handlers/handlers_test.go` (`TestRegister_*`) | — |
| 2 | S | **Active-IdP-session phishing** — malicious DCR client + an active IdP session = silent token issuance without user interaction | Proxy-rendered consent page (default `RENDER_CONSENT_PAGE=true`); per-render `jti` makes the consent token single-use (T1.2); `client_name` rendered via `html/template` contextual escaping; CSP locks the page (no JS, no remote subresources) | `handlers/authorize.go` (consent fork), `handlers/consent.go` | `handlers/consent_test.go`, `handlers/single_use_replay_test.go` | `docs/runbooks/consent-denials.md` |
| 3 | T | **Redirect-URI / open-redirect abuse** — crafted `redirect_uri` matches loosely or smuggles attacker host | Exact-match against registered URIs with RFC 8252 loopback-port relaxation; fragment-bearing URIs rejected at DCR; fragment scrubbed again on the success redirect (defense in depth) | `handlers/helpers.go` (`redirectURIMatches`), `handlers/register.go`, `handlers/callback.go` (fragment scrub) | `handlers/handlers_test.go` (redirect tests) | — |
| 4 | S | **Authorization-code replay** — captured authorization code submitted twice within its TTL | `replay.Store.ClaimOnce` on `TokenID` at `/token`, run after parameter validation but before token issuance so a malformed legitimate retry doesn't burn the code; on detected replay the family of refresh tokens seeded by that code is revoked (RFC 6749 §4.1.2 MUST) | `handlers/token.go` (`handleAuthorizationCode`), `replay/redis.go` | `handlers/handlers_test.go` (replay tests) | `docs/runbooks/redis-outage.md` |
| 5 | S | **Refresh-token replay / family compromise** — captured refresh submitted after legit rotation | Atomic Lua `ClaimOrCheckFamily` on Redis: claim + family revoke happen as one EVAL so the invariant "alreadyClaimed ⇒ family revoked" cannot be violated by a client disconnect or Redis blip. The script also classifies sub-grace-window collisions as `racing` (returns 429 `refresh_concurrent_submit`, family NOT revoked) so benign parallel-tab refreshes don't kill the lineage. `REFRESH_RACE_GRACE_SEC` (default 2s, max 10s, set 0 to disable) tunes the window. **Rolling-deploy transient:** claims minted by a pre-T2.3 binary stored a placeholder value instead of an epoch ms; collisions on those entries fall through to the strict revoke path (matches the pre-T2.3 contract) — the grace window starts applying only to claims minted by the new binary | `handlers/token.go` (`handleRefreshToken`), `replay/redis.go`, `replay/memory.go` | `handlers/handlers_test.go` (refresh tests), `handlers/single_use_replay_test.go` (`TestTokenRefresh_RaceGrace_*`), `replay/redis_test.go` | `docs/runbooks/revoke.md` |
| 6 | S | **Consent-token replay** — captured `consent_token` POSTed twice within its 5-min TTL | `JTI` `ClaimOnce` at POST `/consent` before either Approve or Deny; per-render `JTI` so back-button = re-consent (a new claim slot) | `handlers/consent.go` | `handlers/single_use_replay_test.go` (`TestConsent_SingleUse_*`) | — |
| 7 | S | **Callback-state replay** — captured `/callback` URL replayed (e.g. attacker-observable redirect) | `SessionID` `ClaimOnce` BEFORE the upstream OIDC token-endpoint exchange — replay never fans out to the IdP and never produces audit-log noise | `handlers/callback.go` | `handlers/single_use_replay_test.go` (`TestCallback_SingleUse_*`) | — |
| 8 | D | **Redis outage** — replay store unreachable | Fail-closed at every claim site: 503 `server_error` + `error_code=replay_store_unavailable`. `mcp_auth_access_denied_total{reason="replay_store_unavailable"}` is the single alerting source. `PROD_MODE=true` validates `REDIS_REQUIRED=true` + `REDIS_URL` set at startup | `replay/redis.go`, `config/config.go` (`Validate`), every claim site | `config/config_test.go` (production posture) | `docs/runbooks/redis-outage.md` |
| 9 | D | **IdP outage** — upstream OIDC unavailable | 10s context timeout on `oauth2Cfg.Exchange`; surfaces 502 `server_error`; readiness probe lives on the metrics port only so an unauthenticated public-listener flood cannot flip every replica out of the K8s Service | `handlers/callback.go` (`oidcExchangeTTL`), `main.go` (port split) | `handlers/handlers_test.go` (callback timeout tests) | `docs/runbooks/idp-outage.md` |
| 10 | S | **XFF / proxy-header spoofing** — `X-Forwarded-For` set by an attacker to bypass per-IP rate limiting | `TRUSTED_PROXY_CIDRS` allowlist scopes which upstream hops can set forwarding headers; `TRUSTED_PROXY_HEADER` names the trusted header; `PROD_MODE=true` rejects `TRUST_PROXY_HEADERS=true` without a `TRUSTED_PROXY_CIDRS` allowlist | `config/config.go` (`TrustedProxyCIDRs`), `main.go` (`ipKeyFunc`) | `config/config_test.go` (XFF cases) | — |
| 11 | R | **Multi-replica drift** — two proxy replicas issue inconsistent decisions on the same code, refresh, or callback state | All claim sites use a shared Redis store; `FamilyIssuedAt` + `REVOKE_BEFORE` propagate bulk-cutoff revocations across replicas without per-replica state | `replay/redis.go`, `token/` (`FamilyIssuedAt`) | `replay/redis_test.go` | `docs/runbooks/key-rotation.md` |
| 12 | D | **Sealed-input parse exhaustion** — oversized sealed blob slows `token.Open()` under load | Per-input length cap on every sealed-token open call (PR #18); 1 MB body cap via `MaxBytesReader` on `/token`, `/consent`, `/register` | `token/seal.go`, every handler entry point | `token/seal_test.go` (`FuzzOpenJSON`, `FuzzValidate`) | — |
| 13 | I | **`id_token` claim-shape drift** — IdP schema migration silently bypasses `ALLOWED_GROUPS` via empty-groups admit | Distinct `mcp_auth_groups_claim_shape_mismatch_total` counter and warn-level log on every shape mismatch — surfaces drift before it cascades into a `group` denial spike. Empty groups still trigger the standard `group` denial when `ALLOWED_GROUPS` is non-empty | `handlers/callback.go` | `handlers/handlers_test.go` (group-shape tests) | — |
| 14 | I | **IdP `error_description` phishing** — crafted `/callback?error=…&error_description=<phishing text>` reflects on the proxy origin or in a legit MCP-client error UI | Fixed proxy-owned description on BOTH the validated-session redirect and the no-session JSON paths; RFC 6749 §4.1.2.1 `error` allowlist (anything else collapses to `server_error`) | `handlers/callback.go` (idpError branch) | `handlers/handlers_test.go` (`TestCallback_OIDCError_*`) | — |
| 15 | E | **PKCE downgrade** — client without `code_challenge` at `/authorize` then supplies `code_verifier` at `/token`, papering over the missing PKCE binding | When `PKCE_REQUIRED=false` AND the client omitted `code_challenge`, the proxy mints its own server-side PKCE pair (H6) so the issued code is anchored to a verifier; `/token` rejects `code_verifier` against a code with no challenge (RFC 9700 §4.8.2) | `handlers/authorize.go`, `handlers/consent.go`, `handlers/token.go` | `handlers/handlers_test.go` (PKCE tests) | — |
| 16 | T | **Signing-key compromise / bulk revoke** — proxy signing material exfiltrated, in-flight tokens still valid | `REVOKE_BEFORE` env var: any access or refresh token sealed before the cutoff is rejected by `middleware/auth.go` and `handlers/token.go` regardless of whether the replay store has seen it. Operational pattern: rotate the signing key, set `REVOKE_BEFORE` to the cutoff timestamp, redeploy | `token/`, `middleware/auth.go`, `handlers/token.go` | `middleware/auth_test.go` | `docs/runbooks/key-rotation.md` |

## Out of scope / accepted residual risk

These are documented gaps — the proxy does not claim to defend
against them. Listed so future work can pick them up explicitly
rather than assuming they're already covered.

- **IdP compromise.** If Keycloak / Entra / Auth0 is owned, the
  proxy still trusts what it says. The signed `id_token`
  verification, `nonce` echo, and audience checks all assume the
  IdP itself is honest. Out of scope for this proxy; in scope for
  the IdP operator's own threat model.
- **Browser-side XSS in the consent page.** The page is JS-free and
  CSP-locked (`default-src 'none'`, `style-src 'unsafe-inline'`,
  `script-src` defaults to none, `frame-ancestors 'none'`). A
  browser-engine bug that escapes contextual HTML escaping is not
  separately mitigated.
- **Network-level MITM between proxy and IdP.** TLS verification is
  on by default in the `oauth2` library; an operator who disables
  it (or a CA compromise) lets a MITM observe the upstream code
  exchange. Standard PKI assumption.
- **Side-channel timing on AES-GCM.** Go's `crypto/aes` is constant
  time on architectures with AES-NI (the production target). Not
  separately tested.
- **Quantum / cryptanalytic attacks on AES-GCM-256 or SHA-256.**
  The proxy's sealed-token format is conventional symmetric crypto
  (AES-GCM for authenticated encryption; SHA-256 for key derivation
  and PKCE-S256). Not in scope.
- **Operator misconfiguration that bypasses `PROD_MODE`.** The
  validation rejects unsafe combinations *when `PROD_MODE=true`*.
  An operator who runs in production with `PROD_MODE=false` and a
  permissive config gets the legacy posture by their own choice.
  The CI manifest gate (T1.3) blocks this for the shipped overlay
  but cannot block a hand-rolled deployment.
- **Per-resource-mount RBAC beyond `ALLOWED_GROUPS`.** The proxy
  enforces a single group allowlist for the whole mount. Per-tool
  or per-method RBAC inside the MCP server itself is the
  responsibility of that server.

## How to use this document during review

When a code change touches an authentication or authorization path:

1. Identify which row(s) in the matrix the change sits under.
2. Check that the **Mitigation** column still describes what the
   code does — if not, the row needs an update in the same PR.
3. If the change introduces a new threat that doesn't map to an
   existing row, add a row (with **Code** + **Test** + **Runbook**
   columns filled in) before merge.
4. If a row's **Code** path moves, update the link.
5. If a row gains a test, update the **Test** column.

The matrix is load-bearing: it's the artifact a security reviewer
or auditor reads first. Drift in this document means drift in the
project's claimed posture.
