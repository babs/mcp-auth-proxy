# Runbook — IdP outage

When the upstream OIDC IdP (Keycloak, Entra, Auth0, Okta, …) is
unavailable, the proxy cannot complete new `/authorize` flows. Existing
access tokens keep working for their 1h TTL; existing refresh tokens
keep rotating for their 7d TTL **as long as the IdP is up when the
refresh happens** — but refresh does NOT call the IdP, it only
consults the sealed refresh token and the local replay store. So a
brief IdP outage has a smaller blast radius than you might expect.

## Signals

- `/authorize` redirects to the IdP, user fails to complete login,
  browser returns to `/callback` with `error=server_error` (or the
  IdP's own error code if it's up enough to emit one). We then
  propagate the error verbatim to the MCP client.
- Prom: `mcp_auth_access_denied_total{reason="..."}` climbs for the
  usual IdP-sourced denial reasons (`email_unverified`,
  `group_invalid`, `subject_missing`, `id_token_verification_failed`)
  depending on exactly how the IdP is failing.
- Log: `upstream_token_exchange_failed` (IdP down at the token-
  exchange step) or `id_token_verification_failed` (IdP returned
  something that doesn't pass go-oidc).

## Response

### IdP fully down

1. Check the IdP's status page / run book first. The proxy has no
   IdP-side fix.
2. If the outage is longer than the access-token TTL (1h), customers
   will progressively lose service as their tokens expire. Their MCP
   clients will attempt to refresh — refresh only requires the proxy
   + Redis, so refresh will work. It's **new** `/authorize` flows
   that fail.
3. Monitor `mcp_auth_tokens_issued_total{grant_type="refresh_token"}`
   — it should keep ticking. If it flattens, the proxy→Redis path
   is also broken, which is a different runbook.

### IdP OIDC discovery failing

Startup-time only. The proxy retries discovery with capped backoff
(1s → 15s, 5 attempts, ~60s total) before exiting. A pod stuck in
CrashLoopBackoff with `oidc_discovery_retry` followed by
`oidc_discovery_failed` means the IdP wasn't reachable at startup —
the pod will come up clean once the IdP does.

During this window:
- Existing pods that discovered successfully continue serving.
- Rolling deploys may stall on the first bad pod; `kubectl rollout
  pause deploy/mcp-auth-proxy` to freeze until the IdP returns.

### IdP certificate / OIDC config change

If the IdP rotated its JWKS or changed `issuer`, existing pods' cached
OIDC config won't match any more. Symptom is a sudden spike of
`id_token_verification_failed`. Fix: `kubectl rollout restart
deploy/mcp-auth-proxy`. The proxy re-discovers on startup.

### Wrong `OIDC_CLIENT_SECRET`

Post-rotation symptom: token-exchange calls return
`invalid_client`/`invalid_grant`. Look at the proxy log for
`upstream_token_exchange_failed`. Fix: update the `Secret` and
rollout-restart.

## What NOT to do

- **Do not disable group enforcement.** `ALLOWED_GROUPS` is a denial
  control; removing it to "keep things working" silently expands the
  authorized population.
- **Do not set `email_verified=true` checks off.** The proxy already
  accepts a missing `email_verified` claim; only an explicit
  `email_verified=false` is rejected. Don't stub the claim upstream.
- **Do not expose a backup IdP at the same `OIDC_ISSUER_URL`.** Each
  IdP has its own JWKS, issuer string, and client registration.
  Pointing the proxy at a different IdP requires updating
  `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and a
  rollout.

### IdP overload — proxy → IdP rate-bucket

If `mcp_auth_idp_exchange_throttled_total` is climbing while
inbound traffic stays steady, the optional outbound rate-bucket
(`IDP_EXCHANGE_RATE_PER_SEC` + `IDP_EXCHANGE_BURST`) is doing its
job — capping proxy → IdP fan-out at `/callback` so the IdP isn't
hammered. Throttled requests return 503 `idp_exchange_throttled`
+ `Retry-After: 1`; the user retries and gets through once the
bucket refills.

Tuning playbook (only if the bucket is wired):

1. **Start liberal, narrow if alerting fires.** Default 20/sec +
   burst 50 is generous for a typical MCP deployment doing <1
   auth/sec. Most operators never need this enabled.
2. **Per-replica scope.** The limiter is in-process. An
   `N`-replica Deployment admits up to `N × IDP_EXCHANGE_RATE_PER_SEC`
   to the IdP. Divide your IdP-side ceiling by replica count.
3. **If `idp_exchange_throttled_total` climbs under steady
   inbound traffic, two distinct causes:**
   a. A distributed flood is slipping past the per-IP limiter
      (check `TRUSTED_PROXY_CIDRS` — a permissive XFF trust
      matrix can be the culprit).
   b. The IdP itself is slow enough that the bucket refills
      slower than it drains. In that case raise the rate
      cautiously after confirming the IdP can handle it.
4. **Do not raise the rate to "make the alert go away".** The
   bucket exists to protect the IdP; bypassing it can cascade
   the IdP outage into a proxy outage when the IdP eventually
   drops requests on the floor.

## Prevention

- **Monitor the IdP's availability independently** of the proxy.
  `id_token_verification_failed` is a lagging indicator.
- **Alert on `oidc_discovery_failed`.** A single startup failure is
  normal during deploys; sustained failures are the signal.
- **Keep the IdP + proxy in the same failure domain when possible.**
  If the IdP is only reachable via the internet and the proxy lives
  in a private cluster, a network event can partition them even
  when both are "up".
