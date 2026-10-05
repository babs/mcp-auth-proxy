# Runbook — IdP outage

When the upstream OIDC IdP (Keycloak, Entra, Auth0, Okta, …) is
unavailable, the proxy cannot complete new `/authorize` flows. Existing
access tokens keep working for their 1h TTL; existing refresh tokens
keep rotating for their 7d TTL **as long as the IdP is up when the
refresh happens** — but refresh does NOT call the IdP, it only
consults the sealed refresh token and the local replay store. So a
brief IdP outage has a smaller blast radius than you might expect.

**Exception: upstream IdP token forwarding.** With
`UPSTREAM_FORWARD_IDP_TOKEN=true` every refresh grant (and every code
redemption) DOES call the IdP, to renew the IdP access token the
upstream receives. In that mode an IdP outage stops refreshes too —
see [Forwarding mode](#forwarding-mode-upstream_forward_idp_token)
below.

Error codes quoted below (and by users off the error page) are
catalogued in the [specs.md error-code
table](../../specs.md#oauth2-error-handling).

## Signals

- `/authorize` redirects to the IdP, user fails to complete login,
  browser returns to `/callback` with `error=server_error` (or the
  IdP's own error code if it's up enough to emit one). We then
  propagate the error verbatim to the MCP client.
- Browser users on the exchange failures (`idp_exchange_failed`, 502)
  see the "Temporarily unavailable" page telling them to wait, then go
  back to the application and try again — the callback state is
  claimed before the exchange, so the retry restarts at `/authorize`
  rather than reloading the burnt `/callback` URL. Expect re-auth
  traffic rather than support tickets. This response deliberately
  carries **no** `Retry-After`: the callback state is already claimed,
  so the only thing a retry of that URL can produce is
  `callback_state_replay` — and a false replay-attack signal with it.
  The two permanent misconfigurations
  that share that status — `id_token_missing` (the IdP returns no
  id_token) and `id_token_verification_failed` (signing-key / issuer /
  audience mismatch) — deliberately say "contact the administrator"
  instead, because retrying never clears them.
- Prom: `mcp_auth_access_denied_total{reason="..."}` climbs for the
  usual IdP-sourced denial reasons (`email_unverified` — reported to
  the user as `email_not_verified`,
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
   clients will attempt to refresh. In default mode refresh only
   requires the proxy + Redis, so refresh will work. It's **new**
   `/authorize` flows that fail. With
   `UPSTREAM_FORWARD_IDP_TOKEN=true` refresh fails too, see
   [Forwarding mode](#forwarding-mode-upstream_forward_idp_token).
3. Monitor `mcp_auth_tokens_issued_total{grant_type="refresh_token"}`
   — in default mode it should keep ticking. If it flattens, the
   proxy→Redis path is also broken, which is a different runbook. In
   forwarding mode a flat counter is expected during the outage, see
   [Forwarding mode](#forwarding-mode-upstream_forward_idp_token).

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

### Forwarding mode (`UPSTREAM_FORWARD_IDP_TOKEN`)

In this mode the proxy redeems the IdP refresh token sealed inside
its own tokens at every `/token` call, so the IdP is on the refresh
path as well as on sign-in.

Signals:

- `mcp_auth_idp_refresh_total{result="unavailable"}` climbs; log
  `idp_refresh_unavailable` carries the IdP's status and error code,
  or the proxy's own reason such as a transport error (never a token,
  never the IdP's `error_description`). The result
  also counts clients that hang up during the IdP call, so a low
  steady rate without an outage is expected.
- Clients get 503 `temporarily_unavailable` +
  `error_code=idp_refresh_unavailable` + `Retry-After` at `/token`.
  The code or refresh token they sent is **not** consumed (its
  single-use claim is released). A refresh token's retry succeeds once
  the IdP recovers. An authorization code can only be retried within
  its 60 s lifetime, after which the user signs in again. A
  `replay_claim_release_failed` log line means the release
  itself failed (usually Redis at the same time): that client's retry
  will then read as a reuse and revoke its family — expect a re-login,
  not an attack.
- Access tokens stop at `min(1h, IdP token expiry − 60 s)`, so a
  forwarding deployment loses service after at most that long, not
  after 7 days.

`mcp_auth_idp_refresh_total{result="rejected"}` is different: the IdP
refused the grant (`invalid_grant`, `interaction_required`, …) and the
client must sign in again (`error_code=idp_refresh_rejected`). A spike
right after a password-reset wave, an account disablement or a
Conditional Access change is expected; a spike out of nowhere usually
means the operator changed `OIDC_EXTRA_SCOPES` or the IdP client lost
its consent. `invalid_client` / `unauthorized_client` from the IdP are
counted as `unavailable`, not `rejected`: a new sign-in would not fix
the proxy's own client registration — check `OIDC_CLIENT_SECRET`.

A slow IdP has one more side effect: the IdP call runs while the
client's single-use claim is held, so a client that resends the same
authorization code at any point before the first request returns, or
the same refresh token after `REFRESH_RACE_GRACE_SEC`, is read as a
replay (`authorization_code_replay`
/ `refresh_token_reuse_detected`, family revoked, one extra sign-in).
During an IdP slowdown, treat such alerts as noise unless they persist
after the IdP recovers.

Known limitation: after an ambiguous IdP outcome (the 10 s timeout, or
the client hanging up once the request left) the proxy releases the
single-use claim and the client retries with the same token. An IdP
that rotates refresh tokens and revokes on reuse (Keycloak with
"Revoke Refresh Token", Okta, Auth0) then rejects the retry, and the
user signs in again. Entra ID does not revoke on reuse and is not
affected.

Response: nothing to do on the proxy side for an outage. Do NOT switch
forwarding off to "keep things working": the upstream would then
receive no credential at all and refuse every call.

Enabling or disabling the mode: roll all replicas together. A mixed
fleet answers `idp_token_missing` when a request crosses replicas.
Enabling signs every user out once. Disabling keeps sessions through
refresh, except tokens minted in forwarding mode that exceed 16 KB:
such an access token is refused as `invalid_token` until refreshed,
and such a refresh token is refused as `invalid_grant`, so that user
signs in again.

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
job — capping proxy → IdP calls at `/callback`, and at `/token` in
forwarding mode, so the IdP isn't hammered. A throttled `/token` call
also increments `mcp_auth_idp_refresh_total{result="throttled"}`.
Throttled requests return 503 `idp_exchange_throttled`
+ `Retry-After` (2-4s, jittered); the user retries and gets through once the
bucket refills.

Tuning playbook (only if the bucket is wired):

1. **Start liberal, narrow if alerting fires.** Default 20/sec +
   burst 50 is generous for a typical MCP deployment doing <1
   auth/sec. Default-mode operators rarely need this enabled. In
   forwarding mode it is recommended, because every refresh calls
   the IdP.
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

   In forwarding mode, first check that the rate covers the refresh
   load. See `IDP_EXCHANGE_RATE_PER_SEC` in
   [`configuration.md`](../configuration.md) for the sizing.
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
