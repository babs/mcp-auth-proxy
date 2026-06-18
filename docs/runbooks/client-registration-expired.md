# Runbook — `invalid_client: client registration expired`

When an MCP client (Claude Code, codex_rmcp_client, Cursor, …)
fails with:

```
OAuth token refresh failed: Server returned error response:
invalid_client: client registration expired
```

it has been alive longer than the sealed `client_id`'s TTL.
DCR is one-shot for most MCP clients, so they don't auto-
re-register and the user sees the error directly.

## Signals

- Counter: `mcp_auth_access_denied_total{reason="client_registration_expired"}`
  — incremented on every rejection by both `/authorize` and
  `/token` (`handlers/authorize.go`, `handlers/helpers.go`
  `openAndValidateClient`). A tight, sustained rise = a stuck
  client (e.g. an Azure APIM connector) looping on the 400 instead
  of re-running DCR.
- Log line: `access_denied_client_registration_expired` at WARN with
  the client's `internal_id` and `expired_at` (same `access_denied_*`
  family as every other denial — catchable by a `level>=warn` or
  `event=~"access_denied_.*"` filter).
- HTTP access log: repeated `GET /authorize` (and/or `POST
  /token`) at **status 400** with a **77-byte** response body —
  the 76-byte JSON
  `{"error":"invalid_client","error_description":"client registration expired"}`
  plus the encoder's trailing newline (`resp_bytes=77` on the wire).
- User report: "MCP server stopped working after a few days of
  uptime, restart fixes it."

> **Log volume:** the `access_denied_*` WARN lines are volume-bounded
> by the default per-IP rate limiting plus zap's production sampling.
> A stuck single-client storm is capped well before it reaches the
> handler. If you run with `RATE_LIMIT_ENABLED=false` **and** the dev
> (TTY) logger config (no sampling), an attacker- or bug-driven
> rejection loop logs unbounded — keep rate limiting on in production.

## Why it happens

The sealed `client_id` returned by `POST /register` has a
lifetime baked into its encrypted payload (`ExpiresAt`). After
that timestamp, every endpoint that re-validates the
`client_id` (`/authorize`, `/token` for both grant types)
rejects with `invalid_client: client registration expired`.

The lifetime is the `CLIENT_REGISTRATION_TTL` env var, default
**7 days** (matches `refreshTokenTTL` so a client holding a
still-valid refresh can always exchange it). Cap is 90 days.
Setting it to **`0`** disables expiry entirely (never expires).

## Known client-side root cause

This is the server-side symptom of a widespread MCP client bug:
the client caches its DCR `client_id` and **does not re-run DCR
when it gets `invalid_client`**. The proxy is spec-correct — it
advertises `client_id_expires_at` (an RFC 7591 extension field) and
rejects a lapsed handle — but most clients ignore the field and never
re-register. Notably **Azure APIM-backed connectors** loop on the
400 indefinitely instead of reconnecting. Tracked across Claude
Code, Cursor, LibreChat, et al. The MCP spec is itself moving away
from DCR toward URL-based client IDs to retire this failure mode.

## Response

### Client side

The MCP client must re-register: re-run DCR (`POST /register`)
to obtain a fresh `client_id` + retry the OAuth flow from
`/authorize`. Most MCP clients do this on a fresh connection,
so a restart of the client is the simplest fix.

### Operator side

If users are hitting this faster than `CLIENT_REGISTRATION_TTL`
suggests they should:

1. **Verify `CLIENT_REGISTRATION_TTL` is what you think.**
   `kubectl exec ... -- env | grep CLIENT_REGISTRATION_TTL`.
2. **Check `REVOKE_BEFORE`.** `REVOKE_BEFORE` rejects access
   tokens whose `iat` predates the cutoff, but does NOT shorten
   `client_id` lifetime. If both fire on the same flow, the
   user sees `invalid_client` (client_id check runs first); the
   actual cause may be the token cutoff. Logs disambiguate.
3. **Lengthen the TTL** for long-running deployments by setting
   `CLIENT_REGISTRATION_TTL=720h` (30d) or up to the 90d cap.
4. **Disable expiry** with `CLIENT_REGISTRATION_TTL=0` when the
   client provably never re-registers (e.g. Azure APIM connectors
   that loop on the 400). This emits `client_id_expires_at=0` and
   skips the expiry check on every validation path. It is the
   correct fix when the alternative is a permanently-broken
   connector — at the cost of the reuse-window bound below.
   Reversible: unset the env var to restore the 7d default (only
   newly-issued client_ids are affected, per the rolling-deploy
   note).
5. **Consider Option 4** (auto-extend `client_id` on each
   `/token` use) — see `misc/next-steps.md`. Not yet
   implemented as of this writing.

## Rolling-deploy transient

Bumping `CLIENT_REGISTRATION_TTL` does **NOT** retroactively
extend already-issued `client_id`s. The TTL is sealed into the
encrypted payload at registration time. Existing clients
running on the old TTL keep that TTL until they re-register,
no matter what the env var says now. Plan accordingly:
- A deploy that raises the TTL takes effect immediately for
  newly-registered clients.
- Already-affected users won't be unblocked until their MCP
  client re-registers (manual restart, or running long enough
  to hit any other re-registration trigger).

## What NOT to do

- **Don't reach for `CLIENT_REGISTRATION_TTL=0` by default.** The
  TTL bounds the residual reach of an exfiltrated `client_id`
  (which is unauthenticated metadata sent in the clear on
  `/authorize`). `0` removes that bound — a leaked `client_id`
  stays openable forever. It is a deliberate opt-in (see Response
  step 4), justified only when a client provably never
  re-registers; reserve it for that case rather than as a blanket
  fix. Note a leaked `client_id` alone grants nothing: a full
  OAuth flow with IdP consent is still required. Under `0` the only
  per-`client_id` revocation lever is rotating `TOKEN_SIGNING_SECRET`,
  which invalidates **every** sealed blob fleet-wide (all clients,
  codes, and refresh tokens) — there is no per-client deny-list, so
  losing the TTL backstop means a single bad client can only be
  evicted with a fleet-wide rotation.
- **Don't try to extend an existing `client_id` server-side.**
  The sealed payload is immutable. The only way to extend is
  re-issuing a fresh `client_id`.
- **Don't increase past 90d** (capped at startup). Wider
  windows add no operational value once the auto-extend design
  ships, and increase the residual-reuse threat in the
  meantime.

## Prevention

- **Default `CLIENT_REGISTRATION_TTL` matches refresh-token
  lifetime (7d).** A client that successfully refreshes its
  access token at least every 7d cycles its session before
  the `client_id` envelope lapses. Long-idle clients are
  the failure mode this runbook catches.
- **Document re-registration in the MCP client's own UX.**
  Out of scope for the proxy; in scope for the client author
  if the client expects long-lived sessions without
  intervention.
