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

- Per-client log line: `client_registration_expired`
  (`handlers/helpers.go`, fired by `openAndValidateClient`).
- Counter: `mcp_auth_access_denied_total{reason="invalid_client"}`
  with `error_description="client registration expired"` in the
  log line that accompanies it.
- User report: "MCP server stopped working after a few days of
  uptime, restart fixes it."

## Why it happens

The sealed `client_id` returned by `POST /register` has a
lifetime baked into its encrypted payload (`ExpiresAt`). After
that timestamp, every endpoint that re-validates the
`client_id` (`/authorize`, `/token` for both grant types)
rejects with `invalid_client: client registration expired`.

The lifetime is the `CLIENT_REGISTRATION_TTL` env var, default
**7 days** (matches `refreshTokenTTL` so a client holding a
still-valid refresh can always exchange it). Cap is 90 days.

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
4. **Consider Option 4** (auto-extend `client_id` on each
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

- **Don't disable `CLIENT_REGISTRATION_TTL` checks.** The TTL
  bounds the residual reach of an exfiltrated `client_id`
  (which is unauthenticated metadata sent in the clear on
  `/authorize`). A 0 or near-infinite value silently extends
  that window.
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
