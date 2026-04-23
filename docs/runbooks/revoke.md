# Runbook — bulk token revocation via `REVOKE_BEFORE`

`REVOKE_BEFORE` is the proxy's emergency stop. Any access token or
refresh token with `iat <` the configured cutoff is rejected. Because
every sealed refresh carries its own `iat`, even a leaked refresh
cannot mint new access tokens past the cutoff.

## When

- Token signing secret is suspected leaked. (Also see
  [`key-rotation.md`](./key-rotation.md); revoke + rotate is the
  combined response.)
- An IdP session compromise is being cleaned up and every active
  session must be forced through `/authorize` again.
- A sub/email has been disabled at the IdP and every outstanding
  token for that user must be invalidated immediately (use together
  with `ALLOWED_GROUPS` tightening on the IdP side for per-user
  scope).
- Operational reset — e.g. a major bug just patched and you want
  every client to re-auth before it trusts your new code.

## Rollout

`REVOKE_BEFORE` is an RFC3339 timestamp.

1. Pick the cutoff: the time the compromise window opened, or `now`
   for a global reset. Remember the value is UTC-aware:
   `2026-04-23T12:00:00Z`.
2. Update the ConfigMap (or Secret, if you're stashing it there):
   ```yaml
   REVOKE_BEFORE: "2026-04-23T12:00:00Z"
   ```
3. `kubectl rollout restart deploy/mcp-auth-proxy`.
4. Watch `kubectl rollout status deploy/mcp-auth-proxy` to convergence.
   **Every pod must converge** before you can assume the cutoff is
   fleet-wide enforced — during the rollout window some pods enforce
   the new cutoff while others still use the old one.

## Verification

- `kubectl rollout status` shows `successfully rolled out`.
- `mcp_auth_access_denied_total{reason="token_revoked_iat_cutoff"}` is
  incrementing (confirms the cutoff is being applied).
- At least one MCP client has been observed completing a fresh
  `/authorize` → `/token` flow after the rollout (proves the clients
  see the denial and re-auth cleanly).

## Gotchas

- **Startup-read only.** `REVOKE_BEFORE` is parsed at Load() and never
  re-read. Changing the value without a restart does nothing.
- **Rolling-deploy blind spot.** Pods that already passed the restart
  enforce the cutoff; pods still on the old config do not. Treat the
  cutoff as enforced only when the rollout is fully converged.
- **REVOKE_BEFORE does NOT invalidate clients.** Client registrations
  are signed with the token-signing secret but have their own 24h TTL
  and no `iat` check. Clients re-register transparently on first auth
  after the cutoff.
- **Don't push the cutoff into the future.** The only sensible value is
  `now` (or the known-compromise-start). A future value means every
  token minted up until that timestamp will be silently rejected on
  arrival.

## Clearing

Once the incident is closed and operators no longer want the cutoff
active, either:
- Remove the `REVOKE_BEFORE` key entirely (preferred), or
- Set it to a past value that no current token predates (e.g. the
  original deployment date).

Followed by `kubectl rollout restart`.
