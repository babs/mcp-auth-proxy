# Runbook — rotate `TOKEN_SIGNING_SECRET`

Rolling rotation of the AES-GCM secret that seals every stateless
OAuth blob (client registrations, authorize sessions, auth codes,
access + refresh tokens). Uses the multi-key support in
`token.NewManagerWithRotation`: primary key seals new payloads,
secondary keys accept existing ones for the bleed-in window.

## When

- **Scheduled:** every 12 months. Seal counter approaches 2^32 (AES-GCM
  random-nonce collision bound); the proxy already emits
  `token_seal_rotation_threshold` at 2^28 as a heads-up.
- **Incident:** any credible suspicion the secret leaked (shared-secret
  store incident, accidental commit, compromised operator workstation).
  Treat as emergency — see _Emergency path_ below.

## Prerequisites

- Read access to the secrets store backing
  `mcp-auth-proxy-secret.TOKEN_SIGNING_SECRET`.
- `kubectl` against the target cluster with edit rights on the proxy
  namespace.
- A fresh 32+ byte random secret. Generate with:
  ```
  bash manifests/scripts/generate-signing-secret.sh
  ```

## Rollout

The proxy's refresh TTL is 7 days; every existing token either expires
or rotates to the new secret within one refresh window. Plan the full
rotation as a **two-phase 7–8 day rollout**.

### Phase 1 — prepare (day 0)

1. Generate `NEW_SECRET` (32+ bytes random).
2. Update the `Secret`:
   ```yaml
   TOKEN_SIGNING_SECRET:          <NEW_SECRET>
   TOKEN_SIGNING_SECRETS_PREVIOUS: <OLD_SECRET>
   ```
   Multiple retired secrets are allowed — whitespace-separated.
3. `kubectl rollout restart deploy/mcp-auth-proxy`.
4. Verify every pod logs:
   ```
   {"msg":"token_signing_rotation_in_progress","previous_keys":1,...}
   ```
5. Smoke-test: an access token minted **before** the restart should
   still validate (ask a running MCP session to make a request). A new
   `/authorize` → `/token` flow should mint a token sealed with the
   new secret.

At this point:
- **New tokens** are sealed with `NEW_SECRET`.
- **Old tokens** (pre-rotation) still decrypt because `OLD_SECRET` is
  in the `openKeys` try-list.

### Phase 2 — complete (day 7+)

After a full refresh TTL (7 days) every pre-rotation token has either
expired or been refreshed (rotated to `NEW_SECRET`). Tail
`mcp_auth_tokens_issued_total{grant_type="refresh_token"}` to confirm
rotation activity before the removal step.

1. Update the `Secret` again:
   ```yaml
   TOKEN_SIGNING_SECRET:          <NEW_SECRET>
   TOKEN_SIGNING_SECRETS_PREVIOUS: (remove this key entirely)
   ```
2. `kubectl rollout restart deploy/mcp-auth-proxy`.
3. Confirm no pod logs `token_signing_rotation_in_progress` (the log
   only fires when at least one previous key is configured).
4. Destroy `OLD_SECRET` from the secrets store and any offline backups
   not needed for audit.

## Emergency path (secret leaked)

When the old secret is assumed compromised you **cannot** wait 7 days.
The attacker would mint refresh tokens against it during the bleed-in
window.

1. Run Phase 1 **without** `TOKEN_SIGNING_SECRETS_PREVIOUS`. This hard-
   cuts over to the new secret. Every existing token becomes invalid
   the moment pods finish rolling.
2. Every MCP client is forced back through `/authorize`.
3. Set `REVOKE_BEFORE` to the current RFC3339 timestamp in the same
   deploy for belt-and-braces — in the unlikely event a pod missed the
   hard cutover (e.g. a stuck replica on old config), `REVOKE_BEFORE`
   rejects any `iat` before now.
4. Audit the access log for the 24h window before the rotation (sealed
   client_ids / sub / email are the investigation axes).

## Verification checklist

After any rotation:
- [ ] No pod logs `token_signing_rotation_in_progress` (Phase 2 done) OR
      every pod logs it with the same `previous_keys` count (Phase 1).
- [ ] `mcp_auth_tokens_issued_total` is still flat or rising — not
      stalled. A flat curve at 0 under normal load means no client
      can get a new token.
- [ ] `mcp_auth_access_denied_total{reason="invalid_token"}` is not
      elevated beyond the baseline — an elevated rate means pods
      disagree on the current key set.
- [ ] `/readyz` returns 200 on every pod.

## Gotchas

- **Key count ≤5 is comfortable.** More than 5 secondaries means every
  Open path linearly tries each AEAD; at 100k ops/sec that starts to
  show up in CPU. If you're carrying more than 5, finish rotating.
- **Multi-replica symmetry.** Every replica must carry the same
  `TOKEN_SIGNING_SECRET` + `TOKEN_SIGNING_SECRETS_PREVIOUS` set. A
  mismatch turns into "works on some pods, not others" flakiness —
  there's no warning for it today.
- **REVOKE_BEFORE interacts.** A post-rotation `REVOKE_BEFORE` will
  still apply to tokens sealed with the new key; don't set it unless
  you mean to force a re-auth.
- **Don't destroy OLD_SECRET during Phase 1.** If you need to rollback
  to the old primary (deploy regression, operator error), the old
  secret becomes the new primary and the freshly-generated one becomes
  the secondary.
