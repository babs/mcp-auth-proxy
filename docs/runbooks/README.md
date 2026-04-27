# Runbooks

Operational procedures for running `mcp-auth-proxy` in production.

| Runbook | When |
|---|---|
| [`key-rotation.md`](./key-rotation.md) | Rotate `TOKEN_SIGNING_SECRET` — scheduled (annual) or emergency (suspected leak) |
| [`revoke.md`](./revoke.md) | Bulk revocation via `REVOKE_BEFORE` — force every outstanding token through `/authorize` again |
| [`redis-outage.md`](./redis-outage.md) | Redis down or degraded — includes the `REDIS_REQUIRED=false` emergency escape |
| [`idp-outage.md`](./idp-outage.md) | OIDC IdP unavailable or misbehaving — existing refresh flows keep working, new `/authorize` fails |
| [`consent-denials.md`](./consent-denials.md) | Spike on `mcp_auth_consent_decisions_total{decision="denied"}` — phishing-blocked vs UX-confusion vs CI rig vs ingress-mangled-form triage |

See also [`../redis-production.md`](../redis-production.md) for the
steady-state Redis posture the runbooks assume.

## Conventions

- Commands are `kubectl`-centric; adapt for your orchestrator.
- Every runbook has a **Signals → Response → Verification** spine.
  Start from Signals to confirm you're in the right runbook, then
  work through Response top-to-bottom, and don't close the incident
  until every Verification box is checked.
- **Don't silently disable security controls to "keep things running."**
  Where an escape hatch exists (e.g. `REDIS_REQUIRED=false`), the
  runbook calls out the trade-off explicitly.
