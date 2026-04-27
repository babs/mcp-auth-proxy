# Runbook — consent-page denial spike

Every `/authorize` lands on a proxy-rendered HTML page that
requires the user to click Approve or Deny before any IdP redirect
(unless the operator has explicitly set `RENDER_CONSENT_PAGE=false`).
Approve/Deny clicks are counted on
`mcp_auth_consent_decisions_total{decision="approved"|"denied"}` —
a dedicated funnel counter, intentionally outside
`mcp_auth_access_denied_total` so the existing denial-alert wiring
stays clean.

## Signals

- Prom: `rate(mcp_auth_consent_decisions_total{decision="denied"}[5m])`
  rising without a paired support signal.
- Prom: `mcp_auth_consent_decisions_total{decision="approved"}` and
  `mcp_auth_tokens_issued_total{grant_type="authorization_code"}`
  drifting apart (approves not landing in tokens).
- Log: structured `consent_denied` lines with `client_id` and
  `client_name`. Useful to spot one specific client triggering
  most denials.

## Possible causes (ranked)

1. **Phishing client successfully blocked.** A malicious DCR
   registration with a misleading `client_name` reaches the
   consent page; users notice and click Deny. Working as
   intended — the consent page is the defense.
2. **Legitimate client UX confusion.** New deployment, real
   users, unfamiliar consent shape. `client_name` is missing
   or unhelpful in the registration. Approve rate stays low
   relative to baseline.
3. **Automated test rig.** A CI job that drove `/authorize` and
   expected a 302 now sees a 200 HTML page; whatever scraped
   the form the wrong way looks like a denial in the logs.
4. **Consent page rendering broken behind the ingress.** Strict
   CSP or content-rewriting at the L7 hop mangles the form;
   user can't click. Symptom: zero approves, zero denies, just
   silent drop-off (this counter pair won't actually rise —
   look at `tokens_issued` flatlining instead).

## Response

1. Pull the most recent `consent_denied` log lines. Group by
   `client_id` / `client_name`. If one ID dominates, check its
   `redirect_uris`: is the host one your users would recognise?
   If not, escalate as a phishing-attempt signal — keep the
   consent page on, do not roll back.
2. If denials are spread across many `client_id`s, suspect UX
   confusion. Check whether `MCP_RESOURCE_NAME` is set and
   whether the deployed `client_name` strings are
   self-explanatory. The consent page renders both prominently
   when they are present.
3. If you must roll back the consent step (e.g., a
   non-interactive client suite is broken), set
   `RENDER_CONSENT_PAGE=false` and roll the deployment.
   Existing consent tokens age out within their 5-minute TTL;
   in-flight `/authorize` requests already on the silent path
   are unaffected.
4. After rollback, expect `consent_decisions_total` to flatline
   (no new emissions) and `access_denied_total{reason=…}` to be
   unaffected — the funnel-counter family is disjoint from the
   denial taxonomy by design.

## Out-of-scope

- This counter does not double-count. A user clicking Approve
  twice on a single page increments the approved arm twice;
  that is the expected funnel-data behaviour, not a bug. The
  deduplication boundary is the `sealedConsent` blob's TTL,
  not Redis.
- Consent denial is not a denial-of-service signal. Use
  `mcp_auth_rate_limited_total{endpoint="authorize"}` AND
  `mcp_auth_rate_limited_total{endpoint="consent"}` for that —
  `/authorize` and `/consent` have independent 30/min/IP buckets so
  an attacker that floods only the POST side can saturate the
  click-through path without showing up in the GET-side counter.
  Watch both labels together; abuse on either is interesting.
