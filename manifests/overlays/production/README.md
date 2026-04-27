# Production overlay

This overlay renders a hardened starting point for production-like
clusters:

- version-pinned image tag instead of `latest`,
- `PROD_MODE=true`, Redis required, PKCE required,
- metrics on the pod network with NetworkPolicy enforcement,
- nonroot/read-only pod security inherited from the base deployment,
- stricter resource requests and limits.

Before applying, copy this overlay into your environment repo or fork
and set the values in `kustomization.yaml`:

- `OIDC_ISSUER_URL`
- `OIDC_CLIENT_ID`
- `PROXY_BASE_URL`
- `UPSTREAM_MCP_URL`
- `TRUSTED_PROXY_CIDRS`
- NetworkPolicy selectors for ingress, Prometheus, upstream MCP, and Redis
- image tag or digest

For supply-chain-sensitive deployments, prefer a digest pin over a tag:
replace `newTag: 1.0.0` with the `digest: sha256:...` value you verified
with the release checklist. Tags on registries are mutable; the digest is
the immutable artifact identity.

Set `MCP_RESOURCE_NAME` only after choosing the exact label users should
see in MCP client consent and connection UI. Leaving it unset omits the
optional RFC 9728 `resource_name` field.

## Consent page

`RENDER_CONSENT_PAGE` defaults to `true` globally — every
`/authorize` returns a 200 HTML page, the user clicks Approve before
any IdP redirect happens. This overlay sets the same value
explicitly for visibility (same way it sets `PKCE_REQUIRED=true` or
`PROD_MODE=true` even though both are also defaults).

What to validate before rollout:

- **Browser-driven clients only.** Every supported MCP client today
  (claude.ai, Claude Code, Cursor, MCP Inspector, ChatGPT) lands on
  `/authorize` through a real browser context, so they render the
  consent page just fine. Validate any non-browser / headless test
  rig you maintain — they will hit a 200 HTML body where they used
  to see a 302 and need to drive the form, the same way
  `keycloak_e2e_test.go::approveConsent` does.
- **CSP is relaxed for the consent response only.** The shared
  security-headers middleware emits `default-src 'none'`; the
  consent handler overrides it to add `style-src 'unsafe-inline'`
  for the page's inline `<style>` block. `script-src` stays
  unset (none), `frame-ancestors 'none'`, `form-action 'self'`,
  `base-uri 'none'`. Every other endpoint keeps the strict
  baseline unchanged.

Operational signals to watch:

- `mcp_auth_consent_decisions_total{decision="approved"}` should
  track close to `mcp_auth_tokens_issued_total{grant_type="authorization_code"}`.
  A widening gap = users approving but not completing IdP login.
- `mcp_auth_consent_decisions_total{decision="denied"}` rising
  steadily without a paired support signal = clients confused or
  phishing attempts blocked. See `docs/runbooks/consent-denials.md`.
- These counters are intentionally outside `mcp_auth_access_denied_total`
  so the existing denial-alert wiring stays clean.

The K8s base includes demo Redis for turnkey local testing. This
production overlay deletes those demo Redis resources. Point `REDIS_URL`
at a managed Redis service or an operator-managed Redis inside the
cluster, then adjust `networkpolicy.yaml` so egress to that Redis
endpoint is allowed.

Create `mcp-auth-proxy-secret` through your secret manager before rolling
the Deployment. It must provide:

- `TOKEN_SIGNING_SECRET`
- `OIDC_CLIENT_SECRET`
- optional `UPSTREAM_AUTHORIZATION_HEADER`

Render and inspect:

```bash
kubectl kustomize manifests/overlays/production
```
