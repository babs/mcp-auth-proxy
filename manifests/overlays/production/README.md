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
