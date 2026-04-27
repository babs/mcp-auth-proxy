# K8s manifests — mcp-auth-proxy

## Apply order

```bash
kubectl apply -f namespace.yaml
kubectl apply -f redis.yaml
kubectl apply -f secret.example.yaml   # fill in values first — see below
kubectl apply -f configmap.yaml        # fill in TODO values
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f pdb.yaml
# Optional:
kubectl apply -f ingress.example.yaml         # fill in hostname + TLS secret
kubectl apply -f networkpolicy.example.yaml   # fill in scraper / ingress labels
```

> **Tip:** `secret.example.yaml` is a template. Copy it to `secret.yaml`, fill
> in the values, and apply `secret.yaml` instead (do not commit a filled-in
> secret to source control).

## Before you apply

1. **Secret** — fill both `TOKEN_SIGNING_SECRET` and `OIDC_CLIENT_SECRET` in
   `secret.example.yaml`. Generate the signing secret with:
   ```bash
   bash manifests/scripts/generate-signing-secret.sh
   ```

2. **ConfigMap** — fill in `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`,
   `PROXY_BASE_URL`, `UPSTREAM_MCP_URL` in `configmap.yaml`.

3. **Deployment image** — replace `ghcr.io/babs/mcp-auth-proxy:latest` in
   `deployment.yaml` with the image you built and pushed.

4. **Ingress** — fill in your hostname and TLS secret name in
   `ingress.example.yaml`.

## Production overlay

A production-oriented kustomize overlay is available at
`../overlays/production`. It keeps the reference manifests intact while
adding a renderable baseline with a pinned image tag, `PROD_MODE=true`,
Redis required, PKCE required, NetworkPolicy, and stricter resource
defaults.

Render it before applying:

```bash
kubectl kustomize manifests/overlays/production
```

Before rollout, copy the overlay into your environment repo or fork and
replace the example IdP, public URL, upstream MCP URL, trusted-proxy
CIDRs, NetworkPolicy selectors, Redis URL, and image tag or digest.
Create `mcp-auth-proxy-secret` from your secret manager; the overlay
deliberately does not generate production secrets. The base K8s
kustomization includes demo Redis for turnkey testing; the production
overlay deletes those demo Redis resources and expects a managed or
operator-managed Redis endpoint instead.

## Notes

- Redis (`redis.yaml`) is a **demo-only single replica** with no persistence
  or authentication. Use a managed service or Redis Operator in production.
- `terminationGracePeriodSeconds: 120` matches the default `SHUTDOWN_TIMEOUT`
  so rolling deploys do not cut in-flight SSE streams. Raise both together for
  longer streams.
- The PodDisruptionBudget (`pdb.yaml`) keeps at least one replica available
  during node drains. With 3 replicas this allows one voluntary disruption at
  a time.
- `sessionAffinity: None` is intentional — the stateless design means any pod
  can serve any request.
- **Metrics + `/readyz` on port 9090 are unauthenticated by design** (standard
  Kubernetes practice for in-cluster scrape endpoints). Neither leaks tokens,
  subjects, or other OAuth material — only aggregate counters with bounded
  static labels plus Go runtime metrics. The enforcement boundary is the
  network, not app-level auth: apply `networkpolicy.example.yaml` (or an
  equivalent for your CNI) so only the Prometheus scraper namespace can
  reach `:9090`, and only the ingress controller can reach `:8080`. Without
  a NetworkPolicy, any pod in the cluster can scrape `/metrics` — that
  usually isn't a compromise but it is fingerprinting.
