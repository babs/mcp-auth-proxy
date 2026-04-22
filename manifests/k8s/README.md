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
kubectl apply -f ingress.example.yaml  # fill in hostname + TLS secret
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
