# mcp-auth-proxy — turn-key demo

A local demo that wires **Keycloak → Redis → hello-world MCP server → mcp-auth-proxy** so you can verify a full OAuth 2.1 + MCP auth flow in three commands.

> **⚠ DEMO ONLY** — Keycloak runs in dev mode over HTTP, the client secret and
> user password are hardcoded, and Redis has no authentication. Do not expose
> this stack to the internet and do not reuse these credentials in any real
> deployment.

---

## Prerequisites

1. **Docker + Docker Compose v2** (`docker compose` subcommand).
2. **`127.0.0.1 keycloak` in `/etc/hosts`** — the proxy redirects your browser
   to `http://keycloak:8080/...` during the OAuth flow.  `up.sh` offers to add
   this automatically, or do it once yourself:
   ```bash
   echo '127.0.0.1 keycloak' | sudo tee -a /etc/hosts
   ```

---

## Compose quick start (3 commands)

```bash
# 1. Generate TOKEN_SIGNING_SECRET and write .env
bash manifests/docker-compose/scripts/generate-secrets.sh

# 2. Start all services (builds the proxy from source)
bash manifests/docker-compose/scripts/up.sh

# 3. Smoke-test the two discovery endpoints
bash manifests/docker-compose/scripts/smoke-test.sh
```

Then open **Claude.ai → Settings → Integrations → Add custom integration** and
enter `http://localhost:8080` as the MCP server URL.

| Service | URL |
|---|---|
| Proxy (MCP + OAuth) | http://localhost:8080 |
| Keycloak admin | http://localhost:8180 (admin / admin) |
| MCP server (direct) | http://localhost:3000/mcp |
| Prometheus metrics | http://localhost:9090/metrics |

Test user: **alice / changeme** (DEMO ONLY — rotate before any real use).

To tear down: `bash manifests/docker-compose/scripts/down.sh`

---

## K8s quick start (local cluster — 3 commands)

```bash
# 1. Fill in secret.example.yaml (TOKEN_SIGNING_SECRET, OIDC_CLIENT_SECRET)
#    and configmap.yaml (OIDC_ISSUER_URL, PROXY_BASE_URL, UPSTREAM_MCP_URL).
#    See manifests/k8s/README.md for details.

# 2. Apply in order
kubectl apply -f manifests/k8s/namespace.yaml
kubectl apply -f manifests/k8s/redis.yaml
kubectl apply -f manifests/k8s/secret.example.yaml   # rename to secret.yaml first
kubectl apply -f manifests/k8s/configmap.yaml
kubectl apply -f manifests/k8s/deployment.yaml
kubectl apply -f manifests/k8s/service.yaml
kubectl apply -f manifests/k8s/pdb.yaml

# 3. (Optional) Add ingress with TLS
kubectl apply -f manifests/k8s/ingress.example.yaml  # fill in hostname first
```

See [`k8s/README.md`](k8s/README.md) for the full checklist.

For production-like clusters, start from the kustomize overlay at
[`overlays/production`](overlays/production). It renders a
version-pinned, `PROD_MODE=true` deployment with NetworkPolicy and
stricter resource defaults. Copy it into your environment repo and set
the IdP, ingress, upstream, Redis, trusted-proxy CIDR, NetworkPolicy
selector, and image values before applying.

The base K8s manifests keep a demo Redis deployment for turnkey local
testing. The production overlay deletes that demo Redis and expects a
managed or operator-managed Redis endpoint.

---

## MCP server choice

This demo uses a **custom 30-LOC FastMCP Python server** (`docker-compose/mcp-server/`)
with three tools: `hello`, `add`, `echo`.  It was chosen because:

- [`@modelcontextprotocol/server-everything`](https://github.com/modelcontextprotocol/servers/tree/main/src/everything)
  runs in **stdio** mode only (no HTTP transport) — not suitable for reverse-proxy use.
- [`@modelcontextprotocol/server-filesystem`](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem)
  also uses stdio transport.
- `uv run mcp-server-time` has Streamable HTTP support but adds a ~400 MB
  image layer for a single binary — impractical for a quickstart demo.
- FastMCP (`mcp[cli]>=1.9.0`) supports Streamable HTTP natively and fits in a
  `python:3.12-slim` image with a one-line `pip install`.

The custom server is intentionally minimal.  Swap `UPSTREAM_MCP_URL` in `.env`
to point at any real MCP server that speaks Streamable HTTP.

---

## Security warnings

- **HTTP only** — this demo uses plain HTTP throughout.  In any real deployment
  the proxy MUST be behind HTTPS (Ingress with a real TLS cert).  OAuth 2.1
  tokens sent over HTTP are trivially intercepted.
- **Hardcoded credentials** — `alice / changeme` and `changeme-DEMO-ONLY`
  (client secret) are intentionally weak for demo convenience.  Rotate them
  before connecting any real user or real Claude.ai workspace.
- **Keycloak dev mode** — `start-dev` disables many Keycloak security features
  (strict hostname, TLS requirement, CORS restrictions).  Do not use this
  Keycloak configuration in production.
- **Redis without auth/TLS** — the demo Redis has no password and no TLS.
  The replay-protection guarantees only hold on a trusted network.
- **Do not point Claude.ai at this stack unless it is fronted by HTTPS and a
  real cert** — the Redirect URI registered in Keycloak is HTTP for local use
  only.
