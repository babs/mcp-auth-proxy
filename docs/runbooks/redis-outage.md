# Runbook — Redis outage

Redis backs two security-critical controls in `mcp-auth-proxy`:

1. **Single-use authorization codes** (RFC 6749 §4.1.2 — codes MUST
   NOT be reusable).
2. **Refresh-token rotation with reuse detection** (OAuth 2.1 §6.1 —
   a replayed refresh revokes the whole family).

When `REDIS_REQUIRED=true` (default) both controls are mandatory and
the proxy fails closed on any Redis error.

## Signals

- `/readyz` flips to `503 {"status":"redis_unavailable"}`. K8s pulls
  the pod out of the Service (readiness gate). With 3 replicas all
  probing the same Redis, all 3 flip at once — customer impact is an
  instant 503 on every endpoint.
- Prom: `mcp_auth_access_denied_total{reason="replay_store_unavailable"}`
  climbs on `/token`. Log lines `replay_store_error` at error level.
- If Redis is _slow_ rather than _down_, you'll see `PoolTimeout`,
  `read tcp … i/o timeout`, or context-deadline-exceeded errors (500ms
  default for read/write). `/readyz` may flap.

## Response — first 10 minutes

1. **Confirm Redis is actually down.** From a cluster shell:
   ```bash
   kubectl -n mcp-auth-proxy exec deploy/redis -- redis-cli ping
   ```
   Or, if using managed Redis, check the provider console.
2. **Confirm network path.** If Redis is alive, the proxy may have
   lost the route:
   ```bash
   kubectl -n mcp-auth-proxy get networkpolicy
   kubectl -n mcp-auth-proxy describe networkpolicy mcp-auth-proxy
   ```
   A just-applied NetworkPolicy that drops the Redis egress is the
   classic cause.
3. **Check connection pool.** A saturated pool under a normal Redis
   looks identical to a slow Redis in the logs:
   ```bash
   kubectl -n mcp-auth-proxy logs deploy/mcp-auth-proxy --tail=200 | grep -E 'replay_store|redis'
   ```
   Persistent `PoolTimeout` suggests the pool size (default 20) is
   undersized for the traffic — raise `PoolSize` via a code change,
   not a runtime knob.

## Response — if Redis won't come back

`REDIS_REQUIRED=false` is the emergency escape hatch. It does NOT fix
the outage — it degrades the proxy to stateless mode where codes are
replayable within their 60s TTL and refresh tokens rotate without
reuse detection.

**Do not flip this switch on a production deployment.** The 60s +
7-day replay windows are the specific attacker primitive the audit
was built to close. If you must keep the MCP service serving, accept
the risk explicitly, document the window, and plan to flip back as
soon as Redis returns.

If you do flip:
1. `kubectl set env deploy/mcp-auth-proxy REDIS_REQUIRED=false`
2. Pods restart, `/readyz` returns 200 without Redis.
3. File an incident ticket; every subsequent `/authorize` succeeds
   with reduced replay guarantees until Redis is back.
4. On recovery: `kubectl set env deploy/mcp-auth-proxy REDIS_REQUIRED-`
   (unset) and roll. Re-verify `/readyz` goes back to probing Redis.

## Prevention

- **HA Redis.** The demo `redis.yaml` is single-replica with no
  persistence. Production should use a managed service (ElastiCache,
  Cloud Memorystore, Azure Cache) or Redis Sentinel/Cluster.
- **Resource requests.** The demo pod has 50m/32Mi requests. Under
  production traffic this isn't sized — raise until the container has
  at least 250m CPU and 128Mi RAM.
- **Separate scraper-reachable Redis metrics.** If you can, pair a
  redis-exporter sidecar with an alert on `redis_connected_clients`
  nearing the maxclients limit — that'll predate the proxy-side
  pool-timeout symptom.

## Known-issue checklist

- [ ] Redis pod is Running and Ready.
- [ ] Proxy's NetworkPolicy allows egress to Redis.
- [ ] `REDIS_URL` scheme matches Redis side (`redis://` vs `rediss://`).
- [ ] `REDIS_KEY_PREFIX` is identical across all proxy replicas.
- [ ] Proxy → Redis round-trip latency < 500ms (the
      default `ReadTimeout`). If higher, the pool saturates under
      load even when Redis is otherwise "up".
