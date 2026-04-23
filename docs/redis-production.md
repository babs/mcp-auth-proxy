# Redis — production posture

The demo `manifests/k8s/redis.yaml` is single-replica, unauthenticated,
no TLS, no persistence. **Do not run it in production.** This document
covers what production Redis should look like for this proxy.

## Connection string

`REDIS_URL` accepts the full go-redis URL form:

```
redis://[username:password@]host:port[/db]
rediss://[username:password@]host:port[/db]   # TLS
```

- `rediss://` turns on TLS. The proxy uses the system root CA bundle
  (from the distroless `ca-certificates` layer) — no `InsecureSkipVerify`
  path.
- `username` is optional; Redis 6 introduced ACLs with named users,
  earlier versions use just a password (leave the user segment empty).
- Passing credentials via URL puts them in the `REDIS_URL` value —
  mount that value from a `Secret`, not a `ConfigMap`.

Example for an ElastiCache-style managed Redis:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mcp-auth-proxy-secret
type: Opaque
stringData:
  REDIS_URL: "rediss://mcpauth:s3cr3t@my-redis.abc.ng.0001.use1.cache.amazonaws.com:6379/0"
```

## Pool and timeouts

The proxy sets defaults at store construction that are appropriate for
low-latency single-digit-millisecond Redis:

| Option | Default | Notes |
|---|---|---|
| `PoolSize` | `20` | per pod; raise if you run >1k req/sec per pod |
| `ReadTimeout` | `500ms` | a wedged Redis fails the `/token` call fast |
| `WriteTimeout` | `500ms` | same |
| `DialTimeout` | `2s` | initial connect |
| `MaxRetries` | `1` | one transparent retry; surface the second failure |

Overriding: these are set in code (`replay/redis.go:NewRedisStore`),
not via env vars. If you need to tune, either pass options in
`REDIS_URL` (go-redis honors `?pool_size=N&read_timeout=250ms` and
friends) or fork the store with your own constructor.

## Auth

**Always set a password.** ACL-based auth is stronger than the legacy
`requirepass` but either is a massive improvement over unauthenticated.

Create a Redis user scoped to the keys the proxy actually uses:

```
ACL SETUSER mcpauth on >s3cr3t \
    ~mcp-auth-proxy:* \
    +GET +SET +EXISTS +EVALSHA +EVAL +SCRIPT|LOAD
```

The `~mcp-auth-proxy:*` pattern matches the default
`REDIS_KEY_PREFIX`. If you override the prefix, match that instead.

## TLS

`rediss://` is mandatory for any Redis reachable outside the pod's
network namespace — including in-cluster Services when a mesh or
NetworkPolicy permits peers outside the proxy namespace to talk to
Redis.

If you terminate TLS at a sidecar (e.g. `stunnel`) the proxy speaks
plaintext `redis://` to the sidecar over loopback; not recommended
because it widens the blast radius.

## Persistence

`ClaimOnce` entries are short-lived (60s for codes, 7d for
refresh_family_revoked markers); losing them on a Redis restart
briefly weakens replay protection but doesn't corrupt any token.

- **AOF fsync=everysec** — good balance; operator restarts lose at
  most 1s of claims, which doesn't meaningfully weaken the windows.
- **RDB snapshots every 5 min** — acceptable if Redis is HA and the
  failover standby is synchronous.
- **No persistence** — only for test environments; a Redis restart
  wipes every single-use claim, so an attacker who captured a pre-
  restart auth code can redeem it again.

## High availability

The proxy fails closed on Redis errors. A 30-second Redis restart
produces a 30-second `/token` outage with every pod reporting
`replay_store_unavailable`.

Acceptable HA patterns:

- **Managed Redis** (ElastiCache, Memorystore, Azure Cache) with
  failover. The proxy retries once (`MaxRetries=1`); failover windows
  longer than ~5s will surface as customer-visible errors.
- **Sentinel.** Point `REDIS_URL` at the sentinel-fronted master; the
  client reconnects on promotion.
- **Cluster.** Supported in principle but NOT today — the proxy's
  `ClaimOrCheckFamily` Lua script spans two keys (`family_key` and
  `claim_key`) which will `CROSSSLOT` error unless you hash-tag them
  into the same slot. If you need cluster mode, open an issue; the
  fix is to prefix both keys with the same `{family_id}` hash tag.

## Key namespacing

`REDIS_KEY_PREFIX` (default `mcp-auth-proxy:`) lets multiple proxy
deployments share a single Redis DB. The prefix is validated at
startup — `{`, `}`, CR/LF, and non-printable bytes are rejected to
prevent cluster hash-tag poisoning and RESP/log injection.

Shared Redis is convenient but couples the availability of both
deployments to the single instance — if Redis goes down, both
deployments fail. Consider one Redis per proxy deployment instead.

## Sizing rules of thumb

Per pod, steady-state memory in Redis:

- `authz_code:<uuid>` — 60s TTL, ~40 bytes/entry → negligible
- `refresh:<uuid>` — 7d TTL, ~40 bytes/entry → a few MB per 10k
  unique refresh tokens in the window
- `refresh_family_revoked:<uuid>` — 7d TTL, only on compromise events

Even at 100k active refresh tokens, Redis sees on the order of 10 MB
used for this proxy. A 128 MiB Redis instance is plenty for most
deployments.

## Monitoring

The proxy's Prom counters surface Redis-related behavior:

- `mcp_auth_access_denied_total{reason="replay_store_unavailable"}` —
  counts 503s returned because Redis errored.
- `mcp_auth_replay_detected_total{kind="code"|"refresh"}` — counts
  legitimate replay-detection events. A spike may be an attack, or a
  broken client that retries with the same code.
- `/readyz` on the metrics port — probes Redis with a cached
  `Exists`. Feeds K8s readiness.

Pair with Redis's own metrics (`redis_connected_clients`,
`redis_memory_used_bytes`, `redis_commands_processed_total`) via
redis-exporter for a full picture.
