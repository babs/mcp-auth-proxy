package replay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStore implements Store on top of a Redis cluster or standalone node.
// Use rediss:// in REDIS_URL to enable TLS. All keys passed to the Store are
// transparently prefixed with keyPrefix at the Redis boundary so multiple
// proxy deployments can safely share a single Redis DB (set via
// REDIS_KEY_PREFIX).
type RedisStore struct {
	client    *redis.Client
	keyPrefix string
}

// NewRedisStore dials Redis and probes connectivity. keyPrefix is prepended
// to every key written or read — pass an empty string to opt out of
// namespacing entirely. A misconfigured URL or a failed startup PING returns
// an error so replay protection is never silently disabled.
//
// Pool sizing + per-op timeouts are set explicitly so a /token flood
// cannot starve /readyz (or vice versa) and so a wedged Redis instance
// surfaces as a fast-failing ClaimOnce rather than a pool-exhaustion
// stall. Values are chosen conservatively: ClaimOnce/EXISTS are single
// O(1) commands and should complete in low single-digit milliseconds on
// a healthy Redis, so 500ms read/write is already ~100x the expected
// latency. Operator overrides via REDIS_URL query params (go-redis
// ParseURL honors `?pool_size=...&read_timeout=...`) take precedence
// when set — the defaults below only fill in what the URL didn't.
func NewRedisStore(url, keyPrefix string) (*RedisStore, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse REDIS_URL: %w", err)
	}
	if opt.PoolSize == 0 {
		opt.PoolSize = 20
	}
	if opt.ReadTimeout == 0 {
		opt.ReadTimeout = 500 * time.Millisecond
	}
	if opt.WriteTimeout == 0 {
		opt.WriteTimeout = 500 * time.Millisecond
	}
	if opt.DialTimeout == 0 {
		opt.DialTimeout = 2 * time.Second
	}
	if opt.MaxRetries == 0 {
		opt.MaxRetries = 1
	}
	client := redis.NewClient(opt)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &RedisStore{client: client, keyPrefix: keyPrefix}, nil
}

// k applies the configured keyPrefix. Keeping prefix handling inside the
// store ensures no call site can forget it.
func (s *RedisStore) k(key string) string {
	return s.keyPrefix + key
}

// ClaimOnce uses SET NX with TTL so that concurrent redeem attempts across
// replicas resolve to exactly one winner.
func (s *RedisStore) ClaimOnce(ctx context.Context, key string, ttl time.Duration) error {
	res, err := s.client.SetArgs(ctx, s.k(key), "1", redis.SetArgs{Mode: "NX", TTL: ttl}).Result()
	if err != nil {
		// redis.Nil here means NX condition failed (key already exists).
		if errors.Is(err, redis.Nil) {
			return ErrAlreadyClaimed
		}
		return fmt.Errorf("redis set nx: %w", err)
	}
	if res != "OK" {
		return ErrAlreadyClaimed
	}
	return nil
}

// Mark sets key with TTL unconditionally (used for revocation markers).
func (s *RedisStore) Mark(ctx context.Context, key string, ttl time.Duration) error {
	if err := s.client.Set(ctx, s.k(key), "1", ttl).Err(); err != nil {
		return fmt.Errorf("redis set: %w", err)
	}
	return nil
}

// Exists returns true if the key is present in Redis.
func (s *RedisStore) Exists(ctx context.Context, key string) (bool, error) {
	n, err := s.client.Exists(ctx, s.k(key)).Result()
	if err != nil {
		return false, fmt.Errorf("redis exists: %w", err)
	}
	return n > 0, nil
}

// claimOrCheckFamilyScript collapses the family-revoked check, the
// single-use claim, the grace-window racing detection, AND the
// on-reuse family-revocation into one linearizable EVAL. Running
// all of it inside a single script on the primary closes two
// different fail-open edges:
//
//  1. TOCTOU between EXISTS and SETNX: a stale replica read could
//     previously miss a freshly-SET family marker.
//  2. Client disconnect between reuse-detect and the caller's
//     separate Mark call: previously the handler had to issue a
//     second round trip to set the family marker after detecting
//     reuse, and a cancel mid-request could skip it. Now the marker
//     lands atomically with the detection.
//
// The claim VALUE is the wall-clock millisecond timestamp at which
// the claim was first set (epoch ms as a string). On a collision
// the script reads the stored timestamp and compares it to NOW
// (passed in by Go to avoid Redis-side TIME drift) — within the
// grace window we classify as racing rather than reuse. A
// sysadmin doing `redis-cli GET <prefix>refresh:<tid>` will see a
// large number like "1714567890123" rather than the legacy "1"
// placeholder; this is intentional, not corruption. Pre-T2.3
// claims that still hold the literal "1" parse to 1 ms; the
// `(now - 1)` distance is always larger than any allowed grace
// (≤10s), so they correctly fall through to the strict revoke
// branch — the rolling-deploy contract is "at least as strict
// as before, never looser".
//
// KEYS[1] = family_revoked key
// KEYS[2] = claim key (refresh token id)
// ARGV[1] = claim TTL in milliseconds
// ARGV[2] = family-revoke TTL in milliseconds (used only on stale reuse)
// ARGV[3] = NOW (epoch ms, set by Go side)
// ARGV[4] = grace window ms (0 = strict; every collision revokes family)
// Returns {familyRevoked, racing, alreadyClaimed} as integers in {0,1}.
// At most one of the three is 1.
var claimOrCheckFamilyScript = redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 1 then
  return {1, 0, 0}
end
local ok = redis.call("SET", KEYS[2], ARGV[3], "NX", "PX", ARGV[1])
if ok then
  return {0, 0, 0}
end
local grace = tonumber(ARGV[4])
if grace and grace > 0 then
  local prior = tonumber(redis.call("GET", KEYS[2]))
  local now = tonumber(ARGV[3])
  if prior and now and (now - prior) < grace then
    return {0, 1, 0}
  end
end
redis.call("SET", KEYS[1], "1", "PX", ARGV[2])
return {0, 0, 1}
`)

// ClaimOrCheckFamily implements replay.Store.ClaimOrCheckFamily. See the
// interface doc for semantics. TTLs are truncated to millisecond
// resolution (Redis PX).
func (s *RedisStore) ClaimOrCheckFamily(ctx context.Context, familyKey, claimKey string, claimTTL, familyTTL, graceWindow time.Duration) (familyRevoked bool, racing bool, alreadyClaimed bool, err error) {
	claimMs := max(claimTTL.Milliseconds(), 1)
	familyMs := max(familyTTL.Milliseconds(), 1)
	nowMs := time.Now().UnixMilli()
	graceMs := max(graceWindow.Milliseconds(), 0)
	res, err := claimOrCheckFamilyScript.Run(
		ctx,
		s.client,
		[]string{s.k(familyKey), s.k(claimKey)},
		claimMs,
		familyMs,
		nowMs,
		graceMs,
	).Result()
	if err != nil {
		return false, false, false, fmt.Errorf("redis eval: %w", err)
	}

	arr, ok := res.([]any)
	if !ok || len(arr) != 3 {
		return false, false, false, fmt.Errorf("redis eval: unexpected result %T", res)
	}
	revoked, _ := arr[0].(int64)
	race, _ := arr[1].(int64)
	claimed, _ := arr[2].(int64)
	return revoked == 1, race == 1, claimed == 1, nil
}

// Close releases the underlying Redis connection pool.
func (s *RedisStore) Close() error {
	return s.client.Close()
}
