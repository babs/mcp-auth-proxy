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
func NewRedisStore(url, keyPrefix string) (*RedisStore, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse REDIS_URL: %w", err)
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

// Close releases the underlying Redis connection pool.
func (s *RedisStore) Close() error {
	return s.client.Close()
}
