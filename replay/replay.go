// Package replay provides a pluggable store for enforcing single-use semantics
// on authorization codes. A Redis-backed implementation is provided; when no
// store is wired, the proxy retains its stateless behavior (codes are unique,
// audience-bound and short-lived, but replayable within their TTL).
package replay

import (
	"context"
	"errors"
	"time"
)

// ErrAlreadyClaimed indicates that the key has already been consumed.
var ErrAlreadyClaimed = errors.New("already claimed")

// Store persists one-time claims and revocation markers with a TTL.
// Implementations must make ClaimOnce atomic so that concurrent attempts
// to redeem the same key resolve to exactly one success.
type Store interface {
	// ClaimOnce returns nil the first time a key is seen, and
	// ErrAlreadyClaimed on any subsequent attempt within the TTL window.
	// Other returned errors indicate backend failures and the caller
	// SHOULD fail closed.
	ClaimOnce(ctx context.Context, key string, ttl time.Duration) error

	// Mark unconditionally sets a key with a TTL. Used for revocation
	// markers (e.g. refresh token family revocation). Idempotent: a
	// second call with the same key resets the TTL and is not an error.
	Mark(ctx context.Context, key string, ttl time.Duration) error

	// Exists returns true if the key is currently set.
	Exists(ctx context.Context, key string) (bool, error)

	// Close releases any underlying resources (connections, goroutines).
	Close() error
}

// NamespacedKey prefixes a key so different consumers of the same Store
// don't collide. Callers should use a stable prefix per use-case.
func NamespacedKey(prefix, id string) string {
	return prefix + ":" + id
}
