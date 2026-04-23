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

	// ClaimOrCheckFamily atomically performs three operations as one
	// linearizable step:
	//   1. If familyKey is present, return familyRevoked=true.
	//   2. Else, attempt SET NX on claimKey with claimTTL. On success
	//      return both false (fresh claim).
	//   3. Else (claim collision = reuse detected): atomically set
	//      familyKey with familyTTL, then return alreadyClaimed=true.
	//
	// Step 3 closes the fail-open edge where a caller observed
	// alreadyClaimed and then tried to Mark the family in a second
	// round trip — a client disconnect or Redis blip between steps
	// would leave the family unrevoked and every sibling refresh
	// still usable. Here the revocation is part of the same EVAL, so
	// the invariant "alreadyClaimed ⇒ family revoked" holds without
	// handler cooperation.
	//
	// Returns:
	//   familyRevoked=true  → family marker present; caller MUST refuse.
	//   alreadyClaimed=true → reuse detected; family is NOW revoked
	//                          atomically. Caller MUST refuse.
	//   both false          → fresh claim; caller MAY proceed.
	ClaimOrCheckFamily(ctx context.Context, familyKey, claimKey string, claimTTL, familyTTL time.Duration) (familyRevoked bool, alreadyClaimed bool, err error)

	// Close releases any underlying resources (connections, goroutines).
	Close() error
}

// NamespacedKey prefixes a key so different consumers of the same Store
// don't collide. Callers should use a stable prefix per use-case.
func NamespacedKey(prefix, id string) string {
	return prefix + ":" + id
}
