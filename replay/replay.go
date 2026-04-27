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

	// ClaimOrCheckFamily atomically performs four operations as one
	// linearizable step:
	//   1. If familyKey is present, return familyRevoked=true.
	//   2. Else, attempt SET NX on claimKey with claimTTL, recording the
	//      claim's set time. On success return all-false (fresh claim).
	//   3. Else (claim collision) AND graceWindow > 0 AND the existing
	//      claim was set within graceWindow ago, return racing=true
	//      WITHOUT revoking the family — this is the benign-concurrent-
	//      submit case (parallel tab refresh, double-submit on slow
	//      network) and a legit caller MAY surface a 4xx racing-error
	//      to its peer without losing the session.
	//   4. Else (collision past the grace window): atomically set
	//      familyKey with familyTTL, return alreadyClaimed=true.
	//
	// Steps 3-4 split the prior "any collision = reuse" rule into
	// "fresh racing claim" vs "stale replay". The grace window is the
	// load-bearing security/UX trade-off — set it too wide and an
	// attacker has more time to ride a stolen token; set it to 0 to
	// keep the strict "every collision revokes the family" behavior.
	//
	// Step 4 closes the fail-open edge where a caller observed
	// alreadyClaimed and then tried to Mark the family in a second
	// round trip — a client disconnect or Redis blip between steps
	// would leave the family unrevoked and every sibling refresh
	// still usable. Here the revocation is part of the same EVAL, so
	// the invariant "alreadyClaimed ⇒ family revoked" holds without
	// handler cooperation.
	//
	// Returns:
	//   familyRevoked=true  → family marker present; caller MUST refuse.
	//   racing=true         → benign concurrent submit within grace
	//                          window; family NOT revoked. Caller MAY
	//                          surface a transient error and let the
	//                          legit peer proceed.
	//   alreadyClaimed=true → stale reuse past the grace window; family
	//                          is NOW revoked atomically. Caller MUST
	//                          refuse.
	//   all three false     → fresh claim; caller MAY proceed.
	//
	// Implementations: at most one of {familyRevoked, racing,
	// alreadyClaimed} is true on a given call.
	ClaimOrCheckFamily(ctx context.Context, familyKey, claimKey string, claimTTL, familyTTL, graceWindow time.Duration) (familyRevoked bool, racing bool, alreadyClaimed bool, err error)

	// Close releases any underlying resources (connections, goroutines).
	Close() error
}

// NamespacedKey prefixes a key so different consumers of the same Store
// don't collide. Callers should use a stable prefix per use-case.
func NamespacedKey(prefix, id string) string {
	return prefix + ":" + id
}
