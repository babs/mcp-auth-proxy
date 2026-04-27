package replay

import (
	"context"
	"errors"
	"sync"
	"time"
)

// defaultMemoryGCInterval is the cadence at which MemoryStore sweeps
// expired entries. Small enough that family-revoked markers (7-day TTL)
// don't accumulate on low-traffic instances, big enough that the mutex
// is only held briefly and rarely.
const defaultMemoryGCInterval = 30 * time.Second

// MemoryStore eviction policy
//
// Earlier versions ran a full-map sweep on every write past a small
// watermark, which degraded the ClaimOnce/Mark hot path to O(n²) under
// sustained churn (the attack M5 in the audit report). Eviction now
// rests on three mechanisms that keep the hot path amortized O(1):
//
//  1. Lazy expiry: Exists / ClaimOnce test the per-key expiry before
//     honoring a hit.
//  2. Background ticker (gcLoop): scheduled sweep every 30s.
//  3. Size cap (memoryMaxEntries): when the cap is reached we sweep
//     once at write time to free headroom, then fail closed with
//     ErrStoreFull if none was freed.

// memoryMaxEntries caps the MemoryStore map so sustained attacker-driven
// /authorize or /register churn (which each land one ClaimOnce or Mark
// entry) cannot grow the map without bound. At the cap a single sweep
// runs to free headroom from expired entries; if none was freed, new
// writes return ErrStoreFull so the handler fails closed (503). This
// bounds resident memory and keeps ClaimOnce/Mark amortized O(1) on
// the hot path. Ballpark: 100k entries × ~80 B per entry (key +
// time.Time) ≈ 8 MiB resident.
const memoryMaxEntries = 100_000

// ErrStoreFull indicates the MemoryStore has reached its size cap and
// cannot accept new claims / markers until expired entries age out.
// Callers treat it like a backend failure and fail closed.
var ErrStoreFull = errors.New("replay memory store at capacity")

// memoryEntry tracks both the expiry and the original set time of a
// claim. setAt is only consulted by ClaimOrCheckFamily's grace-window
// logic; for every other path expiresAt is what matters.
type memoryEntry struct {
	expiresAt time.Time
	setAt     time.Time
}

// MemoryStore is a single-process Store. Entries expire lazily on read
// and are also swept by a background ticker. It is intended for tests
// and for single-replica deployments where a full Redis dependency is
// overkill; it does NOT protect against replay across replicas.
type MemoryStore struct {
	mu       sync.Mutex
	entries  map[string]memoryEntry
	stop     chan struct{}
	stopOnce sync.Once
}

// NewMemoryStore returns an in-memory Store whose background GC
// goroutine is stopped by Close. Callers who do not need ticker
// lifecycle tied to a context may use this constructor; the goroutine
// leaks if Close is never called (no runtime.SetFinalizer — tests
// should always Close explicitly).
func NewMemoryStore() *MemoryStore {
	return newMemoryStore(context.Background(), defaultMemoryGCInterval)
}

// NewMemoryStoreWithContext returns an in-memory Store whose background
// GC goroutine exits when either ctx is cancelled or Close is called,
// whichever comes first. Prefer this constructor in production so the
// goroutine is unambiguously tied to process lifetime.
func NewMemoryStoreWithContext(ctx context.Context) *MemoryStore {
	return newMemoryStore(ctx, defaultMemoryGCInterval)
}

// newMemoryStore is the shared constructor. A short interval is exposed
// for tests so eviction can be observed without waiting the full 30s.
func newMemoryStore(ctx context.Context, interval time.Duration) *MemoryStore {
	s := &MemoryStore{
		entries: make(map[string]memoryEntry),
		stop:    make(chan struct{}),
	}
	go s.gcLoop(ctx, interval)
	return s
}

func (s *MemoryStore) gcLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case now := <-t.C:
			s.mu.Lock()
			s.sweepExpired(now)
			s.mu.Unlock()
		case <-s.stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *MemoryStore) ClaimOnce(_ context.Context, key string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if e, ok := s.entries[key]; ok && now.Before(e.expiresAt) {
		return ErrAlreadyClaimed
	}
	if _, exists := s.entries[key]; !exists && !s.hasRoomLocked(now) {
		return ErrStoreFull
	}
	s.entries[key] = memoryEntry{expiresAt: now.Add(ttl), setAt: now}
	return nil
}

func (s *MemoryStore) Mark(_ context.Context, key string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if _, exists := s.entries[key]; !exists && !s.hasRoomLocked(now) {
		return ErrStoreFull
	}
	// setAt is recorded for symmetry with ClaimOnce, but Mark is
	// only used for revocation markers (e.g. refresh_family_revoked)
	// which live in a different keyspace from refresh-claim keys —
	// the racing branch in ClaimOrCheckFamily never reads it from a
	// Mark-written entry under any current call site.
	s.entries[key] = memoryEntry{expiresAt: now.Add(ttl), setAt: now}
	return nil
}

func (s *MemoryStore) Exists(_ context.Context, key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	return ok && time.Now().Before(e.expiresAt), nil
}

// ClaimOrCheckFamily implements replay.Store.ClaimOrCheckFamily under a
// single mutex so the four-step sequence (family-revoked check,
// single-use claim, racing-within-grace, on-stale-reuse family
// revocation) is observationally atomic on this replica — the same
// invariant the Redis EVAL variant enforces across replicas.
func (s *MemoryStore) ClaimOrCheckFamily(_ context.Context, familyKey, claimKey string, claimTTL, familyTTL, graceWindow time.Duration) (familyRevoked bool, racing bool, alreadyClaimed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if e, ok := s.entries[familyKey]; ok && now.Before(e.expiresAt) {
		return true, false, false, nil
	}
	if e, ok := s.entries[claimKey]; ok && now.Before(e.expiresAt) {
		// Collision. If the prior claim is still inside the grace
		// window the call is treated as a benign concurrent submit
		// (parallel-tab refresh, double-submit on slow network) — the
		// family is NOT revoked, the caller surfaces a transient
		// error so the legit peer can keep going. setAt covers the
		// case where an entry left over from a non-claim operation
		// (e.g. a Mark that happened to land on this key) has a
		// zero setAt — `now.Sub(time.Time{})` is huge and exits the
		// grace branch correctly.
		if graceWindow > 0 && now.Sub(e.setAt) < graceWindow {
			return false, true, false, nil
		}
		// Stale reuse past the grace window: revoke the family
		// atomically here so the invariant "alreadyClaimed ⇒ family
		// revoked" holds without relying on a second handler-driven
		// write.
		if _, exists := s.entries[familyKey]; !exists && !s.hasRoomLocked(now) {
			// Cannot satisfy the alreadyClaimed-implies-family-
			// revoked contract under cap pressure. Surface as an
			// error and report alreadyClaimed=false so a future
			// caller that reads the bools first (instead of err
			// first) cannot conclude the family is revoked when it
			// isn't. The handler treats err != nil as a 503 anyway,
			// so no token is issued — the contract gap is the
			// observable risk, not a token leak.
			return false, false, false, ErrStoreFull
		}
		s.entries[familyKey] = memoryEntry{expiresAt: now.Add(familyTTL), setAt: now}
		return false, false, true, nil
	}
	if _, exists := s.entries[claimKey]; !exists && !s.hasRoomLocked(now) {
		return false, false, false, ErrStoreFull
	}
	s.entries[claimKey] = memoryEntry{expiresAt: now.Add(claimTTL), setAt: now}
	return false, false, false, nil
}

func (s *MemoryStore) Close() error {
	s.stopOnce.Do(func() { close(s.stop) })
	return nil
}

// hasRoomLocked returns true if the map has room for a new key under the
// size cap. When at the cap it first attempts an expired-entry sweep;
// if headroom is freed it returns true, otherwise false (caller returns
// ErrStoreFull to the handler). Caller must hold s.mu.
func (s *MemoryStore) hasRoomLocked(now time.Time) bool {
	if len(s.entries) < memoryMaxEntries {
		return true
	}
	s.sweepExpired(now)
	return len(s.entries) < memoryMaxEntries
}

// sweepExpired removes every entry whose expiry is in the past. Caller
// must hold s.mu.
func (s *MemoryStore) sweepExpired(now time.Time) {
	for k, e := range s.entries {
		if now.After(e.expiresAt) {
			delete(s.entries, k)
		}
	}
}
