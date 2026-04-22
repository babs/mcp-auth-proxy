package replay

import (
	"context"
	"sync"
	"time"
)

// defaultMemoryGCInterval is the cadence at which MemoryStore sweeps
// expired entries. Small enough that family-revoked markers (7-day TTL)
// don't accumulate on low-traffic instances, big enough that the mutex
// is only held briefly and rarely.
const defaultMemoryGCInterval = 30 * time.Second

// memoryGCThreshold is the map-size watermark below which the inline
// gcLocked pass short-circuits — entries are still evicted lazily on
// read and by the background ticker, so lowering it from the original
// 1024 reduces the map's steady-state footprint without pushing the
// full-scan cost onto the hot ClaimOnce/Mark paths.
const memoryGCThreshold = 256

// MemoryStore is a single-process Store. Entries expire lazily on read
// and are also swept by a background ticker. It is intended for tests
// and for single-replica deployments where a full Redis dependency is
// overkill; it does NOT protect against replay across replicas.
type MemoryStore struct {
	mu       sync.Mutex
	entries  map[string]time.Time
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
		entries: make(map[string]time.Time),
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
	if exp, ok := s.entries[key]; ok && now.Before(exp) {
		return ErrAlreadyClaimed
	}
	s.entries[key] = now.Add(ttl)
	s.gcLocked(now)
	return nil
}

func (s *MemoryStore) Mark(_ context.Context, key string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.entries[key] = now.Add(ttl)
	s.gcLocked(now)
	return nil
}

func (s *MemoryStore) Exists(_ context.Context, key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.entries[key]
	return ok && time.Now().Before(exp), nil
}

// ClaimOrCheckFamily implements replay.Store.ClaimOrCheckFamily under a
// single mutex so the family-revoked check and the claim are
// observationally atomic on this replica — the same invariant the
// Redis EVAL variant enforces across replicas.
func (s *MemoryStore) ClaimOrCheckFamily(_ context.Context, familyKey, claimKey string, claimTTL time.Duration) (familyRevoked bool, alreadyClaimed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if exp, ok := s.entries[familyKey]; ok && now.Before(exp) {
		return true, false, nil
	}
	if exp, ok := s.entries[claimKey]; ok && now.Before(exp) {
		return false, true, nil
	}
	s.entries[claimKey] = now.Add(claimTTL)
	s.gcLocked(now)
	return false, false, nil
}

func (s *MemoryStore) Close() error {
	s.stopOnce.Do(func() { close(s.stop) })
	return nil
}

// gcLocked opportunistically sweeps expired entries when the map grows
// past the watermark. Caller must hold s.mu. Evictions below the
// watermark are handled by the background ticker (sweepExpired).
func (s *MemoryStore) gcLocked(now time.Time) {
	if len(s.entries) <= memoryGCThreshold {
		return
	}
	s.sweepExpired(now)
}

// sweepExpired removes every entry whose expiry is in the past. Caller
// must hold s.mu.
func (s *MemoryStore) sweepExpired(now time.Time) {
	for k, exp := range s.entries {
		if now.After(exp) {
			delete(s.entries, k)
		}
	}
}
