package replay

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is a single-process Store. Entries expire lazily on read. It is
// intended for tests and for single-replica deployments where a full Redis
// dependency is overkill; it does NOT protect against replay across replicas.
type MemoryStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// NewMemoryStore returns an in-memory Store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: make(map[string]time.Time)}
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

func (s *MemoryStore) Close() error { return nil }

// gcLocked sweeps expired entries. Caller must hold s.mu.
func (s *MemoryStore) gcLocked(now time.Time) {
	if len(s.entries) <= 1024 {
		return
	}
	for k, exp := range s.entries {
		if now.After(exp) {
			delete(s.entries, k)
		}
	}
}
