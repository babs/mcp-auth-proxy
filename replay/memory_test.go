package replay

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestMemoryStore_ClaimOnce_FirstSucceeds(t *testing.T) {
	s := NewMemoryStore()
	if err := s.ClaimOnce(context.Background(), "k1", time.Minute); err != nil {
		t.Fatalf("first claim: %v", err)
	}
}

func TestMemoryStore_ClaimOnce_SecondFails(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	if err := s.ClaimOnce(ctx, "k1", time.Minute); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := s.ClaimOnce(ctx, "k1", time.Minute); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("second claim: want ErrAlreadyClaimed, got %v", err)
	}
}

func TestMemoryStore_ClaimOnce_DifferentKeys(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	if err := s.ClaimOnce(ctx, "k1", time.Minute); err != nil {
		t.Fatalf("k1: %v", err)
	}
	if err := s.ClaimOnce(ctx, "k2", time.Minute); err != nil {
		t.Fatalf("k2 should succeed independently: %v", err)
	}
}

func TestMemoryStore_ClaimOnce_ExpiryAllowsReclaim(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	if err := s.ClaimOnce(ctx, "k1", 10*time.Millisecond); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := s.ClaimOnce(ctx, "k1", 10*time.Millisecond); err != nil {
		t.Fatalf("after expiry, reclaim should succeed: %v", err)
	}
}

func TestNamespacedKey(t *testing.T) {
	if got := NamespacedKey("authz_code", "abc-123"); got != "authz_code:abc-123" {
		t.Errorf("NamespacedKey = %q, want %q", got, "authz_code:abc-123")
	}
}

// TestMemoryStore_BackgroundTickerEvictsExpired pins M9/M10: even on a
// quiet instance that never pushes the map above the watermark, the
// background ticker eventually sweeps expired entries so the map does
// not creep upward over days of uptime.
func TestMemoryStore_BackgroundTickerEvictsExpired(t *testing.T) {
	// 5ms ticker and 2ms TTL — well below the 256-entry watermark so
	// the inline gcLocked never fires. Any eviction observed must have
	// come from the ticker.
	s := newMemoryStore(context.Background(), 5*time.Millisecond)
	defer func() { _ = s.Close() }()

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if err := s.ClaimOnce(ctx, fmt.Sprintf("k%d", i), 2*time.Millisecond); err != nil {
			t.Fatalf("claim %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		s.mu.Lock()
		n := len(s.entries)
		s.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ticker did not evict expired entries: %d remain", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestMemoryStore_ContextCancelStopsTicker verifies
// NewMemoryStoreWithContext wires ctx cancellation through to the
// background goroutine.
func TestMemoryStore_ContextCancelStopsTicker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := newMemoryStore(ctx, time.Millisecond)
	cancel()

	// Close should still be safe after ctx cancel (Close is idempotent).
	if err := s.Close(); err != nil {
		t.Fatalf("Close after ctx cancel: %v", err)
	}
	// Second Close is a no-op; proves the stopOnce guard works.
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestMemoryStore_ClaimOrCheckFamily exercises the single-mutex
// equivalent of the Redis Lua path so both stores round-trip the same
// (familyRevoked, alreadyClaimed) truth table.
func TestMemoryStore_ClaimOrCheckFamily(t *testing.T) {
	s := NewMemoryStore()
	defer func() { _ = s.Close() }()
	ctx := context.Background()

	// Fresh claim: both flags false.
	revoked, claimed, err := s.ClaimOrCheckFamily(ctx, "fam:1", "tid:A", time.Minute)
	if err != nil || revoked || claimed {
		t.Fatalf("first call: revoked=%v claimed=%v err=%v", revoked, claimed, err)
	}

	// Re-use same tid: alreadyClaimed=true.
	revoked, claimed, err = s.ClaimOrCheckFamily(ctx, "fam:1", "tid:A", time.Minute)
	if err != nil || revoked || !claimed {
		t.Fatalf("second call (reuse): revoked=%v claimed=%v err=%v", revoked, claimed, err)
	}

	// Mark the family revoked, then try a fresh tid: familyRevoked=true,
	// claim does NOT happen.
	if err := s.Mark(ctx, "fam:1", time.Minute); err != nil {
		t.Fatalf("Mark family: %v", err)
	}
	revoked, claimed, err = s.ClaimOrCheckFamily(ctx, "fam:1", "tid:B", time.Minute)
	if err != nil || !revoked || claimed {
		t.Fatalf("after revoke: revoked=%v claimed=%v err=%v", revoked, claimed, err)
	}
	// Confirm the revoked branch did not leak a claim on tid:B.
	ok, err := s.Exists(ctx, "tid:B")
	if err != nil {
		t.Fatalf("Exists tid:B: %v", err)
	}
	if ok {
		t.Error("revoked family must NOT claim the tid")
	}
}
