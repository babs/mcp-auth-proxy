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
	for i := range 10 {
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

	// graceWindow=0 keeps the strict "every collision revokes" shape
	// — pinning the pre-grace behaviour explicitly.
	const noGrace time.Duration = 0

	// Fresh claim: all flags false.
	revoked, racing, claimed, err := s.ClaimOrCheckFamily(ctx, "fam:1", "tid:A", time.Minute, 7*24*time.Hour, noGrace)
	if err != nil || revoked || racing || claimed {
		t.Fatalf("first call: revoked=%v racing=%v claimed=%v err=%v", revoked, racing, claimed, err)
	}

	// Re-use same tid with no grace: alreadyClaimed=true.
	revoked, racing, claimed, err = s.ClaimOrCheckFamily(ctx, "fam:1", "tid:A", time.Minute, 7*24*time.Hour, noGrace)
	if err != nil || revoked || racing || !claimed {
		t.Fatalf("second call (reuse, no grace): revoked=%v racing=%v claimed=%v err=%v", revoked, racing, claimed, err)
	}

	// Mark the family revoked, then try a fresh tid: familyRevoked=true,
	// claim does NOT happen.
	if err := s.Mark(ctx, "fam:1", time.Minute); err != nil {
		t.Fatalf("Mark family: %v", err)
	}
	revoked, racing, claimed, err = s.ClaimOrCheckFamily(ctx, "fam:1", "tid:B", time.Minute, 7*24*time.Hour, noGrace)
	if err != nil || !revoked || racing || claimed {
		t.Fatalf("after revoke: revoked=%v racing=%v claimed=%v err=%v", revoked, racing, claimed, err)
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

// TestMemoryStore_ClaimOrCheckFamily_RacingWithinGrace pins the
// new T2.3 grace-window behavior on the in-memory store. A second
// claim within graceWindow returns racing=true and does NOT revoke
// the family.
func TestMemoryStore_ClaimOrCheckFamily_RacingWithinGrace(t *testing.T) {
	s := NewMemoryStore()
	defer func() { _ = s.Close() }()
	ctx := context.Background()

	grace := 5 * time.Second

	// First claim sets the entry's setAt to ~now.
	if _, _, _, err := s.ClaimOrCheckFamily(ctx, "fam:1", "tid:A", time.Minute, 7*24*time.Hour, grace); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Second claim within grace: racing=true, family NOT revoked.
	revoked, racing, claimed, err := s.ClaimOrCheckFamily(ctx, "fam:1", "tid:A", time.Minute, 7*24*time.Hour, grace)
	if err != nil {
		t.Fatalf("racing call: %v", err)
	}
	if revoked || claimed {
		t.Fatalf("racing call: want only racing=true, got revoked=%v racing=%v claimed=%v", revoked, racing, claimed)
	}
	if !racing {
		t.Error("racing call: want racing=true")
	}
	// Confirm the family was NOT marked.
	if exists, _ := s.Exists(ctx, "fam:1"); exists {
		t.Error("racing collision must not revoke the family")
	}
}

// TestMemoryStore_ClaimOrCheckFamily_PastGraceRevokes pins that a
// collision past the grace window still triggers the strict reuse
// path (alreadyClaimed=true, family revoked). Drives the boundary
// by using a small grace + a sleep across it. Margins are generous
// enough to stay stable on a slow CI runner under -race.
func TestMemoryStore_ClaimOrCheckFamily_PastGraceRevokes(t *testing.T) {
	s := NewMemoryStore()
	defer func() { _ = s.Close() }()
	ctx := context.Background()

	grace := 200 * time.Millisecond

	if _, _, _, err := s.ClaimOrCheckFamily(ctx, "fam:1", "tid:A", time.Minute, 7*24*time.Hour, grace); err != nil {
		t.Fatalf("first call: %v", err)
	}
	time.Sleep(grace + 100*time.Millisecond)
	revoked, racing, claimed, err := s.ClaimOrCheckFamily(ctx, "fam:1", "tid:A", time.Minute, 7*24*time.Hour, grace)
	if err != nil {
		t.Fatalf("post-grace call: %v", err)
	}
	if !claimed || racing || revoked {
		t.Fatalf("post-grace: want claimed=true only, got revoked=%v racing=%v claimed=%v", revoked, racing, claimed)
	}
	// Family must be revoked atomically alongside the alreadyClaimed signal.
	if exists, _ := s.Exists(ctx, "fam:1"); !exists {
		t.Error("post-grace reuse must atomically revoke the family")
	}
}

// TestMemoryStore_SizeCap_FailsClosed: a new ClaimOnce against a full
// map (no expired entries to sweep) must return ErrStoreFull so the
// handler can 503 fail-closed rather than silently degrading to O(n²)
// or dropping replay guarantees. Exercises the cap explicitly by
// driving entries to memoryMaxEntries with a long TTL.
func TestMemoryStore_SizeCap_FailsClosed(t *testing.T) {
	s := NewMemoryStore()
	defer func() { _ = s.Close() }()
	ctx := context.Background()

	// Fill to cap with TTLs that cannot expire during the test.
	for i := range memoryMaxEntries {
		if err := s.ClaimOnce(ctx, fmt.Sprintf("k%d", i), time.Hour); err != nil {
			t.Fatalf("fill %d: %v", i, err)
		}
	}
	// Next write must fail closed.
	err := s.ClaimOnce(ctx, "overflow", time.Hour)
	if !errors.Is(err, ErrStoreFull) {
		t.Fatalf("want ErrStoreFull past cap, got %v", err)
	}
	// Mark must also refuse at cap.
	err = s.Mark(ctx, "family-marker", time.Hour)
	if !errors.Is(err, ErrStoreFull) {
		t.Fatalf("Mark past cap: want ErrStoreFull, got %v", err)
	}
	// Overwriting an existing key is still OK (no growth).
	if err := s.Mark(ctx, "k0", time.Hour); err != nil {
		t.Errorf("Mark overwrite at cap should succeed, got %v", err)
	}
}
