package replay

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// Every Redis test starts a fresh miniredis instance and closes it on
// defer. miniredis is an in-process Redis reimplementation — no network
// I/O, fast enough to run in unit tests.
func newTestRedis(t *testing.T, prefix string) (*RedisStore, *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)

	s, err := NewRedisStore("redis://"+mr.Addr(), prefix)
	if err != nil {
		t.Fatalf("NewRedisStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	return s, mr
}

func TestRedisStore_ClaimOnce_AppliesPrefix(t *testing.T) {
	s, mr := newTestRedis(t, "proxy-a:")

	if err := s.ClaimOnce(context.Background(), "authz_code:abc", time.Minute); err != nil {
		t.Fatalf("first claim: %v", err)
	}

	// Namespaced form must exist; bare form must not.
	if !mr.Exists("proxy-a:authz_code:abc") {
		t.Errorf("expected key proxy-a:authz_code:abc, keys=%v", mr.Keys())
	}
	if mr.Exists("authz_code:abc") {
		t.Errorf("bare key should not exist under prefix, keys=%v", mr.Keys())
	}
}

func TestRedisStore_ClaimOnce_SecondAttemptRejected(t *testing.T) {
	s, _ := newTestRedis(t, "t:")

	if err := s.ClaimOnce(context.Background(), "k", time.Minute); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := s.ClaimOnce(context.Background(), "k", time.Minute); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("second claim: want ErrAlreadyClaimed, got %v", err)
	}
}

// TestRedisStore_DifferentPrefixes_Isolate verifies that two proxies
// sharing one Redis DB but using different REDIS_KEY_PREFIX values do
// not see each other's claims — the whole point of the prefix.
func TestRedisStore_DifferentPrefixes_Isolate(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	a, err := NewRedisStore("redis://"+mr.Addr(), "deployment-a:")
	if err != nil {
		t.Fatalf("NewRedisStore a: %v", err)
	}
	defer func() { _ = a.Close() }()

	b, err := NewRedisStore("redis://"+mr.Addr(), "deployment-b:")
	if err != nil {
		t.Fatalf("NewRedisStore b: %v", err)
	}
	defer func() { _ = b.Close() }()

	ctx := context.Background()
	if err := a.ClaimOnce(ctx, "k", time.Minute); err != nil {
		t.Fatalf("a claim: %v", err)
	}
	// Same logical key but in the other deployment's namespace: must succeed.
	if err := b.ClaimOnce(ctx, "k", time.Minute); err != nil {
		t.Fatalf("b claim should not collide with a: %v", err)
	}
}

func TestRedisStore_Mark_Then_Exists(t *testing.T) {
	s, _ := newTestRedis(t, "")

	ctx := context.Background()
	ok, err := s.Exists(ctx, "family:1")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if ok {
		t.Fatal("Exists should be false before Mark")
	}

	if err := s.Mark(ctx, "family:1", time.Minute); err != nil {
		t.Fatalf("Mark: %v", err)
	}

	ok, err = s.Exists(ctx, "family:1")
	if err != nil {
		t.Fatalf("Exists post-Mark: %v", err)
	}
	if !ok {
		t.Fatal("Exists should be true after Mark")
	}
}

func TestRedisStore_Mark_IsIdempotent(t *testing.T) {
	s, _ := newTestRedis(t, "")
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := s.Mark(ctx, "k", time.Minute); err != nil {
			t.Fatalf("Mark iteration %d: %v", i, err)
		}
	}
}

func TestRedisStore_TTLIsApplied(t *testing.T) {
	s, mr := newTestRedis(t, "p:")

	if err := s.ClaimOnce(context.Background(), "k", 42*time.Second); err != nil {
		t.Fatalf("ClaimOnce: %v", err)
	}

	ttl := mr.TTL("p:k")
	if ttl <= 0 || ttl > 42*time.Second {
		t.Errorf("expected TTL in (0, 42s], got %v", ttl)
	}
}

func TestRedisStore_ClaimOnce_AfterExpiry(t *testing.T) {
	s, mr := newTestRedis(t, "")
	ctx := context.Background()

	if err := s.ClaimOnce(ctx, "k", time.Minute); err != nil {
		t.Fatalf("first claim: %v", err)
	}

	// FastForward past the TTL so miniredis expires the key.
	mr.FastForward(2 * time.Minute)

	if err := s.ClaimOnce(ctx, "k", time.Minute); err != nil {
		t.Fatalf("reclaim after expiry should succeed: %v", err)
	}
}

func TestNewRedisStore_BadURL(t *testing.T) {
	if _, err := NewRedisStore("not a url", ""); err == nil {
		t.Fatal("expected error for malformed REDIS_URL")
	}
}

// --- M4 — ClaimOrCheckFamily collapses revoked-check + single-use into one round trip ---

func TestRedisStore_ClaimOrCheckFamily_FreshClaim(t *testing.T) {
	s, mr := newTestRedis(t, "p:")
	ctx := context.Background()

	revoked, claimed, err := s.ClaimOrCheckFamily(ctx, "fam:1", "tid:A", time.Minute)
	if err != nil {
		t.Fatalf("ClaimOrCheckFamily: %v", err)
	}
	if revoked || claimed {
		t.Fatalf("fresh claim: revoked=%v claimed=%v (want both false)", revoked, claimed)
	}
	if !mr.Exists("p:tid:A") {
		t.Errorf("expected claim key present, keys=%v", mr.Keys())
	}
}

func TestRedisStore_ClaimOrCheckFamily_AlreadyClaimed(t *testing.T) {
	s, _ := newTestRedis(t, "")
	ctx := context.Background()

	if _, _, err := s.ClaimOrCheckFamily(ctx, "fam:1", "tid:A", time.Minute); err != nil {
		t.Fatalf("first claim: %v", err)
	}

	revoked, claimed, err := s.ClaimOrCheckFamily(ctx, "fam:1", "tid:A", time.Minute)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if revoked {
		t.Errorf("second claim must not flag familyRevoked")
	}
	if !claimed {
		t.Errorf("second claim must flag alreadyClaimed")
	}
}

func TestRedisStore_ClaimOrCheckFamily_FamilyRevoked(t *testing.T) {
	s, mr := newTestRedis(t, "")
	ctx := context.Background()

	if err := s.Mark(ctx, "fam:1", time.Minute); err != nil {
		t.Fatalf("Mark: %v", err)
	}

	revoked, claimed, err := s.ClaimOrCheckFamily(ctx, "fam:1", "tid:A", time.Minute)
	if err != nil {
		t.Fatalf("ClaimOrCheckFamily: %v", err)
	}
	if !revoked {
		t.Errorf("expected familyRevoked=true")
	}
	if claimed {
		t.Errorf("revoked family must NOT also report alreadyClaimed")
	}
	// Critical: the claim MUST NOT happen when the family is revoked —
	// otherwise a leaked tid silently consumes a claim slot for a
	// lineage the server has already declared dead.
	if mr.Exists("tid:A") {
		t.Errorf("revoked family must not claim tid, keys=%v", mr.Keys())
	}
}

func TestRedisStore_ClaimOrCheckFamily_AppliesPrefix(t *testing.T) {
	s, mr := newTestRedis(t, "proxy-a:")
	ctx := context.Background()

	if _, _, err := s.ClaimOrCheckFamily(ctx, "fam:1", "tid:A", time.Minute); err != nil {
		t.Fatalf("ClaimOrCheckFamily: %v", err)
	}
	if !mr.Exists("proxy-a:tid:A") {
		t.Errorf("expected prefixed claim key, keys=%v", mr.Keys())
	}
	if mr.Exists("tid:A") {
		t.Errorf("bare key must not exist under prefix, keys=%v", mr.Keys())
	}
}
