package replay

import (
	"context"
	"errors"
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
