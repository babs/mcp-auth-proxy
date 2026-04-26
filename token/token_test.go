package token

import (
	"sync"
	"testing"
	"time"
)

func mustNewManager(t *testing.T, secret []byte) *Manager {
	t.Helper()
	m, err := NewManager(secret)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestNewManager(t *testing.T) {
	t.Run("valid secret", func(t *testing.T) {
		secret := make([]byte, 32)
		m, err := NewManager(secret)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if m == nil {
			t.Fatal("expected non-nil manager")
		}
	})

	t.Run("too short secret", func(t *testing.T) {
		secret := make([]byte, 16)
		m, err := NewManager(secret)
		if err == nil {
			t.Fatal("expected error for short secret")
		}
		if m != nil {
			t.Fatal("expected nil manager on error")
		}
	})
}

func TestIssueAndValidate(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))

	audience := "https://proxy.example.com"
	subject := "user-123"
	email := "user@example.com"
	clientID := "client-abc"
	ttl := 5 * time.Minute

	tok, issuedClaims, err := m.Issue(audience, subject, email, clientID, nil, ttl)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}

	validated, err := m.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if validated.Audience != audience {
		t.Errorf("audience: got %q, want %q", validated.Audience, audience)
	}
	if validated.Subject != subject {
		t.Errorf("subject: got %q, want %q", validated.Subject, subject)
	}
	if validated.Email != email {
		t.Errorf("email: got %q, want %q", validated.Email, email)
	}
	if validated.ClientID != clientID {
		t.Errorf("clientID: got %q, want %q", validated.ClientID, clientID)
	}
	if validated.TokenID != issuedClaims.TokenID {
		t.Errorf("tokenID: got %q, want %q", validated.TokenID, issuedClaims.TokenID)
	}
	if !validated.IssuedAt.Equal(issuedClaims.IssuedAt) {
		t.Errorf("issuedAt: got %v, want %v", validated.IssuedAt, issuedClaims.IssuedAt)
	}
	if !validated.ExpiresAt.Equal(issuedClaims.ExpiresAt) {
		t.Errorf("expiresAt: got %v, want %v", validated.ExpiresAt, issuedClaims.ExpiresAt)
	}
}

func TestValidateExpired(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))

	tok, _, err := m.Issue("https://proxy.example.com", "user", "u@example.com", "cid", nil, time.Millisecond)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	_, err = m.Validate(tok)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestValidateTampered(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))

	tok, _, err := m.Issue("https://proxy.example.com", "user", "u@example.com", "cid", nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Flip a character in the middle of the token
	mid := len(tok) / 2
	tampered := []byte(tok)
	if tampered[mid] == 'A' {
		tampered[mid] = 'B'
	} else {
		tampered[mid] = 'A'
	}

	_, err = m.Validate(string(tampered))
	if err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestValidateGarbage(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))

	for _, garbage := range []string{
		"",
		"not-a-token",
		"!!!invalid-base64!!!",
		"AAAA",
	} {
		_, err := m.Validate(garbage)
		if err == nil {
			t.Errorf("expected error for garbage token %q", garbage)
		}
	}
}

func TestDifferentSecrets(t *testing.T) {
	secret1 := make([]byte, 32)
	secret1[0] = 0x01
	secret2 := make([]byte, 32)
	secret2[0] = 0x02

	m1 := mustNewManager(t, secret1)
	m2 := mustNewManager(t, secret2)

	tok, _, err := m1.Issue("https://proxy.example.com", "user", "u@example.com", "cid", nil, 5*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = m2.Validate(tok)
	if err == nil {
		t.Fatal("expected error when validating token with different secret")
	}
}

func TestSealOpenJSON(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))

	type payload struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	original := payload{Name: "test", Value: 42}
	sealed, err := m.SealJSON(original, PurposeClient)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	if sealed == "" {
		t.Fatal("expected non-empty sealed string")
	}

	var decoded payload
	if err := m.OpenJSON(sealed, &decoded, PurposeClient); err != nil {
		t.Fatalf("OpenJSON: %v", err)
	}

	if decoded.Name != original.Name || decoded.Value != original.Value {
		t.Errorf("decoded %+v != original %+v", decoded, original)
	}
}

func TestOpenJSON_InvalidData(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))

	for _, bad := range []string{"", "not-valid", "!!!bad-base64!!!", "AAAA"} {
		var v struct{}
		if err := m.OpenJSON(bad, &v, PurposeClient); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

// TestCrossTypeSubstitution verifies that a payload sealed under one purpose
// cannot be opened as any other purpose.
// Every pairing in the 5x5 matrix except the diagonal must fail.
func TestCrossTypeSubstitution(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))

	purposes := []string{PurposeClient, PurposeSession, PurposeCode, PurposeAccess, PurposeRefresh}
	sealed := make(map[string]string, len(purposes))
	for _, p := range purposes {
		s, err := m.SealJSON(map[string]string{"p": p}, p)
		if err != nil {
			t.Fatalf("SealJSON(%s): %v", p, err)
		}
		sealed[p] = s
	}

	for _, sealPurpose := range purposes {
		for _, openPurpose := range purposes {
			var v map[string]string
			err := m.OpenJSON(sealed[sealPurpose], &v, openPurpose)
			if sealPurpose == openPurpose {
				if err != nil {
					t.Errorf("open(%s, %s) should succeed: %v", sealPurpose, openPurpose, err)
				}
				continue
			}
			if err == nil {
				t.Errorf("open(sealed=%s, as=%s) should have failed but did not", sealPurpose, openPurpose)
			}
		}
	}
}

// L6: the per-Manager seal counter increments on every Seal call and is
// exposed via SealCount() for operator introspection / tests.
func TestSealCount_IncrementsOnEverySeal(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))
	if got := m.SealCount(); got != 0 {
		t.Fatalf("initial SealCount = %d, want 0", got)
	}
	for i := 0; i < 5; i++ {
		if _, err := m.SealJSON(map[string]int{"i": i}, PurposeClient); err != nil {
			t.Fatalf("SealJSON: %v", err)
		}
	}
	if got := m.SealCount(); got != 5 {
		t.Errorf("SealCount = %d, want 5", got)
	}
	// Issue also seals.
	if _, _, err := m.Issue("aud", "sub", "e@e", "cid", nil, time.Minute); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got := m.SealCount(); got != 6 {
		t.Errorf("SealCount after Issue = %d, want 6", got)
	}
}

// TestSealMetric_InvokedPerPurpose pins the cross-replica
// observability hook for the AES-GCM seal-rotation budget. The
// in-process sealCount resets on every pod restart, so a frequently-
// rolled deployment never reaches the 2^28 warning. The metric
// callback fires on every seal labelled by purpose, letting Prometheus
// aggregate fleet-wide via increase(metric[window]).
func TestSealMetric_InvokedPerPurpose(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))

	var mu sync.Mutex
	got := map[string]int{}
	m.SetSealMetric(func(purpose string) {
		mu.Lock()
		got[purpose]++
		mu.Unlock()
	})

	if _, err := m.SealJSON(map[string]int{"x": 1}, PurposeClient); err != nil {
		t.Fatalf("SealJSON client: %v", err)
	}
	if _, err := m.SealJSON(map[string]int{"x": 2}, PurposeSession); err != nil {
		t.Fatalf("SealJSON session: %v", err)
	}
	if _, err := m.SealJSON(map[string]int{"x": 3}, PurposeSession); err != nil {
		t.Fatalf("SealJSON session 2: %v", err)
	}
	// Issue seals an access token too.
	if _, _, err := m.Issue("aud", "sub", "e@e", "cid", nil, time.Minute); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := map[string]int{
		PurposeClient:  1,
		PurposeSession: 2,
		PurposeAccess:  1,
	}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("seal metric purpose=%q: got %d, want %d", p, got[p], w)
		}
	}
}

// TestSealMetric_NilCallback is a no-op (the hot path must not panic
// when SetSealMetric is never called — the default state for tests
// and for callers that don't wire metrics).
func TestSealMetric_NilCallback(t *testing.T) {
	m := mustNewManager(t, make([]byte, 32))
	if _, err := m.SealJSON(map[string]int{"x": 1}, PurposeClient); err != nil {
		t.Fatalf("SealJSON without metric: %v", err)
	}
}

func TestSealJSON_DifferentSecrets(t *testing.T) {
	s1 := make([]byte, 32)
	s1[0] = 1
	s2 := make([]byte, 32)
	s2[0] = 2

	m1 := mustNewManager(t, s1)
	m2 := mustNewManager(t, s2)

	type payload struct{ X int }
	sealed, err := m1.SealJSON(payload{X: 1}, PurposeClient)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}

	var v payload
	if err := m2.OpenJSON(sealed, &v, PurposeClient); err == nil {
		t.Fatal("expected error when opening with different secret")
	}
}

// TestNewManagerWithRotation_PreviousKeyOpens covers the G4.1 rolling
// rotation: tokens minted with the OLD key must still open under a
// manager configured with NEW primary + OLD secondary. Simulates
// step 2 of the rotation — the bleed-in window where both keys are
// accepted but new tokens are already minted with NEW.
func TestNewManagerWithRotation_PreviousKeyOpens(t *testing.T) {
	oldKey := make([]byte, 32)
	for i := range oldKey {
		oldKey[i] = byte(i)
	}
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(255 - i)
	}

	// Pre-rotation: mint a token with OLD as primary.
	oldMgr, err := NewManagerWithRotation(oldKey)
	if err != nil {
		t.Fatalf("old mgr: %v", err)
	}
	type payload struct{ X int }
	sealed, err := oldMgr.SealJSON(payload{X: 42}, PurposeRefresh)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Rotation step 2: NEW as primary, OLD as secondary.
	rotMgr, err := NewManagerWithRotation(newKey, oldKey)
	if err != nil {
		t.Fatalf("rot mgr: %v", err)
	}
	var v payload
	if err := rotMgr.OpenJSON(sealed, &v, PurposeRefresh); err != nil {
		t.Fatalf("rotation manager must still open OLD-sealed payload: %v", err)
	}
	if v.X != 42 {
		t.Errorf("payload corrupted across rotation: got %+v", v)
	}
}

// TestNewManagerWithRotation_NewSealCannotOpenOld validates the
// rotation direction is strict: a token minted AFTER the primary
// changed cannot be opened by a manager that only knows the old key.
// Ensures rolling back a deploy does not silently accept post-
// rotation tokens against the old secret.
func TestNewManagerWithRotation_NewSealCannotOpenOld(t *testing.T) {
	oldKey := make([]byte, 32)
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = 0xFF
	}

	// Post-rotation mgr with NEW primary only.
	newMgr, err := NewManagerWithRotation(newKey)
	if err != nil {
		t.Fatalf("new mgr: %v", err)
	}
	sealed, err := newMgr.SealJSON(struct{ X int }{X: 1}, PurposeAccess)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Rollback mgr with OLD primary only.
	oldMgr, err := NewManagerWithRotation(oldKey)
	if err != nil {
		t.Fatalf("old mgr: %v", err)
	}
	var v struct{ X int }
	if err := oldMgr.OpenJSON(sealed, &v, PurposeAccess); err == nil {
		t.Fatal("old-only manager must not open NEW-sealed payload")
	}
}

// TestNewManagerWithRotation_PurposeStillEnforced confirms AAD
// purpose binding is enforced across rotations — a ciphertext minted
// with the OLD key for one purpose cannot be opened with the NEW
// key as another purpose, and vice versa.
func TestNewManagerWithRotation_PurposeStillEnforced(t *testing.T) {
	oldKey := make([]byte, 32)
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = 0x7F
	}

	oldMgr, _ := NewManagerWithRotation(oldKey)
	sealed, err := oldMgr.SealJSON(struct{ X int }{X: 1}, PurposeRefresh)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	rotMgr, _ := NewManagerWithRotation(newKey, oldKey)
	var v struct{ X int }
	if err := rotMgr.OpenJSON(sealed, &v, PurposeAccess); err == nil {
		t.Fatal("AAD purpose mismatch must fail even through rotation")
	}
}

// TestNewManagerWithRotation_ShortSecretRejected: every key in the
// rotation set must meet the 32-byte floor; a typo that produces a
// 31-byte previous key fails startup rather than silently dropping
// rotation support.
func TestNewManagerWithRotation_ShortSecretRejected(t *testing.T) {
	primary := make([]byte, 32)
	short := make([]byte, 31)
	if _, err := NewManagerWithRotation(primary, short); err == nil {
		t.Fatal("31-byte secondary must be rejected")
	}
}
