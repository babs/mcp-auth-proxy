package token

import (
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
