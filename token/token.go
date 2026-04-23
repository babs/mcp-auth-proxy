package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// sealRotationThreshold is the point at which the caller should rotate the
// signing secret. AES-GCM with random 96-bit nonces is safe up to roughly
// 2^32 messages under a single key before collision risk becomes
// non-negligible; 2^28 is one hop below the safe margin, chosen so a
// one-shot zap.Warn leaves ample headroom for an operator to roll the
// secret without hitting a cryptographic cliff.
const sealRotationThreshold uint64 = 1 << 28

// Purpose constants bind every sealed payload to a specific role via AEAD
// additional-data (AAD). A ciphertext minted with one purpose cannot be
// opened as any other, which closes the sealed-type confusion family
// without relying on JSON typ discriminators
// alone. The Typ field on each sealed struct is a belt-and-braces check
// layered on top of the AAD binding.
const (
	PurposeClient  = "client"
	PurposeSession = "session"
	PurposeCode    = "code"
	PurposeAccess  = "access"
	PurposeRefresh = "refresh"
)

// Claims represents the internal access token payload.
type Claims struct {
	TokenID   string    `json:"tid"`
	Typ       string    `json:"typ"`
	Audience  string    `json:"aud"`
	Subject   string    `json:"sub"`
	Email     string    `json:"email"`
	Groups    []string  `json:"grp,omitempty"`
	ClientID  string    `json:"cid"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
}

// Manager handles AES-GCM encryption for all stateless tokens and sealed payloads.
// All instances sharing the same secret can seal/open each other's payloads,
// enabling horizontal scaling without shared storage.
//
// Multi-key rotation (G4.1): Manager supports one primary key (used
// for every Seal) and zero or more secondary keys (tried in order on
// Open, after the primary fails). A rolling key rotation looks like:
//
//  1. Steady state: primary=A, secondaries=[].
//  2. Rotation prepared: primary=B, secondaries=[A]. Tokens minted
//     going forward are sealed with B; tokens minted before the
//     rotation still decrypt because A remains in the try list.
//  3. Bleed-in wait: at least one access-token TTL + one refresh-
//     token TTL pass (1h + 7d ≈ 7d) so every in-flight A-sealed
//     token either expires or rotates to a B-sealed one.
//  4. Rotation complete: primary=B, secondaries=[]. A is safe to
//     destroy.
//
// Without this, a key rotation was a flag day — every existing session
// broke on the cutover.
type Manager struct {
	// primary is the AEAD used for every Seal.
	primary cipher.AEAD
	// openKeys is the ordered try-list used by Open: primary first,
	// then each secondary. Secondary AEADs accept but never produce
	// new ciphertexts.
	openKeys []cipher.AEAD
	// sealCount is incremented on every successful seal. AES-GCM safety
	// bounds apply per-key; the caller is warned once the count crosses
	// sealRotationThreshold so the operator has a runway to rotate.
	// The count is per-primary; a rotation resets it by instantiating
	// a new Manager with a new primary.
	sealCount atomic.Uint64
	// warnedOnce ensures the rotation warning fires only on the first
	// crossing — the counter will keep climbing, but flooding logs does
	// not add information for the operator.
	warnedOnce atomic.Bool
	// logger is optional; when nil no warning is emitted (tests). Set via
	// SetLogger after construction so existing callers stay ABI-compatible.
	logger *zap.Logger
}

// NewManager creates a token manager from a single signing secret
// (min 32 bytes). Equivalent to NewManagerWithRotation(secret) — kept
// for callers that do not need key rotation.
func NewManager(secret []byte) (*Manager, error) {
	return NewManagerWithRotation(secret)
}

// NewManagerWithRotation creates a token manager with one primary
// signing secret and zero or more secondary secrets. New payloads are
// always sealed with primary; Open tries primary first, then each
// secondary in the order given. Every secret must be at least 32
// bytes. Duplicate secrets are allowed but wasted.
func NewManagerWithRotation(primary []byte, secondaries ...[]byte) (*Manager, error) {
	primaryAEAD, err := buildAEAD(primary)
	if err != nil {
		return nil, fmt.Errorf("primary secret: %w", err)
	}
	openKeys := []cipher.AEAD{primaryAEAD}
	for i, s := range secondaries {
		a, err := buildAEAD(s)
		if err != nil {
			return nil, fmt.Errorf("secondary secret %d: %w", i, err)
		}
		openKeys = append(openKeys, a)
	}
	return &Manager{primary: primaryAEAD, openKeys: openKeys}, nil
}

// buildAEAD derives an AES-256-GCM AEAD from the given secret. Secrets
// may be longer than 32 bytes; SHA-256 normalizes to the AES-256 key
// size so operators can paste hex-encoded secrets of any length ≥32.
func buildAEAD(secret []byte) (cipher.AEAD, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("secret must be at least 32 bytes")
	}
	key := sha256.Sum256(secret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	return aead, nil
}

// SetLogger attaches a zap logger for the one-shot seal-rotation warning.
// Safe to call before any seals happen; passing nil disables the warning.
func (m *Manager) SetLogger(l *zap.Logger) {
	m.logger = l
}

// SealCount returns the current number of successful seals. Exposed for
// tests and operator introspection; not part of the OAuth flow.
func (m *Manager) SealCount() uint64 {
	return m.sealCount.Load()
}

// seal encrypts raw bytes with purpose bound as AEAD additional-data, so a
// ciphertext minted for one purpose fails to open as any other. Always
// uses the primary key — secondary keys are accept-only.
func (m *Manager) seal(data []byte, purpose string) (string, error) {
	nonce := make([]byte, m.primary.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := m.primary.Seal(nonce, nonce, data, []byte(purpose))

	// L6: count successful seals per Manager. When the count crosses the
	// rotation threshold we fire a single warning — AES-GCM with 96-bit
	// random nonces starts to accumulate nontrivial collision risk in the
	// 2^32 range; 2^28 gives the operator headroom to rotate before the
	// bound is approached.
	if n := m.sealCount.Add(1); n == sealRotationThreshold {
		if m.logger != nil && m.warnedOnce.CompareAndSwap(false, true) {
			m.logger.Warn("token_seal_rotation_threshold",
				zap.Uint64("seal_count", n),
				zap.Uint64("threshold", sealRotationThreshold),
				zap.String("hint", "rotate TOKEN_SIGNING_SECRET; AES-GCM nonce safety bound approaches"),
			)
		}
	}
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// open decrypts a base64url-encoded sealed string; purpose must match the
// value used at seal time (AAD tag fails otherwise). Tries the primary
// key first, then each secondary in the order given to
// NewManagerWithRotation. Returns the plaintext from the first AEAD
// that accepts the ciphertext. If none accept, returns the error from
// the primary (most-useful diagnostic — if the payload is genuinely
// corrupt or the purpose mismatched, that's what the operator sees).
func (m *Manager) open(sealed, purpose string) ([]byte, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	nonceSize := m.primary.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("sealed data too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	var primaryErr error
	for i, aead := range m.openKeys {
		plaintext, openErr := aead.Open(nil, nonce, ct, []byte(purpose))
		if openErr == nil {
			return plaintext, nil
		}
		if i == 0 {
			primaryErr = openErr
		}
	}
	return nil, primaryErr
}

// SealJSON encrypts a JSON-serializable value with the given purpose AAD.
func (m *Manager) SealJSON(v any, purpose string) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	return m.seal(data, purpose)
}

// OpenJSON decrypts a sealed string and unmarshals the JSON payload into v.
// purpose must match the value passed to SealJSON.
func (m *Manager) OpenJSON(sealed string, v any, purpose string) error {
	data, err := m.open(sealed, purpose)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// Issue creates a new opaque access token. The audience binds the token to a
// specific proxy deployment so it cannot be replayed against a sibling instance
// that happens to share the same signing secret.
func (m *Manager) Issue(audience, subject, email, clientID string, groups []string, ttl time.Duration) (string, *Claims, error) {
	now := time.Now()
	claims := &Claims{
		TokenID:   uuid.New().String(),
		Typ:       PurposeAccess,
		Audience:  audience,
		Subject:   subject,
		Email:     email,
		Groups:    groups,
		ClientID:  clientID,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}

	plaintext, err := json.Marshal(claims)
	if err != nil {
		return "", nil, fmt.Errorf("marshal claims: %w", err)
	}

	encoded, err := m.seal(plaintext, PurposeAccess)
	if err != nil {
		return "", nil, err
	}
	return encoded, claims, nil
}

// Validate decodes and validates an opaque access token, returning its claims.
// Enforces AAD purpose=access + belt-and-braces typ check + non-empty
// subject/audience + non-zero issued-at, so a decode regression in any single
// layer doesn't collapse the defense.
func (m *Manager) Validate(tokenStr string) (*Claims, error) {
	plaintext, err := m.open(tokenStr, PurposeAccess)
	if err != nil {
		return nil, err
	}

	var claims Claims
	if err := json.Unmarshal(plaintext, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}

	if claims.Typ != PurposeAccess {
		return nil, fmt.Errorf("token type mismatch")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("subject empty")
	}
	if claims.Audience == "" {
		return nil, fmt.Errorf("audience empty")
	}
	if claims.IssuedAt.IsZero() {
		return nil, fmt.Errorf("issued_at zero")
	}
	if time.Now().After(claims.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}
