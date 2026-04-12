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
	"time"

	"github.com/google/uuid"
)

// Claims represents the internal access token payload.
type Claims struct {
	TokenID   string    `json:"tid"`
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
type Manager struct {
	aead cipher.AEAD
}

// NewManager creates a token manager from a signing secret (min 32 bytes).
func NewManager(secret []byte) (*Manager, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("secret must be at least 32 bytes")
	}
	// Secret may be longer than 32 bytes; SHA-256 normalizes to exact AES-256 key size
	key := sha256.Sum256(secret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	return &Manager{aead: aead}, nil
}

// seal encrypts raw bytes and returns a base64url-encoded string.
func (m *Manager) seal(data []byte) (string, error) {
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := m.aead.Seal(nonce, nonce, data, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// open decrypts a base64url-encoded sealed string.
func (m *Manager) open(sealed string) ([]byte, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	nonceSize := m.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("sealed data too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return m.aead.Open(nil, nonce, ciphertext, nil)
}

// SealJSON encrypts a JSON-serializable value and returns a base64url-encoded string.
func (m *Manager) SealJSON(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	return m.seal(data)
}

// OpenJSON decrypts a sealed string and unmarshals the JSON payload into v.
func (m *Manager) OpenJSON(sealed string, v any) error {
	data, err := m.open(sealed)
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

	encoded, err := m.seal(plaintext)
	if err != nil {
		return "", nil, err
	}
	return encoded, claims, nil
}

// Validate decodes and validates an opaque token, returning its claims.
func (m *Manager) Validate(tokenStr string) (*Claims, error) {
	plaintext, err := m.open(tokenStr)
	if err != nil {
		return nil, err
	}

	var claims Claims
	if err := json.Unmarshal(plaintext, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}

	if time.Now().After(claims.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}
