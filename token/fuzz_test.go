package token

import "testing"

// FuzzOpenJSON drives arbitrary strings through the AES-GCM open +
// json.Unmarshal path. The goal isn't to find valid decryptions (the
// chance of hitting a valid AEAD tag by random chance is negligible) but
// to surface panics in the base64 decode, nonce slicing, or downstream
// unmarshal on odd inputs — e.g. truncated ciphertexts, invalid UTF-8,
// non-object JSON shapes.
func FuzzOpenJSON(f *testing.F) {
	m, err := NewManager(make([]byte, 32))
	if err != nil {
		f.Fatalf("NewManager: %v", err)
	}

	// Seed corpus: a valid sealed payload plus a handful of edge cases.
	if sealed, err := m.SealJSON(map[string]any{"foo": "bar"}); err == nil {
		f.Add(sealed)
	}
	f.Add("")
	f.Add("AAAA")
	f.Add("not-base64url!!")
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	f.Fuzz(func(_ *testing.T, sealed string) {
		var v any
		// A failure is fine; a panic is a bug.
		_ = m.OpenJSON(sealed, &v)
	})
}

// FuzzValidate does the same for the access-token validation path, which
// layers Claims unmarshal + expiry check on top of open.
func FuzzValidate(f *testing.F) {
	m, err := NewManager(make([]byte, 32))
	if err != nil {
		f.Fatalf("NewManager: %v", err)
	}

	if tok, _, err := m.Issue("aud", "sub", "e@x", "cid", nil, 60); err == nil {
		f.Add(tok)
	}
	f.Add("")
	f.Add("AAAA")

	f.Fuzz(func(_ *testing.T, tok string) {
		_, _ = m.Validate(tok)
	})
}
