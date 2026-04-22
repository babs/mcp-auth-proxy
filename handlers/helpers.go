package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuthError represents an RFC 6749 error response.
type OAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorCode        string `json:"error_code,omitempty"`
}

// Sealed types: all OAuth flow state is encrypted into tokens/parameters,
// enabling stateless multi-instance deployment without shared storage.
//
// Every sealed type carries an Audience field bound to the proxy base URL
// at creation time. Verifying it on every Open prevents cross-deployment
// replay if two proxies accidentally share the same TOKEN_SIGNING_SECRET.
//
// Every sealed type also carries a Typ discriminator matching its
// token.Purpose AAD tag. The AAD tag is the primary defense against
// sealed-type confusion; the Typ check is
// belt-and-braces so a regression in AAD wiring is still caught.

// sealedClient is the encrypted payload inside a client_id (stateless DCR).
type sealedClient struct {
	ID           string    `json:"id"`
	RedirectURIs []string  `json:"r"`
	ClientName   string    `json:"n"`
	Typ          string    `json:"typ"`
	Audience     string    `json:"aud"`
	ExpiresAt    time.Time `json:"exp"`
}

// sealedSession holds authorize flow state, encrypted into the IdP state parameter.
// Nonce is the upstream OIDC nonce (random 32 hex) verified in the id_token at
// /callback, defending against upstream code-injection. PKCEVerifier is a
// server-side verifier used on the upstream authorization request so even a
// leaked upstream code cannot be exchanged without also leaking the state.
//
// SvrVerifier / SvrChallenge are the DOWNSTREAM server-side PKCE pair used
// when PKCE_REQUIRED=false and the client omits code_challenge (H6). They
// are deliberately distinct from PKCEVerifier, which is the UPSTREAM PKCE
// verifier used on the proxy-to-IdP leg (H3). Mixing the two would cause
// the upstream exchange to fail against a downstream-bound verifier.
type sealedSession struct {
	ClientID      string    `json:"cid"`
	RedirectURI   string    `json:"ru"`
	CodeChallenge string    `json:"cc"`
	OriginalState string    `json:"os"`
	Nonce         string    `json:"nonce"`
	PKCEVerifier  string    `json:"pv"`
	SvrVerifier   string    `json:"sv,omitempty"`
	SvrChallenge  string    `json:"sch,omitempty"`
	Typ           string    `json:"typ"`
	Audience      string    `json:"aud"`
	ExpiresAt     time.Time `json:"exp"`
}

// sealedCode is the encrypted payload inside an authorization code.
// TokenID uniquely identifies the code and is used as the key for single-use
// enforcement when a replay store is wired (RFC 6749 §4.1.2: codes MUST NOT
// be reusable). Without a store, the code is still unique but replayable
// within its TTL.
type sealedCode struct {
	TokenID       string   `json:"tid"`
	ClientID      string   `json:"cid"`
	RedirectURI   string   `json:"ru"`
	CodeChallenge string   `json:"cc"`
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	Name          string   `json:"name"`
	Groups        []string `json:"grp,omitempty"`
	// ServerPKCE is true when the proxy minted the PKCE pair itself
	// because the client omitted code_challenge in relaxed mode (H6).
	// In that case CodeChallenge and SvrVerifier are both populated from
	// the server-generated pair; /token validates them internally so the
	// code is never redeemed without a PKCE anchor, even when the client
	// doesn't participate in PKCE itself.
	ServerPKCE  bool      `json:"spkce,omitempty"`
	SvrVerifier string    `json:"sv,omitempty"`
	Typ         string    `json:"typ"`
	Audience    string    `json:"aud"`
	ExpiresAt   time.Time `json:"exp"`
}

// sealedRefresh is the encrypted payload inside a refresh token.
// IssuedAt enables REVOKE_BEFORE bulk revocation; without it, a compromised
// refresh token would survive a cutoff and silently mint fresh access tokens.
//
// TokenID is unique per refresh; FamilyID is constant across rotations
// (minted at the initial authorization_code grant, inherited by every
// rotated token). When a replay store is wired, TokenID is claimed
// single-use and any reuse revokes the whole FamilyID — OAuth 2.1 §6.1 /
// RFC 6749 §10.4 refresh-rotation-with-reuse-detection. Without a store
// both fields are set but unused (stateless fallback).
type sealedRefresh struct {
	TokenID   string    `json:"tid"`
	FamilyID  string    `json:"fam"`
	Subject   string    `json:"sub"`
	Email     string    `json:"email"`
	Groups    []string  `json:"grp,omitempty"`
	ClientID  string    `json:"cid"`
	Typ       string    `json:"typ"`
	Audience  string    `json:"aud"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
}

// maxBodySize limits POST request bodies to prevent memory exhaustion.
const maxBodySize = 1 << 20 // 1 MB

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string, errorCode ...string) {
	oauthErr := OAuthError{Error: code, ErrorDescription: desc}
	if len(errorCode) > 0 {
		oauthErr.ErrorCode = errorCode[0]
	}
	writeJSON(w, status, oauthErr)
}

// hasOverlap returns true if any element in userGroups matches an element in allowed.
func hasOverlap(userGroups, allowed []string) bool {
	for _, ug := range userGroups {
		for _, ag := range allowed {
			if ug == ag {
				return true
			}
		}
	}
	return false
}

// isLoopback returns true if the URL targets a loopback address, which
// is exempt from the HTTPS requirement per OAuth 2.1 §2.3.1.
//
// M7: the previous implementation only matched "localhost", "127.0.0.1"
// and "::1" verbatim, missing 127.0.0.0/8 (RFC 1122), IPv4-mapped IPv6
// loopback (::ffff:127.0.0.1), and the trailing-dot FQDN form
// ("localhost."). net.ParseIP().IsLoopback() handles the IP family
// correctly; "localhost" is matched literally after stripping one
// trailing dot so both "localhost" and "localhost." are accepted.
func isLoopback(u *url.URL) bool {
	host := strings.TrimSuffix(u.Hostname(), ".")
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
