package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/babs/mcp-auth-proxy/token"
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
	ClientID      string `json:"cid"`
	RedirectURI   string `json:"ru"`
	CodeChallenge string `json:"cc"`
	OriginalState string `json:"os"`
	Nonce         string `json:"nonce"`
	PKCEVerifier  string `json:"pv"`
	SvrVerifier   string `json:"sv,omitempty"`
	SvrChallenge  string `json:"sch,omitempty"`
	Typ           string `json:"typ"`
	Audience      string `json:"aud"`
	// Resource is the canonical RFC 8707 resource indicator the
	// downstream tokens will be bound to. Captured at /authorize so
	// the binding is fixed BEFORE the upstream IdP round trip — a
	// later code-substitution attempt cannot retarget the issued
	// token to a different mount on a future multi-mount proxy
	// (RFC 8707 §2.2). Empty on legacy sessions sealed before this
	// field existed.
	Resource  string    `json:"res,omitempty"`
	ExpiresAt time.Time `json:"exp"`
}

// sealedCode is the encrypted payload inside an authorization code.
// TokenID uniquely identifies the code and is used as the key for single-use
// enforcement when a replay store is wired (RFC 6749 §4.1.2: codes MUST NOT
// be reusable). Without a store, the code is still unique but replayable
// within its TTL.
//
// FamilyID seeds the refresh-rotation lineage minted from this code.
// On RFC 6749 §4.1.2 "revoke previously issued tokens on code reuse",
// detecting a replay of this code is sufficient to revoke the whole
// family of refresh tokens that derived from the first redemption —
// the family marker in the replay store blocks the thief's already-
// issued refresh chain from rotating further.
type sealedCode struct {
	TokenID       string   `json:"tid"`
	FamilyID      string   `json:"fam"`
	ClientID      string   `json:"cid"`
	RedirectURI   string   `json:"ru"`
	CodeChallenge string   `json:"cc"`
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	Name          string   `json:"name"`
	Groups        []string `json:"grp,omitempty"`
	// Resource is inherited from the originating sealedSession so the
	// downstream access + refresh tokens carry the same RFC 8707
	// resource binding the client requested at /authorize. Empty on
	// codes minted before this field existed.
	Resource string `json:"res,omitempty"`
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
	TokenID  string   `json:"tid"`
	FamilyID string   `json:"fam"`
	Subject  string   `json:"sub"`
	Email    string   `json:"email"`
	Groups   []string `json:"grp,omitempty"`
	ClientID string   `json:"cid"`
	Typ      string   `json:"typ"`
	Audience string   `json:"aud"`
	// Resource is inherited from the originating code and stays
	// constant across rotations — every access token in the family
	// must remain bound to the same RFC 8707 resource the client
	// requested at /authorize. Empty on refresh tokens sealed before
	// this field existed.
	Resource string    `json:"res,omitempty"`
	IssuedAt time.Time `json:"iat"`
	// FamilyIssuedAt is the IssuedAt of the FIRST refresh in this
	// rotation lineage (the one minted at code redemption) and is
	// inherited verbatim by every rotated descendant. REVOKE_BEFORE
	// is compared against this value, NOT IssuedAt — otherwise a
	// quietly rotating attacker's refresh would survive a bulk
	// revocation cutoff because each rotation pushed IssuedAt
	// forward. Zero on tokens sealed before this field existed; the
	// refresh handler falls back to IssuedAt in that case so a
	// rolling deploy keeps active sessions valid.
	FamilyIssuedAt time.Time `json:"fiat,omitempty"`
	ExpiresAt      time.Time `json:"exp"`
}

// maxBodySize limits POST request bodies to prevent memory exhaustion.
const maxBodySize = 1 << 20 // 1 MB

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Encode errors here mean the client went away mid-write; nothing to do.
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string, errorCode ...string) {
	// Defense in depth: clamp + strip control bytes at the sink so a
	// future caller piping caller-controlled data through (e.g. an
	// upstream IdP message, a config-supplied prefix) cannot inject
	// CR/LF into the JSON body — and, via writeAuthError, into the
	// WWW-Authenticate header. Every current caller passes a static
	// literal that's a no-op under this filter.
	oauthErr := OAuthError{Error: code, ErrorDescription: sanitizeErrorDescription(desc)}
	if len(errorCode) > 0 {
		oauthErr.ErrorCode = errorCode[0]
	}
	writeJSON(w, status, oauthErr)
}

func rejectRepeatedParams(w http.ResponseWriter, values url.Values, names ...string) bool {
	for _, name := range names {
		if len(values[name]) > 1 {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", name+" must not be repeated")
			return true
		}
	}
	return false
}

func matchAnyResource(resource string, accepted []string) bool {
	for _, candidate := range accepted {
		if matchResource(resource, candidate) {
			return true
		}
	}
	return false
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

// openAndValidateClient decodes a client_id sealed payload and runs
// the four invariants both /token grant handlers need: AAD purpose
// match, belt-and-braces typ discriminator, audience binding, and TTL.
// On any failure it writes the RFC 6749 §5.2 response directly and
// returns nil; callers use the nil return as a short-circuit signal.
// Factoring this out removes the near-identical 20-line block from
// each grant handler; error shapes are preserved verbatim so the
// existing test matrix against both paths keeps exercising them.
func openAndValidateClient(w http.ResponseWriter, tm *token.Manager, clientIDStr, audience string) *sealedClient {
	var client sealedClient
	if err := tm.OpenJSON(clientIDStr, &client, token.PurposeClient); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid client_id")
		return nil
	}
	if client.Typ != token.PurposeClient {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid client_id")
		return nil
	}
	if client.Audience != audience {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "client registered for a different audience")
		return nil
	}
	if time.Now().After(client.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "client registration expired")
		return nil
	}
	return &client
}

// matchResource reports whether a client-supplied RFC 8707 `resource`
// parameter identifies this proxy's base URL. Comparison is
// case-insensitive on scheme and host (per RFC 3986 §3.1, §3.2.2),
// default-port-insensitive (`:443` on https and `:80` on http are
// equivalent to a bare host), and trailing-slash-insensitive on the
// path, so clients may send either the raw PROXY_BASE_URL or the
// trailing-slash form advertised by
// /.well-known/oauth-protected-resource (Claude.ai compatibility).
// Empty resource returns false so callers can distinguish "absent"
// from "present but mismatched".
//
// RFC 8707 §2 also requires the resource value to be an absolute URI
// and forbids a fragment component (MUST NOT) / discourages a query
// (SHOULD NOT). Reject those up front rather than silently ignoring
// them — otherwise `https://proxy#x` would match on host/scheme alone.
func matchResource(resource, baseURL string) bool {
	if resource == "" {
		return false
	}
	ru, err := url.Parse(resource)
	if err != nil {
		return false
	}
	// RFC 8707 §2: resource MUST be an absolute URI (scheme+authority)
	// — not a path-relative reference or an opaque form.
	if !ru.IsAbs() || ru.Host == "" || ru.Opaque != "" {
		return false
	}
	// RFC 8707 §2: MUST NOT include a fragment; SHOULD NOT include a
	// query. Both would otherwise slip through the scheme/host/path
	// comparison below.
	if ru.Fragment != "" || ru.RawFragment != "" {
		return false
	}
	if ru.RawQuery != "" || ru.ForceQuery {
		return false
	}
	bu, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	if !strings.EqualFold(ru.Scheme, bu.Scheme) {
		return false
	}
	if !equalHostPort(ru, bu) {
		return false
	}
	return strings.TrimRight(ru.Path, "/") == strings.TrimRight(bu.Path, "/")
}

// equalHostPort compares host+port with default-port normalization
// (https→443, http→80) so a client that explicitly appends the default
// port still matches a bare-host baseURL. Hostname compare is
// case-insensitive per RFC 3986 §3.2.2.
func equalHostPort(a, b *url.URL) bool {
	if !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	return normalizePort(a) == normalizePort(b)
}

func normalizePort(u *url.URL) string {
	p := u.Port()
	if p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// redirectURIMatches reports whether a client-supplied redirect_uri
// matches a value registered via DCR. Default is strict string
// equality (OAuth 2.1 §2.3.1, RFC 6749 §3.1.2). Exception for
// loopback redirects per RFC 8252 §7.3: the AS MUST allow any port
// so native apps that bind an ephemeral port at launch do not need
// to re-register on every run. Scheme, host literal, and path still
// have to match exactly — only the port may differ, and only when
// both URIs are loopback.
func redirectURIMatches(requested, registered string) bool {
	if requested == registered {
		return true
	}
	ru, err := url.Parse(requested)
	if err != nil {
		return false
	}
	re, err := url.Parse(registered)
	if err != nil {
		return false
	}
	// Port-agnostic relaxation applies ONLY when both URIs are
	// loopback. A registered loopback URI cannot silently match a
	// non-loopback requested URI (or vice versa).
	if !isLoopback(ru) || !isLoopback(re) {
		return false
	}
	if !strings.EqualFold(ru.Scheme, re.Scheme) {
		return false
	}
	// Compare host literals after trailing-dot / case normalization.
	// "127.0.0.1" ≠ "localhost" by design — RFC 8252 §7.3 asks
	// clients to use the same loopback literal they registered.
	if !strings.EqualFold(strings.TrimSuffix(ru.Hostname(), "."), strings.TrimSuffix(re.Hostname(), ".")) {
		return false
	}
	if ru.User != nil || re.User != nil {
		return false
	}
	if ru.EscapedPath() != re.EscapedPath() {
		return false
	}
	if ru.RawQuery != re.RawQuery || ru.ForceQuery != re.ForceQuery {
		return false
	}
	if ru.Fragment != "" || re.Fragment != "" || ru.RawFragment != "" || re.RawFragment != "" {
		return false
	}
	// Port is free to differ; that's the whole point.
	return true
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
