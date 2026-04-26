package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const (
	// OAuth 2.1 §4.1.3 / Security BCP §2.1.1: authorization codes must be
	// short-lived. 60s is tight enough to narrow the replay window while
	// still tolerating slow clients and network hops. Combined with PKCE
	// and, when configured, the replay store, this approximates single-use.
	codeTTL         = 60 * time.Second
	oidcExchangeTTL = 10 * time.Second
)

// verifyIDTokenFunc abstracts OIDC id_token verification for testability.
type verifyIDTokenFunc func(ctx context.Context, rawToken string) (*oidc.IDToken, error)

// rfc6749AuthErrorSet is the closed set of `error` values the IdP may
// legally return on the /authorize redirect path (RFC 6749 §4.1.2.1).
// Anything outside this set is collapsed to `server_error` before we
// echo it to the client.
var rfc6749AuthErrorSet = map[string]struct{}{
	"invalid_request":           {},
	"invalid_client":            {},
	"unauthorized_client":       {},
	"access_denied":             {},
	"unsupported_response_type": {},
	"invalid_scope":             {},
	"server_error":              {},
	"temporarily_unavailable":   {},
}

// normalizeIdPError returns the input if it is in the RFC 6749 §4.1.2.1
// set, otherwise "server_error". Keeps attacker-controlled strings from
// reaching downstream MCP clients that pattern-match on `error`.
func normalizeIdPError(s string) string {
	if _, ok := rfc6749AuthErrorSet[s]; ok {
		return s
	}
	return "server_error"
}

// sanitizeErrorDescription clamps the IdP-supplied error_description to
// 200 bytes and strips any byte outside the ASCII-printable range
// (0x20..0x7E). CR/LF would enable header smuggling when this value is
// later copied into a header or log line; tabs/other control bytes add
// no value to a human-readable description.
func sanitizeErrorDescription(s string) string {
	if len(s) > 200 {
		s = s[:200]
	}
	b := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		if c >= 0x20 && c <= 0x7E {
			b = append(b, c)
		}
	}
	return string(b)
}

// CallbackConfig holds the group filtering parameters for the callback handler.
type CallbackConfig struct {
	AllowedGroups []string // empty = allow all authenticated users
	GroupsClaim   string   // flat claim name in id_token (default "groups")
}

// Callback handles GET /callback (IdP redirect after user authentication).
// audience binds the issued authorization code to a specific proxy deployment.
func Callback(tm *token.Manager, logger *zap.Logger, audience string, oauth2Cfg *oauth2.Config, verifier *oidc.IDTokenVerifier, cbCfg CallbackConfig) http.HandlerFunc {
	return callbackHandler(tm, logger, audience, oauth2Cfg, verifier.Verify, cbCfg)
}

// CallbackWithVerifyFunc allows injecting a custom ID token verification function (for testing).
func CallbackWithVerifyFunc(tm *token.Manager, logger *zap.Logger, audience string, oauth2Cfg *oauth2.Config, verifyFunc verifyIDTokenFunc, cbCfg CallbackConfig) http.HandlerFunc {
	return callbackHandler(tm, logger, audience, oauth2Cfg, verifyFunc, cbCfg)
}

func callbackHandler(tm *token.Manager, logger *zap.Logger, audience string, oauth2Cfg *oauth2.Config, verify verifyIDTokenFunc, cbCfg CallbackConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if rejectRepeatedParams(w, q,
			"code",
			"state",
			"error",
			"error_description",
		) {
			return
		}

		// RFC 6749 §4.1.2.1: the IdP may redirect with error instead of
		// code. When the session is still decodable, we forward the
		// error back to the client's registered redirect_uri (plus
		// OriginalState) so the MCP client sees a spec-compliant error
		// response and can correlate against the state it sent. Only
		// when the session is unreachable (tampered/expired state) do
		// we fall through to a proxy-hosted JSON body.
		//
		// The IdP-supplied `error` is allowlisted against RFC 6749
		// §4.1.2.1 (anything else collapses to server_error) and
		// `error_description` is truncated at 200 chars with
		// non-printable bytes stripped, so neither can smuggle a
		// header-breaking or log-injection payload through the redirect.
		idpError := q.Get("error")
		internalState := q.Get("state")

		if idpError != "" {
			safeError := normalizeIdPError(idpError)
			desc := sanitizeErrorDescription(q.Get("error_description"))
			if desc == "" {
				desc = "authorization denied by identity provider"
			}
			var idpSession sealedSession
			if internalState != "" &&
				tm.OpenJSON(internalState, &idpSession, token.PurposeSession) == nil &&
				idpSession.Typ == token.PurposeSession &&
				idpSession.Audience == audience &&
				time.Now().Before(idpSession.ExpiresAt) {
				redirectAuthzError(w, r, idpSession.RedirectURI, idpSession.OriginalState, safeError, desc, audience)
				return
			}
			writeOAuthError(w, http.StatusBadRequest, safeError, desc)
			return
		}

		upstreamCode := q.Get("code")

		if upstreamCode == "" || internalState == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing code or state")
			return
		}

		var session sealedSession
		if err := tm.OpenJSON(internalState, &session, token.PurposeSession); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unknown or expired state")
			return
		}

		if session.Typ != token.PurposeSession {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unknown or expired state")
			return
		}

		if session.Audience != audience {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "session bound to a different audience")
			return
		}

		if time.Now().After(session.ExpiresAt) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "session expired")
			return
		}

		// Explicit timeout for upstream OIDC token exchange
		exchangeCtx, cancel := context.WithTimeout(r.Context(), oidcExchangeTTL)
		defer cancel()

		// Upstream PKCE verifier (H3): bound to the session at /authorize.
		// Even a leaked upstream code cannot be exchanged without the session.
		oauth2Token, err := oauth2Cfg.Exchange(exchangeCtx, upstreamCode,
			oauth2.VerifierOption(session.PKCEVerifier),
		)
		if err != nil {
			logger.Error("upstream_token_exchange_failed", zap.Error(err))
			writeOAuthError(w, http.StatusBadGateway, "server_error", "upstream authentication failed")
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			writeOAuthError(w, http.StatusBadGateway, "server_error", "no id_token in upstream response")
			return
		}

		idToken, err := verify(r.Context(), rawIDToken)
		if err != nil {
			logger.Error("id_token_verification_failed", zap.Error(err))
			writeOAuthError(w, http.StatusBadGateway, "server_error", "id token verification failed", "id_token_verification_failed")
			return
		}

		// Upstream OIDC nonce check (H3): defends against code-injection
		// using any victim upstream code (sibling OIDC client, open
		// redirect, log leak). The nonce was bound to the session at
		// /authorize and echoed by the IdP inside the signed id_token.
		// Distinguish "IdP didn't echo anything" from "attacker-supplied
		// mismatch" in the log — the first is usually an IdP config bug
		// worth surfacing to the operator separately.
		if idToken.Nonce != session.Nonce {
			reason := "nonce_mismatch"
			if idToken.Nonce == "" {
				reason = "nonce_missing"
			}
			logger.Warn("id_token_nonce_mismatch",
				zap.String("subject", idToken.Subject),
				zap.String("reason", reason),
			)
			writeOAuthError(w, http.StatusForbidden, "server_error", "id token nonce mismatch", "id_token_verification_failed")
			return
		}

		var claims struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified *bool  `json:"email_verified"`
			Name          string `json:"name"`
		}
		if err := idToken.Claims(&claims); err != nil {
			logger.Error("id_token_claims_parse_failed", zap.Error(err))
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to parse claims")
			return
		}

		// L5: an IdP that issues a verified id_token without a `sub` claim
		// is non-compliant (OIDC Core 1.0 §2 REQUIRED), but if we let it
		// through the downstream propagates X-User-Sub="" and any
		// upstream ACL keyed on subject would authorize every caller as
		// the same (empty) principal.
		if claims.Sub == "" {
			metrics.AccessDenied.WithLabelValues("subject_missing").Inc()
			logger.Warn("access_denied_subject_missing", zap.String("email", claims.Email))
			writeOAuthError(w, http.StatusForbidden, "access_denied", "id token missing subject claim", "subject_missing")
			return
		}

		// Reject IdP-unverified emails: without this, a user who self-signs up
		// with someone else's email at the IdP would have that email forwarded
		// verbatim as X-User-Email to the upstream, which may authorize by email.
		// If the claim is absent, we accept — some IdPs do not emit it.
		if claims.EmailVerified != nil && !*claims.EmailVerified {
			metrics.AccessDenied.WithLabelValues("email_unverified").Inc()
			logger.Warn("access_denied_email_unverified",
				zap.String("subject", claims.Sub),
				zap.String("email", claims.Email),
			)
			writeOAuthError(w, http.StatusForbidden, "access_denied", "email address is not verified", "email_not_verified")
			return
		}

		// Extract groups from the configured claim name. A non-[]string
		// shape (e.g. IdP emits a space-separated string, or a nested
		// object) is treated as "no groups" — ignoring the unmarshal
		// error lets the group allowlist make the final call instead of
		// failing the login on a shape mismatch we can't reason about.
		//
		// When the shape is wrong AND ALLOWED_GROUPS is enforced, every
		// login will be denied — an IdP-format change (a new scope
		// layout, a schema migration) would silently mass-lockout users
		// with only a single `group` denial counter to go on. We emit
		// at Warn with a dedicated reason so the denial is visible
		// without enabling id_token debug logging, and increment a
		// dedicated counter so operators can alert on the transition
		// instead of having to spot a spike in `group` denials.
		var groups []string
		if cbCfg.GroupsClaim != "" {
			var raw map[string]json.RawMessage
			if err := idToken.Claims(&raw); err == nil {
				if v, ok := raw[cbCfg.GroupsClaim]; ok {
					if err := json.Unmarshal(v, &groups); err != nil {
						// Distinct counter: the user is admitted with
						// empty groups — this is NOT a denial. Sharing
						// the AccessDenied counter would conflate IdP
						// shape drift with real auth-policy denials and
						// double-count when the empty-groups admit later
						// trips an AllowedGroups mismatch.
						metrics.GroupsClaimShapeMismatch.Inc()
						logger.Warn("groups_claim_shape_mismatch",
							zap.String("claim", cbCfg.GroupsClaim),
							zap.String("subject", claims.Sub),
							zap.Error(err),
						)
					}
				}
			}
		}

		// M12: reject group names containing the delimiter "," (which
		// splits into two groups at the X-User-Groups header parser) or
		// the control characters "\r" / "\n" / "\x00" (header smuggling
		// / log injection). Rejected at callback time so the malformed
		// name never reaches the code/refresh sealed payload.
		for _, g := range groups {
			if strings.ContainsAny(g, ",\r\n\x00") {
				metrics.AccessDenied.WithLabelValues("group_invalid").Inc()
				logger.Warn("access_denied_group_invalid",
					zap.String("subject", claims.Sub),
				)
				writeOAuthError(w, http.StatusForbidden, "access_denied", "group name contains invalid characters", "group_invalid")
				return
			}
		}

		// Enforce group allowlist if configured
		if len(cbCfg.AllowedGroups) > 0 && !hasOverlap(groups, cbCfg.AllowedGroups) {
			metrics.AccessDenied.WithLabelValues("group").Inc()
			logger.Warn("access_denied_group",
				zap.String("subject", claims.Sub),
				zap.Strings("user_groups", groups),
				zap.Strings("allowed_groups", cbCfg.AllowedGroups),
			)
			writeOAuthError(w, http.StatusForbidden, "access_denied", "user not in any allowed group")
			return
		}

		// H6: propagate the server-minted downstream PKCE pair (if any)
		// into the code so /token can verify it internally when the client
		// itself does not participate in PKCE. session.SvrVerifier is set
		// only when /authorize minted the pair (PKCE_REQUIRED=false AND
		// client omitted code_challenge).
		sc := sealedCode{
			TokenID: uuid.New().String(),
			// FamilyID is the refresh-rotation lineage seed. Minted
			// here so a detected code replay can revoke the entire
			// family of refresh tokens that derived from the first
			// (legitimate) redemption — RFC 6749 §4.1.2 MUST.
			FamilyID:      uuid.New().String(),
			ClientID:      session.ClientID,
			RedirectURI:   session.RedirectURI,
			CodeChallenge: session.CodeChallenge,
			Subject:       claims.Sub,
			Email:         claims.Email,
			Name:          claims.Name,
			Groups:        groups,
			ServerPKCE:    session.SvrVerifier != "",
			SvrVerifier:   session.SvrVerifier,
			Typ:           token.PurposeCode,
			Audience:      audience,
			ExpiresAt:     time.Now().Add(codeTTL),
		}

		code, err := tm.SealJSON(sc, token.PurposeCode)
		if err != nil {
			logger.Error("authorization_code_seal_failed", zap.Error(err))
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
			return
		}

		// Safely merge params even if redirect_uri already contains a query string
		redirectParsed, err := url.Parse(session.RedirectURI)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed redirect_uri")
			return
		}
		q2 := redirectParsed.Query()
		q2.Set("code", code)
		if session.OriginalState != "" {
			q2.Set("state", session.OriginalState)
		}
		// RFC 9700 §2.1.4 (mix-up defense): include the AS issuer
		// identifier on the authorization response so a client that
		// talks to multiple ASes can verify the response came from the
		// AS it actually sent the request to. Value matches the
		// `issuer` field published in RFC 8414 AS metadata.
		q2.Set("iss", audience)
		redirectParsed.RawQuery = q2.Encode()
		// Fragment scrub: DCR already rejects fragment-bearing URIs at
		// registration time, but clear here too so a future regression
		// in that check cannot sneak code/state into the fragment (the
		// browser would retain them in history without sending them
		// over the wire to the RP).
		redirectParsed.Fragment = ""
		redirectParsed.RawFragment = ""
		redirectURL := redirectParsed.String()

		logger.Info("callback_success", zap.String("subject", claims.Sub))
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// redirectAuthzError forwards an RFC 6749 §4.1.2.1 error back to the
// client's registered redirect_uri, carrying the original state so the
// client can correlate, and stripping any fragment (defense-in-depth;
// DCR already rejects fragment-bearing URIs). Used by both the /callback
// IdP-error path AND every /authorize failure that occurs after
// client_id + redirect_uri have been validated — §4.1.2.1 mandates
// redirect (not AS-rendered error) once the redirect target is trusted.
//
// The `iss` parameter is emitted on error redirects too (RFC 9207 §2
// / RFC 9700 §2.1.4): a strict client gates its mix-up defense on
// `iss` being present on EVERY authorization response, not just
// success — omitting it on the error path defeats the defense exactly
// when an attacker would want to inject a forged error from a
// different AS. On a parse failure we fall back to a proxy-hosted
// JSON body — the registered URI went through exact-match validation
// upstream, so a parse error here is an invariant violation rather
// than attacker-controlled input.
func redirectAuthzError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc, audience string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, errCode, errDesc)
		return
	}
	q := u.Query()
	q.Set("error", errCode)
	if errDesc != "" {
		q.Set("error_description", errDesc)
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", audience)
	u.RawQuery = q.Encode()
	u.Fragment = ""
	u.RawFragment = ""
	http.Redirect(w, r, u.String(), http.StatusFound)
}
