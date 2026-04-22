package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/replay"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	accessTokenTTL  = 1 * time.Hour
	refreshTokenTTL = 7 * 24 * time.Hour
)

// Token handles POST /token (authorization_code and refresh_token grants).
// audience binds issued tokens to a specific proxy deployment; revokeBefore
// is the bulk-revocation cutoff applied to refresh tokens (the access-token
// path is enforced separately by middleware/auth.go). replayStore, when
// non-nil, enforces single-use authorization codes AND refresh token
// rotation with reuse detection across replicas; when nil, the handler
// retains stateless behavior (codes/refresh tokens unique, audience-bound
// and expiry-checked but not single-use).
func Token(tm *token.Manager, logger *zap.Logger, audience string, revokeBefore time.Time, replayStore replay.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
			return
		}

		// RFC 8707 §2.2: `resource` MAY appear on a /token request; if
		// present it MUST be validated. We are both AS and RS, so the
		// only valid value is our own baseURL. Checked once here before
		// grant-type dispatch so both authorization_code and
		// refresh_token paths enforce it uniformly.
		if resources, ok := r.Form["resource"]; ok {
			for _, res := range resources {
				if !matchResource(res, audience) {
					writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource does not identify this authorization server")
					return
				}
			}
		}

		grantType := r.FormValue("grant_type")

		switch grantType {
		case "authorization_code":
			handleAuthorizationCode(w, r, tm, logger, audience, replayStore)
		case "refresh_token":
			handleRefreshToken(w, r, tm, logger, audience, revokeBefore, replayStore)
		default:
			writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
		}
	}
}

func handleAuthorizationCode(w http.ResponseWriter, r *http.Request, tm *token.Manager, logger *zap.Logger, audience string, replayStore replay.Store) {
	codeStr := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientIDStr := r.FormValue("client_id")
	codeVerifier := r.FormValue("code_verifier")

	if codeStr == "" || redirectURI == "" || clientIDStr == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing required parameters")
		return
	}

	// RFC 7636 §4.1: code_verifier must be 43-128 characters (if provided)
	if codeVerifier != "" && (len(codeVerifier) < 43 || len(codeVerifier) > 128) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_verifier must be 43-128 characters")
		return
	}

	var code sealedCode
	if err := tm.OpenJSON(codeStr, &code, token.PurposeCode); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
		return
	}

	if code.Typ != token.PurposeCode {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
		return
	}

	if code.Audience != audience {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code bound to a different audience")
		return
	}

	if time.Now().After(code.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code expired")
		return
	}

	var client sealedClient
	if err := tm.OpenJSON(clientIDStr, &client, token.PurposeClient); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid client_id")
		return
	}

	if client.Typ != token.PurposeClient {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid client_id")
		return
	}

	if client.Audience != audience {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "client registered for a different audience")
		return
	}

	if time.Now().After(client.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "client registration expired")
		return
	}

	if client.ID != code.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}

	if code.RedirectURI != redirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// Every code must carry a TokenID (single-use key for the replay store).
	// Mirrors the refresh-side invariant (C2): reject upfront so the replay
	// guard below cannot silently no-op if a future code path forgets to
	// populate the field at seal time.
	if code.TokenID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code missing token id")
		return
	}

	// PKCE verification: required if code_challenge was set during /authorize.
	//
	// H6: when the proxy minted the downstream PKCE pair itself
	// (code.ServerPKCE) because PKCE_REQUIRED=false and the client omitted
	// code_challenge, the client is not expected to send a code_verifier
	// either. In that case we substitute the server-side verifier stored on
	// the code — the check is a plumbing invariant, not a client-anchored
	// proof, but pairing it with single-use code enforcement (replay store,
	// C3) still blocks an intercepted code from being redeemed twice.
	if code.CodeChallenge != "" {
		effectiveVerifier := codeVerifier
		if code.ServerPKCE && codeVerifier == "" {
			effectiveVerifier = code.SvrVerifier
		}
		if effectiveVerifier == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier is required")
			return
		}
		if !VerifyPKCE(effectiveVerifier, code.CodeChallenge) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	}

	// Enforce single-use (RFC 6749 §4.1.2). The claim happens AFTER all other
	// validations so that a malformed retry by the legitimate client does not
	// burn the code. Claim TTL matches the remaining code lifetime so the
	// record expires naturally once replay is no longer possible. TokenID is
	// guaranteed non-empty by the upfront check above.
	if replayStore != nil {
		remaining := time.Until(code.ExpiresAt)
		if remaining < time.Second {
			remaining = time.Second
		}
		key := replay.NamespacedKey("authz_code", code.TokenID)
		if err := replayStore.ClaimOnce(r.Context(), key, remaining); err != nil {
			if errors.Is(err, replay.ErrAlreadyClaimed) {
				metrics.ReplayDetected.WithLabelValues("code").Inc()
				logger.Warn("authorization_code_replay",
					zap.String("token_id", code.TokenID),
					zap.String("subject", code.Subject),
					zap.String("client_id", client.ID),
				)
				writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code already used", "code_replay")
				return
			}
			// Fail closed on backend errors — do not issue tokens against an
			// uncertain replay-state result.
			logger.Error("replay_store_error", zap.Error(err))
			writeOAuthError(w, http.StatusServiceUnavailable, "server_error", "replay store unavailable", "replay_store_unavailable")
			return
		}
	}

	accessToken, _, err := tm.Issue(audience, code.Subject, code.Email, client.ID, code.Groups, accessTokenTTL)
	if err != nil {
		logger.Error("token_issue_failed", zap.Error(err))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue token", "token_issue_failed")
		return
	}

	now := time.Now()
	refresh := sealedRefresh{
		TokenID:   uuid.New().String(),
		FamilyID:  uuid.New().String(),
		Subject:   code.Subject,
		Email:     code.Email,
		Groups:    code.Groups,
		ClientID:  client.ID,
		Typ:       token.PurposeRefresh,
		Audience:  audience,
		IssuedAt:  now,
		ExpiresAt: now.Add(refreshTokenTTL),
	}
	refreshToken, err := tm.SealJSON(refresh, token.PurposeRefresh)
	if err != nil {
		logger.Error("refresh_token_seal_failed", zap.Error(err))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	metrics.TokensIssued.WithLabelValues("authorization_code").Inc()
	logger.Info("token_issued", zap.String("subject", code.Subject), zap.String("client_id", client.ID))

	// RFC 6749 §5.1: token responses must not be cached
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"refresh_token": refreshToken,
	})
}

func handleRefreshToken(w http.ResponseWriter, r *http.Request, tm *token.Manager, logger *zap.Logger, audience string, revokeBefore time.Time, replayStore replay.Store) {
	refreshTokenStr := r.FormValue("refresh_token")
	clientIDStr := r.FormValue("client_id")

	if refreshTokenStr == "" || clientIDStr == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing required parameters")
		return
	}

	var refresh sealedRefresh
	if err := tm.OpenJSON(refreshTokenStr, &refresh, token.PurposeRefresh); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
		return
	}

	if refresh.Typ != token.PurposeRefresh {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
		return
	}

	// C2: every refresh must carry both a FamilyID (lineage for reuse
	// detection) and a TokenID (single-use key within the lineage). Empty
	// either side makes the replay guard at line below a silent no-op, so
	// we reject upfront — belt-and-braces against any future code path
	// that forgets to populate both fields at seal time.
	if refresh.FamilyID == "" || refresh.TokenID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token missing family or id")
		return
	}

	if refresh.Audience != audience {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token bound to a different audience")
		return
	}

	// Bulk revocation: reject refresh tokens issued before the cutoff.
	// Without this check, REVOKE_BEFORE only invalidates access tokens and a
	// compromised refresh token would silently mint fresh ones past the cutoff.
	if !revokeBefore.IsZero() && refresh.IssuedAt.Before(revokeBefore) {
		logger.Debug("refresh_token_revoked_iat_cutoff",
			zap.Time("issued_at", refresh.IssuedAt),
			zap.Time("revoke_before", revokeBefore),
		)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token revoked")
		return
	}

	if time.Now().After(refresh.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}

	var client sealedClient
	if err := tm.OpenJSON(clientIDStr, &client, token.PurposeClient); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid client_id")
		return
	}

	if client.Typ != token.PurposeClient {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid client_id")
		return
	}

	if client.Audience != audience {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "client registered for a different audience")
		return
	}

	if time.Now().After(client.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_client", "client registration expired")
		return
	}

	if client.ID != refresh.ClientID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}

	// Refresh rotation with reuse detection (RFC 6749 §10.4 / OAuth 2.1 §6.1).
	// Only active when a replay store is wired — the stateless fallback keeps
	// the original behavior (rotation without reuse detection).
	//
	// Invariants enforced atomically by ClaimOrCheckFamily (M4 — collapsing
	// the prior Exists+ClaimOnce pair into one round trip closes a TOCTOU
	// window where a Redis read routed to a lagging replica allowed one extra
	// rotation against a freshly-revoked family):
	//   1. Family revoked → every sibling of a reused refresh is rejected.
	//   2. TokenID single-use → a refresh already rotated once (legitimately)
	//      cannot be rotated again. A second claim on the same TokenID is the
	//      signal that the token was leaked.
	if replayStore != nil {
		familyKey := replay.NamespacedKey("refresh_family_revoked", refresh.FamilyID)
		claimKey := replay.NamespacedKey("refresh", refresh.TokenID)
		claimTTL := time.Until(refresh.ExpiresAt)
		if claimTTL < time.Second {
			claimTTL = time.Second
		}
		revoked, alreadyClaimed, err := replayStore.ClaimOrCheckFamily(r.Context(), familyKey, claimKey, claimTTL)
		if err != nil {
			logger.Error("replay_store_error", zap.Error(err))
			writeOAuthError(w, http.StatusServiceUnavailable, "server_error", "replay store unavailable", "replay_store_unavailable")
			return
		}
		if revoked {
			metrics.AccessDenied.WithLabelValues("refresh_family_revoked").Inc()
			logger.Warn("refresh_token_family_revoked",
				zap.String("family_id", refresh.FamilyID),
				zap.String("subject", refresh.Subject),
				zap.String("client_id", client.ID),
			)
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token revoked", "refresh_family_revoked")
			return
		}
		if alreadyClaimed {
			// Reuse of a rotated token. Revoke the whole family so every
			// sibling (including the most recently issued legitimate one) is
			// invalidated. 7-day TTL covers the longest-lived refresh in the
			// family.
			if markErr := replayStore.Mark(r.Context(), familyKey, refreshTokenTTL); markErr != nil {
				logger.Error("refresh_family_revoke_failed", zap.Error(markErr))
			}
			metrics.ReplayDetected.WithLabelValues("refresh").Inc()
			logger.Warn("refresh_token_reuse_detected",
				zap.String("token_id", refresh.TokenID),
				zap.String("family_id", refresh.FamilyID),
				zap.String("subject", refresh.Subject),
				zap.String("client_id", client.ID),
			)
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected — family revoked", "refresh_reuse_detected")
			return
		}
	}

	accessToken, _, err := tm.Issue(audience, refresh.Subject, refresh.Email, client.ID, refresh.Groups, accessTokenTTL)
	if err != nil {
		logger.Error("token_refresh_issue_failed", zap.Error(err))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue token", "token_issue_failed")
		return
	}

	// The rotated refresh inherits the FamilyID so reuse detection spans the
	// entire lineage; a fresh TokenID makes it single-use on its own. Empty
	// FamilyID was rejected upfront (C2), so the field is always set here.
	now := time.Now()
	newRefresh := sealedRefresh{
		TokenID:   uuid.New().String(),
		FamilyID:  refresh.FamilyID,
		Subject:   refresh.Subject,
		Email:     refresh.Email,
		Groups:    refresh.Groups,
		ClientID:  client.ID,
		Typ:       token.PurposeRefresh,
		Audience:  audience,
		IssuedAt:  now,
		ExpiresAt: now.Add(refreshTokenTTL),
	}
	newRefreshToken, err := tm.SealJSON(newRefresh, token.PurposeRefresh)
	if err != nil {
		logger.Error("refresh_token_reseal_failed", zap.Error(err))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	metrics.TokensIssued.WithLabelValues("refresh_token").Inc()
	logger.Info("token_refreshed", zap.String("subject", refresh.Subject), zap.String("client_id", client.ID))

	// RFC 6749 §5.1: token responses must not be cached
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"refresh_token": newRefreshToken,
	})
}

// VerifyPKCE checks that SHA256(verifier) base64url-encoded matches the challenge.
// Uses constant-time comparison to prevent timing side-channel attacks.
func VerifyPKCE(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// ComputePKCEChallenge computes the S256 challenge from a verifier.
func ComputePKCEChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
