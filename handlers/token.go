package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/babs/mcp-auth-proxy/token"
	"go.uber.org/zap"
)

const (
	accessTokenTTL  = 1 * time.Hour
	refreshTokenTTL = 7 * 24 * time.Hour
)

// Token handles POST /token (authorization_code and refresh_token grants).
// audience binds issued tokens to a specific proxy deployment; revokeBefore
// is the bulk-revocation cutoff applied to refresh tokens (the access-token
// path is enforced separately by middleware/auth.go).
func Token(tm *token.Manager, logger *zap.Logger, audience string, revokeBefore time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
			return
		}

		grantType := r.FormValue("grant_type")

		switch grantType {
		case "authorization_code":
			handleAuthorizationCode(w, r, tm, logger, audience)
		case "refresh_token":
			handleRefreshToken(w, r, tm, logger, audience, revokeBefore)
		default:
			writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
		}
	}
}

func handleAuthorizationCode(w http.ResponseWriter, r *http.Request, tm *token.Manager, logger *zap.Logger, audience string) {
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
	if err := tm.OpenJSON(codeStr, &code); err != nil {
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
	if err := tm.OpenJSON(clientIDStr, &client); err != nil {
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

	// PKCE verification: required if code_challenge was set during /authorize
	if code.CodeChallenge != "" {
		if codeVerifier == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier is required")
			return
		}
		if !VerifyPKCE(codeVerifier, code.CodeChallenge) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	}

	accessToken, _, err := tm.Issue(audience, code.Subject, code.Email, client.ID, code.Groups, accessTokenTTL)
	if err != nil {
		logger.Error("failed to issue token", zap.Error(err))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue token")
		return
	}

	now := time.Now()
	refresh := sealedRefresh{
		Subject:   code.Subject,
		Email:     code.Email,
		Groups:    code.Groups,
		ClientID:  client.ID,
		Audience:  audience,
		IssuedAt:  now,
		ExpiresAt: now.Add(refreshTokenTTL),
	}
	refreshToken, err := tm.SealJSON(refresh)
	if err != nil {
		logger.Error("failed to seal refresh token", zap.Error(err))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	logger.Info("token issued", zap.String("subject", code.Subject), zap.String("client_id", client.ID))

	// RFC 6749 §5.1: token responses must not be cached
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"refresh_token": refreshToken,
	})
}

func handleRefreshToken(w http.ResponseWriter, r *http.Request, tm *token.Manager, logger *zap.Logger, audience string, revokeBefore time.Time) {
	refreshTokenStr := r.FormValue("refresh_token")
	clientIDStr := r.FormValue("client_id")

	if refreshTokenStr == "" || clientIDStr == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing required parameters")
		return
	}

	var refresh sealedRefresh
	if err := tm.OpenJSON(refreshTokenStr, &refresh); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
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
		logger.Debug("refresh token revoked by iat cutoff",
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
	if err := tm.OpenJSON(clientIDStr, &client); err != nil {
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

	accessToken, _, err := tm.Issue(audience, refresh.Subject, refresh.Email, client.ID, refresh.Groups, accessTokenTTL)
	if err != nil {
		logger.Error("failed to issue token on refresh", zap.Error(err))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to issue token")
		return
	}

	now := time.Now()
	newRefresh := sealedRefresh{
		Subject:   refresh.Subject,
		Email:     refresh.Email,
		Groups:    refresh.Groups,
		ClientID:  client.ID,
		Audience:  audience,
		IssuedAt:  now,
		ExpiresAt: now.Add(refreshTokenTTL),
	}
	newRefreshToken, err := tm.SealJSON(newRefresh)
	if err != nil {
		logger.Error("failed to seal new refresh token", zap.Error(err))
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	logger.Info("token refreshed", zap.String("subject", refresh.Subject), zap.String("client_id", client.ID))

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
