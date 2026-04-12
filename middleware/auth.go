package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/babs/mcp-auth-proxy/token"
	"go.uber.org/zap"
)

type contextKey string

const (
	ContextSubject contextKey = "sub"
	ContextEmail   contextKey = "email"
	ContextGroups  contextKey = "groups"
)

// Auth validates Bearer tokens on proxied MCP routes.
// Stateless: token is validated purely by AES-GCM decryption + expiry/iat check.
type Auth struct {
	tokenManager *token.Manager
	logger       *zap.Logger
	baseURL      string
	revokeBefore time.Time // tokens with iat before this are rejected (zero = disabled)
}

func NewAuth(tm *token.Manager, logger *zap.Logger, baseURL string, revokeBefore time.Time) *Auth {
	return &Auth{tokenManager: tm, logger: logger, baseURL: baseURL, revokeBefore: revokeBefore}
}

func (a *Auth) Validate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			a.writeAuthError(w, "missing or malformed Authorization header")
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		claims, err := a.tokenManager.Validate(tokenStr)
		if err != nil {
			a.logger.Debug("token_validation_failed", zap.Error(err))
			a.writeAuthError(w, "invalid_token")
			return
		}

		// Prevent cross-instance replay: every token must be bound to the
		// proxy base URL that issued it. Two deployments accidentally sharing
		// the same TOKEN_SIGNING_SECRET would otherwise be a confused deputy.
		if claims.Audience != a.baseURL {
			a.logger.Debug("token_audience_mismatch",
				zap.String("got", claims.Audience),
				zap.String("want", a.baseURL),
			)
			a.writeAuthError(w, "invalid_token")
			return
		}

		// Bulk revocation: reject tokens issued before the cutoff
		if !a.revokeBefore.IsZero() && claims.IssuedAt.Before(a.revokeBefore) {
			a.logger.Debug("token_revoked_iat_cutoff",
				zap.Time("issued_at", claims.IssuedAt),
				zap.Time("revoke_before", a.revokeBefore),
			)
			a.writeAuthError(w, "invalid_token")
			return
		}

		ctx := context.WithValue(r.Context(), ContextSubject, claims.Subject)
		ctx = context.WithValue(ctx, ContextEmail, claims.Email)
		ctx = context.WithValue(ctx, ContextGroups, claims.Groups)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeAuthError returns 401 with WWW-Authenticate pointing to the protected resource metadata (RFC 9728 §5.1).
func (a *Auth) writeAuthError(w http.ResponseWriter, desc string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`,
		a.baseURL,
	))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": desc})
}
