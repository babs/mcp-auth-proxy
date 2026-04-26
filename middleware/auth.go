package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/token"
	"go.uber.org/zap"
)

type contextKey string

const (
	ContextSubject   contextKey = "sub"
	ContextEmail     contextKey = "email"
	ContextGroups    contextKey = "groups"
	ContextRPCMethod contextKey = "rpc_method" // JSON-RPC method from request body
	ContextRPCTool   contextKey = "rpc_tool"   // params.name for tools/call
	ContextRPCID     contextKey = "rpc_id"     // request id (number|string, raw JSON)
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

// bearerPrefix is used for a case-insensitive match on the auth scheme,
// per RFC 6750 §2.1 ("the scheme name is case-insensitive").
const bearerPrefix = "Bearer "

func (a *Auth) Validate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) <= len(bearerPrefix) || !strings.EqualFold(authHeader[:len(bearerPrefix)], bearerPrefix) {
			// RFC 6750 §3.1: no credential / malformed scheme → invalid_request.
			// invalid_token is specifically for a presented token that failed
			// validation.
			a.writeAuthError(w, "invalid_request")
			return
		}

		tokenStr := strings.TrimSpace(authHeader[len(bearerPrefix):])
		// `Bearer    ` (whitespace-only credential) is malformed, not a
		// failed token. RFC 6750 §3.1 reserves `invalid_token` for
		// "presented but failed validation"; the absent/blank case
		// belongs in `invalid_request` so a client log observer can
		// tell "I forgot the token" from "my token expired".
		if tokenStr == "" {
			a.writeAuthError(w, "invalid_request")
			return
		}

		claims, err := a.tokenManager.Validate(tokenStr)
		if err != nil {
			a.logger.Debug("token_validation_failed", zap.Error(err))
			// Reason label split: `invalid_token` covers shape /
			// signature / TTL failures; `audience_mismatch` and
			// `token_revoked_iat_cutoff` are tracked separately so a
			// rotation gone wrong (audience drift) or a bulk revoke
			// (REVOKE_BEFORE) is alertable independently of routine
			// expired-token noise.
			metrics.AccessDenied.WithLabelValues("invalid_token").Inc()
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
			metrics.AccessDenied.WithLabelValues("audience_mismatch").Inc()
			a.writeAuthError(w, "invalid_token")
			return
		}

		// Bulk revocation: reject tokens issued before the cutoff
		if !a.revokeBefore.IsZero() && claims.IssuedAt.Before(a.revokeBefore) {
			a.logger.Debug("token_revoked_iat_cutoff",
				zap.Time("issued_at", claims.IssuedAt),
				zap.Time("revoke_before", a.revokeBefore),
			)
			metrics.AccessDenied.WithLabelValues("token_revoked_iat_cutoff").Inc()
			a.writeAuthError(w, "invalid_token")
			return
		}

		ctx := context.WithValue(r.Context(), ContextSubject, claims.Subject)
		ctx = context.WithValue(ctx, ContextEmail, claims.Email)
		ctx = context.WithValue(ctx, ContextGroups, claims.Groups)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeAuthError returns 401 with WWW-Authenticate pointing to the protected
// resource metadata (RFC 9728 §5.1). errCode must be one of the RFC 6750 §3.1
// codes: invalid_request, invalid_token, insufficient_scope.
//
// The challenge includes an `error_description` attribute (RFC 6750 §3 —
// MAY) so a log observer / API gateway / client developer tool that only
// sees the header (not the JSON body) can still tell the two failure
// modes apart. Descriptions are short, fixed, and carry no caller-
// controlled data — pure allowlist lookup to rule out any header-
// injection concerns.
func (a *Auth) writeAuthError(w http.ResponseWriter, errCode string) {
	desc := errorDescriptions[errCode]
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer error="%s", error_description="%s", resource_metadata="%s/.well-known/oauth-protected-resource"`,
		errCode, desc, a.baseURL,
	))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}

// errorDescriptions maps each RFC 6750 §3.1 error code to a short,
// fixed description. Closed allowlist — anything that slips past the
// callers' own allowlist falls back to the empty string rather than
// echoing an unknown value into the header.
var errorDescriptions = map[string]string{
	"invalid_request":    "bearer credential is missing or malformed",
	"invalid_token":      "bearer token is invalid, expired, or not intended for this resource",
	"insufficient_scope": "bearer token lacks the scope required for this resource",
}
