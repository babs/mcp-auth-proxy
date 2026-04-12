package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/babs/mcp-auth-proxy/token"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const (
	codeTTL         = 5 * time.Minute
	oidcExchangeTTL = 10 * time.Second
)

// verifyIDTokenFunc abstracts OIDC id_token verification for testability.
type verifyIDTokenFunc func(ctx context.Context, rawToken string) (*oidc.IDToken, error)

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

		// RFC 6749 §4.1.2.1: IdP may redirect with error instead of code
		if idpError := q.Get("error"); idpError != "" {
			desc := q.Get("error_description")
			if desc == "" {
				desc = "authorization denied by identity provider"
			}
			writeOAuthError(w, http.StatusBadRequest, idpError, desc)
			return
		}

		upstreamCode := q.Get("code")
		internalState := q.Get("state")

		if upstreamCode == "" || internalState == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing code or state")
			return
		}

		var session sealedSession
		if err := tm.OpenJSON(internalState, &session); err != nil {
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

		oauth2Token, err := oauth2Cfg.Exchange(exchangeCtx, upstreamCode)
		if err != nil {
			logger.Error("upstream token exchange failed", zap.Error(err))
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
			logger.Error("id_token verification failed", zap.Error(err))
			writeOAuthError(w, http.StatusBadGateway, "server_error", "id_token verification failed")
			return
		}

		var claims struct {
			Sub   string `json:"sub"`
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		if err := idToken.Claims(&claims); err != nil {
			logger.Error("failed to parse id_token claims", zap.Error(err))
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to parse claims")
			return
		}

		// Extract groups from the configured claim name
		var groups []string
		if cbCfg.GroupsClaim != "" {
			var raw map[string]json.RawMessage
			if err := idToken.Claims(&raw); err == nil {
				if v, ok := raw[cbCfg.GroupsClaim]; ok {
					json.Unmarshal(v, &groups) // ignore error — non-[]string claim is treated as empty
				}
			}
		}

		// Enforce group allowlist if configured
		if len(cbCfg.AllowedGroups) > 0 && !hasOverlap(groups, cbCfg.AllowedGroups) {
			logger.Warn("access denied: user not in allowed groups",
				zap.String("subject", claims.Sub),
				zap.Strings("user_groups", groups),
				zap.Strings("allowed_groups", cbCfg.AllowedGroups),
			)
			writeOAuthError(w, http.StatusForbidden, "access_denied", "user not in any allowed group")
			return
		}

		sc := sealedCode{
			ClientID:      session.ClientID,
			RedirectURI:   session.RedirectURI,
			CodeChallenge: session.CodeChallenge,
			Subject:       claims.Sub,
			Email:         claims.Email,
			Name:          claims.Name,
			Groups:        groups,
			Audience:      audience,
			ExpiresAt:     time.Now().Add(codeTTL),
		}

		code, err := tm.SealJSON(sc)
		if err != nil {
			logger.Error("failed to seal authorization code", zap.Error(err))
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
		redirectParsed.RawQuery = q2.Encode()
		redirectURL := redirectParsed.String()

		logger.Info("callback successful", zap.String("subject", claims.Sub))
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}
