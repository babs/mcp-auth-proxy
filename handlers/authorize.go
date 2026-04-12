package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/babs/mcp-auth-proxy/token"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const sessionTTL = 10 * time.Minute

// AuthorizeConfig holds optional relaxation flags for /authorize.
type AuthorizeConfig struct {
	PKCERequired bool // false = allow clients that omit code_challenge (Cursor, MCP Inspector)
}

// Authorize handles GET /authorize (OAuth 2.1 PKCE authorization request).
// Session state is encrypted into the IdP state parameter for stateless operation.
func Authorize(tm *token.Manager, logger *zap.Logger, baseURL string, oauth2Cfg *oauth2.Config, authzCfg AuthorizeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		responseType := q.Get("response_type")
		clientIDStr := q.Get("client_id")
		redirectURI := q.Get("redirect_uri")
		codeChallenge := q.Get("code_challenge")
		codeChallengeMethod := q.Get("code_challenge_method")
		state := q.Get("state")
		// RFC 8707: accepted but not enforced — we are both AS and RS
		_ = q.Get("resource")

		if responseType != "code" {
			writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "response_type must be 'code'")
			return
		}

		if clientIDStr == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
			return
		}

		var client sealedClient
		if err := tm.OpenJSON(clientIDStr, &client); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
			return
		}

		if client.Audience != baseURL {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client", "client registered for a different audience")
			return
		}

		if time.Now().After(client.ExpiresAt) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client", "client registration expired")
			return
		}

		if redirectURI == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
			return
		}

		// OAuth 2.1 requires exact match — no prefix/subdomain matching
		validRedirect := false
		for _, uri := range client.RedirectURIs {
			if uri == redirectURI {
				validRedirect = true
				break
			}
		}
		if !validRedirect {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri does not match registered URIs")
			return
		}

		if authzCfg.PKCERequired {
			if codeChallenge == "" {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge is required")
				return
			}
			if codeChallengeMethod != "S256" {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
				return
			}
		} else if codeChallenge != "" && codeChallengeMethod != "" && codeChallengeMethod != "S256" {
			// PKCE optional, but if provided must be S256
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
			return
		}

		// Some clients (MCP Inspector, Cursor) omit state — generate one server-side
		// so the encrypted session always has a value to round-trip
		if state == "" {
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
				return
			}
			state = hex.EncodeToString(b)
		}

		session := sealedSession{
			ClientID:      client.ID,
			RedirectURI:   redirectURI,
			CodeChallenge: codeChallenge, // empty if PKCE not required and client omitted it
			OriginalState: state,
			Audience:      baseURL,
			ExpiresAt:     time.Now().Add(sessionTTL),
		}

		internalState, err := tm.SealJSON(session)
		if err != nil {
			logger.Error("failed to seal session", zap.Error(err))
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
			return
		}

		// Scopes are already set in oauth2Cfg — no override needed
		authURL := oauth2Cfg.AuthCodeURL(internalState,
			oauth2.SetAuthURLParam("response_mode", "query"),
		)

		logger.Debug("redirecting to IdP", zap.String("internal_client_id", client.ID))
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}
