package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/babs/mcp-auth-proxy/token"
	"go.uber.org/zap"
)

const clientTTL = 24 * time.Hour

type registerRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type registerResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// Register handles POST /register (RFC 7591 Dynamic Client Registration).
// Client record is encrypted into the client_id itself for stateless operation.
// audience binds the client to a specific proxy deployment.
func Register(tm *token.Manager, logger *zap.Logger, audience string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

		var req registerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}

		if len(req.RedirectURIs) == 0 {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uris is required and must not be empty")
			return
		}

		// OAuth 2.1 §2.3.1: non-loopback redirect URIs must use HTTPS
		for _, raw := range req.RedirectURIs {
			u, err := url.Parse(raw)
			if err != nil {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed redirect_uri")
				return
			}
			if u.Scheme != "https" && !isLoopback(u) {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri must use HTTPS for non-loopback addresses")
				return
			}
		}

		authMethod := req.TokenEndpointAuthMethod
		if authMethod == "" {
			authMethod = "none"
		}

		now := time.Now()
		sc := sealedClient{
			ID:           uuid.New().String(),
			RedirectURIs: req.RedirectURIs,
			ClientName:   req.ClientName,
			Audience:     audience,
			ExpiresAt:    now.Add(clientTTL),
		}

		clientID, err := tm.SealJSON(sc)
		if err != nil {
			logger.Error("failed to seal client", zap.Error(err))
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to register client")
			return
		}

		logger.Info("client registered", zap.String("internal_id", sc.ID), zap.String("client_name", req.ClientName))

		writeJSON(w, http.StatusCreated, registerResponse{
			ClientID:                clientID,
			ClientIDIssuedAt:        now.Unix(),
			RedirectURIs:            req.RedirectURIs,
			TokenEndpointAuthMethod: authMethod,
		})
	}
}
