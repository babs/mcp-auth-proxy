package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	clientTTL = 24 * time.Hour
	// Cap DCR amplification: a client
	// registration bloats the sealed client_id (and any logs/metrics
	// referencing it) in proportion to the submitted redirect_uris. Five
	// URIs of 512 chars each is well above any legitimate need.
	maxRedirectURIs      = 5
	maxRedirectURILength = 512
)

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

		// M5: hard cap the number of redirect_uris. Without this, an
		// unauthenticated caller can register thousands of URIs and bloat
		// the sealed client_id / logs / metrics indefinitely.
		if len(req.RedirectURIs) > maxRedirectURIs {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uris exceeds maximum count")
			return
		}

		// OAuth 2.1 §2.3.1: non-loopback redirect URIs must use HTTPS.
		// M5/M6: also reject oversize, fragment-bearing, and userinfo-bearing
		// URIs. Fragment is forbidden by OAuth 2.1 §7.5; userinfo amplifies
		// phishing (https://attacker:pass@legit.example/cb visually legit).
		for _, raw := range req.RedirectURIs {
			if len(raw) > maxRedirectURILength {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri exceeds maximum length")
				return
			}
			u, err := url.Parse(raw)
			if err != nil {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed redirect_uri")
				return
			}
			// Require an absolute URI with a real authority.
			// url.Parse("https:foo")  → Scheme="https", Opaque="foo", Host=""
			// url.Parse("https:///x") → Scheme="https", Host=""
			// Neither is a valid OAuth redirect target per RFC 3986 §3.
			// Without these checks the scheme switch below lets them
			// through and the /callback redirect later emits a broken
			// Location header to the browser.
			if u.Opaque != "" {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri must be an absolute URI with authority, not opaque")
				return
			}
			if u.Host == "" {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri must include a host")
				return
			}
			// Also trip on a trailing bare "#" (url.Parse leaves Fragment
			// empty for "https://x/cb#" even though the marker is present).
			if u.Fragment != "" || strings.Contains(raw, "#") {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri must not contain a fragment")
				return
			}
			if u.User != nil {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri must not contain userinfo")
				return
			}
			// Only http(s) schemes are meaningful for a browser-driven
			// OAuth callback. Anything else (custom app schemes, ftp, ldap,
			// etc.) is almost certainly a mistake; rejecting them early
			// avoids a confusing failure mode downstream.
			switch u.Scheme {
			case "https":
				// always allowed
			case "http":
				if !isLoopback(u) {
					writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri must use HTTPS for non-loopback addresses")
					return
				}
			default:
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri scheme must be http (loopback only) or https")
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
			Typ:          token.PurposeClient,
			Audience:     audience,
			ExpiresAt:    now.Add(clientTTL),
		}

		clientID, err := tm.SealJSON(sc, token.PurposeClient)
		if err != nil {
			logger.Error("client_seal_failed", zap.Error(err))
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to register client")
			return
		}

		metrics.ClientsRegistered.Inc()
		logger.Info("client_registered", zap.String("internal_id", sc.ID), zap.String("client_name", req.ClientName))

		writeJSON(w, http.StatusCreated, registerResponse{
			ClientID:                clientID,
			ClientIDIssuedAt:        now.Unix(),
			RedirectURIs:            req.RedirectURIs,
			TokenEndpointAuthMethod: authMethod,
		})
	}
}
