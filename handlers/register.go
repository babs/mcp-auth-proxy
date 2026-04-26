package handlers

import (
	"encoding/json"
	"errors"
	"io"
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
	maxClientNameLength  = 512
)

type registerRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type registerResponse struct {
	ClientID         string `json:"client_id"`
	ClientIDIssuedAt int64  `json:"client_id_issued_at"`
	// ClientIDExpiresAt is the UNIX timestamp at which the sealed
	// client_id stops opening (RFC 7591 §3.2.1 OPTIONAL). Published
	// so clients can proactively re-register before hitting a 400 on
	// /authorize once the sealed TTL lapses (default 24h, see
	// clientTTL). Value of 0 per §3.2.1 would mean "never expires";
	// we always emit a real timestamp.
	ClientIDExpiresAt int64    `json:"client_id_expires_at"`
	RedirectURIs      []string `json:"redirect_uris"`
	// ClientName is echoed only when the client actually submitted
	// one — RFC 7591 §3.2.1 MUST return registered metadata but does
	// not require empty values in the response. omitempty keeps the
	// JSON identical for clients that didn't set it.
	ClientName              string `json:"client_name,omitempty"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
}

// Register handles POST /register (RFC 7591 Dynamic Client Registration).
// Client record is encrypted into the client_id itself for stateless operation.
// audience binds the client to a specific proxy deployment.
func Register(tm *token.Manager, logger *zap.Logger, audience string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

		var req registerRequest
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil {
			// Distinguish a body that exceeded MaxBodySize (1 MB
			// cap) from a structurally-malformed body so a client
			// log observer can tell "I posted too much" from "I
			// posted garbage". Mirrors /token's branching at
			// handlers/token.go.
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeOAuthError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body exceeds the 1 MB cap")
				return
			}
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}
		var trailing any
		if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}

		// RFC 7591 §3.2.2: defects on redirect_uris use the dedicated
		// "invalid_redirect_uri" error code; "invalid_request" stays
		// reserved for structural request problems (bad JSON, missing
		// field). Clients switch on these codes to surface the specific
		// defect to the operator.
		if len(req.RedirectURIs) == 0 {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required and must not be empty")
			return
		}

		// M5: hard cap the number of redirect_uris. Without this, an
		// unauthenticated caller can register thousands of URIs and bloat
		// the sealed client_id / logs / metrics indefinitely.
		if len(req.RedirectURIs) > maxRedirectURIs {
			writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris exceeds maximum count")
			return
		}

		// client_name is unauthenticated metadata that is both logged
		// and sealed into the returned client_id. Keep it bounded so
		// /register cannot amplify a large request body into oversized
		// logs and responses.
		if len(req.ClientName) > maxClientNameLength {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "client_name exceeds maximum length")
			return
		}
		// Reject control bytes (NUL / CR / LF / TAB / etc.) and the
		// X-User-Groups delimiter `,`. zap escapes the access-log
		// line so log injection is neutralized at the transport, but
		// the sealed client_id carries the raw bytes — anything
		// downstream that unseals and parses ClientName would
		// inherit them. Mirrors the group-name filter at
		// callback.go (M12). RFC 7591 §2 permits operator-side
		// rejection of metadata; §3.2.2 prescribes the error code.
		if strings.ContainsAny(req.ClientName, ",\r\n\t\x00\x0b\x0c") {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "client_name must not contain control bytes or commas")
			return
		}

		// OAuth 2.1 §2.3.1: non-loopback redirect URIs must use HTTPS.
		// M5/M6: also reject oversize, fragment-bearing, and userinfo-bearing
		// URIs. Fragment is forbidden by OAuth 2.1 §7.5; userinfo amplifies
		// phishing (https://attacker:pass@legit.example/cb visually legit).
		for _, raw := range req.RedirectURIs {
			if len(raw) > maxRedirectURILength {
				writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri exceeds maximum length")
				return
			}
			u, err := url.Parse(raw)
			if err != nil {
				writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "malformed redirect_uri")
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
				writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must be an absolute URI with authority, not opaque")
				return
			}
			if u.Host == "" {
				writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must include a host")
				return
			}
			// Also trip on a trailing bare "#" (url.Parse leaves Fragment
			// empty for "https://x/cb#" even though the marker is present).
			if u.Fragment != "" || strings.Contains(raw, "#") {
				writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must not contain a fragment")
				return
			}
			if u.User != nil {
				writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must not contain userinfo")
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
					writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must use HTTPS for non-loopback addresses")
					return
				}
			default:
				writeOAuthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri scheme must be http (loopback only) or https")
				return
			}
		}

		// Discovery advertises token_endpoint_auth_methods_supported=["none"].
		// Accept empty or "none" only; reject anything else per RFC 7591 §3.2.2
		// so a client cannot be "registered" as client_secret_post and then
		// wrongly assume /token authenticates secrets.
		authMethod := req.TokenEndpointAuthMethod
		switch authMethod {
		case "", "none":
			authMethod = "none"
		default:
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported token_endpoint_auth_method; only \"none\" is supported")
			return
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

		// RFC 7591 examples mark client information responses non-cacheable.
		// Our client_id is a 24h bearer-like registration handle, so keep it
		// out of shared caches even though POST responses are rarely cached.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		writeJSON(w, http.StatusCreated, registerResponse{
			ClientID:                clientID,
			ClientIDIssuedAt:        now.Unix(),
			ClientIDExpiresAt:       sc.ExpiresAt.Unix(),
			RedirectURIs:            req.RedirectURIs,
			ClientName:              req.ClientName,
			TokenEndpointAuthMethod: authMethod,
		})
	}
}
