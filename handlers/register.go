package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/babs/mcp-auth-proxy/config"
	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	// DefaultClientTTL is the default lifetime of a sealed
	// client_id. Set to match refreshTokenTTL so a client holding
	// a still-valid refresh token can always exchange it: a shorter
	// clientTTL would silently kill long-running MCP clients
	// (which treat DCR as one-shot at startup) the moment their
	// access token first expired and they tried to rotate. The
	// operator can override via CLIENT_REGISTRATION_TTL when their
	// deployment needs a different lifetime envelope.
	DefaultClientTTL = 7 * 24 * time.Hour
	// Cap DCR amplification: a client
	// registration bloats the sealed client_id (and any logs/metrics
	// referencing it) in proportion to the submitted redirect_uris. Five
	// URIs of 512 chars each (config.MaxRedirectURILength) is well
	// above any legitimate need.
	maxRedirectURIs     = 5
	maxClientNameLength = 512
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
	// client_id stops opening. It is an RFC 7591 extension field (the
	// spec defines client_secret_expires_at, not client_id_expires_at);
	// we publish it so clients can proactively re-register before hitting
	// a 400 on /authorize once the sealed TTL lapses (default 7d, see
	// clientTTL). Emitted as 0 ("never expires", mirroring §3.2.1
	// client_secret_expires_at) when the operator sets
	// CLIENT_REGISTRATION_TTL=0.
	ClientIDExpiresAt int64    `json:"client_id_expires_at"`
	RedirectURIs      []string `json:"redirect_uris"`
	// ClientName is echoed only when the client actually submitted
	// one — RFC 7591 §3.2.1 MUST return registered metadata but does
	// not require empty values in the response. omitempty keeps the
	// JSON identical for clients that didn't set it.
	ClientName              string `json:"client_name,omitempty"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
}

// RegisterConfig holds the /register settings.
type RegisterConfig struct {
	// ClientTTL is the sealed client_id's lifetime; pass
	// DefaultClientTTL to keep the standard 7-day envelope (aligns with
	// refreshTokenTTL so a client holding a still-valid refresh can
	// always exchange it). 0 = never expires.
	ClientTTL time.Duration
	// RedirectURIsExtra admits operator-listed custom-scheme redirect
	// URIs (REDIRECT_URIS_EXTRA).
	RedirectURIsExtra config.RedirectAllowlist
	// RedirectURIsAllowlist, when set, limits http(s) redirect URIs to
	// the operator's list (REDIRECT_URIS_ALLOWLIST).
	RedirectURIsAllowlist config.WebRedirectAllowlist
}

// Register handles POST /register (RFC 7591 Dynamic Client Registration).
// Client record is encrypted into the client_id itself for stateless operation.
// audience binds the client to a specific proxy deployment.
func Register(tm *token.Manager, logger *zap.Logger, audience string, regCfg RegisterConfig) http.HandlerFunc {
	clientTTL := regCfg.ClientTTL
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
				writeOAuthError(w, r, http.StatusRequestEntityTooLarge, "invalid_request", "request body exceeds the 1 MB cap")
				return
			}
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}
		var trailing any
		if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "invalid JSON body")
			return
		}

		// RFC 7591 §3.2.2: defects on redirect_uris use the dedicated
		// "invalid_redirect_uri" error code; "invalid_request" stays
		// reserved for structural request problems (bad JSON, missing
		// field). Clients switch on these codes to surface the specific
		// defect to the operator.
		if len(req.RedirectURIs) == 0 {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required and must not be empty")
			return
		}

		// M5: hard cap the number of redirect_uris. Without this, an
		// unauthenticated caller can register thousands of URIs and bloat
		// the sealed client_id / logs / metrics indefinitely.
		if len(req.RedirectURIs) > maxRedirectURIs {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris exceeds maximum count")
			return
		}

		// client_name is unauthenticated metadata that is both logged
		// and sealed into the returned client_id. Keep it bounded so
		// /register cannot amplify a large request body into oversized
		// logs and responses.
		if len(req.ClientName) > maxClientNameLength {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_client_metadata", "client_name exceeds maximum length")
			return
		}
		// Reject control bytes (NUL / CR / LF / TAB / etc.), bidi
		// controls and the X-User-Groups delimiter `,`. zap escapes the access-log
		// line so log injection is neutralized at the transport, but
		// the sealed client_id carries the raw bytes — anything
		// downstream that unseals and parses ClientName would
		// inherit them. Mirrors the group-name filter at
		// callback.go (M12). RFC 7591 §2 permits operator-side
		// rejection of metadata; §3.2.2 prescribes the error code.
		if clientNameForbidden(req.ClientName) {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_client_metadata", "client_name must not contain control bytes or commas")
			return
		}

		for _, raw := range req.RedirectURIs {
			if !validateRedirectURI(w, r, logger, raw, regCfg) {
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
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_client_metadata", "unsupported token_endpoint_auth_method; only \"none\" is supported")
			return
		}

		now := time.Now()
		// clientTTL of 0 means "never expires" (CLIENT_REGISTRATION_TTL=0;
		// config rejects negatives, so 0 is the only non-positive value
		// that reaches here): seal the zero time so the validation paths
		// (openAndValidateClient / authorize) skip the expiry check, and
		// emit client_id_expires_at=0 below.
		var expiresAt time.Time
		if clientTTL > 0 {
			expiresAt = now.Add(clientTTL)
		}
		sc := sealedClient{
			ID:           uuid.New().String(),
			RedirectURIs: req.RedirectURIs,
			ClientName:   req.ClientName,
			Typ:          token.PurposeClient,
			Audience:     audience,
			ExpiresAt:    expiresAt,
		}

		clientID, err := tm.SealJSON(sc, token.PurposeClient)
		if err != nil {
			logger.Error("client_seal_failed", zap.Error(err))
			writeOAuthError(w, r, http.StatusInternalServerError, "server_error", "failed to register client")
			return
		}

		metrics.ClientsRegistered.Inc()
		logger.Info("client_registered", zap.String("internal_id", sc.ID), zap.String("client_name", req.ClientName))

		// RFC 7591 examples mark client information responses non-cacheable.
		// Our client_id is a bearer-like registration handle (7d default
		// TTL, or non-expiring when CLIENT_REGISTRATION_TTL=0), so keep it
		// out of shared caches even though POST responses are rarely cached.
		noStore(w.Header())
		// 0 = never expires; zero time must not be rendered via .Unix()
		// (which yields a large negative epoch).
		var clientIDExpiresAt int64
		if !sc.ExpiresAt.IsZero() {
			clientIDExpiresAt = sc.ExpiresAt.Unix()
		}
		writeJSON(w, http.StatusCreated, registerResponse{
			ClientID:                clientID,
			ClientIDIssuedAt:        now.Unix(),
			ClientIDExpiresAt:       clientIDExpiresAt,
			RedirectURIs:            req.RedirectURIs,
			ClientName:              req.ClientName,
			TokenEndpointAuthMethod: authMethod,
		})
	}
}

// checkRegisterRedirectURI applies the redirect URI rules /register
// enforces: shape first, then the operator lists, which narrow
// (REDIRECT_URIS_ALLOWLIST, http(s)) or widen (REDIRECT_URIS_EXTRA,
// custom schemes) the set; RFC 7591 §2 lets the server reject requested
// metadata. u is nil exactly when the shape check failed, so callers can
// tell the error families apart without a sentinel list. Shared with the
// CIMD resolver so a metadata document cannot register a redirect URI
// /register would refuse.
func checkRegisterRedirectURI(raw string, extra config.RedirectAllowlist, allow config.WebRedirectAllowlist) (*url.URL, error) {
	u, err := config.CheckRedirectShape(raw)
	if err != nil {
		return nil, err
	}
	// Non-http(s) schemes only via REDIRECT_URIS_EXTRA.
	if !config.IsWebScheme(u.Scheme) {
		return u, extra.Check(raw)
	}
	if !webRedirectAllowed(raw, allow) {
		return u, errNotInWebAllowlist
	}
	return u, nil
}

// validateRedirectURI writes the RFC 7591 §3.2.2 error and returns
// false when raw is not an acceptable redirect URI.
func validateRedirectURI(w http.ResponseWriter, r *http.Request, logger *zap.Logger, raw string, regCfg RegisterConfig) bool {
	u, err := checkRegisterRedirectURI(raw, regCfg.RedirectURIsExtra, regCfg.RedirectURIsAllowlist)
	switch {
	case u == nil:
		writeRedirectShapeError(w, r, err)
		return false
	case !config.IsWebScheme(u.Scheme):
		return checkCustomRedirect(w, r, err)
	case err != nil:
		// No query, and printable ASCII only: the client chose these bytes.
		logger.Warn("register_redirect_uri_not_allowlisted", zap.String("scheme", u.Scheme),
			zap.String("host", sanitizeErrorDescription(u.Host)), zap.String("path", sanitizeErrorDescription(u.EscapedPath())))
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri is not allowlisted by the operator")
		return false
	}
	return true
}

// writeRedirectShapeError maps a config.CheckRedirectShape error to a
// fixed description (descriptions stay compile-time literals).
func writeRedirectShapeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, config.ErrRedirectTooLong):
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri exceeds maximum length")
	case errors.Is(err, config.ErrRedirectOpaque):
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must not be opaque")
	case errors.Is(err, config.ErrRedirectNoHost):
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must include a host")
	case errors.Is(err, config.ErrRedirectFragment):
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must not contain a fragment")
	case errors.Is(err, config.ErrRedirectUserinfo):
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must not contain userinfo")
	case errors.Is(err, config.ErrRedirectHTTPNotLoopback):
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must use HTTPS for non-loopback addresses")
	case errors.Is(err, config.ErrRedirectMalformed):
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "malformed redirect_uri")
	default: // fail-safe for a sentinel added without its case
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri is not allowed")
	}
}

// checkCustomRedirect maps a RedirectAllowlist.Check result to a fixed
// description (descriptions stay compile-time literals) and returns
// whether the URI is accepted.
func checkCustomRedirect(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, config.ErrRedirectNotAllowlisted):
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must be http (loopback only), https, or a URI allowlisted by the operator")
	case errors.Is(err, config.ErrRedirectNoHostOrPath):
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must include a host or a path")
	case errors.Is(err, config.ErrRedirectForbiddenChar):
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must not contain unencoded spaces, non-ASCII characters, '\"', '<' or '>', or percent-encoded control characters")
	case errors.Is(err, config.ErrRedirectQuerySemicolon):
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri query must not use ';' separators")
	case errors.Is(err, config.ErrRedirectQueryEscape):
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri query contains an invalid percent-escape")
	case errors.Is(err, config.ErrRedirectNonCanonical):
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri must be in canonical form; percent-encode special characters")
	default: // fail-safe for conditions validateRedirectURI checks before Check
		writeOAuthError(w, r, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uri is not allowed")
	}
	return false
}
