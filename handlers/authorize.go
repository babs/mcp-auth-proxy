package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/token"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const sessionTTL = 10 * time.Minute

// AuthorizeConfig holds optional relaxation flags for /authorize.
type AuthorizeConfig struct {
	PKCERequired bool // false = allow clients that omit code_challenge (Cursor, MCP Inspector)
	ResourceURIs []string
	// CompatAllowStateless keeps the legacy behavior of synthesizing a
	// server-side state when the client omits it. Default false — strict
	// mode refuses (400 invalid_request) so a client-side CSRF bug cannot
	// hide behind the proxy. Either way the denial is counted under
	// mcp_auth_access_denied_total{reason="state_missing"} for visibility.
	CompatAllowStateless bool
}

// Authorize handles GET /authorize (OAuth 2.1 PKCE authorization request).
// Session state is encrypted into the IdP state parameter for stateless operation.
func Authorize(tm *token.Manager, logger *zap.Logger, baseURL string, oauth2Cfg *oauth2.Config, authzCfg AuthorizeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if rejectRepeatedParams(w, q,
			"response_type",
			"client_id",
			"redirect_uri",
			"code_challenge",
			"code_challenge_method",
			"state",
		) {
			return
		}

		responseType := q.Get("response_type")
		clientIDStr := q.Get("client_id")
		redirectURI := q.Get("redirect_uri")
		codeChallenge := q.Get("code_challenge")
		codeChallengeMethod := q.Get("code_challenge_method")
		state := q.Get("state")

		if responseType != "code" {
			writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "response_type must be 'code'")
			return
		}

		if clientIDStr == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
			return
		}

		var client sealedClient
		if err := tm.OpenJSON(clientIDStr, &client, token.PurposeClient); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client", "unknown client_id")
			return
		}

		if client.Typ != token.PurposeClient {
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

		// OAuth 2.1 §2.3.1 requires exact match (no prefix/subdomain).
		// RFC 8252 §7.3 relaxes this for loopback redirects: the AS MUST
		// allow any port so native apps using an ephemeral localhost
		// port can authenticate without re-registering on every run.
		// redirectURIMatches implements both.
		validRedirect := false
		for _, uri := range client.RedirectURIs {
			if redirectURIMatches(redirectURI, uri) {
				validRedirect = true
				break
			}
		}
		if !validRedirect {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri does not match registered URIs")
			return
		}

		// RFC 8707 §2/§4: if `resource` is present it must identify a
		// resource this AS serves. We are both AS and RS, so the only
		// valid value is our own baseURL (trailing-slash + default-port
		// insensitive via matchResource). Multiple `resource` values
		// are permitted per RFC 8707 §2; every one must match. Absent
		// `resource` is accepted — not every MCP client sends it.
		//
		// Checked AFTER client_id + redirect_uri so that RFC 6749
		// §4.1.2.1 "redirect errors where the client is known" holds:
		// probing `?resource=…` cannot reveal anything a client doesn't
		// already learn from /.well-known/oauth-authorization-server.
		if resources, ok := q["resource"]; ok {
			for _, res := range resources {
				if !matchAnyResource(res, append([]string{baseURL}, authzCfg.ResourceURIs...)) {
					writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource does not identify this authorization server")
					return
				}
			}
		}

		if codeChallenge != "" {
			if codeChallengeMethod != "S256" {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
				return
			}
			if !validPKCEValue(codeChallenge) {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge must be 43-128 unreserved characters")
				return
			}
		} else if authzCfg.PKCERequired {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge is required")
			return
		}

		// H7: a missing state hides a client-side CSRF bug. Strict mode
		// refuses the request outright; compat mode synthesizes one
		// server-side so legacy clients (MCP Inspector, Cursor) keep
		// working. Either way we count the event so operators can see
		// how many clients still rely on the compat path.
		if state == "" {
			metrics.AccessDenied.WithLabelValues("state_missing").Inc()
			if !authzCfg.CompatAllowStateless {
				logger.Warn("access_denied_state_missing",
					zap.String("client_id", client.ID),
				)
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "state is required")
				return
			}
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
				return
			}
			state = hex.EncodeToString(b)
		}

		// Upstream OIDC nonce (H3): random 32 hex, bound to this session,
		// verified against the id_token at /callback to defend against
		// code-injection with a leaked upstream code.
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
			return
		}
		nonce := hex.EncodeToString(nonceBytes)

		// Server-side PKCE verifier for the upstream authorization request
		// (H3). Decoupled from the downstream (MCP client) PKCE challenge so
		// the proxy always participates in PKCE even when relaxed mode lets
		// a client omit it.
		upstreamVerifier := oauth2.GenerateVerifier()

		// H6: when PKCE_REQUIRED=false and the client omits code_challenge,
		// the proxy mints a downstream PKCE pair itself so the issued
		// authorization code is still anchored to a verifier. Combined with
		// single-use enforcement in the replay store (C3) this keeps a
		// leaked/logged code from being redeemed by another party within TTL.
		// Distinct from upstreamVerifier — mixing them would break the
		// upstream exchange.
		var svrVerifier, svrChallenge, sessionChallenge string
		sessionChallenge = codeChallenge
		if !authzCfg.PKCERequired && codeChallenge == "" {
			svrVerifier = oauth2.GenerateVerifier()
			svrChallenge = ComputePKCEChallenge(svrVerifier)
			sessionChallenge = svrChallenge
		}

		session := sealedSession{
			ClientID:      client.ID,
			RedirectURI:   redirectURI,
			CodeChallenge: sessionChallenge, // client-supplied challenge, or the server-minted one for H6
			OriginalState: state,
			Nonce:         nonce,
			PKCEVerifier:  upstreamVerifier,
			SvrVerifier:   svrVerifier,  // empty unless H6 server-side PKCE kicked in
			SvrChallenge:  svrChallenge, // mirrors sessionChallenge in that case
			Typ:           token.PurposeSession,
			Audience:      baseURL,
			ExpiresAt:     time.Now().Add(sessionTTL),
		}

		internalState, err := tm.SealJSON(session, token.PurposeSession)
		if err != nil {
			logger.Error("session_seal_failed", zap.Error(err))
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal error")
			return
		}

		// Scopes are already set in oauth2Cfg — no override needed
		authURL := oauth2Cfg.AuthCodeURL(internalState,
			oauth2.SetAuthURLParam("response_mode", "query"),
			oauth2.SetAuthURLParam("nonce", nonce),
			oauth2.S256ChallengeOption(upstreamVerifier),
		)

		logger.Debug("idp_redirect", zap.String("internal_client_id", client.ID))
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}
