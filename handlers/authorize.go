package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const sessionTTL = 10 * time.Minute

// AuthorizeConfig holds optional relaxation flags for /authorize.
type AuthorizeConfig struct {
	PKCERequired bool // false = allow clients that omit code_challenge (Cursor, MCP Inspector)
	ResourceURIs []string
	// CanonicalResource is the RFC 8707 resource indicator every
	// issued access + refresh token will be bound to. For the
	// single-mount proxy this is {baseURL}{mountPath}. Sealed into
	// the session at /authorize so the binding is locked BEFORE
	// the upstream IdP round trip — a later code-substitution
	// cannot retarget the issued token to a different mount on a
	// future multi-mount proxy (RFC 8707 §2.2). Empty disables the
	// resource-binding plumbing (legacy / non-MCP callers).
	CanonicalResource string
	// CompatAllowStateless keeps the legacy behavior of synthesizing a
	// server-side state when the client omits it. Default false — strict
	// mode refuses (400 invalid_request) so a client-side CSRF bug cannot
	// hide behind the proxy. Either way the denial is counted under
	// mcp_auth_access_denied_total{reason="state_missing"} for visibility.
	CompatAllowStateless bool
	// RenderConsentPage gates the proxy-side consent screen. When
	// true, /authorize stops after parameter validation, seals the
	// validated request as a sealedConsent, and renders an HTML
	// page that requires an explicit user click before the upstream
	// IdP redirect happens. Closes the silent-issuance phishing
	// path where a malicious DCR client + an active upstream IdP
	// session = a token issued without the user ever seeing the
	// proxy.
	//
	// Production wiring (main.go) defaults this to true via the
	// RENDER_CONSENT_PAGE env var. The struct zero-value is false
	// so tests / callers wiring AuthorizeConfig directly default
	// to the silent-redirect path and opt in explicitly.
	RenderConsentPage bool
	// ResourceName mirrors config.ResourceName so the consent page
	// can show "{ClientName} wants to access {ResourceName}" rather
	// than the raw mount URI when the operator has set a friendly
	// name via MCP_RESOURCE_NAME. Falls back to CanonicalResource
	// when empty.
	ResourceName string
}

// Authorize handles GET /authorize (OAuth 2.1 PKCE authorization request).
// Session state is encrypted into the IdP state parameter for stateless operation.
//
// Error-delivery follows RFC 6749 §4.1.2.1: errors that occur BEFORE
// client_id + redirect_uri are validated render on the AS as JSON
// (the redirect target is not yet trusted, so we cannot bounce to it).
// Once both are validated, every subsequent failure redirects 302 to
// the registered redirect_uri with `error=…&state=…&iss=…` so the
// client never sees a JSON body it can't correlate. The function flow
// reflects this split: client/redirect validation is deliberately
// front-loaded above the response_type / resource / PKCE / state
// checks.
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

		// OIDC params the proxy doesn't forward upstream are silently
		// dropped. Log at debug so an operator who notices a client
		// trying `prompt=none` (SSO-silent flow) or other forwarding-
		// dependent params can decide whether to add explicit support
		// before the client UX gets confused. Pure observability —
		// no behaviour change.
		logUnknownOIDCParams(logger, q)

		// === Phase 1: validate client_id + redirect_uri (JSON on failure). ===
		// Per RFC 6749 §4.1.2.1, an unauthenticated redirect target must
		// not receive an `error=` redirect — we'd be forwarding to whatever
		// host an attacker chose. JSON 400 keeps these errors visible to
		// the resource owner instead.
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

		// === Phase 2: redirect-uri is trusted. RFC 6749 §4.1.2.1 ===
		// requires §4.1.2.1 redirect-style errors from here on. The
		// `state` we forward is whatever the client sent (possibly "");
		// we MUST NOT synthesize one for the error path because doing so
		// would lie to the client about CSRF binding.

		if responseType != "code" {
			redirectAuthzError(w, r, redirectURI, state, "unsupported_response_type", "response_type must be 'code'", baseURL)
			return
		}

		// RFC 8707 §2/§4: if `resource` is present it must identify a
		// resource this AS serves. We are both AS and RS, so valid
		// values are our baseURL (trailing-slash + default-port
		// insensitive via matchResource) and the per-mount resource
		// URI. Multiple `resource` values are permitted per §2; every
		// one must match.
		if resources, ok := q["resource"]; ok {
			for _, res := range resources {
				if !matchAnyResource(res, append([]string{baseURL}, authzCfg.ResourceURIs...)) {
					redirectAuthzError(w, r, redirectURI, state, "invalid_target", "resource does not identify this authorization server", baseURL)
					return
				}
			}
		}

		if codeChallenge != "" {
			if codeChallengeMethod != "S256" {
				redirectAuthzError(w, r, redirectURI, state, "invalid_request", "code_challenge_method must be S256", baseURL)
				return
			}
			if !validPKCEValue(codeChallenge) {
				redirectAuthzError(w, r, redirectURI, state, "invalid_request", "code_challenge must be 43-128 unreserved characters", baseURL)
				return
			}
		} else if authzCfg.PKCERequired {
			redirectAuthzError(w, r, redirectURI, state, "invalid_request", "code_challenge is required", baseURL)
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
				// state was already empty; redirect carries error+iss
				// without state so the strict-mode rejection is still
				// visible to the registered redirect_uri.
				redirectAuthzError(w, r, redirectURI, "", "invalid_request", "state is required", baseURL)
				return
			}
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				redirectAuthzError(w, r, redirectURI, "", "server_error", "internal error", baseURL)
				return
			}
			state = hex.EncodeToString(b)
		}

		// Consent-page fork (default path; bypassed only when the
		// operator sets RENDER_CONSENT_PAGE=false). All /authorize
		// parameters have been validated, but the upstream IdP
		// redirect MUST NOT happen yet — the user has to see and
		// approve a proxy-rendered page first. Seal the validated
		// shape into a short-lived sealedConsent and hand it to
		// the consent renderer. The remainder of /authorize
		// (nonce, upstream PKCE verifier, sealedSession, IdP
		// redirect) replays from POST /consent on approval.
		if authzCfg.RenderConsentPage {
			renderConsent(w, r, tm, logger, baseURL, authzCfg.ResourceName, sealedConsent{
				// Per-render JTI: a fresh id every GET /authorize so
				// back-button = re-consent (each render gets its own
				// single-use claim slot) rather than dead-state errors.
				JTI:                   uuid.New().String(),
				ClientID:              client.ID,
				ClientName:            client.ClientName,
				RedirectURI:           redirectURI,
				OriginalState:         state,
				CodeChallenge:         codeChallenge,
				SvrChallengeRequested: !authzCfg.PKCERequired && codeChallenge == "",
				Resource:              authzCfg.CanonicalResource,
				Typ:                   token.PurposeConsent,
				Audience:              baseURL,
				ExpiresAt:             time.Now().Add(consentTTL),
			})
			return
		}

		// Upstream OIDC nonce (H3): random 32 hex, bound to this session,
		// verified against the id_token at /callback to defend against
		// code-injection with a leaked upstream code.
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			redirectAuthzError(w, r, redirectURI, state, "server_error", "internal error", baseURL)
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
			SessionID:     uuid.New().String(),
			Typ:           token.PurposeSession,
			Audience:      baseURL,
			Resource:      authzCfg.CanonicalResource,
			ExpiresAt:     time.Now().Add(sessionTTL),
		}

		internalState, err := tm.SealJSON(session, token.PurposeSession)
		if err != nil {
			logger.Error("session_seal_failed", zap.Error(err))
			redirectAuthzError(w, r, redirectURI, state, "server_error", "internal error", baseURL)
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

// knownOIDCAuthorizeParams enumerates query parameters this proxy
// recognises on /authorize. Anything outside the set is silently
// dropped (the proxy does not forward arbitrary OIDC params upstream
// today). Listed by name so logUnknownOIDCParams emits one debug
// line per drop — operators get a signal when a client tries
// `prompt=none` or similar before the missing-forwarding bites them.
var knownOIDCAuthorizeParams = map[string]struct{}{
	"response_type":         {},
	"client_id":             {},
	"redirect_uri":          {},
	"code_challenge":        {},
	"code_challenge_method": {},
	"state":                 {},
	"resource":              {},
	"scope":                 {},
}

// commonOIDCExtensionParams lists OIDC extension parameters the
// proxy explicitly recognises as "known but not forwarded" so the
// debug log distinguishes "client used a real OIDC param we
// dropped" from "client sent a typo". Keeps the log line useful as
// an operator signal rather than noise.
var commonOIDCExtensionParams = map[string]struct{}{
	"prompt":        {},
	"id_token_hint": {},
	"login_hint":    {},
	"acr_values":    {},
	"claims":        {},
	"display":       {},
	"ui_locales":    {},
	"max_age":       {},
	"request":       {},
	"request_uri":   {},
	"nonce":         {},
}

func logUnknownOIDCParams(logger *zap.Logger, q url.Values) {
	for name := range q {
		if _, known := knownOIDCAuthorizeParams[name]; known {
			continue
		}
		category := "unknown"
		if _, ext := commonOIDCExtensionParams[name]; ext {
			category = "oidc_extension_not_forwarded"
		}
		logger.Debug("authorize_param_dropped",
			zap.String("param", name),
			zap.String("category", category),
		)
	}
}
