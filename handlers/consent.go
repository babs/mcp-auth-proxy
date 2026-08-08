package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/replay"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// consentTTL bounds how long a sealedConsent stays usable.
//
// 5 minutes is enough for a real human to read the page, glance at
// the redirect host, and click — and short enough that a stolen
// blob (which can only redirect to the registered redirect_uri the
// user just saw, not an attacker-chosen one) has minimal residual
// value.
const consentTTL = 5 * time.Minute

// consentPageData is the model passed to the embedded HTML template.
// All fields go through html/template's contextual escaping so an
// attacker-supplied client_name (already control-byte-filtered at
// DCR time but accepted as arbitrary printable bytes) cannot inject
// markup or scripts.
type consentPageData struct {
	ClientName     string
	ResourceName   string
	RedirectHost   string
	ResourceURI    string
	ConsentToken   string
	ApproveURL     string
	HasClientName  bool
	HasResourceURI bool
	// ReplayNotice is set when this render replaces a rejected
	// replayed submit — the user sees why they are being asked again.
	ReplayNotice bool
}

// consentTmpl is the proxy-rendered consent page. Plain HTML, no
// JavaScript, CSP-tight (consentPageCSP, set self-contained by
// renderConsent — it overrides the security-headers middleware
// baseline) — the only interactivity is the two submit buttons on
// the embedded form. Keeping the page free of remote subresources
// also keeps the operator from having to relax CSP just to render
// consent.
var consentTmpl = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>Authorize MCP client</title>
  <style>` + consentPageStyle + `</style>
</head>
<body>
<main>
  <h1>Authorize this MCP client?</h1>
  {{if .ReplayNotice}}
  <p class="notice">Your previous response was already processed. If you
  want to authorize this client again, please confirm below.</p>
  {{end}}
  {{if .HasClientName}}
  <p><strong>{{.ClientName}}</strong> is requesting access to {{if .ResourceName}}<strong>{{.ResourceName}}</strong>{{else}}this MCP service{{end}}.</p>
  {{else}}
  <p>An MCP client is requesting access to {{if .ResourceName}}<strong>{{.ResourceName}}</strong>{{else}}this MCP service{{end}}. The client did not provide a registered name.</p>
  {{end}}

  <dl>
    <dt>Will redirect to</dt>
    <dd>{{.RedirectHost}}</dd>
    {{if .HasResourceURI}}
    <dt>Resource</dt>
    <dd>{{.ResourceURI}}</dd>
    {{end}}
  </dl>

  <p class="hint">
    Approving redirects you to your identity provider to sign in. If
    you did not initiate this request, deny.
  </p>

  <form method="POST" action="{{.ApproveURL}}">
    <input type="hidden" name="consent_token" value="{{.ConsentToken}}">
    {{/* Deny button first by deliberate choice: pressing Enter inside
         the form submits via the first button, so an accidental Enter
         denies rather than grants. Don't reorder for visual prominence
         without thinking through the safe-default consequence. */}}
    <div class="actions">
      <button class="deny"    type="submit" name="action" value="deny">Deny</button>
      <button class="approve" type="submit" name="action" value="approve">Approve &amp; sign in</button>
    </div>
  </form>
</main>
</body>
</html>
`))

// navInterstitialTmpl carries the user from a /consent form POST to
// the next location: the IdP authorize URL on approve, the client
// redirect_uri error envelope on deny / server error.
//
// WHY a 200 page instead of a 302: Chromium enforces the consent
// page's form-action directive against EVERY hop of the redirect
// chain a form submit initiates (CSP §6.5 "form submission" check,
// "navigate" algorithm; Firefox and Safari check only the immediate
// action= URL). With a live IdP session the chain runs POST /consent
// → IdP authorize → /callback → client redirect_uri → any further
// redirects the CLIENT performs (e.g. Power Platform's
// global.consent.azure-apim.net hops onward to a regional UI
// origin). Those client-side hops are unknowable in advance, so no
// form-action source list can ever be complete — enumerating origins
// (#33 IdP extras, #35 redirect_uri) was whack-a-mole. Terminating
// the form navigation at this same-origin 200 ends form-action
// enforcement; the meta refresh then starts a regular navigation
// that form-action does not govern. Meta refresh needs no
// JavaScript, so script-src stays 'none'.
//
// {{.URL}} in the content attribute relies on the upstream
// builders for `;`-safety: html/template HTML-escapes the
// attribute (quotes, <, &) but leaves `;` raw, and the meta-refresh
// parse algorithm takes everything after "url=" as the URL — safe
// because both producers (oauth2Cfg.AuthCodeURL, authzErrorURL's
// q.Encode) percent-encode `;` in query values.
var navInterstitialTmpl = template.Must(template.New("nav").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="refresh" content="0;url={{.URL}}">
  <title>Continuing&hellip;</title>
  <style>` + navInterstitialStyle + `</style>
</head>
<body>
<p>Continuing&hellip; If you are not redirected automatically,
<a href="{{.URL}}">click here</a>.</p>
</body>
</html>
`))

// renderNavInterstitial answers a /consent form POST with the
// same-origin chain-breaking page described on navInterstitialTmpl.
func renderNavInterstitial(w http.ResponseWriter, r *http.Request, logger *zap.Logger, targetURL string) {
	// The target URL embeds a single-use sealed session (approve) or
	// the client's error envelope — renderHTMLPage marks it no-store.
	if err := renderHTMLPage(w, "interstitial", http.StatusOK, navInterstitialCSP, navInterstitialTmpl, struct{ URL string }{targetURL}); err != nil {
		logger.Warn("nav_interstitial_execute_failed", zap.Error(err))
		writeOAuthError(w, r, http.StatusInternalServerError, "server_error", "internal error", codeInterstitialFailed)
	}
}

// consentNavError delivers redirectAuthzError's RFC 6749 §4.1.2.1
// error envelope through the interstitial. Responses to the consent
// form POST must not 302 cross-origin — Chromium would block the
// redirect against the consent page's form-action 'self'. Same
// parse-failure fallback as redirectAuthzError: a proxy-hosted error
// response, negotiated (JSON, or the page on a browser-facing route).
func consentNavError(w http.ResponseWriter, r *http.Request, logger *zap.Logger, consent sealedConsent, errCode, errDesc, audience string) {
	target, err := authzErrorURL(consent.RedirectURI, consent.OriginalState, errCode, errDesc, audience)
	if err != nil {
		writeOAuthError(w, r, http.StatusBadRequest, errCode, errDesc, codeRedirectURIMalformed)
		return
	}
	renderNavInterstitial(w, r, logger, target)
}

// renderConsent seals the validated /authorize parameters into a
// sealedConsent token and writes the consent HTML page. The token
// is the only thing carried across the user click — POST /consent
// reopens it, runs the original Phase-3 logic (mint nonce + upstream
// PKCE verifier + sealedSession), and redirects to the IdP.
//
// On a seal failure we deliver the error envelope to the registered
// redirect_uri (server_error, RFC 6749 §4.1.2.1) via the
// interstitial rather than rendering a partial page — the client is
// already trusted at this point in the flow. The interstitial (not
// a 302) because this renderer also answers the POST /consent
// replay path, where a cross-origin redirect would trip form-action.
//
// replayNotice=true adds the "previous response already processed"
// banner — set only by the POST /consent replay re-render; the
// GET /authorize first render passes false.
func renderConsent(w http.ResponseWriter, r *http.Request, tm *token.Manager, logger *zap.Logger, baseURL, resourceName string, consent sealedConsent, replayNotice bool) {
	consentToken, err := tm.SealJSON(consent, token.PurposeConsent)
	if err != nil {
		logger.Error("consent_seal_failed", zap.Error(err))
		consentNavError(w, r, logger, consent, "server_error", "internal error", baseURL)
		return
	}

	host := redirectHost(consent.RedirectURI)
	data := consentPageData{
		ClientName:     consent.ClientName,
		HasClientName:  consent.ClientName != "",
		ResourceName:   resourceName,
		ResourceURI:    consent.Resource,
		HasResourceURI: consent.Resource != "" && resourceName == "",
		RedirectHost:   host,
		ConsentToken:   consentToken,
		ApproveURL:     baseURL + "/consent",
		ReplayNotice:   replayNotice,
	}

	// Consent page must not be cached: a back-button replay after a
	// completed flow would re-show the form against a stale (and
	// possibly already-redeemed) consent token — renderHTMLPage marks
	// it no-store.
	//
	// The shared securityHeaders middleware sets `default-src 'none'`
	// which is right for every other public response (JSON / 302 /
	// 4xx) but blocks the consent page's inline <style> block. Relax
	// style-src for this response only; script-src stays default
	// (none) so the page remains JavaScript-free, and frame-ancestors
	// stays none so the consent UI cannot be framed by an attacker
	// origin. form-action is 'self'-only — the POST is answered by
	// the same-origin interstitial, see consentPageCSP.
	if err := renderHTMLPage(w, "consent", http.StatusOK, consentPageCSP, consentTmpl, data); err != nil {
		logger.Error("consent_template_execute_failed", zap.Error(err))
		consentNavError(w, r, logger, consent, "server_error", "internal error", baseURL)
	}
}

// redirectHost returns the host[:port] component of a redirect URI
// for the consent page's "Will redirect to" line. The full URI is
// not shown because the path/query are noise for the user's trust
// decision — the registered host is what matters. Falls back to the
// raw input on parse failure (the URI was already validated at DCR
// time, so a parse failure here is an invariant breach worth
// surfacing rather than hiding behind an empty string).
func redirectHost(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Host == "" {
		return redirectURI
	}
	return u.Host
}

// ConsentConfig holds optional dependencies for the consent
// approval handler. Mirrors the shape of CallbackConfig.
type ConsentConfig struct {
	// ReplayStore, when non-nil, enforces single-use semantics on the
	// consent token's JTI: a captured consent_token can be POSTed at
	// most once. nil = stateless fallback (configured opt-out — the
	// token is still audience- and TTL-bound).
	ReplayStore replay.Store
	// ResourceName mirrors the AuthorizeConfig field of the same
	// name. Needed because a detected replay re-renders the consent
	// page (fresh JTI) instead of returning a dead-end 400.
	ResourceName string
}

// Consent handles POST /consent (consent-page approval submit).
//
// Replays /authorize Phase 3 on approval: opens the sealedConsent,
// mints the upstream OIDC nonce and PKCE verifier, seals a
// sealedSession, and answers with the navigation interstitial
// targeting the IdP (see renderNavInterstitial for why not a 302).
// The original sealedClient is NOT reopened here — the consent blob
// carries only the inner client_id UUID, not the sealed
// registration handle, so a re-validation would have nothing to
// re-validate against. The audience + TTL + AAD-purpose triple
// binding on the consent blob is the integrity check.
//
// On deny: answers with the interstitial targeting the user's
// registered redirect_uri carrying `error=access_denied` per
// RFC 6749 §4.1.2.1.
//
// CSRF: the sealedConsent itself is the CSRF token (audience- and
// purpose-bound, 5-min TTL). A POST without a valid consent_token
// is rejected.
//
// Replay defense: when ConsentConfig.ReplayStore is wired, the
// consent token's JTI is claimed single-use before either branch
// runs. Each GET /authorize render mints a fresh JTI so the
// back-button case still works (a re-render gets a new claim
// slot); a stolen consent_token can be POSTed at most once. Empty
// JTI (token sealed by an older binary still in flight during
// rollout) falls through to the prior stateless behavior.
//
// A detected replay re-renders the consent page with a fresh JTI
// instead of returning a dead-end 400. This loses nothing: the
// protected action is the approval *decision* (the replayed blob
// never auto-approves — a new explicit click is required), and
// /authorize is unauthenticated, so anyone holding the client's
// authorize URL can obtain a fresh consent page anyway. It fixes
// the back-button / double-submit UX where the user's second
// Approve used to land on a JSON error.
func Consent(tm *token.Manager, logger *zap.Logger, baseURL string, oauth2Cfg *oauth2.Config, cfg ConsentConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

		// Mirrors the /token guard: a sealed consent_token sent via
		// the URL query would end up in access logs, browser history,
		// Referer headers, and any intermediary cache. Reject the
		// request rather than silently accepting via r.ParseForm
		// merging URL and body into r.Form.
		if r.URL.RawQuery != "" {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "consent endpoint parameters must be in the request body, not the URL query", codeConsentQueryParamsForbidden)
			return
		}

		// Discovery advertises no client-auth scheme; an Authorization
		// header on /consent is meaningless and lets a confused
		// client believe the credential was honoured. Mirrors the
		// /token guard.
		// 400, not 401: RFC 7235 §3.1 makes WWW-Authenticate mandatory
		// on every 401, and a challenge here would pop a browser
		// credential dialog on an endpoint that rejects credentials by
		// design. invalid_request fits — the request carries a header
		// it must not.
		if r.Header.Get("Authorization") != "" {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "this consent endpoint does not authenticate clients; retry without the Authorization header", codeConsentAuthHeaderPresent)
			return
		}

		if err := r.ParseForm(); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeOAuthError(w, r, http.StatusRequestEntityTooLarge, "invalid_request", "request body exceeds the 1 MB cap", codeConsentBodyTooLarge)
				return
			}
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "malformed form body", codeConsentFormMalformed)
			return
		}
		if rejectRepeatedParams(w, r, r.Form, "consent_token", "action") {
			return
		}

		consentTokenStr := r.FormValue("consent_token")
		action := r.FormValue("action")
		if consentTokenStr == "" {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "consent token is required", codeConsentTokenMissing)
			return
		}

		var consent sealedConsent
		if err := tm.OpenJSON(consentTokenStr, &consent, token.PurposeConsent); err != nil {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "consent token invalid or expired", codeConsentTokenInvalid)
			return
		}
		if consent.Typ != token.PurposeConsent {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "consent token invalid or expired", codeConsentTokenInvalid)
			return
		}
		if consent.Audience != baseURL {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "consent token bound to a different audience", codeConsentTokenAudienceMismatch)
			return
		}
		if time.Now().After(consent.ExpiresAt) {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "consent token expired", codeConsentTokenExpired)
			return
		}

		// Single-use claim on the consent JTI — applies BEFORE the
		// approve/deny branch so a captured token cannot be replayed
		// for either decision. Mirrors the /token authorization-code
		// claim policy: nil store = stateless fallback (configured
		// opt-out); ErrAlreadyClaimed = 400 + replay metric; other
		// backend errors = fail-closed 503 so we never proceed
		// against an uncertain replay-state result. Empty JTI is the
		// in-flight-rollout fallback (older binary sealed the token
		// before this field existed).
		if cfg.ReplayStore != nil && consent.JTI != "" {
			remaining := max(time.Until(consent.ExpiresAt), time.Second)
			key := replay.NamespacedKey("consent", consent.JTI)
			if err := cfg.ReplayStore.ClaimOnce(r.Context(), key, remaining); err != nil {
				if errors.Is(err, replay.ErrAlreadyClaimed) {
					metrics.ReplayDetected.WithLabelValues("consent").Inc()
					logger.Warn("consent_token_replay",
						zap.String("jti", consent.JTI),
						zap.String("client_id", consent.ClientID),
					)
					// Re-render with a fresh single-use slot rather
					// than a dead-end 400 — the blob is authentic,
					// unexpired and audience-bound (all checked
					// above), only its JTI is spent. The fresh token
					// still requires a new explicit click, so the
					// single-use guarantee on the *decision* holds.
					// ExpiresAt is deliberately NOT refreshed: the
					// consentTTL window counts from the original
					// /authorize render, otherwise replay→re-render
					// cycles would keep a captured blob alive
					// indefinitely.
					consent.JTI = uuid.New().String()
					renderConsent(w, r, tm, logger, baseURL, cfg.ResourceName, consent, true)
					return
				}
				// Reuse the same access_denied{replay_store_unavailable}
				// counter as /token rather than a per-site counter — a
				// Redis outage hits every claim site at once and a single
				// alerting rule on this counter covers all of them.
				logger.Error("replay_store_error", zap.String("op", "claim_consent"), zap.Error(err))
				metrics.AccessDenied.WithLabelValues("replay_store_unavailable").Inc()
				retryAfterReplayStore(w.Header())
				writeOAuthError(w, r, http.StatusServiceUnavailable, "server_error", "replay store unavailable", codeReplayStoreUnavailable)
				return
			}
		}

		if action == "deny" {
			// Counted on a dedicated funnel counter rather than
			// AccessDenied: clicking Deny is a normal expected user
			// action, not a policy rejection — mixing it into the
			// denial taxonomy would noise up alerts wired against
			// actual policy violations.
			metrics.ConsentDecisions.WithLabelValues("denied").Inc()
			logger.Info("consent_denied",
				zap.String("client_id", consent.ClientID),
				zap.String("client_name", consent.ClientName),
			)
			consentNavError(w, r, logger, consent, "access_denied", "user declined to authorize this client", baseURL)
			return
		}
		if action != "approve" {
			writeOAuthError(w, r, http.StatusBadRequest, "invalid_request", "action must be approve or deny", codeConsentActionInvalid)
			return
		}

		// Phase-3 replay. Same shape as the inline /authorize path
		// when RenderConsentPage is false.
		//
		// Upstream OIDC nonce (H3): random 32 hex, bound to this
		// session, verified against the id_token at /callback.
		// Same shape as /authorize so IdP logs see one nonce
		// format for every flow regardless of which path the
		// proxy used.
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			consentNavError(w, r, logger, consent, "server_error", "internal error", baseURL)
			return
		}
		nonce := hex.EncodeToString(nonceBytes)
		// Upstream PKCE verifier — independent of the client's
		// downstream challenge.
		upstreamVerifier := oauth2.GenerateVerifier()

		// H6: regenerate the server-side PKCE pair when the consent
		// blob recorded that /authorize was operating in PKCE-relaxed
		// mode without a client-supplied challenge.
		var svrVerifier, svrChallenge, sessionChallenge string
		sessionChallenge = consent.CodeChallenge
		if consent.SvrChallengeRequested {
			svrVerifier = oauth2.GenerateVerifier()
			svrChallenge = ComputePKCEChallenge(svrVerifier)
			sessionChallenge = svrChallenge
		}

		session := sealedSession{
			ClientID:      consent.ClientID,
			RedirectURI:   consent.RedirectURI,
			CodeChallenge: sessionChallenge,
			OriginalState: consent.OriginalState,
			Nonce:         nonce,
			PKCEVerifier:  upstreamVerifier,
			SvrVerifier:   svrVerifier,
			SvrChallenge:  svrChallenge,
			SessionID:     uuid.New().String(),
			Typ:           token.PurposeSession,
			Audience:      baseURL,
			Resource:      consent.Resource,
			ExpiresAt:     time.Now().Add(sessionTTL),
		}

		internalState, err := tm.SealJSON(session, token.PurposeSession)
		if err != nil {
			logger.Error("session_seal_failed", zap.Error(err))
			consentNavError(w, r, logger, consent, "server_error", "internal error", baseURL)
			return
		}

		authURL := oauth2Cfg.AuthCodeURL(internalState,
			oauth2.SetAuthURLParam("response_mode", "query"),
			oauth2.SetAuthURLParam("nonce", nonce),
			oauth2.S256ChallengeOption(upstreamVerifier),
		)

		// Counter + log + interstitial together — none of the three
		// can fail (oauth2Cfg.AuthCodeURL is a string-builder, the
		// interstitial render only logs on template error), so the
		// order is observability-only. Keeping increment immediately
		// before the render call keeps the funnel-counter semantics
		// unambiguous if a future change introduces failure between
		// these two lines.
		//
		// 200 interstitial, NOT a 302: see navInterstitialTmpl — a
		// redirect here would re-enter Chromium's form-action chain
		// enforcement that the interstitial exists to terminate.
		logger.Info("consent_approved",
			zap.String("client_id", consent.ClientID),
			zap.String("client_name", consent.ClientName),
		)
		metrics.ConsentDecisions.WithLabelValues("approved").Inc()
		renderNavInterstitial(w, r, logger, authURL)
	}
}
