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
	"github.com/babs/mcp-auth-proxy/token"
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
}

// consentTmpl is the proxy-rendered consent page. Plain HTML, no
// JavaScript, CSP-tight (default-src 'none' from the
// security-headers middleware) — the only interactivity is the two
// submit buttons on the embedded form. Keeping the page free of
// remote subresources also keeps the operator from having to relax
// CSP just to render consent.
var consentTmpl = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>Authorize MCP client</title>
  <style>
    body { font: 16px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif;
           background: #f4f4f5; color: #18181b;
           display: flex; align-items: center; justify-content: center;
           min-height: 100vh; margin: 0; padding: 1.5rem; }
    main { max-width: 32rem; width: 100%; background: #fff;
           border: 1px solid #e4e4e7; border-radius: 0.75rem;
           padding: 2rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    h1 { font-size: 1.25rem; margin: 0 0 1rem; }
    p  { margin: 0 0 0.75rem; }
    dl { margin: 1rem 0; padding: 0.75rem 1rem; background: #f4f4f5;
         border-radius: 0.5rem; }
    dt { font-size: 0.85rem; color: #52525b; margin-top: 0.5rem; }
    dt:first-child { margin-top: 0; }
    dd { margin: 0 0 0.25rem; font-family: ui-monospace, "SFMono-Regular", monospace;
         word-break: break-all; }
    .actions { display: flex; gap: 0.5rem; margin-top: 1.5rem; }
    button { flex: 1; padding: 0.75rem 1rem; font: inherit;
             border-radius: 0.5rem; cursor: pointer; }
    .approve { background: #18181b; color: #fafafa; border: 1px solid #18181b; }
    .deny    { background: #fafafa; color: #18181b; border: 1px solid #d4d4d8; }
    .hint { font-size: 0.85rem; color: #52525b; margin-top: 1rem; }
  </style>
</head>
<body>
<main>
  <h1>Authorize this MCP client?</h1>
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

// renderConsent seals the validated /authorize parameters into a
// sealedConsent token and writes the consent HTML page. The token
// is the only thing carried across the user click — POST /consent
// reopens it, runs the original Phase-3 logic (mint nonce + upstream
// PKCE verifier + sealedSession), and redirects to the IdP.
//
// On a seal failure we redirect the original error envelope back to
// the registered redirect_uri (server_error, RFC 6749 §4.1.2.1)
// rather than rendering a partial page — the client is already
// trusted at this point in the flow.
func renderConsent(w http.ResponseWriter, r *http.Request, tm *token.Manager, logger *zap.Logger, baseURL, resourceName string, consent sealedConsent) {
	consentToken, err := tm.SealJSON(consent, token.PurposeConsent)
	if err != nil {
		logger.Error("consent_seal_failed", zap.Error(err))
		redirectAuthzError(w, r, consent.RedirectURI, consent.OriginalState, "server_error", "internal error", baseURL)
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
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Consent page must not be cached: a back-button replay after a
	// completed flow would re-show the form against a stale (and
	// possibly already-redeemed) consent token.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	// The shared securityHeaders middleware sets `default-src 'none'`
	// which is right for every other public response (JSON / 302 /
	// 4xx) but blocks the consent page's inline <style> block. Relax
	// style-src for this response only; script-src stays default
	// (none) so the page remains JavaScript-free, and frame-ancestors
	// stays none so the consent UI cannot be framed by an attacker
	// origin.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(http.StatusOK)
	if err := consentTmpl.Execute(w, data); err != nil {
		// Body already started — log only.
		logger.Warn("consent_template_execute_failed", zap.Error(err))
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
// approval handler. Mirrors the shape of CallbackConfig — no
// runtime tunables today, kept as a struct so future fields don't
// re-break the constructor signature.
type ConsentConfig struct{}

// Consent handles POST /consent (consent-page approval submit).
//
// Replays /authorize Phase 3 on approval: opens the sealedConsent,
// mints the upstream OIDC nonce and PKCE verifier, seals a
// sealedSession, and 302s to the IdP. The original sealedClient is
// NOT reopened here — the consent blob carries only the inner
// client_id UUID, not the sealed registration handle, so a
// re-validation would have nothing to re-validate against. The
// audience + TTL + AAD-purpose triple binding on the consent blob
// is the integrity check.
//
// On deny: redirects 302 to the user's registered redirect_uri
// with `error=access_denied` per RFC 6749 §4.1.2.1.
//
// CSRF: the sealedConsent itself is the CSRF token (audience- and
// purpose-bound, 5-min TTL). A POST without a valid consent_token
// is rejected.
//
// Replay note: the consent token is NOT integrated with the replay
// store. A given token can be redeemed multiple times within its
// 5-min window. Each Approve mints a fresh sealedSession (different
// nonce / verifier), and the IdP login still has to complete; each
// Deny just emits another error=access_denied to the registered
// redirect_uri. Neither path produces an effect the original user
// couldn't reproduce by clicking again. Wiring single-use through
// the replay store would be belt-and-braces against an attacker
// who exfiltrated the consent token (a stronger compromise than
// this defense addresses) — accepted as a deliberate trade-off.
func Consent(tm *token.Manager, logger *zap.Logger, baseURL string, oauth2Cfg *oauth2.Config, _ ConsentConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

		// Mirrors the /token guard: a sealed consent_token sent via
		// the URL query would end up in access logs, browser history,
		// Referer headers, and any intermediary cache. Reject the
		// request rather than silently accepting via r.ParseForm
		// merging URL and body into r.Form.
		if r.URL.RawQuery != "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "consent endpoint parameters must be in the request body, not the URL query")
			return
		}

		// Discovery advertises no client-auth scheme; an Authorization
		// header on /consent is meaningless and lets a confused
		// client believe the credential was honoured. Mirrors the
		// /token guard.
		if r.Header.Get("Authorization") != "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="consent", error="invalid_client", error_description="this consent endpoint does not authenticate clients"`)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "this consent endpoint does not authenticate clients")
			return
		}

		if err := r.ParseForm(); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeOAuthError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request body exceeds the 1 MB cap")
				return
			}
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
			return
		}
		if rejectRepeatedParams(w, r.Form, "consent_token", "action") {
			return
		}

		consentTokenStr := r.FormValue("consent_token")
		action := r.FormValue("action")
		if consentTokenStr == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "consent_token is required")
			return
		}

		var consent sealedConsent
		if err := tm.OpenJSON(consentTokenStr, &consent, token.PurposeConsent); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "consent token invalid or expired")
			return
		}
		if consent.Typ != token.PurposeConsent {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "consent token invalid or expired")
			return
		}
		if consent.Audience != baseURL {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "consent token bound to a different audience")
			return
		}
		if time.Now().After(consent.ExpiresAt) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "consent token expired")
			return
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
			redirectAuthzError(w, r, consent.RedirectURI, consent.OriginalState, "access_denied", "user declined to authorize this client", baseURL)
			return
		}
		if action != "approve" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "action must be approve or deny")
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
			redirectAuthzError(w, r, consent.RedirectURI, consent.OriginalState, "server_error", "internal error", baseURL)
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
			Typ:           token.PurposeSession,
			Audience:      baseURL,
			Resource:      consent.Resource,
			ExpiresAt:     time.Now().Add(sessionTTL),
		}

		internalState, err := tm.SealJSON(session, token.PurposeSession)
		if err != nil {
			logger.Error("session_seal_failed", zap.Error(err))
			redirectAuthzError(w, r, consent.RedirectURI, consent.OriginalState, "server_error", "internal error", baseURL)
			return
		}

		authURL := oauth2Cfg.AuthCodeURL(internalState,
			oauth2.SetAuthURLParam("response_mode", "query"),
			oauth2.SetAuthURLParam("nonce", nonce),
			oauth2.S256ChallengeOption(upstreamVerifier),
		)

		// Counter + log + redirect together — none of the three can
		// fail (oauth2Cfg.AuthCodeURL is a string-builder,
		// http.Redirect just writes a 302), so the order is
		// observability-only. Keeping increment immediately before
		// the redirect call keeps the funnel-counter semantics
		// unambiguous if a future change introduces failure between
		// these two lines.
		logger.Info("consent_approved",
			zap.String("client_id", consent.ClientID),
			zap.String("client_name", consent.ClientName),
		)
		metrics.ConsentDecisions.WithLabelValues("approved").Inc()
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}
