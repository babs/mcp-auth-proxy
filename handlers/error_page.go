package handlers

import (
	"html/template"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The two rejection paths no per-endpoint limiter covers: the 429,
// which by definition fires once the bucket is spent, and the 405,
// which chi resolves at router level so route middleware never runs.
// Both bodies are constant for their status, so both are rendered once
// at init — an unbounded path must not cost a template execute per
// request. Package-level, not lazily cached: a lazy cache can be
// poisoned by a test that swaps the template before the first hit.
var (
	throttlePage         = mustRenderPage(http.StatusTooManyRequests, throttleBody)
	methodNotAllowedPage = mustRenderPage(http.StatusMethodNotAllowed, methodNotAllowedBody)
	notFoundPage         = mustRenderPage(http.StatusNotFound, notFoundBody)
)

const (
	throttleDesc         = "rate limit exceeded"
	methodNotAllowedDesc = "this endpoint does not accept that HTTP method"
	notFoundDesc         = "this address does not exist on this service"
)

var (
	throttleBody         = OAuthError{Error: "temporarily_unavailable", ErrorDescription: throttleDesc}
	methodNotAllowedBody = OAuthError{Error: "invalid_request", ErrorDescription: methodNotAllowedDesc, ErrorCode: codeMethodNotAllowed}
	notFoundBody         = OAuthError{Error: "invalid_request", ErrorDescription: notFoundDesc, ErrorCode: codeNotFound}
)

func mustRenderPage(status int, body OAuthError) []byte {
	page, err := renderStaticPage(status, body)
	if err != nil {
		panic("error page template does not render: " + err.Error())
	}
	return page
}

func renderStaticPage(status int, body OAuthError) ([]byte, error) {
	page, err := executePage(errorPageTmpl, newErrorPageData(status, body))
	if err != nil {
		return nil, err
	}
	// cap == len: an append by any caller must copy rather than land in
	// the backing array every in-flight rejection is reading.
	return page[:len(page):len(page)], nil
}

// RateLimitExceeded writes the throttle response for the per-endpoint
// limiters. Exported because the limiters are built in main, and going
// through the shared sink is what keeps a throttled human on the page
// instead of a JSON dead end.
func RateLimitExceeded(w http.ResponseWriter, r *http.Request) {
	// Vary only on the routes that genuinely have two representations,
	// like writeOAuthError: elsewhere (/token, /register, discovery, the
	// MCP mount) this 429 is JSON whatever the request headers say, and
	// advertising negotiation would invite a cache to key on headers
	// that change nothing. Sec-Fetch-Dest joins Accept in the arm choice
	// below, so where it does vary, it varies on both.
	h := w.Header()
	if browserFacing(r) {
		h.Set("Vary", "Accept, Sec-Fetch-Dest")
	}
	// The JSON arm is written directly, NOT via the negotiating sink,
	// which would re-open the page arm on Accept alone.
	if wantsHTMLNavigation(r) {
		writeHTMLPage(w, http.StatusTooManyRequests, errorPageCSP, throttlePage)
		return
	}
	noStore(h)
	writeJSON(w, http.StatusTooManyRequests, throttleBody)
}

// MethodNotAllowed answers a wrong-method request so a browser gets a
// readable page instead of the router's empty body. Exported because
// the router installs it (chi resolves MethodNotAllowed per router, not
// per route) — which is also why it does not go through the negotiating
// sink: at router level no per-route limiter has run, so this shares
// the 429's unbounded-path rules rather than the sink's.
func MethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	if browserFacing(r) {
		h.Set("Vary", "Accept, Sec-Fetch-Dest")
	}
	if wantsHTMLNavigation(r) {
		writeHTMLPage(w, http.StatusMethodNotAllowed, errorPageCSP, methodNotAllowedPage)
		return
	}
	noStore(h)
	writeJSON(w, http.StatusMethodNotAllowed, methodNotAllowedBody)
}

// NotFound answers an unrouted browser-facing path — a mistyped or
// trailing-slash bookmark on /authorize, /consent or /callback, which
// never reaches MethodNotAllowed. Same unbounded-path rules as the 405:
// the router resolves it before any per-route limiter.
func NotFound(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	if browserFacing(r) {
		h.Set("Vary", "Accept, Sec-Fetch-Dest")
	}
	if wantsHTMLNavigation(r) {
		writeHTMLPage(w, http.StatusNotFound, errorPageCSP, notFoundPage)
		return
	}
	noStore(h)
	writeJSON(w, http.StatusNotFound, notFoundBody)
}

// wantsHTMLNavigation is wantsHTML plus the Fetch Metadata signal that
// this is a real top-level navigation. Required on the two rejection
// paths no limiter covers (429, 405): the page is ~16x the JSON body,
// so a spoofed Accept alone must not buy the amplification. It only
// suppresses blind and accidental floods — Sec-Fetch-* is a forbidden
// header for browser JS, not for a raw HTTP client, so an adversary
// sets it freely; the per-IP limiter is the real bound on every path
// that has one.
func wantsHTMLNavigation(r *http.Request) bool {
	return wantsHTML(r) && r.Header.Get("Sec-Fetch-Dest") == "document"
}

// errorPageData is the model passed to errorPageTmpl.
//
// Reason is the JSON body's error_description re-cased for reading (see
// sentence), so there is one source for both responses. It still goes
// through html/template's contextual escaping: sanitizeErrorDescription
// strips control bytes only, so markup would survive it if a future
// call site ever pipes IdP- or config-supplied text through here.
//
// Error and ErrorCode carry the same values under the same names as the
// JSON body's fields (OAuthError), so the two cannot be wired the wrong
// way round without the mismatch being visible.
type errorPageData struct {
	Title     string
	Reason    string
	Hint      string
	Error     string
	ErrorCode string
}

// newErrorPageData is the single place the model is derived from a
// failure, shared by the sink and the pre-rendered throttle page so a
// new field cannot be populated on one and silently zero on the other.
// It takes the wire body rather than loose strings: three adjacent
// string parameters are three chances to swap two of them.
func newErrorPageData(status int, body OAuthError) errorPageData {
	return errorPageData{
		Title:     errorPageTitle(status, body.Error, body.ErrorCode),
		Reason:    sentence(body.ErrorDescription),
		Hint:      errorPageHint(status, body.ErrorCode),
		Error:     body.Error,
		ErrorCode: body.ErrorCode,
	}
}

// errorPageTmpl is the human-facing rendering of an OAuth error.
// Deliberately the same shell as the consent page (no JavaScript, no
// remote subresources) so both browser-facing surfaces stay renderable
// under one locked CSP and the operator never has to relax it.
var errorPageTmpl = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>{{.Title}}</title>
  <style>` + errorPageStyle + `</style>
</head>
<body>
<main>
  <h1>{{.Title}}</h1>
  {{if .Reason}}<p>{{.Reason}}</p>{{end}}
  <p class="hint">{{.Hint}}</p>
  <p class="code">{{.Error}}{{if .ErrorCode}} &middot; {{.ErrorCode}}{{end}}</p>
</main>
</body>
</html>
`))

// sentence turns an error_description into a standalone sentence for
// the page: the descriptions are written lowercase and unterminated for
// the JSON body, and read as a machine dump under a title. One function
// owns the whole transform, so the template never adds punctuation of
// its own. The JSON keeps the literal verbatim.
//
// Rune-wise, not byte-wise: sanitizeErrorDescription drops everything
// outside 0x20..0x7E today, but slicing the first byte would silently
// produce invalid UTF-8 the day that precondition moves.
func sentence(s string) string {
	if s == "" {
		return s
	}
	// Leave an identifier-leading description alone: "Client_id is
	// required." reads worse than the raw literal to the very
	// non-technical reader this page exists for.
	if head, _, _ := strings.Cut(s, " "); !strings.Contains(head, "_") {
		first, size := utf8.DecodeRuneInString(s)
		s = string(unicode.ToUpper(first)) + s[size:]
	}
	if strings.HasSuffix(s, ".") || strings.HasSuffix(s, "!") || strings.HasSuffix(s, "?") {
		return s
	}
	return s + "."
}

// Advice shown under the reason. The default sends the user to their
// administrator, which is wrong for the failures they can clear
// themselves — and those dominate browser traffic.
const (
	hintTransient        = "This is temporary. Wait a moment, then try again."
	hintTransientRestart = "This is temporary. Wait a moment, then go back to the application and try again."
	hintRestart          = "Go back to the application and start again."
	hintReconnect        = "Reconnect this service in your application; if that does not help, contact the administrator of this service and quote the code below."
	hintContact          = "You can close this window. If you believe this is a mistake, contact the administrator of this service and quote the code below."
	hintVerifyEmail      = "Verify your email address with your identity provider, then go back to the application and try again; if it is already verified, contact the administrator of this service and quote the code below."
)

// codeHints maps an error_code to the advice a human gets. Keyed on the
// code, never on the description text: a reworded description must not
// be able to change what a user is told, and a substring rule cannot
// tell "your session expired" (the user restarts) from "client
// registration expired" (only re-registering clears it).
//
// A code absent from this map falls back to hintContact via
// errorPageHint — safe but unhelpful, so give every browser-reachable
// call site a code and a row here.
var codeHints = map[string]string{
	// Dead flow state: starting over mints fresh state.
	codeSessionUnknown:               hintRestart,
	codeSessionExpired:               hintRestart,
	codeSessionAudienceMismatch:      hintRestart,
	codeCallbackParamsMissing:        hintRestart,
	codeCallbackStateReplay:          hintRestart,
	codeConsentTokenMissing:          hintRestart,
	codeConsentTokenInvalid:          hintRestart,
	codeConsentTokenExpired:          hintRestart,
	codeConsentTokenAudienceMismatch: hintRestart,
	// POST /consent request-shape rejections: a restarted flow produces
	// a fresh well-formed submit, so none of these needs an operator.
	codeConsentQueryParamsForbidden: hintRestart,
	codeConsentAuthHeaderPresent:    hintRestart,
	codeConsentBodyTooLarge:         hintRestart,
	codeConsentFormMalformed:        hintRestart,
	codeConsentActionInvalid:        hintRestart,
	codeParameterRepeated:           hintRestart,
	// Wrong method on a browser-facing route: the user reached it by a
	// bookmark or a stale form, so the flow has to start over.
	codeMethodNotAllowed: hintRestart,
	// A mistyped or trailing-slash bookmark: the flow has to start over.
	codeNotFound: hintRestart,
	// The only denial in the set the user clears without an operator.
	codeEmailNotVerified: hintVerifyEmail,
	// The client holds a client_id this proxy will not honour — expired,
	// or minted under a rotated signing key. Reconnecting the service
	// re-runs DCR and fixes both; restarting the flow loops on the same
	// client_id (see the client-registration-expired runbook).
	codeClientRegistrationExpired: hintReconnect,
	codeClientIDUnknown:           hintReconnect,
	// Same stale-registration class, and specs.md groups it with
	// client_registration_expired on one row: a fresh DCR clears it,
	// restarting the flow loops on the same client_id.
	codeClientAudienceMismatch: hintReconnect,
	// The client changed its callback URL while reusing a stored
	// client_id. Re-registering fixes the benign case; the rogue-URI
	// case reaches an operator through the denial metric, not the page.
	codeRedirectURIMismatch: hintReconnect,
	// The callback state is claimed BEFORE the upstream exchange
	// (callback.go), so reloading an idp_exchange_failed URL can only
	// yield callback_state_replay: wait, then restart the flow.
	codeIdPExchangeFailed: hintTransientRestart,
}

// capacityHints reframe the generic "wait" advice for a code that rides
// a capacity status and needs different wording. They must all still
// tell the user to wait — this table changes the framing, never the
// verdict, which is what keeps the capacity rule below intact.
var capacityHints = map[string]string{
	// The /consent 503 leaves the consent token unclaimed, so retrying
	// is genuinely valid — but the user is looking at a form result,
	// where a bare "try again" means a browser re-POST prompt.
	codeReplayStoreUnavailable: hintTransientRestart,
}

// errorPageHint picks the advice for a failure from the status and the
// error_code — the two values the call site states explicitly. A
// capacity status wins over the code's own row: at 429/503 the user has
// to wait regardless of what failed.
func errorPageHint(status int, errorCode string) string {
	if isCapacityStatus(status) {
		if hint, ok := capacityHints[errorCode]; ok {
			return hint
		}
		return hintTransient
	}
	if hint, ok := codeHints[errorCode]; ok {
		return hint
	}
	if isTransient(status, errorCode) {
		return hintTransient
	}
	return hintContact
}

// transientCodes are the failures that clear on their own, keyed like
// restartCodes. 502 is NOT transient by status: the same status covers
// a real IdP outage and two permanent misconfigurations (no id_token in
// the response, signature/issuer/audience mismatch) that no amount of
// waiting fixes — and verification failure can also be the one attack
// signal on this surface, which "wait and retry" would bury.
var transientCodes = map[string]struct{}{
	codeIdPExchangeFailed:      {},
	codeIdPExchangeThrottled:   {},
	codeReplayStoreUnavailable: {},
}

// isTransient reports the failures the user clears by waiting. 429 and
// 503 qualify whatever their code: both mean "capacity", and the
// throttle path carries no error_code of its own.
func isTransient(status int, errorCode string) bool {
	if isCapacityStatus(status) {
		return true
	}
	_, ok := transientCodes[errorCode]
	return ok
}

// isCapacityStatus reports the statuses that mean "wait", whatever the
// error_code: the throttle path carries no code of its own.
func isCapacityStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
}

// errorPageTitle maps a failure to a title a non-technical reader can
// act on. Grouped by what the user should do next, not by status
// family.
//
// 401 deliberately has no case of its own: the only 401 that reaches
// this sink (/token) means "this endpoint does not authenticate clients
// — drop the Authorization header", the opposite of "please
// authenticate". The repo's other 401 — middleware/auth.go's Bearer
// challenge on the proxied MCP route — IS a genuine authentication
// prompt, but it never routes through here.
func errorPageTitle(status int, oauthError, errorCode string) string {
	if isTransient(status, errorCode) {
		return "Temporarily unavailable"
	}
	// server_error is never an authorization decision, whatever status
	// it rides on — the id_token nonce mismatch answers 403 with it,
	// and "Access denied" would tell the user their account was
	// refused when the real cause is a stale or duplicated flow.
	if status >= 500 || oauthError == "server_error" {
		return "Something went wrong"
	}
	if status == http.StatusForbidden {
		return "Access denied"
	}
	return "Authentication request rejected"
}

// wantsHTML reports whether this response should render as a page:
// a browser-terminated route (see BrowserFacing) whose caller asked
// for text/html explicitly.
//
// Only an explicit `text/html` media type counts, so every non-browser
// caller keeps the RFC 6749 JSON body.
//
// The scan is linear in the header's length — each step consumes what
// it scanned — so its cost is bounded by the server's MaxHeaderBytes
// (main.go) and by nothing here. That matters because this runs
// pre-authentication, including on the two rejection paths no limiter
// covers.
//
// A malformed parameter does not disqualify the fragment
// (`text/html;charset` still asks for HTML), which is why the media type
// is taken as the text before `;` rather than parsed.
//
// Splitting is quote-aware: a comma inside a quoted parameter value
// does not separate media types (RFC 9110 §5.6.4), so
// `application/json;profile="a, text/html, b"` is a JSON request.
//
// The only q-value honoured is an explicit q=0 — "not acceptable",
// RFC 9110 §12.4.2. Preference ordering between the two
// representations buys nothing here.
func wantsHTML(r *http.Request) bool {
	if !browserFacing(r) {
		return false
	}
	// Values, not Get: a caller may legally split its preferences over
	// several Accept header lines, and Get would only see the first.
	for _, header := range r.Header.Values("Accept") {
		for header != "" {
			var part string
			part, header = cutOutsideQuotes(header, ',')
			mediaType, params, _ := strings.Cut(part, ";")
			if strings.EqualFold(strings.TrimSpace(mediaType), "text/html") && !refusesMediaType(params) {
				return true
			}
		}
	}
	return false
}

// refusesMediaType reports an explicit q=0 ("not acceptable", RFC 9110
// §12.4.2) among a media type's parameters. Splitting is quote-aware
// like the media-type split: a `;` inside a quoted value is data, and
// treating it as a separator would let `profile="a;q=0;b"` fabricate a
// refusal and drop a real browser to JSON.
func refusesMediaType(params string) bool {
	for params != "" {
		var p string
		p, params = cutOutsideQuotes(params, ';')
		p = strings.TrimSpace(p)
		if len(p) < 3 || (p[0] != 'q' && p[0] != 'Q') || p[1] != '=' {
			continue
		}
		// Any number of zero decimals is still zero; RFC 9110 caps a
		// qvalue at three, but failing open on `q=0.0000` would let a
		// caller force the page past its own explicit refusal.
		v := p[2:]
		if v == "0" || (strings.HasPrefix(v, "0.") && strings.Trim(v[2:], "0") == "") {
			return true
		}
	}
	return false
}

// cutOutsideQuotes splits on the first unquoted occurrence of sep,
// honouring RFC 9110 §5.6.4 quoted strings and their backslash escapes.
// Callers pass ',' to split media types and ';' to split a media type's
// parameters — in both cases a separator inside a quoted value is data,
// so `application/json;profile="a, text/html, b"` stays one JSON type.
func cutOutsideQuotes(header string, sep byte) (part, rest string) {
	inQuote := false
	for i := 0; i < len(header); i++ {
		switch header[i] {
		case '\\':
			if inQuote {
				i++ // quoted-pair: the next byte is data, never a quote
			}
		case '"':
			inQuote = !inQuote
		case sep:
			if !inQuote {
				return header[:i], header[i+1:]
			}
		}
	}
	return header, ""
}

// renderErrorPage writes the human-facing variant of an OAuth error and
// reports whether it did. Status code, and therefore every
// machine-observable outcome, is identical to the JSON variant — only
// the representation differs. false means nothing was written and the
// caller must fall back to JSON.
func renderErrorPage(w http.ResponseWriter, status int, data errorPageData) bool {
	// renderHTMLPage owns the buffer-then-write sequence and the header
	// set (including dropping any WWW-Authenticate challenge, which it
	// does only once the body exists — so a render failure leaves the
	// JSON fallback carrying whatever challenge it arrived with).
	if err := renderHTMLPage(w, "error", status, errorPageCSP, errorPageTmpl, data); err != nil {
		// The sink carries no logger, so renderHTMLPage's counter is
		// what makes a silent every-browser downgrade to JSON visible.
		return false
	}
	return true
}
