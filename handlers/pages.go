package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"math/rand/v2"
	"net/http"
	"strconv"

	"github.com/babs/mcp-auth-proxy/metrics"
)

// Shared style for the proxy-rendered pages. One source per rule, so a
// cosmetic edit cannot land on two of the three pages and skip the
// third.
const (
	pageBodyCSS = `
    body { font: 16px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif;
           background: #f4f4f5; color: #18181b;
           display: flex; align-items: center; justify-content: center;
           min-height: 100vh; margin: 0; padding: 1.5rem; }`
	pageCardCSS = `
    main { max-width: 32rem; width: 100%; background: #fff;
           border: 1px solid #e4e4e7; border-radius: 0.75rem;
           padding: 2rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
    h1 { font-size: 1.25rem; margin: 0 0 1rem; }
    p  { margin: 0 0 0.75rem; }
    .hint { font-size: 0.85rem; color: #52525b; margin-top: 1rem; }`
)

// Each page's <style> content is addressable so its CSP can name the
// sha256 of exactly what the template embeds — see pageCSP.
const (
	consentPageStyle = pageBodyCSS + pageCardCSS + `
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
    .notice { background: #fef3c7; border: 1px solid #fcd34d; border-radius: 0.5rem;
              padding: 0.75rem 1rem; font-size: 0.9rem; }
  `
	navInterstitialStyle = pageBodyCSS + `
  `
	errorPageStyle = pageBodyCSS + pageCardCSS + `
    .code { font-size: 0.8rem; color: #71717a; margin: 1.5rem 0 0;
            font-family: ui-monospace, "SFMono-Regular", monospace;
            word-break: break-all; }
  `
)

// CSP for the proxy-rendered pages, built from one base so the
// security-critical directives cannot drift apart between pages. Only
// form-action differs: 'self' on the consent page, whose approve/deny
// POST is answered by a same-origin interstitial
// (renderNavInterstitial) rather than a redirect — that terminates
// Chromium's form-action enforcement of the navigation chain, so the
// header never has to enumerate IdP or client origins. The other two
// pages carry no form at all.
//
// style-src names each page's own style hash rather than
// 'unsafe-inline', so injected markup cannot carry styles of its own —
// on the consent page that also means an injected style cannot hide the
// Deny button or overlay the client name. The hash is derived from the
// same constant the template embeds, so the two cannot diverge
// (pinned by TestPageCSPHashMatchesRenderedStyle).
const (
	cspPagePrefix = "default-src 'none'; style-src "
	cspPageSuffix = "; frame-ancestors 'none'; base-uri 'none'"
)

var (
	consentPageCSP     = pageCSP(consentPageStyle, "'self'")
	navInterstitialCSP = pageCSP(navInterstitialStyle, "'none'")
	errorPageCSP       = pageCSP(errorPageStyle, "'none'")
)

func pageCSP(style, formAction string) string {
	return cspPagePrefix + styleHashSource(style) + "; form-action " + formAction + cspPageSuffix
}

// styleHashSource returns the CSP source expression for an inline
// <style> element's exact text content (CSP3 hash-source — CSP2
// defined hashes for scripts only, so a pre-CSP3 browser drops the
// styling and renders the page unstyled but readable).
func styleHashSource(style string) string {
	sum := sha256.Sum256([]byte(style))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// Template escaping resolves on the first Execute, not at Parse, so
// force every page once at startup: an escaping regression then panics
// the deploy instead of surfacing as a first-request failure.
// throttlePage (error_page.go) covers the error page by being rendered
// at init already.
func init() {
	if _, err := executePage(consentTmpl, consentPageData{}); err != nil {
		panic("consent template does not render: " + err.Error())
	}
	if _, err := executePage(navInterstitialTmpl, struct{ URL string }{"https://example.invalid/"}); err != nil {
		panic("interstitial template does not render: " + err.Error())
	}
}

// executePage renders a page template to memory. The body is built
// before any header is committed: html/template does its contextual
// escaping on the first Execute, not at Parse, so a template that
// parses cleanly can still fail here — and committing the status first
// would ship an empty 4xx with no way back. Callers decide what a
// failure means; none of them can un-send a header.
func executePage(tmpl *template.Template, data any) ([]byte, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// renderHTMLPage writes a self-contained proxy-rendered page — see
// executePage for the buffer-before-header constraint.
//
// The failure counter lives here rather than at each call site: with
// three pages sharing this path, a per-caller increment is one a fourth
// page can forget, and the error page was for a while the only one that
// counted at all.
// page names the metric series; passed explicitly rather than taken
// from tmpl.Name() so a swapped template cannot silently relabel it.
func renderHTMLPage(w http.ResponseWriter, page string, status int, csp string, tmpl *template.Template, data any) error {
	body, err := executePage(tmpl, data)
	if err != nil {
		metrics.PageRenderFailed.WithLabelValues(page).Inc()
		return err
	}
	writeHTMLPage(w, status, csp, body)
	return nil
}

// writeHTMLPage ships an already-rendered page. Split out so a caller
// holding a pre-rendered body (the throttle response) shares the exact
// header set rather than growing a second copy of it.
func writeHTMLPage(w http.ResponseWriter, status int, csp string, body []byte) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	noStore(h)
	// A challenge would make the browser pop a credential dialog and
	// discard this body. Dropped for every page, not just the error
	// page: none of them is an authentication prompt.
	h.Del("WWW-Authenticate")
	// Set, not Add: the securityHeaders middleware already wrote a
	// baseline policy, and two Content-Security-Policy headers are
	// intersected by browsers — the inline <style> would be blocked.
	h.Set("Content-Security-Policy", csp)
	w.WriteHeader(status)
	// A write error here means the client went away mid-body.
	_, _ = w.Write(body)
}

// retryAfterReplayStore paces a client past a replay-store outage.
// Jittered: every replica rejects with the same value, so a fixed
// number re-converges the whole rejected population on one instant —
// which is the thundering herd the pacing exists to prevent. The floor
// is the useful wait; the spread is what desynchronises it.
//
// math/rand is deliberate: the jitter carries no secret and guards no
// decision. A caller already controls its own retry timing, so
// predicting the spread buys nothing a caller cannot simply do.
func retryAfterReplayStore(h http.Header) {
	h.Set("Retry-After", strconv.Itoa(5+rand.IntN(6))) //nolint:gosec // G404: herd desynchronisation, not a secret
}

// retryAfterIdPExchange paces a caller past the shared outbound IdP
// bucket. Same jitter rationale, shorter floor: the bucket refills on a
// per-second cadence, so the wait only has to outlast one refill.
func retryAfterIdPExchange(h http.Header) {
	h.Set("Retry-After", strconv.Itoa(2+rand.IntN(3))) //nolint:gosec // G404: herd desynchronisation, not a secret
}

// noStore marks a response uncacheable. Every proxy-rendered page and
// every OAuth error carries flow state (spent single-use tokens,
// expired sessions); an intermediary must never replay one.
func noStore(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}
