package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

// browserAccept is what Chrome/Firefox/Safari send on a top-level
// navigation — the exact shape /callback sees when the IdP redirects
// the human back.
const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"

// reqWithAccept builds a /callback request carrying the given Accept.
func reqWithAccept(accept string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/callback", nil)
	r.Header.Set("Accept", accept)
	return r
}

// browserRoute returns r as the BrowserFacing middleware hands it to a
// handler. Negotiation is gated on that marker, so a test that skips it
// is testing an unrouted request, not the deployed behaviour.
func browserRoute(r *http.Request) *http.Request {
	var routed *http.Request
	BrowserFacing(http.HandlerFunc(func(_ http.ResponseWriter, got *http.Request) {
		routed = got
	})).ServeHTTP(httptest.NewRecorder(), r)
	return routed
}

// denyOnGroup drives /authorize → /callback with an id_token whose
// groups claim misses the allowlist, and returns the /callback
// response. accept is set verbatim on the callback request; empty
// means no Accept header at all (the header-less programmatic caller).
func denyOnGroup(t *testing.T, accept string) *httptest.ResponseRecorder {
	t.Helper()

	tm := newTestTokenManager(t)
	oauth2Cfg := testOAuth2Config()

	encClientID, _ := registerClient(t, tm, []string{"https://app.example.com/callback"})
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {encClientID},
		"redirect_uri":          {"https://app.example.com/callback"},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
		"state":                 {"client-state"},
	}
	rr := httptest.NewRecorder()
	Authorize(tm, zap.NewNop(), testBaseURL, oauth2Cfg, AuthorizeConfig{PKCERequired: true})(
		rr, httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d: %s", rr.Result().StatusCode, rr.Body.String())
	}
	idpURL, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse IdP Location: %v", err)
	}
	state := idpURL.Query().Get("state")
	upstreamNonce := idpURL.Query().Get("nonce")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "up",
			"token_type":   "Bearer",
			"id_token":     "dummy",
		})
	}))
	defer upstream.Close()
	oauth2Cfg.Endpoint.TokenURL = upstream.URL + "/token"

	idTokenJSON, _ := json.Marshal(map[string]any{
		"sub":    "user-sub",
		"groups": []string{"interns"},
		"nonce":  upstreamNonce,
	})
	verifyFunc := func(_ context.Context, _ string) (*oidc.IDToken, error) {
		tok := &oidc.IDToken{Subject: "user-sub", Nonce: upstreamNonce}
		setIDTokenClaims(t, tok, idTokenJSON)
		return tok, nil
	}

	cbReq := httptest.NewRequest(http.MethodGet, "/callback?code=fake&state="+url.QueryEscape(state), nil)
	if accept != "" {
		cbReq.Header.Set("Accept", accept)
	}
	cbRR := httptest.NewRecorder()
	BrowserFacing(CallbackWithVerifyFunc(tm, zap.NewNop(), testBaseURL, oauth2Cfg, verifyFunc,
		CallbackConfig{GroupsClaim: "groups", AllowedGroups: []string{"staff"}})).ServeHTTP(cbRR, cbReq)
	return cbRR
}

// The user lands on /callback in a BROWSER: a group denial must render
// as a readable page, not as the RFC 6749 JSON blob the MCP client
// would have consumed.
func TestCallback_GroupDenialRendersPageForBrowser(t *testing.T) {
	rr := denyOnGroup(t, browserAccept)

	if rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rr.Result().StatusCode, rr.Body.String())
	}
	if ct := rr.Result().Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}

	body := rr.Body.String()
	// Anchored to their markup: a bare "Access denied" also matches the
	// <title>, and a bare "group" matches the reason sentence, so the
	// loose form stays green with the heading or the code line deleted.
	for _, want := range []string{
		"<h1>Access denied</h1>",                                       // status-derived human title
		"<p>User not in any allowed group.</p>",                        // the JSON reason, read as a sentence
		`<p class="code">access_denied &middot; group_not_allowed</p>`, // support code + detail
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not carry %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `"error":`) {
		t.Errorf("page still carries the JSON envelope:\n%s", body)
	}
	// A group denial is not self-clearable: the advice must be the
	// support one, not "start again".
	if !strings.Contains(body, hintContact) {
		t.Errorf("page does not carry the contact advice:\n%s", body)
	}

	// A shared cache must not hand this page to an MCP client, nor
	// replay a terminal flow error to anyone.
	if got := rr.Result().Header.Get("Vary"); got != "Accept" {
		t.Errorf("Vary = %q, want Accept", got)
	}
	if got := rr.Result().Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	assertErrorPageCSP(t, rr.Result().Header.Get("Content-Security-Policy"))
}

// The CSP names a hash of the <style> CONTENT AS RENDERED — a template
// change that alters those bytes (e.g. an action inside the style
// block) would silently unstyle every page while the structural
// assertions stay green. Hash the rendered bytes and compare to the
// served header on both hash-carrying pages.
func TestPageCSPHashMatchesRenderedStyle(t *testing.T) {
	styleRE := regexp.MustCompile(`(?s)<style>(.*?)</style>`)
	hashOf := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}

	m := styleRE.FindStringSubmatch(string(throttlePage))
	if m == nil {
		t.Fatal("no <style> element in the rendered error page")
	}
	if !strings.Contains(errorPageCSP, hashOf(m[1])) {
		t.Errorf("errorPageCSP %q does not name the rendered style content's hash %s — browsers will block the styling", errorPageCSP, hashOf(m[1]))
	}

	rr := httptest.NewRecorder()
	renderNavInterstitial(rr, httptest.NewRequest(http.MethodGet, "/", nil), zap.NewNop(), "https://example.invalid/x")
	m = styleRE.FindStringSubmatch(rr.Body.String())
	if m == nil {
		t.Fatal("no <style> element in the rendered interstitial")
	}
	if got := rr.Result().Header.Get("Content-Security-Policy"); !strings.Contains(got, hashOf(m[1])) {
		t.Errorf("interstitial CSP %q does not name the rendered style content's hash %s", got, hashOf(m[1]))
	}

	// The consent page is where a blocked <style> costs the most: the
	// Approve and Deny buttons are told apart by their styling alone.
	consentBody, err := executePage(consentTmpl, consentPageData{})
	if err != nil {
		t.Fatalf("render consent page: %v", err)
	}
	m = styleRE.FindStringSubmatch(string(consentBody))
	if m == nil {
		t.Fatal("no <style> element in the rendered consent page")
	}
	if !strings.Contains(consentPageCSP, hashOf(m[1])) {
		t.Errorf("consentPageCSP %q does not name the rendered style content's hash %s — browsers will block the styling", consentPageCSP, hashOf(m[1]))
	}
}

// assertErrorPageCSP pins every directive of the error-page CSP with
// literals — not `!= errorPageCSP`, which would pass whatever that
// value becomes. Only the style hash value is derived, from the same
// constant the template embeds (correspondence with the rendered bytes
// pinned by TestPageCSPHashMatchesRenderedStyle), so it cannot be
// pinned literally without breaking on every deliberate CSS edit.
func assertErrorPageCSP(t *testing.T, got string) {
	t.Helper()
	if !strings.HasPrefix(got, "default-src 'none'; style-src 'sha256-") {
		t.Errorf("CSP = %q, want prefix \"default-src 'none'; style-src 'sha256-…\"", got)
	}
	if !strings.HasSuffix(got, "'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'") {
		t.Errorf("CSP = %q, want the locked form-action/frame-ancestors/base-uri suffix", got)
	}
	if strings.Contains(got, "unsafe-inline") {
		t.Errorf("CSP still allows unsafe-inline styles: %q", got)
	}
	if strings.Contains(got, "script-src") {
		t.Errorf("CSP names script-src — the page must stay script-free: %q", got)
	}
}

// /consent is the other browser-terminated endpoint: negotiation lives
// in the shared sink, so a dead consent token must render as a page
// too. Guards against a future handler writing its errors elsewhere.
func TestConsent_InvalidTokenRendersPageForBrowser(t *testing.T) {
	tm := newTestTokenManager(t)
	req := httptest.NewRequest(http.MethodPost, "/consent",
		strings.NewReader(url.Values{"consent_token": {"not-a-sealed-blob"}, "action": {"approve"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", browserAccept)
	rr := httptest.NewRecorder()

	BrowserFacing(Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{})).ServeHTTP(rr, req)

	if rr.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Result().StatusCode, rr.Body.String())
	}
	if ct := rr.Result().Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Authentication request rejected") ||
		!strings.Contains(body, "Consent token invalid or expired") {
		t.Errorf("page does not carry title + reason:\n%s", body)
	}
	// A dead consent token is cleared by starting over, and this is
	// what pins that the error_code actually reaches errorPageHint.
	if !strings.Contains(body, hintRestart) {
		t.Errorf("page does not advise restarting:\n%s", body)
	}
}

// The machine contract is unchanged: same status, same JSON body, for
// every caller that does not explicitly ask for HTML.
func TestCallback_GroupDenialStaysJSONForClients(t *testing.T) {
	cases := []struct{ name, accept string }{
		{"no_accept_header", ""},
		{"wildcard", "*/*"},
		{"json", "application/json"},
		{"mcp_client", "application/json, text/event-stream"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := denyOnGroup(t, tc.accept)

			if rr.Result().StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (same as the HTML variant): %s", rr.Result().StatusCode, rr.Body.String())
			}
			if ct := rr.Result().Header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}
			// Raw, not decoded: decoding into OAuthError would pass a
			// serialization change (a dropped omitempty, a renamed tag)
			// that every MCP client would see on the wire.
			const wantBody = `{"error":"access_denied","error_description":"user not in any allowed group","error_code":"group_not_allowed"}`
			if got := strings.TrimSpace(rr.Body.String()); got != wantBody {
				t.Errorf("body = %s\nwant %s", got, wantBody)
			}
			// Flow-state errors must not be replayed from a cache, on
			// either representation.
			if got := rr.Result().Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
			if got := rr.Result().Header.Get("Pragma"); got != "no-cache" {
				t.Errorf("Pragma = %q, want no-cache", got)
			}
			// Values, not Get: Get hides a duplicated header, and Set
			// vs Add is exactly the regression this pins.
			if vary := rr.Result().Header.Values("Vary"); len(vary) != 1 {
				t.Errorf("got %d Vary headers %q, want exactly 1", len(vary), vary)
			}
			var oe OAuthError
			if err := json.NewDecoder(rr.Body).Decode(&oe); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if oe.Error != "access_denied" {
				t.Errorf("error = %q, want access_denied", oe.Error)
			}
			if oe.ErrorDescription != "user not in any allowed group" {
				t.Errorf("error_description = %q", oe.ErrorDescription)
			}
			if oe.ErrorCode != "group_not_allowed" {
				t.Errorf("error_code = %q, want group_not_allowed", oe.ErrorCode)
			}
			if got := rr.Result().Header.Get("Vary"); got != "Accept" {
				t.Errorf("Vary = %q, want Accept", got)
			}
		})
	}
}

// RFC 6749 §5.2 and RFC 7591 §3.2.2 require these two to answer
// application/json. They are not routed through BrowserFacing, so even
// a caller shouting text/html at them gets the JSON body.
func TestMachineEndpoints_NeverRenderHTML(t *testing.T) {
	tm := newTestTokenManager(t)

	cases := []struct {
		name    string
		request func() *http.Request
		serve   func(http.ResponseWriter, *http.Request)
	}{
		{
			name: "token",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=bogus"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			},
			serve: Token(tm, zap.NewNop(), testBaseURL, time.Time{}, nil, TokenConfig{}),
		},
		{
			name: "register",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{"redirect_uris":[]}`))
				r.Header.Set("Content-Type", "application/json")
				return r
			},
			serve: Register(tm, zap.NewNop(), testBaseURL, time.Hour),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.request()
			req.Header.Set("Accept", browserAccept)
			rr := httptest.NewRecorder()

			tc.serve(rr, req)

			if ct := rr.Result().Header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("Content-Type = %q, want application/json (body: %s)", ct, rr.Body.String())
			}
			var oe OAuthError
			if err := json.NewDecoder(rr.Body).Decode(&oe); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if oe.Error == "" {
				t.Errorf("expected an RFC 6749 error body, got %s", rr.Body.String())
			}
			// One representation by RFC mandate, so no Vary: advertising
			// negotiation here invites a cache to key on an Accept that
			// changes nothing about the response.
			if got := rr.Result().Header.Get("Vary"); got != "" {
				t.Errorf("Vary = %q, want empty on a machine-only endpoint", got)
			}
		})
	}
}

func TestWantsHTML(t *testing.T) {
	cases := []struct {
		accept string
		want   bool
	}{
		{browserAccept, true},
		{"text/html", true},
		{"application/json, text/html", true},
		{" TEXT/HTML ;q=0.9", true}, // media types are case-insensitive
		{"", false},
		{"*/*", false},
		{"application/json", false},
		{"application/json, text/event-stream", false},
		{"text/*", false}, // a range is not an explicit text/html ask
		{"application/xhtml+xml", false},
		{"text/htmlx", false}, // prefix must not match a different type
		{"nottext/html", false},
		// Malformed parameters, deliberately honoured: the caller
		// plainly asked for text/html, and answering JSON because its
		// parameter list is malformed was never the goal. (A strict
		// parser rejects these; we do not use one — see wantsHTML.)
		{"text/html;;q=1", true},
		{"text/html;q=1;q=2", true},
		{"text/html;charset", true},
		// The ONE q-value honoured: an explicit q=0 is "not acceptable"
		// (RFC 9110 §12.4.2) — rendering the page against it would defy
		// the caller. Preference ordering is otherwise ignored.
		{"text/html;q=0", false},
		{"text/html;q=0.0", false},
		{"text/html;charset=utf-8;q=0", false},
		{"text/html;q=0.5", true},
		{"text/html;q=0.000", false},
		{"text/html;q=0, text/html", true}, // a later fragment re-asks
		// A comma inside a quoted parameter is data, not a separator —
		// including when there are several of them.
		{`application/json;profile="a, text/html"`, false},
		{`application/json;profile="x, text/html, y"`, false},
		// A backslash-escaped quote inside the parameter must not end
		// the quoted string and turn the rest into media types. The
		// second form is the one that discriminates: without the escape
		// handling the quote would close and ` + "`text/html`" + ` would be read
		// as a media type.
		{`application/json;profile="a \", text/html", b`, false},
		{`application/json;profile="a\", text/html`, false},
		// An unterminated quoted string swallows the rest of the header
		// — the one behaviour the hand-rolled splitter adds over a
		// naive comma split.
		{`application/json;profile="a, text/html`, false},
	}

	for _, tc := range cases {
		t.Run(tc.accept, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/callback", nil)
			if tc.accept != "" {
				r.Header.Set("Accept", tc.accept)
			}
			if got := wantsHTML(browserRoute(r)); got != tc.want {
				t.Errorf("wantsHTML(%q) = %v, want %v", tc.accept, got, tc.want)
			}
		})
	}

	if wantsHTML(nil) {
		t.Error("wantsHTML(nil) = true, want false")
	}

	// Preferences split over several Accept lines are legal; Header.Get
	// would only ever see the first one.
	t.Run("multiple_accept_headers", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/callback", nil)
		r.Header.Add("Accept", "application/json")
		r.Header.Add("Accept", "text/html")
		if !wantsHTML(browserRoute(r)) {
			t.Error("wantsHTML = false, want true (second Accept line ignored)")
		}
	})

	// A comma inside a quoted parameter does not start a new media type
	// (RFC 9110 §5.6.4); splitting naively would read text/html here.
	t.Run("comma_in_quoted_parameter", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/callback", nil)
		r.Header.Set("Accept", `application/json;profile="a, text/html; b"`)
		if wantsHTML(browserRoute(r)) {
			t.Error("wantsHTML = true, want false (text/html sits inside a quoted parameter)")
		}
	})

	// The route marker, not Accept, is what opens the HTML branch —
	// this is what keeps /token and /register on JSON (RFC 6749 §5.2,
	// RFC 7591 §3.2.2) whatever the caller asks for.
	t.Run("unrouted_request_never_negotiates", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/token", nil)
		r.Header.Set("Accept", browserAccept)
		if wantsHTML(r) {
			t.Error("wantsHTML = true on a request that never passed BrowserFacing")
		}
	})
}

// Descriptions are static literals today, but sanitizeErrorDescription
// strips control bytes only — markup would reach the page intact if the
// template ever stopped escaping.
func TestWriteOAuthError_PageEscapesDescription(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	req.Header.Set("Accept", "text/html")

	writeOAuthError(rr, browserRoute(req), http.StatusForbidden, "access_denied", `<script>alert(1)</script>`)

	body := rr.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("description injected raw markup:\n%s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("expected the description escaped into the page:\n%s", body)
	}
}

// An Authorization header on /consent is rejected 400 on BOTH arms:
// RFC 7235 §3.1 mandates WWW-Authenticate on every 401, and a challenge
// here would pop a browser credential dialog on an endpoint that
// rejects credentials by design — so no 401 and no challenge, ever.
func TestConsent_AuthHeaderRejected_400NoChallenge(t *testing.T) {
	tm := newTestTokenManager(t)

	probe := func(accept string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader("action=approve"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")
		req.Header.Set("Accept", accept)
		rr := httptest.NewRecorder()
		BrowserFacing(Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{})).ServeHTTP(rr, req)
		return rr
	}

	for name, accept := range map[string]string{"browser": browserAccept, "client": "application/json"} {
		rr := probe(accept)
		if rr.Result().StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 — a 401 without a challenge violates RFC 7235 §3.1", name, rr.Result().StatusCode)
		}
		if got := rr.Result().Header.Get("WWW-Authenticate"); got != "" {
			t.Errorf("%s: WWW-Authenticate = %q, want empty", name, got)
		}
	}
}

// A challenge already on the writer must be stripped before a page ships:
// left in place the browser pops a credential dialog and discards the
// body. Asserted on the page arm specifically — the JSON fallback
// deliberately keeps it (TestWriteOAuthError_RenderFailureKeepsChallenge),
// so only this direction covers the deletion.
func TestPageArm_StripsPresetChallenge(t *testing.T) {
	rr := httptest.NewRecorder()
	rr.Header().Set("WWW-Authenticate", `Basic realm="whatever"`)

	writeOAuthError(rr, browserRoute(reqWithAccept(browserAccept)),
		http.StatusBadRequest, "invalid_request", "consent token expired", codeConsentTokenExpired)

	if ct := rr.Result().Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want the page arm", ct)
	}
	if got := rr.Result().Header.Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q, want empty — the challenge hides the page behind a credential dialog", got)
	}
}

// The sink sanitizes before either representation is produced: CR/LF
// would smuggle headers, and a non-ASCII byte would reach the page.
func TestWriteOAuthError_SanitizesDescriptionInBothVariants(t *testing.T) {
	const dirty = "bad\r\ndesc\x00é"

	for _, tc := range []struct{ name, accept string }{
		{"json", "application/json"},
		{"page", browserAccept},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := browserRoute(httptest.NewRequest(http.MethodGet, "/callback", nil))
			req.Header.Set("Accept", tc.accept)
			rr := httptest.NewRecorder()

			writeOAuthError(rr, req, http.StatusForbidden, "access_denied", dirty)

			body := rr.Body.String()
			if strings.ContainsAny(body, "\r\x00") {
				t.Errorf("control bytes survived into the body: %q", body)
			}
			if !utf8.ValidString(body) {
				t.Errorf("body is not valid UTF-8: %q", body)
			}
		})
	}
}

// Each renderer commits its status only after its body exists, so a
// broken template still answers instead of shipping a blank 200.
func TestConsentRenderers_FallBackOnRenderFailure(t *testing.T) {
	t.Run("nav_interstitial", func(t *testing.T) {
		swapTmpl(t, &navInterstitialTmpl, brokenTmpl(t))

		rr := httptest.NewRecorder()
		renderNavInterstitial(rr, httptest.NewRequest(http.MethodGet, "/consent", nil),
			zap.NewNop(), "https://idp.example.com/authorize")

		if rr.Result().StatusCode != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", rr.Result().StatusCode)
		}
		if !strings.Contains(rr.Body.String(), codeInterstitialFailed) {
			t.Errorf("interstitial fallback does not carry its error_code:\n%s", rr.Body.String())
		}
	})

	t.Run("consent_page", func(t *testing.T) {
		swapTmpl(t, &consentTmpl, brokenTmpl(t))

		tm := newTestTokenManager(t)
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
		renderConsent(rr, req, tm, zap.NewNop(), testBaseURL, "",
			sealedConsent{RedirectURI: "https://app.example.com/callback", OriginalState: "s"}, false)

		if rr.Body.Len() == 0 {
			t.Error("empty body after a render failure")
		}
		// The interstitial answers 200 — a committed error status before
		// the fallback body would break the meta-refresh delivery.
		if rr.Result().StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 (the interstitial)", rr.Result().StatusCode)
		}
		// The fallback is the RFC 6749 §4.1.2.1 envelope delivered
		// through the interstitial, not a blank page: the client is
		// already trusted at this point in the flow.
		if body := rr.Body.String(); !strings.Contains(body, "error=server_error") {
			t.Errorf("consent render failure did not deliver the error envelope:\n%s", body)
		}
	})
}

func TestSentence(t *testing.T) {
	cases := map[string]string{
		"user not in any allowed group": "User not in any allowed group.",
		"":                              "", // no reason paragraph at all
		"Already capital":               "Already capital.",
		"403 denied":                    "403 denied.",
		"already ended.":                "Already ended.", // no doubled stop
		"really?":                       "Really?",
		// Identifier-leading descriptions stay verbatim: "Client_id is
		// required." reads worse than the literal.
		"client_id is required":     "client_id is required.",
		"consent_token is required": "consent_token is required.",
		// Scoped to the FIRST word: an underscore later in the sentence
		// must not suppress the capital.
		"user not in allowed_group": "User not in allowed_group.",
		// Rune-wise: byte-slicing the first char would emit invalid UTF-8.
		"élève not allowed": "Élève not allowed.",
	}
	for in, want := range cases {
		if got := sentence(in); got != want {
			t.Errorf("sentence(%q) = %q, want %q", in, got, want)
		}
	}
}

// The advice is the only actionable line on the page. Telling someone
// to call an administrator about a throttle or an expired session is
// worse than saying nothing.
// The throttle answer is the one a real user is most likely to meet.
// main wires it into the rate limiter; this pins the sink's own output.
func TestRateLimitExceeded(t *testing.T) {
	for _, tc := range []struct {
		name, accept, secFetchDest, wantCT string
		browser                            bool
	}{
		// A real navigation carries Sec-Fetch-Dest: document; without
		// it, Accept alone must not buy the amplified page on this
		// unbounded path.
		{"browser", browserAccept, "document", "text/html; charset=utf-8", true},
		{"accept_without_navigation", browserAccept, "", "application/json", true},
		{"spoofed_fetch_dest", browserAccept, "empty", "application/json", true},
		{"client", "application/json", "", "application/json", true},
		{"machine_route", browserAccept, "document", "application/json", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/callback", nil)
			req.Header.Set("Accept", tc.accept)
			if tc.secFetchDest != "" {
				req.Header.Set("Sec-Fetch-Dest", tc.secFetchDest)
			}
			if tc.browser {
				req = browserRoute(req)
			}
			rr := httptest.NewRecorder()

			RateLimitExceeded(rr, req)

			if rr.Result().StatusCode != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want 429", rr.Code)
			}
			if ct := rr.Result().Header.Get("Content-Type"); ct != tc.wantCT {
				t.Errorf("Content-Type = %q, want %q", ct, tc.wantCT)
			}
			if tc.wantCT == "text/html; charset=utf-8" && !strings.Contains(rr.Body.String(), hintTransient) {
				t.Errorf("throttle page does not advise retrying:\n%s", rr.Body.String())
			}
			if tc.wantCT == "application/json" {
				const wantBody = `{"error":"temporarily_unavailable","error_description":"rate limit exceeded"}`
				if got := strings.TrimSpace(rr.Body.String()); got != wantBody {
					t.Errorf("throttle body = %s\nwant %s", got, wantBody)
				}
			}
			// Off a browser-facing route this 429 has exactly one
			// representation, so it must not advertise negotiation —
			// same rule as writeOAuthError.
			wantVary := "Accept, Sec-Fetch-Dest"
			if !tc.browser {
				wantVary = ""
			}
			if got := rr.Result().Header.Get("Vary"); got != wantVary {
				t.Errorf("Vary = %q, want %q", got, wantVary)
			}
		})
	}
}

// The page must survive the production middleware chain: securityHeaders
// writes a baseline CSP first, so an Add instead of a Set would ship two
// policies, which browsers intersect — the inline <style> would be
// blocked and every proxy-rendered page would lose its styling.
func TestErrorPage_OverridesSecurityHeadersBaseline(t *testing.T) {
	baseline := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
			next.ServeHTTP(w, r)
		})
	}
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	req.Header.Set("Accept", browserAccept)
	rr := httptest.NewRecorder()

	baseline(BrowserFacing(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeOAuthError(w, r, http.StatusForbidden, "access_denied", "user not in any allowed group", codeGroupNotAllowed)
	}))).ServeHTTP(rr, req)

	csp := rr.Result().Header.Values("Content-Security-Policy")
	if len(csp) != 1 {
		t.Fatalf("got %d Content-Security-Policy headers %q, want exactly 1 — browsers intersect them", len(csp), csp)
	}
	assertErrorPageCSP(t, csp[0])
	if vary := rr.Result().Header.Values("Vary"); len(vary) != 1 || vary[0] != "Accept" {
		t.Errorf("Vary = %q, want exactly one \"Accept\"", vary)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"<title>Access denied</title>",
		`<meta name="referrer" content="no-referrer">`,
		pageBodyCSS,
		pageCardCSS,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

// Zero-allocation scan: AllocsPerRun pins the runtime for its duration,
// so a regression to strings.Split — which allocates a slice holding the
// whole header — shows up here as a non-zero count.
func TestWantsHTML_ScanIsAllocationFree(t *testing.T) {
	shapes := map[string]string{
		"browser":      browserAccept,
		"many_commas":  strings.Repeat(",", 4000) + "text/html",
		"quoted_junk":  `application/json;profile="` + strings.Repeat("a,", 2000) + `"`,
		"padded_junk":  strings.Repeat("application/json;x="+strings.Repeat("y", 200)+",", 40) + "text/html",
		"no_separator": strings.Repeat("z", 8000),
	}
	for name, accept := range shapes {
		t.Run(name, func(t *testing.T) {
			r := browserRoute(httptest.NewRequest(http.MethodGet, "/callback", nil))
			r.Header.Set("Accept", accept)
			if n := testing.AllocsPerRun(50, func() { wantsHTML(r) }); n != 0 {
				t.Errorf("wantsHTML allocated %v times, want 0", n)
			}
		})
	}
}

// The scan has no fragment-count or fragment-length bound of its own —
// MaxHeaderBytes is the bound (main.go), and each step consumes what it
// scanned, so the work is linear in the header. These are the inputs a
// count-based cap used to answer differently; a real browser sending a
// long preference list must still get its page.
func TestWantsHTML_NoCountOrLengthCap(t *testing.T) {
	cases := []struct {
		name   string
		accept string
		want   bool
	}{
		{"text_html_past_any_plausible_cap", strings.Repeat("application/json,", 200) + "text/html", true},
		{"text_html_after_padded_fragments", strings.Repeat("application/json;x="+strings.Repeat("y", 300)+",", 40) + "text/html", true},
		{"over_long_fragment_still_counts", "text/html;x=" + strings.Repeat("y", 4000), true},
		{"still_no_false_positive", strings.Repeat("application/json,", 200) + "application/xml", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := browserRoute(httptest.NewRequest(http.MethodGet, "/callback", nil))
			r.Header.Set("Accept", tc.accept)
			if got := wantsHTML(r); got != tc.want {
				t.Errorf("wantsHTML = %v, want %v", got, tc.want)
			}
		})
	}
}

// The real ceiling, asserted where it lives: a header at the server's
// MaxHeaderBytes limit must stay cheap. Fails loudly if the scan ever
// becomes super-linear — a quadratic scan on 16 KB is milliseconds, not
// microseconds.
func TestWantsHTML_WorstCaseAtHeaderCeiling(t *testing.T) {
	const maxHeaderBytes = 16 << 10
	worst := map[string]string{
		"quoted_commas": `application/json;profile="` + strings.Repeat("a,", maxHeaderBytes/2-20) + `"`,
		"all_semis":     "text/html;" + strings.Repeat("q=0.5;", maxHeaderBytes/6-10),
		"all_commas":    strings.Repeat(",", maxHeaderBytes-16) + "text/html",
	}
	for name, accept := range worst {
		t.Run(name, func(t *testing.T) {
			if len(accept) > maxHeaderBytes {
				t.Fatalf("probe header is %d bytes, over the %d ceiling it models", len(accept), maxHeaderBytes)
			}
			r := browserRoute(httptest.NewRequest(http.MethodGet, "/callback", nil))
			r.Header.Set("Accept", accept)
			start := time.Now()
			for range 100 {
				wantsHTML(r)
			}
			if el := time.Since(start); el > time.Second {
				t.Errorf("100 scans of a %d-byte header took %v — the scan is not linear", len(accept), el)
			}
		})
	}
}

func TestWriteOAuthError_VaryIsSetNotAdded(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)

	writeOAuthError(rr, req, http.StatusBadRequest, "invalid_request", "first")
	// Second pass on the HTML arm, so both branches are covered.
	writeOAuthError(rr, browserRoute(reqWithAccept(browserAccept)), http.StatusBadRequest, "invalid_request", "second")

	// The live map here, deliberately: Result() snapshots at the first
	// WriteHeader and would hide the accumulation this test is about.
	if vary := rr.Header().Values("Vary"); len(vary) != 1 {
		t.Errorf("got %d Vary headers %q, want exactly 1", len(vary), vary)
	}
}

// tmplSwapMu serializes package-template swaps. The templates are shared
// process state, so a t.Parallel() added to any test in this package
// would make the swappers race; taking a real lock turns that into an
// obvious deadlock or serialization instead of a rare flake.
var tmplSwapMu sync.Mutex

// swapTmpl replaces a package-level template for one test and restores
// it afterwards.
func swapTmpl(t *testing.T, dst **template.Template, tmpl *template.Template) {
	t.Helper()
	tmplSwapMu.Lock()
	original := *dst
	*dst = tmpl
	t.Cleanup(func() {
		*dst = original
		tmplSwapMu.Unlock()
	})
}

// brokenTmpl parses cleanly and fails at Execute — html/template does
// its contextual escaping on first Execute, which is the failure shape
// a bad edit actually produces.
func brokenTmpl(t *testing.T) *template.Template {
	t.Helper()
	return template.Must(template.New("broken").Parse(`{{if .Nope}}<a href="{{end}}{{.Nope}}`))
}

// The pre-rendered throttle body is the anti-amplification defence for
// the one path where rejections are unbounded; without this, deleting
// the cache or serving an empty body is invisible.
func TestThrottlePage_RenderedOnceAtInit(t *testing.T) {
	if len(throttlePage) == 0 {
		t.Fatal("throttlePage is empty — the 429 fast path serves nothing")
	}
	body := string(throttlePage)
	for _, want := range []string{
		"<h1>Temporarily unavailable</h1>",
		"<p>Rate limit exceeded.</p>",
		`<p class="code">temporarily_unavailable</p>`,
		hintTransient,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("throttle page missing %q:\n%s", want, body)
		}
	}
	// Serving it must not re-render: the whole point of the pre-render.
	req := browserRoute(reqWithAccept(browserAccept))
	req.Header.Set("Sec-Fetch-Dest", "document")
	if allocs := testing.AllocsPerRun(50, func() {
		RateLimitExceeded(httptest.NewRecorder(), req)
	}); allocs > 20 {
		t.Errorf("RateLimitExceeded allocated %v times — the page is being re-rendered", allocs)
	}
}

// The throttle page is written outside writeOAuthError, so it shares
// none of the sink's assertions — its CSP in particular. The page arm
// additionally requires Sec-Fetch-Dest: document (a real top-level
// navigation): the 429 path is unbounded, and a spoofed Accept alone
// must not buy the ~16x body amplification.
func TestRateLimitExceeded_PageHeaders(t *testing.T) {
	req := browserRoute(reqWithAccept(browserAccept))
	req.Header.Set("Sec-Fetch-Dest", "document")
	rr := httptest.NewRecorder()
	RateLimitExceeded(rr, req)

	assertErrorPageCSP(t, rr.Result().Header.Get("Content-Security-Policy"))
	for h, want := range map[string]string{
		"Content-Type":  "text/html; charset=utf-8",
		"Cache-Control": "no-store",
		"Pragma":        "no-cache",
		"Vary":          "Accept, Sec-Fetch-Dest",
	} {
		if got := rr.Result().Header.Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}

	// Accept alone — no navigation signal — must stay on the JSON arm,
	// and NOT via the negotiating sink, which would re-render the page.
	t.Run("accept_alone_gets_json", func(t *testing.T) {
		rr := httptest.NewRecorder()
		RateLimitExceeded(rr, browserRoute(reqWithAccept(browserAccept)))
		if ct := rr.Result().Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json — Accept alone bought the page", ct)
		}
		if got := rr.Result().Header.Get("Vary"); got != "Accept, Sec-Fetch-Dest" {
			t.Errorf("Vary = %q, want \"Accept, Sec-Fetch-Dest\"", got)
		}
		if got := rr.Result().Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", got)
		}
	})
}

// The Del must sit between a successful Execute and the write: moved
// back above the render, a template failure strips the RFC 6749 §5.2
// challenge off the JSON fallback.
func TestWriteOAuthError_RenderFailureKeepsChallenge(t *testing.T) {
	swapTmpl(t, &errorPageTmpl, brokenTmpl(t))

	rr := httptest.NewRecorder()
	rr.Header().Set("WWW-Authenticate", `Basic realm="consent"`)

	writeOAuthError(rr, browserRoute(reqWithAccept(browserAccept)),
		http.StatusUnauthorized, "invalid_client", "this consent endpoint does not authenticate clients")

	if ct := rr.Result().Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json (the fallback)", ct)
	}
	if got := rr.Result().Header.Get("WWW-Authenticate"); got == "" {
		t.Error("the JSON fallback lost its WWW-Authenticate challenge")
	}
}

// The title takes the OAuth error code, not the error_code detail —
// wiring them the wrong way round is invisible without a rendered page.
func TestErrorPage_ServerErrorTitleThroughRender(t *testing.T) {
	rr := httptest.NewRecorder()
	writeOAuthError(rr, browserRoute(reqWithAccept(browserAccept)),
		http.StatusForbidden, "server_error", "id token nonce mismatch", codeIDTokenVerificationFailed)

	if body := rr.Body.String(); !strings.Contains(body, "<h1>Something went wrong</h1>") {
		t.Errorf("a server_error on a 403 must not read as an authorization decision:\n%s", body)
	}
}

func TestErrorPageHint(t *testing.T) {
	cases := []struct {
		status    int
		errorCode string
		want      string
	}{
		// Capacity failures are transient whatever their code — the
		// throttle path carries none of its own.
		{http.StatusTooManyRequests, "", hintTransient},
		// Non-transient statuses on purpose: at 503 the status branch
		// answers and the map lookup is never exercised.
		{http.StatusBadGateway, codeIdPExchangeThrottled, hintTransient},
		{http.StatusInternalServerError, codeReplayStoreUnavailable, hintTransient},
		// A real upstream outage is transient, but the callback state
		// was claimed before the exchange — the retry must restart the
		// flow, not reload the burnt URL.
		{http.StatusBadGateway, codeIdPExchangeFailed, hintTransientRestart},
		// ...but the two permanent IdP misconfigurations riding the same
		// status are not: retrying loops the user, and a verification
		// failure is the one signal here worth escalating.
		{http.StatusBadGateway, codeIDTokenMissing, hintContact},
		{http.StatusBadGateway, codeIDTokenVerificationFailed, hintContact},
		// Dead flow state: starting over is what clears it.
		{http.StatusBadRequest, codeSessionUnknown, hintRestart},
		{http.StatusBadRequest, codeSessionExpired, hintRestart},
		{http.StatusBadRequest, codeSessionAudienceMismatch, hintRestart},
		{http.StatusBadRequest, codeCallbackParamsMissing, hintRestart},
		{http.StatusBadRequest, codeCallbackStateReplay, hintRestart},
		{http.StatusBadRequest, codeConsentTokenMissing, hintRestart},
		{http.StatusBadRequest, codeConsentTokenInvalid, hintRestart},
		{http.StatusBadRequest, codeConsentTokenExpired, hintRestart},
		{http.StatusBadRequest, codeConsentTokenAudienceMismatch, hintRestart},
		// The user cannot clear these — only an operator or the IdP can.
		{http.StatusForbidden, codeGroupNotAllowed, hintContact},
		{http.StatusForbidden, codeEmailNotVerified, hintVerifyEmail},
		{http.StatusMethodNotAllowed, codeMethodNotAllowed, hintRestart},
		{http.StatusNotFound, codeNotFound, hintRestart},
		{http.StatusInternalServerError, codeCodeSealFailed, hintContact},
		// Keyed on the code, not the word "expired": a client_id this
		// proxy will not honour — expired, or minted under a rotated
		// signing key — is cleared by reconnecting the service (fresh
		// DCR). "Start again" would loop on the same client_id, and
		// "contact the administrator" contradicts the runbook's
		// client-side fix.
		{http.StatusBadRequest, codeClientRegistrationExpired, hintReconnect},
		{http.StatusBadRequest, codeClientIDUnknown, hintReconnect},
		// Request-shape rejections on /consent: restarting the flow is
		// what produces a fresh, well-formed POST.
		{http.StatusBadRequest, codeConsentQueryParamsForbidden, hintRestart},
		{http.StatusBadRequest, codeConsentAuthHeaderPresent, hintRestart},
		{http.StatusBadRequest, codeConsentBodyTooLarge, hintRestart},
		{http.StatusBadRequest, codeConsentFormMalformed, hintRestart},
		{http.StatusBadRequest, codeConsentActionInvalid, hintRestart},
		{http.StatusBadRequest, codeParameterRepeated, hintRestart},
		// Client misconfiguration the user can't clear by restarting.
		{http.StatusBadRequest, codeClientIDMissing, hintContact},
		{http.StatusBadRequest, codeRedirectURIMissing, hintContact},
	}

	for _, tc := range cases {
		if got := errorPageHint(tc.status, tc.errorCode); got != tc.want {
			t.Errorf("errorPageHint(%d, %q) = %q, want %q", tc.status, tc.errorCode, got, tc.want)
		}
	}

	// Drive the whole map: a row added without a decision fails here.
	for code, want := range codeHints {
		if got := errorPageHint(http.StatusBadRequest, code); got != want {
			t.Errorf("codeHints[%q] resolves to %q, want %q", code, got, want)
		}
		// A capacity status wins over the code's own row — swapping the
		// checks inside errorPageHint flips this.
		if got := errorPageHint(http.StatusServiceUnavailable, code); got != hintTransient {
			t.Errorf("errorPageHint(503, %q) = %q, want hintTransient — the capacity branch must win", code, got)
		}
	}
	// transientCodes drives the title, so every entry must still resolve
	// to a wait-flavoured hint on a non-capacity status.
	for code := range transientCodes {
		got := errorPageHint(http.StatusInternalServerError, code)
		if got != hintTransient && got != hintTransientRestart {
			t.Errorf("transientCodes[%q] resolves to %q, want a wait-flavoured hint", code, got)
		}
	}
}

// The two redirect_uri denials were given a metric so an operator can
// see what a user is quoting; without an assertion the call is free to
// disappear again.
func TestAuthorize_RedirectURIDenials_AreMetered(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, _ := registerClient(t, tm, []string{"https://app.example.com/callback"})

	cases := []struct{ name, redirectURI, reason string }{
		{"missing", "", codeRedirectURIMissing},
		{"mismatch", "https://evil.example.com/cb", codeRedirectURIMismatch},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues(tc.reason))

			params := url.Values{"response_type": {"code"}, "client_id": {encClientID}}
			if tc.redirectURI != "" {
				params.Set("redirect_uri", tc.redirectURI)
			}
			rr := httptest.NewRecorder()
			Authorize(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})(
				rr, httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil))

			if rr.Result().StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Result().StatusCode, rr.Body.String())
			}
			var oe OAuthError
			if err := json.NewDecoder(rr.Body).Decode(&oe); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if oe.ErrorCode != tc.reason {
				t.Errorf("error_code = %q, want %q", oe.ErrorCode, tc.reason)
			}
			if after := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues(tc.reason)); after-before != 1 {
				t.Errorf("AccessDenied{%s} delta = %v, want 1", tc.reason, after-before)
			}
		})
	}
}

// The pre-rendered body is shared by every 429; spare capacity would
// let an in-package append scribble on it mid-flight.
func TestThrottlePage_HasNoSpareCapacity(t *testing.T) {
	if cap(throttlePage) != len(throttlePage) {
		t.Errorf("cap=%d len=%d — an append would land in the shared backing array",
			cap(throttlePage), len(throttlePage))
	}
}

// The render error arm, unreachable through the package-level var.
func TestRenderThrottlePage_ReportsTemplateFailure(t *testing.T) {
	swapTmpl(t, &errorPageTmpl, brokenTmpl(t))
	if _, err := renderStaticPage(http.StatusTooManyRequests, throttleBody); err == nil {
		t.Error("a broken template rendered without error")
	}
}

// The marker is keyed on an unexported named type: a plain string key
// from any package must not be able to forge it.
func TestWantsHTML_PlainStringKeyCannotForgeTheMarker(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/token", nil)
	r.Header.Set("Accept", browserAccept)
	//nolint:staticcheck // SA1029 is the point: a string key must not collide.
	r = r.WithContext(context.WithValue(r.Context(), "browser_facing", true))

	if wantsHTML(r) {
		t.Error("a plain string context key opened the HTML branch")
	}
}

// html/template escapes on first Execute, not at Parse: a template that
// compiles can still fail to render. This is what makes that a test
// failure instead of a blank 4xx in production.
func TestErrorPageTemplateExecutes(t *testing.T) {
	if err := errorPageTmpl.Execute(io.Discard, errorPageData{
		Title: "t", Reason: "r", Hint: "h", Error: "c", ErrorCode: "d",
	}); err != nil {
		t.Fatalf("error page template does not execute: %v", err)
	}
}

// A page that cannot render must not leave the caller with a committed
// status and an empty body — the JSON sink still answers.
func TestWriteOAuthError_FallsBackToJSONOnRenderFailure(t *testing.T) {
	swapTmpl(t, &errorPageTmpl, brokenTmpl(t))
	before := testutil.ToFloat64(metrics.PageRenderFailed.WithLabelValues("error"))

	rr := httptest.NewRecorder()
	req := browserRoute(httptest.NewRequest(http.MethodGet, "/callback", nil))
	req.Header.Set("Accept", browserAccept)

	writeOAuthError(rr, req, http.StatusForbidden, "access_denied", "user not in any allowed group", codeGroupNotAllowed)

	if rr.Result().StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
	if ct := rr.Result().Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var oe OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oe); err != nil {
		t.Fatalf("no usable body after a render failure: %v (body %q)", err, rr.Body.String())
	}
	if oe.ErrorCode != "group_not_allowed" {
		t.Errorf("error_code = %q, want group_not_allowed", oe.ErrorCode)
	}
	// The downgrade is silent on the wire — the counter is the only
	// signal an operator gets that every browser is now seeing JSON.
	if got := testutil.ToFloat64(metrics.PageRenderFailed.WithLabelValues("error")); got-before != 1 {
		t.Errorf("PageRenderFailed{page=error} delta = %v, want 1", got-before)
	}
}

// An empty description must not ship an empty key: the JSON body is a
// wire contract, and only error_code's omitempty was pinned.
func TestWriteOAuthError_OmitsEmptyDescription(t *testing.T) {
	rr := httptest.NewRecorder()
	writeOAuthError(rr, nil, http.StatusBadRequest, "invalid_request", "")

	const wantBody = `{"error":"invalid_request"}`
	if got := strings.TrimSpace(rr.Body.String()); got != wantBody {
		t.Errorf("body = %s, want %s", got, wantBody)
	}
}

func TestErrorPageTitle(t *testing.T) {
	cases := []struct {
		status          int
		code, errorCode string
		want            string
	}{
		{http.StatusBadRequest, "invalid_request", "", "Authentication request rejected"},
		// The two 401s that reach this sink mean "do not send
		// credentials", so the generic 4xx title is the honest one.
		{http.StatusUnauthorized, "invalid_client", "", "Authentication request rejected"},
		{http.StatusForbidden, "access_denied", codeGroupNotAllowed, "Access denied"},
		{http.StatusRequestEntityTooLarge, "invalid_request", "", "Authentication request rejected"},
		{http.StatusTooManyRequests, "temporarily_unavailable", "", "Temporarily unavailable"},
		{http.StatusServiceUnavailable, "server_error", codeReplayStoreUnavailable, "Temporarily unavailable"},
		{http.StatusInternalServerError, "server_error", codeCodeSealFailed, "Something went wrong"},
		// 502 is transient only for a genuine upstream outage...
		{http.StatusBadGateway, "server_error", codeIdPExchangeFailed, "Temporarily unavailable"},
		// ...not for the two permanent IdP misconfigurations that ride
		// the same status, which no amount of waiting clears.
		{http.StatusBadGateway, "server_error", codeIDTokenMissing, "Something went wrong"},
		{http.StatusBadGateway, "server_error", codeIDTokenVerificationFailed, "Something went wrong"},
		// server_error on a 403 is the id_token nonce mismatch: a stale
		// flow, not a refused account.
		{http.StatusForbidden, "server_error", codeIDTokenVerificationFailed, "Something went wrong"},
	}

	for _, tc := range cases {
		if got := errorPageTitle(tc.status, tc.code, tc.errorCode); got != tc.want {
			t.Errorf("errorPageTitle(%d, %q, %q) = %q, want %q", tc.status, tc.code, tc.errorCode, got, tc.want)
		}
	}
}

// The two router-level responders share the unbounded-path rules: a
// real navigation gets the pre-rendered page, everything else the JSON
// body, and an unmarked route never negotiates at all.
func TestRouterLevelResponders_NegotiateOnNavigation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		h       func(http.ResponseWriter, *http.Request)
		status  int
		code    string
		browser bool
		nav     bool
		wantCT  string
	}{
		{"405 browser navigation", MethodNotAllowed, http.StatusMethodNotAllowed, codeMethodNotAllowed, true, true, "text/html; charset=utf-8"},
		{"405 accept only", MethodNotAllowed, http.StatusMethodNotAllowed, codeMethodNotAllowed, true, false, "application/json"},
		{"405 unmarked route", MethodNotAllowed, http.StatusMethodNotAllowed, codeMethodNotAllowed, false, true, "application/json"},
		{"404 browser navigation", NotFound, http.StatusNotFound, codeNotFound, true, true, "text/html; charset=utf-8"},
		{"404 accept only", NotFound, http.StatusNotFound, codeNotFound, true, false, "application/json"},
		{"404 unmarked route", NotFound, http.StatusNotFound, codeNotFound, false, true, "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := reqWithAccept(browserAccept)
			if tc.nav {
				req.Header.Set("Sec-Fetch-Dest", "document")
			}
			if tc.browser {
				req = browserRoute(req)
			}
			rr := httptest.NewRecorder()
			tc.h(rr, req)

			if rr.Result().StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", rr.Result().StatusCode, tc.status)
			}
			if ct := rr.Result().Header.Get("Content-Type"); ct != tc.wantCT {
				t.Errorf("Content-Type = %q, want %q", ct, tc.wantCT)
			}
			if !strings.Contains(rr.Body.String(), tc.code) {
				t.Errorf("body carries no %s support code:\n%s", tc.code, rr.Body.String())
			}
			// Both are terminal flow errors: never cacheable.
			if got := rr.Result().Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
			wantVary := "Accept, Sec-Fetch-Dest"
			if !tc.browser {
				wantVary = ""
			}
			if got := rr.Result().Header.Get("Vary"); got != wantVary {
				t.Errorf("Vary = %q, want %q", got, wantVary)
			}
			if tc.wantCT == "text/html; charset=utf-8" {
				assertErrorPageCSP(t, rr.Result().Header.Get("Content-Security-Policy"))
			}
		})
	}
}
