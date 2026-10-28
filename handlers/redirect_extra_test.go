package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/babs/mcp-auth-proxy/config"
	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/replay"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const warpURI = "warp://dev.warp.Warp-Stable/mcp/callback"

func mustAllowlist(t *testing.T, raw string) config.RedirectAllowlist {
	t.Helper()
	a, err := config.ParseRedirectAllowlist(raw)
	if err != nil {
		t.Fatalf("ParseRedirectAllowlist(%q): %v", raw, err)
	}
	return a
}

// registerExtra runs /register for uri under the allowlist extra and
// returns the recorder.
func registerExtra(t *testing.T, tm *token.Manager, extra config.RedirectAllowlist, uri string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	Register(tm, zap.NewNop(), testBaseURL, RegisterConfig{ClientTTL: DefaultClientTTL, RedirectURIsExtra: extra})(rr, newRegisterRequest([]string{uri}))
	return rr
}

func registerExtraClientID(t *testing.T, tm *token.Manager, extra config.RedirectAllowlist, uri string) string {
	t.Helper()
	clientID, _ := registerClientWith(t, tm, RegisterConfig{ClientTTL: DefaultClientTTL, RedirectURIsExtra: extra}, []string{uri})
	return clientID
}

// TestRegister_RedirectURIsExtra pins how REDIRECT_URIS_EXTRA widens
// /register: only listed custom schemes / URIs pass, and every
// pre-existing rejection (fragment, userinfo, http rules) still holds.
func TestRegister_RedirectURIsExtra(t *testing.T) {
	const (
		schemeErr    = "redirect_uri must be http (loopback only), https, or a URI allowlisted by the operator"
		hostPathErr  = "redirect_uri must include a host or a path"
		charErr      = `redirect_uri must not contain unencoded spaces, non-ASCII characters, '"', '<' or '>', or percent-encoded control characters`
		semicolonErr = "redirect_uri query must not use ';' separators"
		escapeErr    = "redirect_uri query contains an invalid percent-escape"
		canonicalErr = "redirect_uri must be in canonical form; percent-encode special characters"
	)
	for _, tc := range []struct {
		name    string
		extra   string
		uri     string
		wantErr string // "" = 201
	}{
		{"unset rejects custom scheme", "", warpURI, schemeErr},
		{"unset rejects host-less custom scheme", "", "com.example.app:/cb", schemeErr},
		{"exact entry accepted", warpURI, warpURI, ""},
		{"exact entry with query accepted", warpURI + "?x=1", warpURI + "?x=1", ""},
		{"exact entry scheme case-insensitive", "Warp://h/cb", "warp://h/cb", ""},
		{"exact request scheme case-insensitive", "warp://h/cb", "Warp://h/cb", ""},
		{"other warp URI rejected under exact", warpURI, "warp://dev.warp.Warp-Stable/mcp/other", schemeErr},
		{"scheme wildcard accepts other host and path", "warp://*", "warp://evil.example/x/y", ""},
		{"scheme wildcard is case-insensitive", "warp://*", "WARP://dev.warp.Warp-Stable/mcp/callback", ""},
		{"scheme wildcard does not leak to other schemes", "warp://*", "cursor://x/cb", schemeErr},
		{"scheme wildcard does not leak to prefix scheme", "warp://*", "warpx://x/cb", schemeErr},
		{"host-less allowed when listed", "com.example.app:/cb", "com.example.app:/cb", ""},
		{"host-less allowed under scheme wildcard", "com.example.app://*", "com.example.app:/cb", ""},
		{"host-less rejected when not listed", "warp://*", "com.example.app:/cb", schemeErr},
		{"host-less rejected when other path listed", "com.example.app:/cb", "com.example.app:/other", schemeErr},
		{"no host no path rejected", "myapp://*", "myapp://", hostPathErr},
		{"empty warp rejected", "warp://*", "warp://", hostPathErr},
		{"bare scheme rejected", "myapp://*", "myapp:", hostPathErr},
		{"shape error under exact-only scheme stays unlisted", "warp://h/cb", "warp://h/c b", schemeErr},
		{"space in path rejected", "warp://*", "warp://h/a b", charErr},
		{"quote in path rejected", "warp://*", `warp://h/c"b`, charErr},
		{"lt in path rejected", "warp://*", "warp://h/c<b", charErr},
		{"gt in path rejected", "warp://*", "warp://h/c>b", charErr},
		{"quote in host rejected", "warp://*", `warp://a"b/cb`, charErr},
		{"markup in host rejected", "warp://*", "warp://a<script>/cb", charErr},
		{"space in query rejected", "warp://*", "warp://h/cb?q=a b", charErr},
		{"non-ASCII query rejected", "warp://*", "warp://h/cb?q=é", charErr},
		{"non-ASCII path rejected", "warp://*", "warp://h/café", charErr},
		{"non-ASCII host rejected", "warp://*", "warp://hé/cb", charErr},
		{"non-ASCII host rejected (ô)", "warp://*", "warp://hôte/cb", charErr},
		{"percent-encoded IRI accepted", "warp://*", "warp://h/caf%C3%A9?q=%C3%A9", ""},
		{"encoded NUL rejected", "myapp://*", "myapp://h/%00", charErr},
		{"encoded CRLF rejected", "myapp://*", "myapp://h/%0d%0a", charErr},
		{"encoded DEL rejected", "myapp://*", "myapp://h/%7F", charErr},
		{"encoded US rejected", "myapp://*", "myapp://h/cb?x=%1f", charErr},
		{"encoded space accepted", "myapp://*", "myapp://h/a%20b", ""},
		{"encoded slash accepted", "myapp://*", "myapp://h/a%2Fb", ""},
		{"encoded percent before 0d accepted", "myapp://*", "myapp://h/%250d", ""},
		{"trailing percent rejected", "warp://*", "warp://h/cb?x=%", escapeErr},
		{"truncated escape rejected", "warp://*", "warp://h/cb?x=%0", escapeErr},
		{"double percent rejected", "warp://*", "warp://h/cb?x=%%", escapeErr},
		{"encoded CR in query rejected", "warp://*", "warp://h/cb?x=%0D", charErr},
		{"pipe in path rejected", "warp://*", "warp://h/a|b", canonicalErr},
		{"semicolon query rejected", "warp://*", "warp://h/cb?a=1;b=2", semicolonErr},
		{"bad escape in query rejected", "warp://*", "warp://h/cb?a=%zz", escapeErr},
		{"bad escape in path is malformed", "warp://*", "warp://h/%zz", "malformed redirect_uri"},
		{"vscode-style query accepted", "vscode://*", "vscode://h/cb?windowId=1&x=a%20b", ""},
		{"fragment still rejected", "warp://*", warpURI + "#frag", "redirect_uri must not contain a fragment"},
		{"trailing # still rejected", "warp://*", warpURI + "#", "redirect_uri must not contain a fragment"},
		{"userinfo still rejected", "warp://*", "warp://user@dev.warp.Warp-Stable/cb", "redirect_uri must not contain userinfo"},
		{"opaque still rejected", "warp://*", "warp:foo", "redirect_uri must not be opaque"},
		{"https unchanged", "warp://*", "https://app.example.com/cb", ""},
		{"https host-less unchanged", "warp://*", "https:///cb", "redirect_uri must include a host"},
		{"loopback http unchanged", "warp://*", "http://127.0.0.1:8765/cb", ""},
		{"non-loopback http still rejected", "warp://*", "http://app.example.com/cb", "redirect_uri must use HTTPS for non-loopback addresses"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := registerExtra(t, newTestTokenManager(t), mustAllowlist(t, tc.extra), tc.uri)
			if tc.wantErr == "" {
				if rr.Code != http.StatusCreated {
					t.Fatalf("want 201, got %d: %s", rr.Code, rr.Body.String())
				}
				return
			}
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
			}
			var oe OAuthError
			if err := json.NewDecoder(rr.Body).Decode(&oe); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if oe.Error != "invalid_redirect_uri" || oe.ErrorDescription != tc.wantErr {
				t.Errorf("got %q / %q, want invalid_redirect_uri / %q", oe.Error, oe.ErrorDescription, tc.wantErr)
			}
		})
	}
}

func authorizeCustom(t *testing.T, tm *token.Manager, logger *zap.Logger, clientID, redirectURI string, challenge bool, cfg AuthorizeConfig) *httptest.ResponseRecorder {
	t.Helper()
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"state":         {"s"},
	}
	if challenge {
		params.Set("code_challenge", pkceChallenge("test-verifier-string"))
		params.Set("code_challenge_method", "S256")
	}
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	rr := httptest.NewRecorder()
	Authorize(tm, logger, testBaseURL, testOAuth2Config(), cfg)(rr, req)
	return rr
}

// TestAuthorize_CustomSchemeRedirectExactMatch pins that /authorize
// stays exact-match for custom-scheme redirect URIs.
func TestAuthorize_CustomSchemeRedirectExactMatch(t *testing.T) {
	for _, registered := range []string{warpURI, "com.example.app:/cb", "warp://localhost:1/cb"} {
		for _, tc := range []struct {
			requested string
			wantCode  int
		}{
			{registered, http.StatusFound},
			{registered + "x", http.StatusBadRequest},
			{strings.ToUpper(registered[:4]) + registered[4:], http.StatusBadRequest},
		} {
			t.Run(registered+"→"+tc.requested, func(t *testing.T) {
				tm := newTestTokenManager(t)
				extra := mustAllowlist(t, registered)
				clientID := registerExtraClientID(t, tm, extra, registered)
				rr := authorizeCustom(t, tm, zap.NewNop(), clientID, tc.requested, true, AuthorizeConfig{PKCERequired: true, RedirectURIsExtra: extra})
				if rr.Code != tc.wantCode {
					t.Fatalf("want %d, got %d: %s", tc.wantCode, rr.Code, rr.Body.String())
				}
			})
		}
	}
}

// TestAuthorize_CustomSchemeRequiresAllowlist pins the /authorize
// re-check: a client registered under an entry the operator has since
// removed or narrowed is refused on the AS, not redirected.
func TestAuthorize_CustomSchemeRequiresAllowlist(t *testing.T) {
	for name, current := range map[string]string{
		"entry removed":  "",
		"entry narrowed": "warp://other/cb",
	} {
		t.Run(name, func(t *testing.T) {
			tm := newTestTokenManager(t)
			clientID := registerExtraClientID(t, tm, mustAllowlist(t, "warp://*"), warpURI)
			before := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("redirect_uri_not_allowlisted"))
			core, logs := observer.New(zap.WarnLevel)

			rr := authorizeCustom(t, tm, zap.New(core), clientID, warpURI, true, AuthorizeConfig{PKCERequired: true, RedirectURIsExtra: mustAllowlist(t, current)})
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
			}
			var oe OAuthError
			if err := json.NewDecoder(rr.Body).Decode(&oe); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if oe.ErrorDescription != "redirect_uri is not allowlisted by the operator" || oe.ErrorCode != codeRedirectURIMismatch {
				t.Errorf("got %q / %q", oe.ErrorDescription, oe.ErrorCode)
			}
			if got := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("redirect_uri_not_allowlisted")) - before; got != 1 {
				t.Errorf("access_denied{redirect_uri_not_allowlisted} delta = %v, want 1", got)
			}
			entries := logs.FilterMessage("access_denied_redirect_uri_not_allowlisted").All()
			if len(entries) != 1 {
				t.Fatalf("want 1 denial log, got %d", len(entries))
			}
			fields := entries[0].ContextMap()
			if fields["internal_id"] == "" || fields["internal_id"] == nil || fields["scheme"] != "warp" || fields["error"] == nil {
				t.Errorf("denial log fields = %v, want internal_id, scheme=warp, error", fields)
			}
		})
	}
}

// TestAuthorize_CustomSchemeForcesPKCE pins that PKCE_REQUIRED=false
// never relaxes S256 for a custom-scheme redirect, while http(s)
// keeps the optional behaviour.
func TestAuthorize_CustomSchemeForcesPKCE(t *testing.T) {
	const httpsURI = "https://app.example.com/cb"
	for _, tc := range []struct {
		name      string
		uri       string
		challenge bool
		wantIdP   bool
	}{
		{"custom scheme without challenge rejected", warpURI, false, false},
		{"host-less custom scheme without challenge rejected", "com.example.app:/cb", false, false},
		{"custom scheme with S256 accepted", warpURI, true, true},
		{"https without challenge unchanged", httpsURI, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tm := newTestTokenManager(t)
			extra := mustAllowlist(t, "warp://*,com.example.app:/cb")
			clientID := registerExtraClientID(t, tm, extra, tc.uri)
			rr := authorizeCustom(t, tm, zap.NewNop(), clientID, tc.uri, tc.challenge, AuthorizeConfig{RedirectURIsExtra: extra})
			if rr.Code != http.StatusFound {
				t.Fatalf("want 302, got %d: %s", rr.Code, rr.Body.String())
			}
			loc, err := url.Parse(rr.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			if tc.wantIdP {
				if loc.Host != "idp.example.com" {
					t.Errorf("want IdP redirect, got %s", loc)
				}
				return
			}
			if !strings.HasPrefix(loc.String(), tc.uri+"?") || loc.Query().Get("error") != "invalid_request" || loc.Query().Get("error_description") != "code_challenge is required" {
				t.Errorf("want code_challenge is required on %s, got %s", tc.uri, loc)
			}
		})
	}
}

// TestRedirectURIMatches_CustomSchemeNoPortRelaxation pins that the
// RFC 8252 §7.3 loopback port relaxation stays http(s)-only.
func TestRedirectURIMatches_CustomSchemeNoPortRelaxation(t *testing.T) {
	for _, tc := range []struct {
		requested, registered string
		want                  bool
	}{
		{"warp://localhost:9/cb", "warp://localhost:1/cb", false},
		{"warp://127.0.0.1:9/cb", "warp://127.0.0.1:1/cb", false},
		{"http://localhost:9/cb", "http://localhost:1/cb", true},
		{"https://127.0.0.1:9/cb", "https://127.0.0.1/cb", true},
	} {
		if got := redirectURIMatches(tc.requested, tc.registered); got != tc.want {
			t.Errorf("redirectURIMatches(%q, %q) = %v, want %v", tc.requested, tc.registered, got, tc.want)
		}
	}
}

// TestRedirectDisplay_CustomScheme pins the consent page "Will redirect
// to" line: the receiving app's scheme stays visible.
func TestRedirectDisplay_CustomScheme(t *testing.T) {
	for in, want := range map[string]string{
		"https://app.example.com:8443/cb?x=1": "app.example.com:8443",
		warpURI + "?x=1":                      warpURI,
		"com.example.app:/cb?x=1":             "com.example.app:/cb",
		"warp:///p":                           "warp:///p",
		"warp://%E2%80%AEmoc.elgoog/cb":       "warp://%E2%80%AEmoc.elgoog/cb",
		"http://[::1":                         "http://[::1",
		"https:///cb":                         "https:///cb",
	} {
		got := redirectDisplay(in)
		if got != want {
			t.Errorf("redirectDisplay(%q) = %q, want %q", in, got, want)
		}
		if strings.ContainsRune(got, '\u202e') {
			t.Errorf("redirectDisplay(%q) leaked a bidi override: %q", in, got)
		}
	}
}

// TestRenderNavInterstitial_DeniedSchemes pins that the template.URL
// cast never lets a browser-executable scheme or an unparsable target
// into href or refresh.
func TestRenderNavInterstitial_DeniedSchemes(t *testing.T) {
	for _, tc := range []struct {
		target, reason string
		scheme         any // nil = no scheme field (unparsable target)
	}{
		{"javascript:alert(1)", "denied", "javascript"},
		{"JAVASCRIPT:alert(1)", "denied", "javascript"},
		{"data:text/html,x", "denied", "data"},
		{"vbscript:x", "denied", "vbscript"},
		{"javascript://x/%0aalert(1)", "denied", "javascript"},
		{"http://[::1", "parse", nil},
		{"//evil.example/x", "empty_scheme", ""},
		{"/rel", "empty_scheme", ""},
	} {
		target := tc.target
		t.Run(target, func(t *testing.T) {
			before := testutil.ToFloat64(metrics.PageRenderFailed.WithLabelValues("interstitial"))
			core, logs := observer.New(zap.DebugLevel)
			req := httptest.NewRequest(http.MethodPost, "/consent", nil)
			rr := httptest.NewRecorder()
			renderNavInterstitial(rr, req, zap.New(core), target)
			refused := logs.FilterMessage("nav_interstitial_refused").All()
			if len(refused) != 1 || logs.Len() != 1 {
				t.Fatalf("want exactly 1 nav_interstitial_refused log, got %d of %d", len(refused), logs.Len())
			}
			fields := refused[0].ContextMap()
			if _, ok := fields["error"]; ok {
				t.Errorf("log carries the target-quoting parse error: %v", fields)
			}
			if fields["reason"] != tc.reason || fields["scheme"] != tc.scheme {
				t.Errorf("log fields = %v, want reason=%q scheme=%v", fields, tc.reason, tc.scheme)
			}
			if rr.Code != http.StatusInternalServerError {
				t.Errorf("want 500, got %d", rr.Code)
			}
			if got := testutil.ToFloat64(metrics.PageRenderFailed.WithLabelValues("interstitial")) - before; got != 1 {
				t.Errorf("page_render_failed{interstitial} delta = %v, want 1", got)
			}
			body := strings.ToLower(rr.Body.String())
			for _, bad := range []string{"javascript:", "data:", "vbscript:", "url=", "href="} {
				if strings.Contains(body, bad) {
					t.Errorf("body contains %q:\n%s", bad, rr.Body.String())
				}
			}
		})
	}
}

// TestCustomSchemeRedirect_ErrorEnvelope pins that the authz error
// envelope and the consent interstitial (html/template URL filtering)
// keep custom-scheme and host-less redirect URIs intact.
func TestCustomSchemeRedirect_ErrorEnvelope(t *testing.T) {
	for _, tc := range []struct{ uri, prefix string }{
		{warpURI + "?x=1", warpURI + "?"},
		{"com.example.app:/cb", "com.example.app:/cb?"},
	} {
		t.Run(tc.uri, func(t *testing.T) {
			target, err := authzErrorURL(tc.uri, "st", "access_denied", "d", testBaseURL)
			if err != nil || !strings.HasPrefix(target, tc.prefix) {
				t.Errorf("authzErrorURL = %q, %v; want prefix %q", target, err, tc.prefix)
			}

			tm := newTestTokenManager(t)
			form := url.Values{"consent_token": {mintConsentToken(t, tm, tc.uri, "st")}, "action": {"deny"}}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/consent", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{})(rr, req)
			loc := extractNavTarget(t, rr)
			if got := loc.String(); !strings.HasPrefix(got, tc.prefix) || loc.Query().Get("error") != "access_denied" {
				t.Errorf("interstitial target = %q, want prefix %q with error=access_denied", got, tc.prefix)
			}
			if strings.Contains(rr.Body.String(), "ZgotmplZ") {
				t.Errorf("html/template filtered the custom-scheme URL:\n%s", rr.Body.String())
			}
		})
	}
}

// TestCheckCustomRedirect_DistinctDescriptions pins one fixed
// description per Check error, none falling through to the default.
func TestCheckCustomRedirect_DistinctDescriptions(t *testing.T) {
	const fallback = "redirect_uri is not allowed"
	seen := map[string]error{}
	for _, err := range []error{
		config.ErrRedirectNotAllowlisted,
		config.ErrRedirectNoHostOrPath,
		config.ErrRedirectForbiddenChar,
		config.ErrRedirectQuerySemicolon,
		config.ErrRedirectQueryEscape,
		config.ErrRedirectNonCanonical,
		errors.New("unmapped"),
	} {
		rr := httptest.NewRecorder()
		if checkCustomRedirect(rr, httptest.NewRequest(http.MethodPost, "/register", nil), err) {
			t.Fatalf("%v: accepted", err)
		}
		var oe OAuthError
		if decErr := json.NewDecoder(rr.Body).Decode(&oe); decErr != nil {
			t.Fatalf("decode: %v", decErr)
		}
		if oe.Error != "invalid_redirect_uri" {
			t.Errorf("%v: error = %q", err, oe.Error)
		}
		if prev, dup := seen[oe.ErrorDescription]; dup {
			t.Errorf("%v and %v share description %q", prev, err, oe.ErrorDescription)
		}
		seen[oe.ErrorDescription] = err
		if (oe.ErrorDescription == fallback) != (err.Error() == "unmapped") {
			t.Errorf("%v: description %q, fallback only for unmapped errors", err, oe.ErrorDescription)
		}
		if mapped := err.Error() != "unmapped" && !errors.Is(err, config.ErrRedirectNotAllowlisted); mapped && oe.ErrorDescription != "redirect_uri "+err.Error() {
			t.Errorf("description %q != \"redirect_uri \" + %q", oe.ErrorDescription, err.Error())
		}
	}
	if !checkCustomRedirect(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/register", nil), nil) {
		t.Error("nil error rejected")
	}
}

// TestToken_RedirectURIsExtraRecheck pins the /token re-check of
// REDIRECT_URIS_EXTRA: once the entry that admitted a custom-scheme
// session is gone (list emptied, scheme dropped, exact entry for another
// URI), the code and refresh grants are refused before their single-use
// claims, and pass again when the entry comes back.
func TestToken_RedirectURIsExtraRecheck(t *testing.T) {
	const listedURI = "https://allowed.example/cb"
	tm := newTestTokenManager(t)
	encClientID, internalID := registerClientWith(t, tm, RegisterConfig{ClientTTL: DefaultClientTTL, RedirectURIsExtra: mustAllowlist(t, "warp://*")}, []string{warpURI, listedURI})
	codeForm := func() url.Values {
		return url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {sealCode(t, tm, internalID, warpURI, pkceChallenge(fwdVerifier), "user", "u@example.com")},
			"redirect_uri":  {warpURI},
			"client_id":     {encClientID},
			"code_verifier": {fwdVerifier},
		}
	}
	grants := []struct {
		name string
		form func() url.Values
	}{
		{"authorization_code", codeForm},
		{"refresh_token", func() url.Values { return refreshForm(encClientID, sealSession(t, tm, internalID, 1)) }},
	}
	for _, removed := range []string{"", "other://*", "warp://dev.warp.Warp-Stable/other"} {
		for _, g := range grants {
			t.Run(fmt.Sprintf("%s under %q", g.name, removed), func(t *testing.T) {
				store := replay.NewMemoryStore()
				t.Cleanup(func() { _ = store.Close() })
				form := g.form()
				before := notAllowlistedDenials()
				core, logs := observer.New(zap.WarnLevel)
				rr := postGrant(t, tm, zap.New(core), store, TokenConfig{RedirectURIsExtra: mustAllowlist(t, removed)}, form)
				assertNotAllowlisted(t, rr, logs, before, "invalid_grant", noLongerAllowlistedErr, "grant_type", g.name)
				if cause := logs.FilterMessage("access_denied_redirect_uri_not_allowlisted").All()[0].ContextMap()["error"]; cause != config.ErrRedirectNotAllowlisted.Error() {
					t.Errorf("log error = %v, want %q", cause, config.ErrRedirectNotAllowlisted)
				}

				for _, extra := range []string{"warp://*", warpURI} {
					rr = postGrant(t, tm, zap.NewNop(), store, TokenConfig{RedirectURIsExtra: mustAllowlist(t, extra)}, g.form())
					if rr.Code != http.StatusOK {
						t.Fatalf("listed again as %q: want 200, got %d: %s", extra, rr.Code, rr.Body.String())
					}
				}
				rr = postGrant(t, tm, zap.NewNop(), store, TokenConfig{RedirectURIsExtra: mustAllowlist(t, "warp://*")}, form)
				if rr.Code != http.StatusOK {
					t.Fatalf("refused grant replayed once listed again: want 200 (nothing burned), got %d: %s", rr.Code, rr.Body.String())
				}
			})
		}
	}
}
