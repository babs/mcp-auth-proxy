package handlers

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	tokenpkg "github.com/babs/mcp-auth-proxy/token"
	"go.uber.org/zap"
)

// The error_code vocabulary is a wire contract (specs.md table): a
// constant renamed or retyped changes what users quote to operators.
// Every value is pinned literally so drift fails here before a release
// freezes it.
func TestErrorCodeValues_ArePinned(t *testing.T) {
	pinned := map[string]string{
		codeClientIDMissing:              "client_id_missing",
		codeClientIDUnknown:              "client_id_unknown",
		codeClientAudienceMismatch:       "client_audience_mismatch",
		codeClientRegistrationExpired:    "client_registration_expired",
		codeRedirectURIMissing:           "redirect_uri_missing",
		codeRedirectURIMismatch:          "redirect_uri_mismatch",
		codeRedirectURIMalformed:         "redirect_uri_malformed",
		codeSessionUnknown:               "session_unknown",
		codeSessionExpired:               "session_expired",
		codeSessionAudienceMismatch:      "session_audience_mismatch",
		codeCallbackParamsMissing:        "callback_params_missing",
		codeCallbackStateReplay:          "callback_state_replay",
		codeIdPExchangeFailed:            "idp_exchange_failed",
		codeIdPExchangeThrottled:         "idp_exchange_throttled",
		codeReplayStoreUnavailable:       "replay_store_unavailable",
		codeIDTokenMissing:               "id_token_missing",
		codeIDTokenVerificationFailed:    "id_token_verification_failed",
		codeIDTokenClaimsUnparsable:      "id_token_claims_unparsable",
		codeSubjectMissing:               "subject_missing",
		codeEmailNotVerified:             "email_not_verified",
		codeGroupNotAllowed:              "group_not_allowed",
		codeGroupInvalid:                 "group_invalid",
		codeConsentTokenMissing:          "consent_token_missing",
		codeConsentTokenInvalid:          "consent_token_invalid",
		codeConsentTokenExpired:          "consent_token_expired",
		codeConsentTokenAudienceMismatch: "consent_token_audience_mismatch",
		codeConsentQueryParamsForbidden:  "consent_query_params_forbidden",
		codeConsentAuthHeaderPresent:     "consent_auth_header_present",
		codeConsentBodyTooLarge:          "consent_body_too_large",
		codeConsentFormMalformed:         "consent_form_malformed",
		codeConsentActionInvalid:         "consent_action_invalid",
		codeParameterRepeated:            "parameter_repeated",
		codeMethodNotAllowed:             "method_not_allowed",
		codeNotFound:                     "not_found",
		codeCodeSealFailed:               "code_seal_failed",
		codeInterstitialFailed:           "interstitial_render_failed",
		codeCodeReplay:                   "code_replay",
		codeRefreshConcurrent:            "refresh_concurrent_submit",
		codeRefreshFamilyRevoked:         "refresh_family_revoked",
		codeRefreshRevokedCutoff:         "refresh_revoked_iat_cutoff",
		codeRefreshReuse:                 "refresh_reuse_detected",
		codeTokenIssueFailed:             "token_issue_failed",
	}
	for got, want := range pinned {
		if got != want {
			t.Errorf("error_code constant = %q, want %q", got, want)
		}
	}

	// Completeness: a constant added without a row above would be
	// unpinned and could change value silently. Counted from the AST so
	// the guard cannot drift from the declarations.
	declared := codeConstNames(t)
	if len(pinned) != len(declared) {
		t.Errorf("pinned %d error_code values but the package declares %d code* constants (%v) — every constant needs a row",
			len(pinned), len(declared), declared)
	}
}

// codeConstNames lists the package's wire error_code constants: named
// code<Something> AND string-valued, which excludes non-wire constants
// that happen to share the prefix (codeTTL is a duration).
func codeConstNames(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, file := range parsePackage(t, token.NewFileSet()) {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, n := range vs.Names {
					if i < len(vs.Values) && isWireCodeConst(n.Name, vs.Values[i]) {
						names = append(names, n.Name)
					}
				}
			}
		}
	}
	sort.Strings(names)
	return names
}

// isWireCodeConst reports a wire error_code declaration: named
// code<Something> AND string-valued, which excludes non-wire constants
// sharing the prefix (codeTTL is a duration).
func isWireCodeConst(name string, value ast.Expr) bool {
	if !strings.HasPrefix(name, "code") || len(name) < 5 || name[4] < 'A' || name[4] > 'Z' {
		return false
	}
	bl, ok := value.(*ast.BasicLit)
	return ok && bl.Kind == token.STRING
}

// Call-site → error_code binding, end to end through the real handlers
// with a browser Accept: TestErrorPageHint pins the map→advice edge in
// isolation, so a constant swapped at a call site (compiles fine, both
// are strings) was invisible without this — the user silently gets the
// wrong support code AND the wrong advice.
func TestBrowserCallSites_EmitDocumentedErrorCode(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, _ := registerClient(t, tm, []string{"https://app.example.com/cb"})

	sealClient := func(sc sealedClient) string {
		s, err := tm.SealJSON(sc, tokenpkg.PurposeClient)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		return s
	}
	expiredClient := sealClient(sealedClient{
		ID: "x", Typ: tokenpkg.PurposeClient, Audience: testBaseURL,
		RedirectURIs: []string{"https://app.example.com/cb"}, ExpiresAt: time.Now().Add(-time.Hour),
	})

	authorize := func(params url.Values) *http.Request {
		return httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	}
	withHeader := func(r *http.Request, k, v string) *http.Request {
		r.Header.Set(k, v)
		return r
	}
	consentPost := func(target, form string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}

	authorizeH := Authorize(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), AuthorizeConfig{PKCERequired: true})
	consentH := Consent(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), ConsentConfig{})
	callbackH := Callback(tm, zap.NewNop(), testBaseURL, testOAuth2Config(), nil, CallbackConfig{})

	cases := []struct {
		name          string
		handler       http.HandlerFunc
		req           *http.Request
		wantErrorCode string
		wantHint      string
	}{
		{"authorize_client_id_missing", authorizeH,
			authorize(url.Values{"response_type": {"code"}}),
			codeClientIDMissing, hintContact},
		// A client_id this proxy will not honour (garbage, or minted
		// under a rotated key) is cleared by reconnecting the service,
		// not by phoning an operator.
		{"authorize_client_id_unknown", authorizeH,
			authorize(url.Values{"client_id": {"bogus"}}),
			codeClientIDUnknown, hintReconnect},
		{"authorize_client_registration_expired", authorizeH,
			authorize(url.Values{"client_id": {expiredClient}}),
			codeClientRegistrationExpired, hintReconnect},
		{"authorize_redirect_uri_missing", authorizeH,
			authorize(url.Values{"client_id": {encClientID}}),
			codeRedirectURIMissing, hintContact},
		{"authorize_redirect_uri_mismatch", authorizeH,
			authorize(url.Values{"client_id": {encClientID}, "redirect_uri": {"https://evil.example.com/cb"}}),
			codeRedirectURIMismatch, hintReconnect},
		{"authorize_parameter_repeated", authorizeH,
			httptest.NewRequest(http.MethodGet, "/authorize?client_id=a&client_id=b", nil),
			codeParameterRepeated, hintRestart},
		{"consent_query_params_forbidden", consentH,
			consentPost("/consent?x=1", "action=approve"),
			codeConsentQueryParamsForbidden, hintRestart},
		{"consent_auth_header_present", consentH,
			withHeader(consentPost("/consent", "action=approve"), "Authorization", "Basic Zm9vOmJhcg=="),
			codeConsentAuthHeaderPresent, hintRestart},
		{"consent_form_malformed", consentH,
			consentPost("/consent", "%zz=1"),
			codeConsentFormMalformed, hintRestart},
		{"consent_token_missing", consentH,
			consentPost("/consent", "action=approve"),
			codeConsentTokenMissing, hintRestart},
		{"consent_token_invalid", consentH,
			consentPost("/consent", "consent_token=garbage&action=approve"),
			codeConsentTokenInvalid, hintRestart},
		{"consent_action_invalid", consentH,
			consentPost("/consent", "consent_token="+url.QueryEscape(mintConsentToken(t, tm, "https://app.example.com/cb", "s"))+"&action=shrug"),
			codeConsentActionInvalid, hintRestart},
		{"callback_params_missing", callbackH,
			httptest.NewRequest(http.MethodGet, "/callback", nil),
			codeCallbackParamsMissing, hintRestart},
		{"callback_session_unknown", callbackH,
			httptest.NewRequest(http.MethodGet, "/callback?code=x&state=bogus", nil),
			codeSessionUnknown, hintRestart},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			req.Header.Set("Accept", browserAccept)
			rr := httptest.NewRecorder()
			BrowserFacing(tc.handler).ServeHTTP(rr, req)

			if ct := rr.Result().Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
				t.Fatalf("Content-Type = %q, want text/html; charset=utf-8 (body: %s)", ct, rr.Body.String())
			}
			body := rr.Body.String()
			if !strings.Contains(body, "&middot; "+tc.wantErrorCode+"</p>") {
				t.Errorf("page does not carry error_code %q:\n%s", tc.wantErrorCode, body)
			}
			if !strings.Contains(body, tc.wantHint) {
				t.Errorf("page does not carry the expected advice %q:\n%s", tc.wantHint, body)
			}
		})
	}
}

// The §4.1.2.1 invariant-violation fallbacks (a registered redirect_uri
// that fails to re-parse) must negotiate like any other proxy-hosted
// error and carry a support code — they are the paths where a support
// code matters most.
func TestRedirectFallbacks_NegotiateAndCarryErrorCode(t *testing.T) {
	// url.Parse rejects a control byte in the URI.
	const unparsable = "https://app.example.com/\x7f"

	t.Run("redirectAuthzError", func(t *testing.T) {
		req := browserRoute(reqWithAccept(browserAccept))
		rr := httptest.NewRecorder()
		redirectAuthzError(rr, req, unparsable, "s", "access_denied", "user declined to authorize this client", testBaseURL)

		if rr.Result().StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Result().StatusCode)
		}
		if ct := rr.Result().Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("Content-Type = %q, want the negotiated page", ct)
		}
		if got := rr.Result().Header.Get("Vary"); got != "Accept" {
			t.Errorf("Vary = %q, want Accept", got)
		}
		if body := rr.Body.String(); !strings.Contains(body, "&middot; "+codeRedirectURIMalformed+"</p>") {
			t.Errorf("fallback page carries no support code:\n%s", body)
		}
	})

	t.Run("consentNavError", func(t *testing.T) {
		req := browserRoute(httptest.NewRequest(http.MethodPost, "/consent", nil))
		req.Header.Set("Accept", browserAccept)
		rr := httptest.NewRecorder()
		consentNavError(rr, req, zap.NewNop(),
			sealedConsent{RedirectURI: unparsable, OriginalState: "s"},
			"server_error", "internal error", testBaseURL)

		if rr.Result().StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Result().StatusCode)
		}
		if ct := rr.Result().Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("Content-Type = %q, want the negotiated page", ct)
		}
		if body := rr.Body.String(); !strings.Contains(body, "&middot; "+codeRedirectURIMalformed+"</p>") {
			t.Errorf("fallback page carries no support code:\n%s", body)
		}
	})
}

// descToCode pins the error_code of every writeOAuthError call site in
// the package, keyed "<enclosing function>: <error_description>". Both
// parts are compile-time values, so the AST reads them without running a
// handler — the only affordable way to cover ~100 sites. The function
// name is part of the key because one description legitimately appears
// under several handlers (a 1 MB body cap on /register, /token and
// /consent) with a different code each time. Its purpose
// is to kill the swap: a call site handed a sibling's constant compiles
// fine, both being strings, and changes the advice a human is shown
// (`id_token_verification_failed` → `idp_exchange_failed` turns
// "contact the administrator" into "wait and retry" on a permanent
// misconfiguration). An empty value means the site deliberately passes
// no code.
//
// "<var> must not be repeated" is rejectRepeatedParams' composed
// description, whose only variable part is a parameter fed from literal
// argument lists.
var descToCode = map[string]string{
	"Authorize: client registered for a different audience":                                                codeClientAudienceMismatch,
	"Authorize: client registration expired":                                                               codeClientRegistrationExpired,
	"Authorize: client_id is required":                                                                     codeClientIDMissing,
	"Authorize: redirect_uri does not match registered URIs":                                               codeRedirectURIMismatch,
	"Authorize: redirect_uri is required":                                                                  codeRedirectURIMissing,
	"Authorize: unknown client_id":                                                                         codeClientIDUnknown,
	"Consent: action must be approve or deny":                                                              codeConsentActionInvalid,
	"Consent: consent endpoint parameters must be in the request body, not the URL query":                  codeConsentQueryParamsForbidden,
	"Consent: consent token bound to a different audience":                                                 codeConsentTokenAudienceMismatch,
	"Consent: consent token expired":                                                                       codeConsentTokenExpired,
	"Consent: consent token invalid or expired":                                                            codeConsentTokenInvalid,
	"Consent: consent token is required":                                                                   codeConsentTokenMissing,
	"Consent: malformed form body":                                                                         codeConsentFormMalformed,
	"Consent: replay store unavailable":                                                                    codeReplayStoreUnavailable,
	"Consent: request body exceeds the 1 MB cap":                                                           codeConsentBodyTooLarge,
	"Consent: this consent endpoint does not authenticate clients; retry without the Authorization header": codeConsentAuthHeaderPresent,
	"MethodNotAllowed: this endpoint does not accept that HTTP method":                                     codeMethodNotAllowed,
	"Register: client_name exceeds maximum length":/* no code */ "",
	"Register: client_name must not contain control bytes or commas":/* no code */ "",
	"Register: failed to register client":/* no code */ "",
	"Register: invalid JSON body":/* no code */ "",
	"Register: malformed redirect_uri":/* no code */ "",
	"Register: redirect_uri exceeds maximum length":/* no code */ "",
	"Register: redirect_uri must be an absolute URI with authority, not opaque":/* no code */ "",
	"Register: redirect_uri must include a host":/* no code */ "",
	"Register: redirect_uri must not contain a fragment":/* no code */ "",
	"Register: redirect_uri must not contain userinfo":/* no code */ "",
	"Register: redirect_uri must use HTTPS for non-loopback addresses":/* no code */ "",
	"Register: redirect_uri scheme must be http (loopback only) or https":/* no code */ "",
	"Register: redirect_uris exceeds maximum count":/* no code */ "",
	"Register: redirect_uris is required and must not be empty":/* no code */ "",
	"Register: request body exceeds the 1 MB cap":/* no code */ "",
	"Register: unsupported token_endpoint_auth_method; only \"none\" is supported":/* no code */ "",
	"Token: grant_type must be authorization_code or refresh_token":/* no code */ "",
	"Token: malformed form body":/* no code */ "",
	"Token: request body exceeds the 1 MB cap":/* no code */ "",
	"Token: resource does not identify this authorization server":/* no code */ "",
	"Token: this token endpoint does not authenticate clients (token_endpoint_auth_method=none); remove the Authorization header":/* no code */ "",
	"Token: token endpoint parameters must be in the request body, not the URL query":/* no code */ "",
	"callbackHandler: authorization request could not be matched to a known session": codeSessionUnknown,
	"callbackHandler: callback state already used":                                   codeCallbackStateReplay,
	"callbackHandler: email address is not verified":                                 codeEmailNotVerified,
	"callbackHandler: failed to parse claims":                                        codeIDTokenClaimsUnparsable,
	"callbackHandler: group name contains invalid characters":                        codeGroupInvalid,
	"callbackHandler: id_token is missing the subject claim":                         codeSubjectMissing,
	"callbackHandler: id_token nonce mismatch":                                       codeIDTokenVerificationFailed,
	"callbackHandler: id_token verification failed":                                  codeIDTokenVerificationFailed,
	"callbackHandler: internal error":                                                codeCodeSealFailed,
	"callbackHandler: malformed redirect_uri":                                        codeRedirectURIMalformed,
	"callbackHandler: missing code or state":                                         codeCallbackParamsMissing,
	"callbackHandler: no id_token in upstream response":                              codeIDTokenMissing,
	"callbackHandler: replay store unavailable":                                      codeReplayStoreUnavailable,
	"callbackHandler: session bound to a different audience":                         codeSessionAudienceMismatch,
	"callbackHandler: session expired":                                               codeSessionExpired,
	"callbackHandler: unknown or expired state":                                      codeSessionUnknown,
	"callbackHandler: upstream IdP exchange throttled; retry shortly":                codeIdPExchangeThrottled,
	"callbackHandler: upstream authentication failed":                                codeIdPExchangeFailed,
	"callbackHandler: user not in any allowed group":                                 codeGroupNotAllowed,
	"handleAuthorizationCode: PKCE verification failed":/* no code */ "",
	"handleAuthorizationCode: authorization code already used": codeCodeReplay,
	"handleAuthorizationCode: authorization code bound to a different audience":/* no code */ "",
	"handleAuthorizationCode: authorization code expired":/* no code */ "",
	"handleAuthorizationCode: authorization code missing token id or family id":/* no code */ "",
	"handleAuthorizationCode: client_id mismatch":/* no code */ "",
	"handleAuthorizationCode: code_verifier is required":/* no code */ "",
	"handleAuthorizationCode: code_verifier must be 43-128 unreserved characters":/* no code */ "",
	"handleAuthorizationCode: code_verifier supplied but code was issued without a code_challenge":/* no code */ "",
	"handleAuthorizationCode: failed to issue token": codeTokenIssueFailed,
	"handleAuthorizationCode: internal error":/* no code */ "",
	"handleAuthorizationCode: invalid or expired authorization code":/* no code */ "",
	"handleAuthorizationCode: missing required parameters":/* no code */ "",
	"handleAuthorizationCode: redirect_uri mismatch":/* no code */ "",
	"handleAuthorizationCode: replay store unavailable": codeReplayStoreUnavailable,
	"handleRefreshToken: client_id mismatch":/* no code */ "",
	"handleRefreshToken: failed to issue token": codeTokenIssueFailed,
	"handleRefreshToken: internal error":/* no code */ "",
	"handleRefreshToken: invalid or expired refresh token":/* no code */ "",
	"handleRefreshToken: missing required parameters":/* no code */ "",
	"handleRefreshToken: refresh token bound to a different audience":/* no code */ "",
	"handleRefreshToken: refresh token concurrent submit; the legitimate peer is rotating, retry after the new refresh lands": codeRefreshConcurrent,
	"handleRefreshToken: refresh token expired":/* no code */ "",
	"handleRefreshToken: refresh token missing family or id":/* no code */ "",
	"handleRefreshToken: refresh token reuse detected — family revoked":  codeRefreshReuse,
	"handleRefreshToken: refresh token revoked":                          codeRefreshFamilyRevoked,
	"handleRefreshToken: refresh token revoked by the configured cutoff": codeRefreshRevokedCutoff,
	"handleRefreshToken: replay store unavailable":                       codeReplayStoreUnavailable,
	"openAndValidateClient: client registered for a different audience":  codeClientAudienceMismatch,
	"openAndValidateClient: client registration expired":                 codeClientRegistrationExpired,
	"openAndValidateClient: invalid client_id":                           codeClientIDUnknown,
	"rejectRepeatedParams: <var> must not be repeated":                   codeParameterRepeated,
	"renderNavInterstitial: internal error":                              codeInterstitialFailed,
}

// sinkDescArg is the seed set: the sinks whose desc argument is known by
// position. Wrapper functions that forward a string parameter into one
// of these are discovered from the AST (see discoverSinks) rather than
// listed, so adding a wrapper cannot quietly widen the surface this test
// covers.
var sinkDescArg = map[string]int{
	"writeOAuthError":    4,
	"redirectAuthzError": 5,
	"consentNavError":    5,
	// Variadic: its `names ...string` are concatenated into the
	// description, and every call site passes a literal list.
	"rejectRepeatedParams": 3,
}

// variadicSinks take their description parts as a trailing variadic, so
// every argument from the recorded position on is checked.
var variadicSinks = map[string]bool{"rejectRepeatedParams": true}

// compile-time literal (sanitizeErrorDescription strips control bytes,
// not markup), and on each site pairing that description with the right
// error_code. One AST walk covers both: every sink call in the package
// is located, its description proven literal-built, and its (desc, code)
// pair checked against descToCode.
//
// The sink set is closed by construction: any function that forwards a
// string parameter into a known sink's desc position becomes a sink
// itself, transitively. Without that, a one-line wrapper around
// writeOAuthError was enough to smuggle a caller-supplied description
// onto the page with this test still green.
// descSite is one resolved sink call: everything the three checks below
// need, gathered once by the walk so each check reads as a rule rather
// than as AST plumbing.
type descSite struct {
	where  string
	callee string
	fn     *ast.FuncDecl
	call   *ast.CallExpr
	argPos int
}

// checkLiteral enforces the threat-model invariant itself: the
// description must be built from compile-time literals. Variadic sinks
// take every trailing argument as a description part.
func (s descSite) checkLiteral(t *testing.T, sinks map[string]int) bool {
	t.Helper()
	args := s.call.Args[s.argPos : s.argPos+1]
	if variadicSinks[s.callee] {
		args = s.call.Args[s.argPos:]
	}
	ok := true
	for _, arg := range args {
		if msg := checkLiteralExpr(arg, s.fn, sinks, 0); msg != "" {
			ok = false
			t.Errorf("%s: %s description: %s — descriptions must be compile-time literals (threat-model invariant)",
				s.where, s.callee, msg)
		}
	}
	return ok && !variadicSinks[s.callee]
}

// resolveDesc returns the description's literal value. A forwarded
// parameter has none to pin — the wrapper's own callers are sites in
// this walk and get paired there — but anything else unresolvable means
// the pair check below silently did not run, which is how a wrong
// error_code shipped behind a `d := "…"` local.
func (s descSite) resolveDesc(t *testing.T, consts map[string]string) (string, bool) {
	t.Helper()
	desc, ok := literalValue(s.call.Args[s.argPos], s.fn, consts)
	if ok {
		return desc, true
	}
	if arg, isIdent := s.call.Args[s.argPos].(*ast.Ident); isIdent {
		if _, isParam := paramIndex(s.fn, arg.Name); isParam {
			return "", false
		}
	}
	t.Errorf("%s: description is literal but its value could not be resolved, so the (desc, error_code) pair check was skipped — inline the literal or extend literalValue", s.where)
	return "", false
}

// checkShape enforces the convention sentence() assumes: lowercase,
// unterminated, no leading space. A literal that breaks it is silently
// mangled on the page — "  leading space" keeps its space and gains a
// stop outside any closing quote.
func (s descSite) checkShape(t *testing.T, desc string) {
	t.Helper()
	if desc == "" {
		return
	}
	if strings.TrimLeft(desc, " \t") != desc {
		t.Errorf("%s: description %q starts with whitespace — sentence() cannot capitalise it", s.where, desc)
	}
	if strings.HasSuffix(desc, ".") || strings.HasSuffix(desc, "!") || strings.HasSuffix(desc, "?") {
		t.Errorf("%s: description %q is already terminated — sentence() adds the stop for the page and the JSON keeps it verbatim", s.where, desc)
	}
}

// checkPair pins the (description, error_code) binding: both are
// strings, so a swapped constant compiles and silently changes the
// advice a user is shown.
func (s descSite) checkPair(t *testing.T, desc string, consts map[string]string) bool {
	t.Helper()
	key := s.fn.Name.Name + ": " + desc
	wantCode, pinned := descToCode[key]
	if !pinned {
		t.Errorf("%s: %q is not in descToCode — add its (description, error_code) pair so a swapped constant cannot pass", s.where, key)
		return false
	}
	gotCode := ""
	if len(s.call.Args) > s.argPos+1 {
		id, ok := s.call.Args[s.argPos+1].(*ast.Ident)
		if !ok {
			t.Errorf("%s: error_code argument is not a code* constant", s.where)
			return false
		}
		// Compare the constant's VALUE: that is what reaches the wire,
		// and it keeps the pin readable as the vocabulary users quote.
		if gotCode, ok = consts[id.Name]; !ok {
			t.Errorf("%s: error_code %s is not a package string constant", s.where, id.Name)
			return false
		}
	}
	if gotCode != wantCode {
		t.Errorf("%s: %q carries error_code %q, want %q — a swapped constant changes the advice a user is shown",
			s.where, key, gotCode, wantCode)
	}
	return true
}

// sinkCallSites resolves every call to a known sink in one declaration,
// and reports any place a sink is named as a VALUE rather than called —
// `f := writeOAuthError` then `f(…)` would otherwise reach the sink
// with this walk none the wiser.
func sinkCallSites(decl ast.Decl, fset *token.FileSet, fileName string, sinks map[string]int) (sites []descSite, escapes []string) {
	fn, isFunc := decl.(*ast.FuncDecl)
	own := (*ast.Ident)(nil)
	if isFunc {
		own = fn.Name
	}
	// Package-level too: `var alias = writeOAuthError` never appears
	// inside a function body.
	escapes = sinkValueEscapes(decl, fset, fileName, sinks, own)
	if !isFunc {
		return nil, escapes
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		// Name, not Ident: a method call's Fun is a SelectorExpr, and a
		// method forwarding its desc parameter is a sink like any other
		// wrapper.
		callee, ok := calleeName(call.Fun)
		if !ok {
			return true
		}
		argPos, isSink := sinks[callee]
		if !isSink || len(call.Args) <= argPos {
			return true
		}
		sites = append(sites, descSite{
			where:  fmt.Sprintf("%s:%d", fileName, fset.Position(call.Pos()).Line),
			callee: callee, fn: fn, call: call, argPos: argPos,
		})
		return true
	})
	return sites, escapes
}

func TestWriteOAuthError_DescriptionsAreLiterals(t *testing.T) {
	fset := token.NewFileSet()
	files := parsePackage(t, fset)
	sinks := discoverSinks(files)
	for name := range sinkDescArg {
		if _, found := sinks[name]; !found {
			t.Fatalf("seed sink %q not found in the package — it was renamed and this test went blind", name)
		}
	}

	consts := packageStringConsts(files)
	sitesChecked := 0
	pairsChecked := 0
	for fileName, file := range files {
		for _, decl := range file.Decls {
			sites, escapes := sinkCallSites(decl, fset, fileName, sinks)
			for _, where := range escapes {
				t.Errorf("%s — a sink used as a value escapes the call-site walk; call it directly", where)
			}
			for _, site := range sites {
				sitesChecked++
				if !site.checkLiteral(t, sinks) {
					continue
				}
				// Pair check only where the code rides the same call: a
				// wrapper forwards whatever its caller passed, and that
				// caller is itself a site in this walk.
				if site.callee != "writeOAuthError" {
					continue
				}
				desc, ok := site.resolveDesc(t, consts)
				if !ok {
					continue
				}
				site.checkShape(t, desc)
				if site.checkPair(t, desc, consts) {
					pairsChecked++
				}
			}
		}
	}
	if sitesChecked < 117 {
		t.Fatalf("only %d sink call sites found, want >=117 — the package layout changed under this test", sitesChecked)
	}
	if pairsChecked < 96 {
		t.Fatalf("only %d (desc, code) pairs checked, want >=96 — descriptions stopped resolving to literals", pairsChecked)
	}
}

// parsePackage parses every non-test file of the package under test.
func parsePackage(t *testing.T, fset *token.FileSet) map[string]*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	files := map[string]*ast.File{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		files[e.Name()] = f
	}
	return files
}

// discoverSinks expands sinkDescArg to a fixpoint: a function that
// forwards one of its own string parameters into a known sink's desc
// position is a sink too, at that parameter's position. Iterating to a
// fixpoint catches wrappers of wrappers.
func discoverSinks(files map[string]*ast.File) map[string]int {
	sinks := map[string]int{}
	for k, v := range sinkDescArg {
		sinks[k] = v
	}
	for {
		grew := false
		for _, file := range files {
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				if _, known := sinks[fn.Name.Name]; known {
					continue
				}
				if pos, forwards := forwardedParamPos(fn, sinks); forwards {
					sinks[fn.Name.Name] = pos
					grew = true
				}
			}
		}
		if !grew {
			return sinks
		}
	}
}

// forwardedParamPos reports the position of the parameter fn passes into
// a known sink's desc position, if any.
// calleeName is the callee's identifier for both a plain call and a
// method call. Matching a method by its Sel.Name alone is deliberately
// loose — an unrelated method sharing a sink's name is reported rather
// than skipped, which is the safe direction for this guard.
func calleeName(fun ast.Expr) (string, bool) {
	switch v := fun.(type) {
	case *ast.Ident:
		return v.Name, true
	case *ast.SelectorExpr:
		return v.Sel.Name, true
	}
	return "", false
}

// sinkValueEscapes reports every place fn names a sink outside call
// position. Following the value would mean tracking assignments through
// the package; refusing it outright costs nothing, since no legitimate
// caller needs a handle to the error sink.
// own is the declaration's own name, skipped because a sink's own
// `func` header is a definition rather than a use; nil for package-level
// declarations, which have none.
func sinkValueEscapes(node ast.Node, fset *token.FileSet, fileName string, sinks map[string]int, own *ast.Ident) []string {
	called := map[*ast.Ident]bool{}
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok {
				called[id] = true
			}
		}
		return true
	})
	var out []string
	ast.Inspect(node, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || called[id] || (own != nil && id == own) {
			return true
		}
		if _, isSink := sinks[id.Name]; isSink {
			out = append(out, fmt.Sprintf("%s:%d: %s", fileName, fset.Position(id.Pos()).Line, id.Name))
		}
		return true
	})
	return out
}

func forwardedParamPos(fn *ast.FuncDecl, sinks map[string]int) (int, bool) {
	found, pos := false, 0
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee, ok := calleeName(call.Fun)
		if !ok {
			return true
		}
		argPos, isSink := sinks[callee]
		if !isSink || len(call.Args) <= argPos {
			return true
		}
		arg, ok := call.Args[argPos].(*ast.Ident)
		if !ok {
			return true
		}
		if p, isParam := paramIndex(fn, arg.Name); isParam {
			found, pos = true, p
		}
		return true
	})
	return pos, found
}

// paramIndex returns the flat position of a named parameter.
func paramIndex(fn *ast.FuncDecl, name string) (int, bool) {
	if fn.Type.Params == nil {
		return 0, false
	}
	i := 0
	for _, field := range fn.Type.Params.List {
		for _, n := range field.Names {
			if n.Name == name {
				return i, true
			}
			i++
		}
	}
	return 0, false
}

// checkLiteralExpr reports why an expression is not literal-built, or ""
// when it is. String literals, concatenations of them, package consts
// and locals assigned only literal-shaped values all qualify.
func checkLiteralExpr(e ast.Expr, fn *ast.FuncDecl, sinks map[string]int, depth int) string {
	if depth > 5 {
		return "identifier chain too deep to prove literal"
	}
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "non-string literal"
		}
		return ""
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "non-concatenation operator"
		}
		if msg := checkLiteralExpr(v.X, fn, sinks, depth+1); msg != "" {
			return msg
		}
		return checkLiteralExpr(v.Y, fn, sinks, depth+1)
	case *ast.ParenExpr:
		return checkLiteralExpr(v.X, fn, sinks, depth+1)
	case *ast.Ident:
		return checkIdent(v, fn, sinks, depth)
	default:
		return "expression is not literal-built (call, selector, index, …)"
	}
}

// checkIdent resolves an identifier appearing in a desc argument.
//
// A parameter is acceptable ONLY when the enclosing function is itself a
// sink: then its callers are sites this walk also visits, so the value is
// proven literal there. In any other function a parameter is an open
// door — that is the wrapper bypass this rule closes.
func checkIdent(id *ast.Ident, fn *ast.FuncDecl, sinks map[string]int, depth int) string {
	if _, isParam := paramIndex(fn, id.Name); isParam {
		if _, isSink := sinks[fn.Name.Name]; isSink {
			return ""
		}
		return "parameter " + id.Name + " of non-sink " + fn.Name.Name +
			" reaches the sink — its callers are not checked, so the value is unproven"
	}
	return checkLocalAssignments(id, fn, sinks, depth)
}

// checkLocalAssignments resolves a local: it qualifies when it has at
// least one literal-shaped assignment and no non-literal one. Two
// explicit values rather than a rebuilt default message, so "never
// assigned" and "assigned something non-literal" stay distinguishable.
func checkLocalAssignments(id *ast.Ident, fn *ast.FuncDecl, sinks map[string]int, depth int) string {
	sawLiteral := false
	firstFailure := ""
	ast.Inspect(fn, func(n ast.Node) bool {
		switch st := n.(type) {
		case *ast.AssignStmt:
			if msg, assigned := assignedLiteral(st, id.Name, fn, sinks, depth); assigned {
				if msg != "" && firstFailure == "" {
					firstFailure = "assignment to " + id.Name + ": " + msg
				} else if msg == "" {
					sawLiteral = true
				}
			}
		case *ast.RangeStmt:
			// `for _, x := range param` — x iterates a parameter's
			// elements, so the parameter rule applies to it.
			if v, ok := st.Value.(*ast.Ident); ok && v.Name == id.Name {
				if r, ok := st.X.(*ast.Ident); ok && checkIdent(r, fn, sinks, depth+1) == "" {
					sawLiteral = true
				}
			}
		}
		return true
	})
	if firstFailure != "" {
		return firstFailure
	}
	if !sawLiteral {
		return "identifier " + id.Name + " has no literal-shaped assignment in " + fn.Name.Name
	}
	return ""
}

// assignedLiteral reports whether st assigns to name, and if so whether
// the assigned expression is literal-built ("" means it is).
func assignedLiteral(st *ast.AssignStmt, name string, fn *ast.FuncDecl, sinks map[string]int, depth int) (msg string, assigned bool) {
	for i, lhs := range st.Lhs {
		l, ok := lhs.(*ast.Ident)
		if !ok || l.Name != name || i >= len(st.Rhs) {
			continue
		}
		if m := checkLiteralExpr(st.Rhs[i], fn, sinks, depth+1); m != "" {
			return m, true
		}
		return "", true
	}
	return "", false
}

// packageStringConsts collects the package's string constants so a
// description built from one resolves to its value.
func packageStringConsts(files map[string]*ast.File) map[string]string {
	consts := map[string]string{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if v, ok := literalValue(vs.Values[i], nil, consts); ok {
						consts[name.Name] = v
					}
				}
			}
		}
	}
	return consts
}

// literalValue evaluates a literal-built string expression. A
// concatenation with a non-literal part yields the "<var>" placeholder
// so descToCode can still pin the shape (see rejectRepeatedParams).
func literalValue(e ast.Expr, fn *ast.FuncDecl, consts map[string]string) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.Ident:
		if s, ok := consts[v.Name]; ok {
			return s, ok
		}
		// A local holding a literal is still a literal, and the pair
		// check must see through it: `d := "…"` is idiomatic Go, and
		// skipping it silently is how a swapped error_code shipped.
		return localLiteralValue(v.Name, fn, consts)
	case *ast.ParenExpr:
		return literalValue(v.X, fn, consts)
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		x, okX := literalValue(v.X, fn, consts)
		y, okY := literalValue(v.Y, fn, consts)
		switch {
		case okX && okY:
			return x + y, true
		case okY:
			return "<var>" + y, true
		case okX:
			return x + "<var>", true
		}
		return "", false
	}
	return "", false
}

// localLiteralValue resolves a local whose assignments are all literal
// (`d := "…"`). Any non-literal assignment disqualifies the name — a
// value that is literal on one path and not on another is not a
// literal. fn is nil when resolving package-level declarations, which
// have no locals.
func localLiteralValue(name string, fn *ast.FuncDecl, consts map[string]string) (string, bool) {
	if fn == nil {
		return "", false
	}
	value, found := "", false
	ast.Inspect(fn, func(n ast.Node) bool {
		st, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range st.Lhs {
			l, ok := lhs.(*ast.Ident)
			if !ok || l.Name != name || i >= len(st.Rhs) {
				continue
			}
			v, ok := literalValue(st.Rhs[i], fn, consts)
			if !ok {
				value, found = "", false
				return false
			}
			value, found = v, true
		}
		return true
	})
	return value, found
}

// Every error_code a browser can actually reach must carry an explicit
// advice decision. Derived from the source, not restated: the codes are
// collected from the error_code argument of every sink call in the
// three browser-facing handlers, so a new call site cannot inherit
// "contact the administrator" by omission — which is how
// client_audience_mismatch shipped advising an operator for a failure
// its two documented siblings clear with "reconnect".
//
// hintContact stays legitimate for the failures a user genuinely cannot
// clear; the point is that it has to be chosen, so unmappedIsDeliberate
// is the record of that choice.
func TestBrowserReachableCodes_HaveDeliberateAdvice(t *testing.T) {
	// Codes that correctly fall through to hintContact: an internal
	// failure, or a rejection only an operator can clear.
	unmappedIsDeliberate := map[string]bool{
		codeClientIDMissing:           true, // malformed client request
		codeRedirectURIMissing:        true, // client misconfiguration
		codeRedirectURIMalformed:      true, // invariant violation
		codeCodeSealFailed:            true, // internal
		codeInterstitialFailed:        true, // internal
		codeIDTokenMissing:            true, // IdP misconfiguration
		codeIDTokenVerificationFailed: true, // IdP misconfiguration or attack
		codeIDTokenClaimsUnparsable:   true, // IdP schema drift
		codeSubjectMissing:            true, // IdP schema drift
		codeGroupInvalid:              true, // IdP data defect
		codeGroupNotAllowed:           true, // access policy: only an admin grants it
		codeIdPExchangeThrottled:      true, // transientCodes carries it
		codeReplayStoreUnavailable:    true, // capacityHints carries it
	}

	fset := token.NewFileSet()
	files := parsePackage(t, fset)
	sinks := discoverSinks(files)
	consts := packageStringConsts(files)

	// Same walk the literal guard uses, rather than a second hand-rolled
	// one: two walks would drift, and this one already knows how to see
	// through method calls and wrappers.
	reached := map[string]string{}
	for fileName, file := range files {
		switch fileName {
		case "authorize.go", "consent.go", "callback.go", "error_page.go":
		default:
			continue
		}
		for _, decl := range file.Decls {
			sites, _ := sinkCallSites(decl, fset, fileName, sinks)
			for _, site := range sites {
				// The error_code rides immediately after the description.
				if site.callee != "writeOAuthError" || len(site.call.Args) <= site.argPos+1 {
					continue
				}
				id, ok := site.call.Args[site.argPos+1].(*ast.Ident)
				if !ok {
					continue
				}
				if value, isCode := consts[id.Name]; isCode && strings.HasPrefix(id.Name, "code") {
					reached[id.Name] = value
				}
			}
		}
	}

	// The pre-rendered 405 body never passes through a sink call.
	reached["codeMethodNotAllowed"] = codeMethodNotAllowed

	if len(reached) < 20 {
		t.Fatalf("only %d browser-reachable error_codes found, want >=20 — the walk went blind", len(reached))
	}
	for name, value := range reached {
		if _, mapped := codeHints[value]; mapped {
			continue
		}
		if unmappedIsDeliberate[value] {
			continue
		}
		t.Errorf("%s (%q) is browser-reachable but has no codeHints row and is not listed as deliberately unmapped — the user silently gets %q",
			name, value, hintContact)
	}
}

// Cache-Control/Pragma is a pair: setting one without the other, or
// setting them at a new site, is how a flow-state response drifts into
// a shared cache. noStore is the single owner, so the literals must not
// appear anywhere else in the package.
func TestNoStore_IsTheOnlyCacheHeaderWriter(t *testing.T) {
	for fileName, file := range parsePackage(t, token.NewFileSet()) {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name == "noStore" {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				switch lit.Value {
				case `"Cache-Control"`, `"Pragma"`:
					t.Errorf("%s: %s writes %s directly — call noStore(h) so the pair cannot drift apart",
						fileName, fn.Name.Name, lit.Value)
				}
				return true
			})
		}
	}
}
