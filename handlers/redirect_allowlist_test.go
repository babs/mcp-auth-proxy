package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/babs/mcp-auth-proxy/config"
	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/replay"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const (
	notAllowlistedErr      = "redirect_uri is not allowlisted by the operator"
	noLongerAllowlistedErr = "client redirect_uri is no longer allowlisted by the operator"
)

func mustWebAllowlist(t *testing.T, raw string) config.WebRedirectAllowlist {
	t.Helper()
	a, err := config.ParseWebRedirectAllowlist(raw)
	if err != nil {
		t.Fatalf("ParseWebRedirectAllowlist(%q): %v", raw, err)
	}
	return a
}

func notAllowlistedDenials() float64 {
	return testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("redirect_uri_not_allowlisted"))
}

// assertNotAllowlisted checks a refusal's body, its metric and its log
// line; field/value names the endpoint-specific log field.
func assertNotAllowlisted(t *testing.T, rr *httptest.ResponseRecorder, logs *observer.ObservedLogs, before float64, wantErr, wantDesc, field, value string) {
	t.Helper()
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want none: the refusal must not reach the client's redirect_uri", loc)
	}
	var oe OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oe); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if oe.Error != wantErr || oe.ErrorDescription != wantDesc || oe.ErrorCode != codeRedirectURIMismatch {
		t.Errorf("got %q / %q / %q, want %q / %q / %q", oe.Error, oe.ErrorDescription, oe.ErrorCode, wantErr, wantDesc, codeRedirectURIMismatch)
	}
	if got := notAllowlistedDenials() - before; got != 1 {
		t.Errorf("access_denied{redirect_uri_not_allowlisted} delta = %v, want 1", got)
	}
	entries := logs.FilterMessage("access_denied_redirect_uri_not_allowlisted").All()
	if len(entries) != 1 {
		t.Fatalf("want 1 denial log, got %d", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["internal_id"] == "" || fields["internal_id"] == nil || fields["error"] == nil || fields[field] != value {
		t.Errorf("denial log fields = %v, want internal_id, error, %s=%s", fields, field, value)
	}
}

// TestRegister_RedirectURIsAllowlist pins how REDIRECT_URIS_ALLOWLIST
// narrows /register: once set, only listed http(s) URIs pass (scheme
// case-insensitive, loopback entries with any port), every URI of a
// request must pass, custom schemes keep their own list, and the shape
// rules still answer first.
func TestRegister_RedirectURIsAllowlist(t *testing.T) {
	const (
		listed    = "https://allowed.example/cb"
		loopback  = "http://127.0.0.1/cb"
		both      = listed + "," + loopback
		schemeErr = "redirect_uri must be http (loopback only), https, or a URI allowlisted by the operator"
	)
	for _, tc := range []struct {
		name      string
		allowlist string
		extra     string
		uris      []string
		wantErr   string // "" = 201
	}{
		{"unset accepts any https", "", "", []string{"https://other.example/cb"}, ""},
		{"unset accepts any loopback", "", "", []string{"http://localhost:49152/cb"}, ""},
		{"listed https accepted", both, "", []string{listed}, ""},
		{"upper-case scheme accepted", both, "", []string{"HTTPS://allowed.example/cb"}, ""},
		{"unlisted https rejected", both, "", []string{"https://other.example/cb"}, notAllowlistedErr},
		{"longer path rejected", both, "", []string{listed + "x"}, notAllowlistedErr},
		{"added query rejected", both, "", []string{listed + "?x=1"}, notAllowlistedErr},
		{"other port rejected for https", both, "", []string{"https://allowed.example:8443/cb"}, notAllowlistedErr},
		{"upper-case host rejected", both, "", []string{"https://ALLOWED.example/cb"}, notAllowlistedErr},
		{"loopback entry accepts any port", both, "", []string{"http://127.0.0.1:49152/cb"}, ""},
		{"loopback entry accepts its own form", both, "", []string{loopback}, ""},
		{"loopback literal must match", both, "", []string{"http://localhost:49152/cb"}, notAllowlistedErr},
		{"loopback path must match", both, "", []string{"http://127.0.0.1:49152/other"}, notAllowlistedErr},
		{"loopback not implicit once set", listed, "", []string{"http://127.0.0.1:49152/cb"}, notAllowlistedErr},
		{"every URI must pass", both, "", []string{listed, "https://other.example/cb"}, notAllowlistedErr},
		{"two listed URIs accepted", both, "", []string{listed, "http://127.0.0.1:1/cb"}, ""},
		// Custom schemes are judged by REDIRECT_URIS_EXTRA, never by this list.
		{"custom scheme still under EXTRA", listed, "warp://*", []string{warpURI}, ""},
		{"custom scheme without EXTRA still rejected", listed, "", []string{warpURI}, schemeErr},
		{"non-loopback http keeps its error", both, "", []string{"http://allowed.example/cb"}, "redirect_uri must use HTTPS for non-loopback addresses"},
		{"fragment keeps its error", both, "", []string{listed + "#f"}, "redirect_uri must not contain a fragment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			regCfg := RegisterConfig{ClientTTL: DefaultClientTTL, RedirectURIsExtra: mustAllowlist(t, tc.extra), RedirectURIsAllowlist: mustWebAllowlist(t, tc.allowlist)}
			Register(newTestTokenManager(t), zap.NewNop(), testBaseURL, regCfg)(rr, newRegisterRequest(tc.uris))
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

// TestRegister_RedirectURIsAllowlistLogsRefusal pins the operator signal
// for a typo in the list: scheme, host and path, never the query.
func TestRegister_RedirectURIsAllowlistLogsRefusal(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	rr := httptest.NewRecorder()
	regCfg := RegisterConfig{ClientTTL: DefaultClientTTL, RedirectURIsAllowlist: mustWebAllowlist(t, "https://allowed.example/cb")}
	Register(newTestTokenManager(t), zap.New(core), testBaseURL, regCfg)(rr, newRegisterRequest([]string{"https://other.example/cb/x?tenant=secret"}))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	entries := logs.FilterMessage("register_redirect_uri_not_allowlisted").All()
	if len(entries) != 1 {
		t.Fatalf("want 1 refusal log, got %d", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["scheme"] != "https" || fields["host"] != "other.example" || fields["path"] != "/cb/x" {
		t.Errorf("refusal log fields = %v, want scheme=https host=other.example path=/cb/x", fields)
	}
	for k, v := range fields {
		if s, ok := v.(string); ok && strings.Contains(s, "secret") {
			t.Errorf("refusal log field %s = %q carries the query", k, s)
		}
	}

	// The client chose these bytes: a BiDi override or NEL in the host must
	// not reach the log (CWE-117).
	core, logs = observer.New(zap.WarnLevel)
	rr = httptest.NewRecorder()
	Register(newTestTokenManager(t), zap.New(core), testBaseURL, regCfg)(rr, newRegisterRequest([]string{"https://\u202eevil.example\u0085/cb"}))
	entries = logs.FilterMessage("register_redirect_uri_not_allowlisted").All()
	if rr.Code != http.StatusBadRequest || len(entries) != 1 {
		t.Fatalf("want 400 and 1 refusal log, got %d and %d: %s", rr.Code, len(entries), rr.Body.String())
	}
	for k, v := range entries[0].ContextMap() {
		s, _ := v.(string)
		for _, c := range []byte(s) {
			if c < 0x20 || c > 0x7e {
				t.Errorf("refusal log field %s = %q carries a non-printable or non-ASCII byte", k, s)
				break
			}
		}
	}
}

// TestWriteRedirectShapeError_DistinctDescriptions pins one fixed
// description per config.CheckRedirectShape error, none falling through
// to the default.
func TestWriteRedirectShapeError_DistinctDescriptions(t *testing.T) {
	const fallback = "redirect_uri is not allowed"
	unmapped := errors.New("unmapped")
	seen := map[string]error{}
	for _, err := range []error{
		config.ErrRedirectTooLong,
		config.ErrRedirectMalformed,
		config.ErrRedirectOpaque,
		config.ErrRedirectNoHost,
		config.ErrRedirectFragment,
		config.ErrRedirectUserinfo,
		config.ErrRedirectHTTPNotLoopback,
		unmapped,
	} {
		rr := httptest.NewRecorder()
		writeRedirectShapeError(rr, httptest.NewRequest(http.MethodPost, "/register", nil), err)
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
		if (oe.ErrorDescription == fallback) != (err == unmapped) {
			t.Errorf("%v: description %q, fallback only for unmapped errors", err, oe.ErrorDescription)
		}
		want := "redirect_uri " + err.Error()
		if err == config.ErrRedirectMalformed {
			want = "malformed redirect_uri"
		}
		if err != unmapped && oe.ErrorDescription != want {
			t.Errorf("%v: description %q, want %q", err, oe.ErrorDescription, want)
		}
	}
}

// TestRegister_EveryAllowlistEntryRegistrable pins the promise the
// shared shape check exists for: whatever the startup check accepts, a
// client can register under a list containing it.
func TestRegister_EveryAllowlistEntryRegistrable(t *testing.T) {
	for _, entry := range []string{
		"https://app.example.com/oauth/callback",
		"http://127.0.0.1/cb",
		"http://localhost/cb?x=1",
		"http://[::1]/cb",
		"http://localhost./cb",
		"HTTPS://App.Example.com/cb",
		"https://app.example.com:8443/cb",
		"https://x/" + strings.Repeat("a", 502),
	} {
		t.Run(entry[:min(len(entry), 40)], func(t *testing.T) {
			rr := httptest.NewRecorder()
			regCfg := RegisterConfig{ClientTTL: DefaultClientTTL, RedirectURIsAllowlist: mustWebAllowlist(t, entry)}
			Register(newTestTokenManager(t), zap.NewNop(), testBaseURL, regCfg)(rr, newRegisterRequest([]string{entry}))
			if rr.Code != http.StatusCreated {
				t.Fatalf("entry %q accepted at startup but not registrable: %d %s", entry, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestAuthorize_RedirectURIsAllowlistRecheck pins the /authorize
// re-check on the requested URI: a client registered before the list
// was set, under an entry since removed, or asking for its unlisted URI
// while another of its URIs is listed, is refused on the AS, with or
// without the consent page.
func TestAuthorize_RedirectURIsAllowlistRecheck(t *testing.T) {
	const requested = "https://second.example/cb"
	for _, tc := range []struct {
		name       string
		atRegister string
		registered []string
	}{
		{"list set after registration", "", []string{requested}},
		{"entry removed", "https://allowed.example/cb," + requested, []string{requested}},
		{"another registered URI listed", "", []string{"https://allowed.example/cb", requested}},
	} {
		for _, consent := range []bool{false, true} {
			name := tc.name
			if consent {
				name += " with consent page"
			}
			t.Run(name, func(t *testing.T) {
				tm := newTestTokenManager(t)
				clientID, _ := registerClientWith(t, tm, RegisterConfig{ClientTTL: DefaultClientTTL, RedirectURIsAllowlist: mustWebAllowlist(t, tc.atRegister)}, tc.registered)
				before := notAllowlistedDenials()
				core, logs := observer.New(zap.WarnLevel)
				cfg := AuthorizeConfig{PKCERequired: true, RenderConsentPage: consent, RedirectURIsAllowlist: mustWebAllowlist(t, "https://allowed.example/cb")}
				rr := authorizeCustom(t, tm, zap.New(core), clientID, requested, true, cfg)
				assertNotAllowlisted(t, rr, logs, before, "invalid_request", notAllowlistedErr, "scheme", "https")
			})
		}
	}
}

// TestAuthorize_RedirectURIsAllowlistPasses pins that listed clients
// keep working: exact https, loopback on another port than registered,
// and custom schemes, which this list never judges.
func TestAuthorize_RedirectURIsAllowlistPasses(t *testing.T) {
	for _, tc := range []struct {
		name, registered, requested string
	}{
		{"listed https", "https://allowed.example/cb", "https://allowed.example/cb"},
		{"loopback on another port", "http://127.0.0.1:5000/cb", "http://127.0.0.1:6000/cb"},
		{"custom scheme ignores the list", warpURI, warpURI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tm := newTestTokenManager(t)
			allow := mustWebAllowlist(t, "https://allowed.example/cb,http://127.0.0.1/cb")
			extra := mustAllowlist(t, "warp://*")
			clientID, _ := registerClientWith(t, tm, RegisterConfig{ClientTTL: DefaultClientTTL, RedirectURIsExtra: extra, RedirectURIsAllowlist: allow}, []string{tc.registered})
			rr := authorizeCustom(t, tm, zap.NewNop(), clientID, tc.requested, true, AuthorizeConfig{PKCERequired: true, RedirectURIsExtra: extra, RedirectURIsAllowlist: allow})
			if rr.Code != http.StatusFound {
				t.Fatalf("want 302, got %d: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

// postGrant runs /token with form under cfg against store.
func postGrant(t *testing.T, tm *token.Manager, logger *zap.Logger, store replay.Store, cfg TokenConfig, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	Token(tm, logger, testBaseURL, time.Time{}, store, cfg)(rr, req)
	return rr
}

// sealSession seals a refresh token for clientUUID whose code was issued
// for its registered redirect URI number uriIndex (1-based; 0 = a token
// sealed before the field existed).
func sealSession(t *testing.T, tm *token.Manager, clientUUID string, uriIndex int) string {
	t.Helper()
	now := time.Now()
	tok, err := tm.SealJSON(sealedRefresh{
		TokenID: uuid.New().String(), FamilyID: uuid.New().String(),
		Subject: "user", Email: "u@example.com", ClientID: clientUUID,
		Typ: token.PurposeRefresh, Audience: testBaseURL, RedirectURIIndex: uriIndex,
		IssuedAt: now, FamilyIssuedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour),
	}, token.PurposeRefresh)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	return tok
}

// sealClientDirect seals a client_id without /register, for registrations
// an older release could have made.
func sealClientDirect(t *testing.T, tm *token.Manager, uris []string) (encClientID, internalID string) {
	t.Helper()
	sc := sealedClient{ID: uuid.New().String(), RedirectURIs: uris, Typ: token.PurposeClient, Audience: testBaseURL, ExpiresAt: time.Now().Add(time.Hour)}
	enc, err := tm.SealJSON(sc, token.PurposeClient)
	if err != nil {
		t.Fatalf("SealJSON: %v", err)
	}
	return enc, sc.ID
}

func refreshForm(encClientID, refreshToken string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {encClientID}}
}

// TestToken_RefreshJudgesSessionURI pins the refresh re-check on the URI
// the session was issued for: one listed sibling does not keep alive a
// session obtained through an unlisted URI; the refusal burns nothing;
// rotation carries the URI forward.
func TestToken_RefreshJudgesSessionURI(t *testing.T) {
	const listed, unlisted = "https://allowed.example/cb", "https://second.example/cb"
	tm := newTestTokenManager(t)
	store := replay.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })
	encClientID, internalID := registerClient(t, tm, []string{unlisted, listed})
	onlyListed := TokenConfig{RedirectURIsAllowlist: mustWebAllowlist(t, listed)}

	t.Run("session through the unlisted URI is refused", func(t *testing.T) {
		form := refreshForm(encClientID, sealSession(t, tm, internalID, 1))
		before := notAllowlistedDenials()
		core, logs := observer.New(zap.WarnLevel)
		rr := postGrant(t, tm, zap.New(core), store, onlyListed, form)
		assertNotAllowlisted(t, rr, logs, before, "invalid_grant", noLongerAllowlistedErr, "grant_type", "refresh_token")

		rr = postGrant(t, tm, zap.NewNop(), store, TokenConfig{RedirectURIsAllowlist: mustWebAllowlist(t, listed+","+unlisted)}, form)
		if rr.Code != http.StatusOK {
			t.Fatalf("listed again: want 200 with the same refresh token, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("session through the listed URI survives and rotation keeps the URI", func(t *testing.T) {
		rr := postGrant(t, tm, zap.NewNop(), store, onlyListed, refreshForm(encClientID, sealSession(t, tm, internalID, 2)))
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var resp map[string]any
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		rotated, _ := resp["refresh_token"].(string)
		var sr sealedRefresh
		if err := tm.OpenJSON(rotated, &sr, token.PurposeRefresh); err != nil {
			t.Fatalf("OpenJSON rotated: %v", err)
		}
		if sr.RedirectURIIndex != 2 {
			t.Fatalf("rotated RedirectURIIndex = %d, want 2", sr.RedirectURIIndex)
		}
		rr = postGrant(t, tm, zap.NewNop(), store, TokenConfig{RedirectURIsAllowlist: mustWebAllowlist(t, unlisted)}, refreshForm(encClientID, rotated))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("rotated token after narrowing: want 400, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// TestToken_RefreshLegacyTokenNeedsEveryURI pins the fallback for refresh
// tokens sealed before the session URI existed: every registered URI must
// be admitted, http(s) by REDIRECT_URIS_ALLOWLIST and custom schemes by
// REDIRECT_URIS_EXTRA.
func TestToken_RefreshLegacyTokenNeedsEveryURI(t *testing.T) {
	const listed = "https://allowed.example/cb"
	for _, tc := range []struct {
		name, extra string
		uris        []string
		index       int
		wantCode    int
	}{
		{"one unlisted sibling refuses", "warp://*", []string{"https://second.example/cb", listed}, 0, http.StatusBadRequest},
		{"every URI listed passes", "warp://*", []string{listed}, 0, http.StatusOK},
		{"custom-scheme sibling still in REDIRECT_URIS_EXTRA passes", "warp://*", []string{warpURI, listed}, 0, http.StatusOK},
		{"custom-scheme sibling dropped from REDIRECT_URIS_EXTRA refuses", "", []string{warpURI, listed}, 0, http.StatusBadRequest},
		{"out-of-range index falls back", "warp://*", []string{"https://second.example/cb", listed}, 7, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tm := newTestTokenManager(t)
			encClientID, internalID := registerClientWith(t, tm, RegisterConfig{ClientTTL: DefaultClientTTL, RedirectURIsExtra: mustAllowlist(t, "warp://*")}, tc.uris)
			cfg := TokenConfig{RedirectURIsExtra: mustAllowlist(t, tc.extra), RedirectURIsAllowlist: mustWebAllowlist(t, listed)}
			rr := postGrant(t, tm, zap.NewNop(), nil, cfg, refreshForm(encClientID, sealSession(t, tm, internalID, tc.index)))
			if rr.Code != tc.wantCode {
				t.Fatalf("want %d, got %d: %s", tc.wantCode, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestToken_RefreshAllowlistPasses pins sessions that keep refreshing:
// loopback on another port, a custom-scheme session still in
// REDIRECT_URIS_EXTRA whatever REDIRECT_URIS_ALLOWLIST says, and an unset
// list, which changes nothing even for registrations today's /register
// would refuse.
func TestToken_RefreshAllowlistPasses(t *testing.T) {
	for _, tc := range []struct {
		name, allowlist string
		session         int
		uris            []string
	}{
		{"loopback registered with a port", "http://127.0.0.1/cb", 1, []string{"http://127.0.0.1:5000/cb"}},
		{"custom-scheme session", "https://allowed.example/cb", 1, []string{warpURI}},
		{"custom-scheme session, list unset", "", 1, []string{warpURI}},
		{"list unset", "", 1, []string{"https://second.example/cb"}},
		{"list unset, unparsable legacy URI", "", 0, []string{"https://app.example.com/%zz"}},
		{"list unset, no registered URI", "", 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tm := newTestTokenManager(t)
			encClientID, internalID := sealClientDirect(t, tm, tc.uris)
			cfg := TokenConfig{RedirectURIsExtra: mustAllowlist(t, "warp://*"), RedirectURIsAllowlist: mustWebAllowlist(t, tc.allowlist)}
			rr := postGrant(t, tm, zap.NewNop(), nil, cfg, refreshForm(encClientID, sealSession(t, tm, internalID, tc.session)))
			if rr.Code != http.StatusOK {
				t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestToken_CodeJudgesItsRedirectURI pins the code-grant re-check on the
// code's own redirect_uri (another listed URI of the client does not
// help), before the single-use claim, and that the issued refresh token
// carries that URI.
func TestToken_CodeJudgesItsRedirectURI(t *testing.T) {
	const listed, unlisted = "https://allowed.example/cb", "https://second.example/cb"
	tm := newTestTokenManager(t)
	store := replay.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })
	encClientID, internalID := registerClient(t, tm, []string{listed, unlisted})
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {sealCode(t, tm, internalID, unlisted, pkceChallenge(fwdVerifier), "user", "u@example.com")},
		"redirect_uri":  {unlisted},
		"client_id":     {encClientID},
		"code_verifier": {fwdVerifier},
	}

	before := notAllowlistedDenials()
	core, logs := observer.New(zap.WarnLevel)
	rr := postGrant(t, tm, zap.New(core), store, TokenConfig{RedirectURIsAllowlist: mustWebAllowlist(t, listed)}, form)
	assertNotAllowlisted(t, rr, logs, before, "invalid_grant", noLongerAllowlistedErr, "grant_type", "authorization_code")

	rr = postGrant(t, tm, zap.NewNop(), store, TokenConfig{RedirectURIsAllowlist: mustWebAllowlist(t, unlisted)}, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("listed again: want 200 with the same code, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var sr sealedRefresh
	refreshToken, _ := resp["refresh_token"].(string)
	if err := tm.OpenJSON(refreshToken, &sr, token.PurposeRefresh); err != nil {
		t.Fatalf("OpenJSON: %v", err)
	}
	if sr.RedirectURIIndex != 2 {
		t.Errorf("issued refresh RedirectURIIndex = %d, want 2 (the code's %q)", sr.RedirectURIIndex, unlisted)
	}
}

// TestToken_CodeIndexesLoopbackRegistration pins that a code issued on
// another loopback port than registered still records which registered
// URI it used, so its refreshes are judged and pass.
func TestToken_CodeIndexesLoopbackRegistration(t *testing.T) {
	tm := newTestTokenManager(t)
	encClientID, internalID := registerClient(t, tm, []string{"https://other.example/cb", "http://127.0.0.1:5000/cb"})
	allow := TokenConfig{RedirectURIsAllowlist: mustWebAllowlist(t, "http://127.0.0.1/cb")}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {sealCode(t, tm, internalID, "http://127.0.0.1:6000/cb", pkceChallenge(fwdVerifier), "user", "u@example.com")},
		"redirect_uri":  {"http://127.0.0.1:6000/cb"},
		"client_id":     {encClientID},
		"code_verifier": {fwdVerifier},
	}
	rr := postGrant(t, tm, zap.NewNop(), nil, allow, form)
	if rr.Code != http.StatusOK {
		t.Fatalf("code grant: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	refreshToken, _ := resp["refresh_token"].(string)
	var sr sealedRefresh
	if err := tm.OpenJSON(refreshToken, &sr, token.PurposeRefresh); err != nil {
		t.Fatalf("OpenJSON: %v", err)
	}
	if sr.RedirectURIIndex != 2 {
		t.Fatalf("RedirectURIIndex = %d, want 2", sr.RedirectURIIndex)
	}
	if rr := postGrant(t, tm, zap.NewNop(), nil, allow, refreshForm(encClientID, refreshToken)); rr.Code != http.StatusOK {
		t.Fatalf("refresh: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestToken_RefreshFromNearCapCodeOpens pins that a long redirect URI
// does not make the refresh token outgrow its code (both share one open()
// size cap): a code just under the cap, with a 512-char redirect URI,
// still yields a refresh token the next refresh grant can open.
func TestToken_RefreshFromNearCapCodeOpens(t *testing.T) {
	tm := newTestTokenManager(t)
	long := "https://x.example/" + strings.Repeat("p", 512-len("https://x.example/"))
	encClientID, internalID := registerClient(t, tm, []string{long})
	var code string
	for groups := []string{}; ; groups = append(groups, fmt.Sprintf("group-%04d-%s", len(groups), strings.Repeat("g", 20))) {
		sealed, err := tm.SealJSON(sealedCode{
			TokenID: uuid.New().String(), FamilyID: uuid.New().String(), ClientID: internalID,
			RedirectURI: long, CodeChallenge: pkceChallenge(fwdVerifier), Subject: "user", Email: "u@example.com",
			Groups: groups, Typ: token.PurposeCode, Audience: testBaseURL, ExpiresAt: time.Now().Add(5 * time.Minute),
		}, token.PurposeCode)
		if err != nil {
			t.Fatal(err)
		}
		if !tm.FitsOpenCap(sealed, token.PurposeCode) {
			break
		}
		code = sealed
	}
	if !tm.FitsOpenCap(code, token.PurposeCode) || tm.FitsOpenCap(code+strings.Repeat("A", 64), token.PurposeCode) {
		t.Fatalf("probe code is %d bytes, not within 64 bytes of the cap", len(code))
	}
	allow := TokenConfig{RedirectURIsAllowlist: mustWebAllowlist(t, long)}
	rr := postGrant(t, tm, zap.NewNop(), nil, allow, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {long},
		"client_id": {encClientID}, "code_verifier": {fwdVerifier},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("code grant: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	refreshToken, _ := resp["refresh_token"].(string)
	if rr := postGrant(t, tm, zap.NewNop(), nil, allow, refreshForm(encClientID, refreshToken)); rr.Code != http.StatusOK {
		t.Fatalf("refresh of a near-cap code's token: want 200, got %d: %s (code %d bytes, refresh %d bytes)", rr.Code, rr.Body.String(), len(code), len(refreshToken))
	}
}
