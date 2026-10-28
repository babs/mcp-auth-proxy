package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
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
	cimdAppRedirect = "https://app.example/cb"
	cimdAppName     = "CIMD Example App"
)

// cimdDocServer serves the document body(clientID) at /client.json and
// counts hits; the client_id is the server's own URL.
func cimdDocServer(t *testing.T, body func(id string) string) (srv *httptest.Server, clientID string, hits *atomic.Int32) {
	t.Helper()
	hits = &atomic.Int32{}
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body(clientID)))
	}))
	t.Cleanup(srv.Close)
	clientID = cimdURL(t, srv, "/client.json")
	return srv, clientID, hits
}

func cimdValidDoc(id string) string {
	return `{"client_id":` + jsonStr(id) + `,"client_name":` + jsonStr(cimdAppName) + `,"redirect_uris":[` + jsonStr(cimdAppRedirect) + `]}`
}

func authorizeCIMD(t *testing.T, tm *token.Manager, logger *zap.Logger, clientID, redirectURI string, cfg AuthorizeConfig, accept string) *httptest.ResponseRecorder {
	t.Helper()
	params := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "state": {"s"},
		"code_challenge": {pkceChallenge(fwdVerifier)}, "code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rr := httptest.NewRecorder()
	BrowserFacing(Authorize(tm, logger, testBaseURL, testOAuth2Config(), cfg)).ServeHTTP(rr, req)
	return rr
}

// MAP-002-AC8
func TestAuthorize_CIMDDisabled(t *testing.T) {
	_, clientID, hits := cimdDocServer(t, cimdValidDoc)
	before := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("client_id_invalid"))
	rr := authorizeCIMD(t, newTestTokenManager(t), zap.NewNop(), clientID, cimdAppRedirect, AuthorizeConfig{PKCERequired: true}, "")
	var oe OAuthError
	if err := json.NewDecoder(rr.Body).Decode(&oe); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rr.Code != http.StatusBadRequest || oe.Error != "invalid_client" || oe.ErrorCode != codeClientIDUnknown {
		t.Fatalf("got %d %+v, want 400 invalid_client / %s", rr.Code, oe, codeClientIDUnknown)
	}
	if got := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("client_id_invalid")) - before; got != 1 {
		t.Errorf("access_denied{client_id_invalid} delta = %v, want 1", got)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("document server hits = %d, want 0 with CIMD disabled", n)
	}
}

// MAP-002-AC6: a redirect_uri outside the document is refused on the AS
// with the exact shape a DCR client gets.
func TestAuthorize_CIMDRedirectMismatch(t *testing.T) {
	tm := newTestTokenManager(t)
	srv, clientID, _ := cimdDocServer(t, cimdValidDoc)
	decode := func(rr *httptest.ResponseRecorder) OAuthError {
		t.Helper()
		if rr.Code != http.StatusBadRequest || rr.Header().Get("Location") != "" {
			t.Fatalf("want 400 on the AS without Location, got %d Location=%q: %s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
		}
		var oe OAuthError
		if err := json.NewDecoder(rr.Body).Decode(&oe); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return oe
	}
	cimd := decode(authorizeCIMD(t, tm, zap.NewNop(), clientID, "https://evil.example/cb", AuthorizeConfig{PKCERequired: true, CIMD: newTestCIMDResolver(t, srv, "")}, ""))
	encClientID, _ := registerClient(t, tm, []string{cimdAppRedirect})
	dcr := decode(authorizeCIMD(t, tm, zap.NewNop(), encClientID, "https://evil.example/cb", AuthorizeConfig{PKCERequired: true}, ""))
	if cimd.Error != "invalid_request" || cimd.ErrorCode != codeRedirectURIMismatch {
		t.Errorf("CIMD mismatch = %+v, want invalid_request / %s", cimd, codeRedirectURIMismatch)
	}
	if cimd != dcr {
		t.Errorf("CIMD mismatch %+v differs from the DCR mismatch %+v", cimd, dcr)
	}
}

// A resolved document is the registration: the session binds the URL.
func TestAuthorize_CIMDResolvedClient(t *testing.T) {
	tm := newTestTokenManager(t)
	srv, clientID, hits := cimdDocServer(t, cimdValidDoc)
	rr := authorizeCIMD(t, tm, zap.NewNop(), clientID, cimdAppRedirect, AuthorizeConfig{PKCERequired: true, CIMD: newTestCIMDResolver(t, srv, "")}, "")
	if rr.Code != http.StatusFound {
		t.Fatalf("want 302, got %d: %s", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	var session sealedSession
	if err := tm.OpenJSON(loc.Query().Get("state"), &session, token.PurposeSession); err != nil {
		t.Fatalf("open state: %v", err)
	}
	if session.ClientID != clientID || session.RedirectURI != cimdAppRedirect {
		t.Errorf("session = client %q redirect %q, want %q / %q", session.ClientID, session.RedirectURI, clientID, cimdAppRedirect)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("document server hits = %d, want 1", n)
	}
}

// Every resolution failure maps to one of the two metadata codes, with
// its own denial reason and the advice a browser gets.
func TestAuthorize_CIMDResolveFailures(t *testing.T) {
	cases := []struct {
		name     string
		body     func(id string) string
		status   int
		clientID string // "" = the document server's URL
		guarded  bool   // production dial guard
		result   cimdResult
		wantCode string
		wantHint string
	}{
		{name: "url_invalid", clientID: "https://meta.example", body: cimdValidDoc, result: cimdURLInvalid, wantCode: codeClientMetadataInvalid, wantHint: hintClientPublisher},
		{name: "doc_invalid", body: func(id string) string { return cimdValidDoc(id + "/") }, result: cimdDocInvalid, wantCode: codeClientMetadataInvalid, wantHint: hintClientPublisher},
		{name: "auth_method_unsupported", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"private_key_jwt"}`
		}, result: cimdAuthMethodUnsupported, wantCode: codeClientMetadataInvalid, wantHint: hintClientPublisher},
		{name: "fetch_error", body: cimdValidDoc, status: http.StatusNotFound, result: cimdFetchError, wantCode: codeClientMetadataUnavailable, wantHint: hintTransientRestart},
		{name: "too_large", body: func(id string) string {
			return cimdValidDoc(id)[:len(cimdValidDoc(id))-1] + `,"pad":"` + strings.Repeat("a", cimdMaxBodyBytes) + `"}`
		}, result: cimdTooLarge, wantCode: codeClientMetadataUnavailable, wantHint: hintTransientRestart},
		{name: "ssrf_blocked", body: cimdValidDoc, guarded: true, result: cimdSSRFBlocked, wantCode: codeClientMetadataUnavailable, wantHint: hintTransientRestart},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var srv *httptest.Server
			var clientID string
			srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				_, _ = w.Write([]byte(tc.body(clientID)))
			}))
			defer srv.Close()
			clientID = cimdURL(t, srv, "/client.json")
			if tc.clientID != "" {
				clientID = tc.clientID
			}
			opts := CIMDResolverOptions{DialGuardOverride: allowLoopbackDial, TLSClientConfigOverride: trustTestServer(srv)}
			if tc.guarded {
				opts.DialGuardOverride = nil
			}
			cfg := AuthorizeConfig{PKCERequired: true, CIMD: NewCIMDResolver(zap.NewNop(), config.RedirectAllowlist{}, config.WebRedirectAllowlist{}, opts)}
			reason := "cimd_" + string(tc.result)
			before := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues(reason))

			rr := authorizeCIMD(t, newTestTokenManager(t), zap.NewNop(), clientID, cimdAppRedirect, cfg, "")
			var oe OAuthError
			if err := json.NewDecoder(rr.Body).Decode(&oe); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if rr.Code != http.StatusBadRequest || oe.Error != "invalid_client" || oe.ErrorCode != tc.wantCode {
				t.Errorf("got %d %+v, want 400 invalid_client / %s", rr.Code, oe, tc.wantCode)
			}
			if got := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues(reason)) - before; got != 1 {
				t.Errorf("access_denied{%s} delta = %v, want 1", reason, got)
			}

			rr = authorizeCIMD(t, newTestTokenManager(t), zap.NewNop(), clientID, cimdAppRedirect, cfg, browserAccept)
			if body := rr.Body.String(); !strings.Contains(body, "&middot; "+tc.wantCode+"</p>") || !strings.Contains(body, tc.wantHint) {
				t.Errorf("page lacks error_code %q or advice %q:\n%s", tc.wantCode, tc.wantHint, body)
			}
		})
	}
}

// cimdCodeForm is the code grant for a CIMD client.
func cimdCodeForm(t *testing.T, tm *token.Manager, clientID, redirectURI string) url.Values {
	t.Helper()
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {sealCode(t, tm, clientID, redirectURI, pkceChallenge(fwdVerifier), "user", "u@example.com")},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {fwdVerifier},
	}
}

func openRefresh(t *testing.T, tm *token.Manager, rr *httptest.ResponseRecorder) (string, sealedRefresh) {
	t.Helper()
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	rt, _ := resp["refresh_token"].(string)
	var sr sealedRefresh
	if err := tm.OpenJSON(rt, &sr, token.PurposeRefresh); err != nil {
		t.Fatalf("open refresh: %v", err)
	}
	return rt, sr
}

// The refresh token of a CIMD session carries its redirect URI, and the
// refresh grant re-checks it against REDIRECT_URIS_ALLOWLIST exactly as a
// DCR session's indexed URI is re-checked.
func TestToken_CIMDRefreshRecheck(t *testing.T) {
	const clientID = "https://meta.example/client.json"
	tm := newTestTokenManager(t)
	store := replay.NewMemoryStore()
	t.Cleanup(func() { _ = store.Close() })
	admits := TokenConfig{CIMDEnabled: true, RedirectURIsAllowlist: mustWebAllowlist(t, cimdAppRedirect)}
	narrowed := TokenConfig{CIMDEnabled: true, RedirectURIsAllowlist: mustWebAllowlist(t, "https://other.example/cb")}

	rr := postGrant(t, tm, zap.NewNop(), store, admits, cimdCodeForm(t, tm, clientID, cimdAppRedirect))
	if rr.Code != http.StatusOK {
		t.Fatalf("code grant: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	rt, sr := openRefresh(t, tm, rr)
	if sr.ClientID != clientID || sr.RedirectURI != cimdAppRedirect || sr.RedirectURIIndex != 0 {
		t.Fatalf("issued refresh = client %q uri %q index %d, want %q / %q / 0", sr.ClientID, sr.RedirectURI, sr.RedirectURIIndex, clientID, cimdAppRedirect)
	}

	before := notAllowlistedDenials()
	core, logs := observer.New(zap.WarnLevel)
	rr = postGrant(t, tm, zap.New(core), store, narrowed, refreshForm(clientID, rt))
	assertNotAllowlisted(t, rr, logs, before, "invalid_grant", noLongerAllowlistedErr, "grant_type", "refresh_token")

	rr = postGrant(t, tm, zap.NewNop(), store, admits, refreshForm(clientID, rt))
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh under the admitting list: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if _, rotated := openRefresh(t, tm, rr); rotated.RedirectURI != cimdAppRedirect {
		t.Errorf("rotated refresh RedirectURI = %q, want %q", rotated.RedirectURI, cimdAppRedirect)
	}
}

// A CIMD refresh token without its redirect URI is refused: the synthetic
// client has no registered list, so the legacy fallback would pass it.
func TestToken_CIMDRefreshWithoutRedirectURIRefused(t *testing.T) {
	const clientID = "https://meta.example/client.json"
	tm := newTestTokenManager(t)
	rr := postGrant(t, tm, zap.NewNop(), nil, TokenConfig{CIMDEnabled: true}, refreshForm(clientID, sealSession(t, tm, clientID, 0)))
	if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.ErrorCode != codeRedirectURIMismatch {
		t.Fatalf("got %d %+v, want 400 invalid_grant / %s", rr.Code, body, codeRedirectURIMismatch)
	}
}

// /token binds a CIMD grant to the URL by string comparison, and refuses
// the URL outright when CIMD is disabled.
func TestToken_CIMDClientBinding(t *testing.T) {
	const clientID = "https://meta.example/client.json"
	tm := newTestTokenManager(t)
	enabled := TokenConfig{CIMDEnabled: true}

	t.Run("disabled", func(t *testing.T) {
		before := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("client_id_invalid"))
		rr := postGrant(t, tm, zap.NewNop(), nil, TokenConfig{}, cimdCodeForm(t, tm, clientID, cimdAppRedirect))
		if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.Error != "invalid_grant" || body.ErrorCode != codeClientIDUnknown {
			t.Errorf("got %d %+v, want 400 invalid_grant / %s", rr.Code, body, codeClientIDUnknown)
		}
		if got := testutil.ToFloat64(metrics.AccessDenied.WithLabelValues("client_id_invalid")) - before; got != 1 {
			t.Errorf("access_denied{client_id_invalid} delta = %v, want 1", got)
		}
	})
	t.Run("other URL", func(t *testing.T) {
		form := cimdCodeForm(t, tm, clientID, cimdAppRedirect)
		form.Set("client_id", "https://meta.example/other.json")
		rr := postGrant(t, tm, zap.NewNop(), nil, enabled, form)
		if body := oauthErrorOf(t, rr); rr.Code != http.StatusBadRequest || body.ErrorDescription != "client_id mismatch" {
			t.Errorf("got %d %+v, want 400 client_id mismatch", rr.Code, body)
		}
	})
	t.Run("sealed client_id still opens", func(t *testing.T) {
		encClientID, internalID := registerClient(t, tm, []string{cimdAppRedirect})
		form := cimdCodeForm(t, tm, internalID, cimdAppRedirect)
		form.Set("client_id", encClientID)
		rr := postGrant(t, tm, zap.NewNop(), nil, enabled, form)
		if rr.Code != http.StatusOK {
			t.Fatalf("DCR code grant with CIMD enabled: want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		if _, sr := openRefresh(t, tm, rr); sr.RedirectURI != "" || sr.RedirectURIIndex != 1 {
			t.Errorf("DCR refresh = uri %q index %d, want the index only", sr.RedirectURI, sr.RedirectURIIndex)
		}
	})
}

// In forwarding mode a CIMD refresh token carries the longest host the
// proxy accepts (only the host is bounded; the document's 5 KiB cap
// bounds the rest of the client_id), the longest redirect URI, and the
// IdP refresh token: it either seals under the cap or fails closed
// through the existing path.
func TestToken_CIMDForwardingSealCap(t *testing.T) {
	label := strings.Repeat("a", 63)
	clientID := "https://" + strings.Join([]string{label, label, label, strings.Repeat("a", 61)}, ".") + "/client.json"
	long := "https://x.example/" + strings.Repeat("p", 512-len("https://x.example/"))
	for _, tc := range []struct {
		name  string
		idpRT string
		want  int
	}{
		{"seals", fwdIdPRTNext, http.StatusOK},
		{"fails closed", strings.Repeat("r", 70<<10), http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tm := newTestTokenManager(t)
			for _, purpose := range []string{token.PurposeCode, token.PurposeAccess, token.PurposeRefresh} {
				tm.SetMaxSealedLen(purpose, token.ForwardingMaxSealedLen)
			}
			idp := newFakeIdP(t)
			idp.succeed(fwdIdPAT, tc.idpRT, 3600)
			cfg := TokenConfig{ForwardIdPToken: true, IdPRefresher: idp.refresher(), VerifyIDToken: fakeVerifyIDToken, CIMDEnabled: true}
			code, err := tm.SealJSON(sealedCode{
				TokenID: uuid.New().String(), FamilyID: uuid.New().String(), ClientID: clientID,
				RedirectURI: long, CodeChallenge: pkceChallenge(fwdVerifier), Subject: "user", Email: "u@example.com",
				Typ: token.PurposeCode, Audience: testBaseURL, ExpiresAt: time.Now().Add(time.Minute), IdPRefreshToken: fwdIdPRT,
			}, token.PurposeCode)
			if err != nil {
				t.Fatal(err)
			}
			core, logs := observer.New(zap.ErrorLevel)
			rr := postGrant(t, tm, zap.New(core), replay.NewMemoryStore(), cfg, url.Values{
				"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {long},
				"client_id": {clientID}, "code_verifier": {fwdVerifier},
			})
			if rr.Code != tc.want {
				t.Fatalf("want %d, got %d: %s", tc.want, rr.Code, rr.Body.String())
			}
			if tc.want != http.StatusOK {
				if body := oauthErrorOf(t, rr); body.Error != "invalid_grant" || body.ErrorCode != codeTokenIssueFailed {
					t.Errorf("got %+v, want invalid_grant / %s", body, codeTokenIssueFailed)
				}
				if logs.FilterMessage("refresh_token_seal_failed").Len() != 1 {
					t.Errorf("want one refresh_token_seal_failed log, got %v", logs.All())
				}
				return
			}
			rt, sr := openRefresh(t, tm, rr)
			if sr.RedirectURI != long || sr.ClientID != clientID || sr.IdPRefreshToken != tc.idpRT {
				t.Errorf("refresh = uri %d bytes client %d bytes idp_rt %q", len(sr.RedirectURI), len(sr.ClientID), sr.IdPRefreshToken)
			}
			if !tm.FitsOpenCap(rt, token.PurposeRefresh) {
				t.Errorf("issued refresh token (%d bytes) exceeds its own open() cap", len(rt))
			}
		})
	}
}
