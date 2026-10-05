package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	testIdPClientID     = "proxy-client"
	testIdPClientSecret = "s3cr:et/with&chars%+"
	testIdPRefresh      = "idp-refresh-token-value-do-not-log"
)

func newTestRefresher(tokenURL string, style oauth2.AuthStyle, timeout time.Duration) *IdPRefresher {
	return NewIdPRefresher(&oauth2.Config{
		ClientID:     testIdPClientID,
		ClientSecret: testIdPClientSecret,
		Endpoint:     oauth2.Endpoint{TokenURL: tokenURL, AuthStyle: style},
		Scopes:       []string{"openid", "email", "profile", "api://upstream-app/access_as_user", "offline_access"},
	}, timeout)
}

// tokenEndpoint answers like an IdP token endpoint and records what it
// was sent.
type tokenEndpoint struct {
	t       *testing.T
	calls   atomic.Int32
	handler func(w http.ResponseWriter, form url.Values, basicUser, basicPass string, basicOK bool)
	last    atomic.Value // url.Values
}

func (e *tokenEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.calls.Add(1)
	if r.Method != http.MethodPost {
		e.t.Errorf("method = %s, want POST", r.Method)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		e.t.Errorf("Content-Type = %q", ct)
	}
	if err := r.ParseForm(); err != nil {
		e.t.Fatalf("ParseForm: %v", err)
	}
	e.last.Store(r.PostForm)
	user, pass, ok := r.BasicAuth()
	e.handler(w, r.PostForm, user, pass, ok)
}

func okTokenJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func oauthErrorJSON(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `","error_description":"described"}`))
}

func TestIdPRefresher_HeaderAuthExplicitScope(t *testing.T) {
	ep := &tokenEndpoint{t: t, handler: func(w http.ResponseWriter, form url.Values, user, pass string, ok bool) {
		if !ok {
			t.Error("no Basic credentials with AuthStyleInHeader")
		}
		// RFC 6749 §2.3.1: both halves are form-encoded before Basic.
		if user != url.QueryEscape(testIdPClientID) {
			t.Errorf("basic user = %q", user)
		}
		if pass != url.QueryEscape(testIdPClientSecret) || pass == testIdPClientSecret {
			t.Errorf("basic password = %q, want it form-encoded", pass)
		}
		if form.Get("client_secret") != "" {
			t.Error("client_secret also sent in the body")
		}
		okTokenJSON(w, `{"access_token":"new-at","token_type":"Bearer","expires_in":3600,"refresh_token":"rotated-rt","id_token":"raw.id.token"}`)
	}}
	srv := httptest.NewServer(ep)
	defer srv.Close()

	before := time.Now()
	tokens, err := newTestRefresher(srv.URL, oauth2.AuthStyleInHeader, 5*time.Second).Refresh(context.Background(), testIdPRefresh)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	form := ep.last.Load().(url.Values)
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != testIdPRefresh {
		t.Errorf("grant fields = %v", form)
	}
	if got, want := form.Get("scope"), "openid email profile api://upstream-app/access_as_user offline_access"; got != want {
		t.Errorf("scope = %q, want %q", got, want)
	}
	if tokens.AccessToken != "new-at" || tokens.RefreshToken != "rotated-rt" || tokens.IDToken != "raw.id.token" {
		t.Errorf("tokens = %+v", tokens)
	}
	if d := tokens.ExpiresAt.Sub(before.Add(time.Hour)); d < -2*time.Second || d > 2*time.Second {
		t.Errorf("ExpiresAt = %v, want ~now+1h", tokens.ExpiresAt)
	}
}

func TestIdPRefresher_ParamsAuth(t *testing.T) {
	ep := &tokenEndpoint{t: t, handler: func(w http.ResponseWriter, form url.Values, _, _ string, ok bool) {
		if ok {
			t.Error("Basic credentials sent with AuthStyleInParams")
		}
		if form.Get("client_id") != testIdPClientID || form.Get("client_secret") != testIdPClientSecret {
			t.Errorf("client credentials in body = %q / %q", form.Get("client_id"), form.Get("client_secret"))
		}
		okTokenJSON(w, `{"access_token":"new-at","token_type":"bearer","expires_in":"1800"}`)
	}}
	srv := httptest.NewServer(ep)
	defer srv.Close()

	before := time.Now()
	tokens, err := newTestRefresher(srv.URL, oauth2.AuthStyleInParams, 5*time.Second).Refresh(context.Background(), testIdPRefresh)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tokens.RefreshToken != "" {
		t.Errorf("RefreshToken = %q, want empty when the IdP did not rotate", tokens.RefreshToken)
	}
	if d := tokens.ExpiresAt.Sub(before.Add(30 * time.Minute)); d < -2*time.Second || d > 2*time.Second {
		t.Errorf("string expires_in: ExpiresAt = %v, want ~now+30m", tokens.ExpiresAt)
	}
}

func TestIdPRefresher_AutoDetectFallsBackToParamsAndRemembers(t *testing.T) {
	ep := &tokenEndpoint{t: t, handler: func(w http.ResponseWriter, form url.Values, _, _ string, ok bool) {
		if ok {
			oauthErrorJSON(w, http.StatusUnauthorized, "invalid_client")
			return
		}
		if form.Get("client_secret") != testIdPClientSecret {
			t.Errorf("params attempt without client_secret")
		}
		okTokenJSON(w, `{"access_token":"new-at","token_type":"Bearer"}`)
	}}
	srv := httptest.NewServer(ep)
	defer srv.Close()
	r := newTestRefresher(srv.URL, oauth2.AuthStyleAutoDetect, 5*time.Second)

	if _, err := r.Refresh(context.Background(), testIdPRefresh); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	if n := ep.calls.Load(); n != 2 {
		t.Fatalf("first refresh made %d calls, want 2 (header, then params)", n)
	}
	if _, err := r.Refresh(context.Background(), testIdPRefresh); err != nil {
		t.Fatalf("second Refresh: %v", err)
	}
	if n := ep.calls.Load(); n != 3 {
		t.Errorf("second refresh made %d calls in total, want 3 (params remembered)", n)
	}
}

// A grant error under Basic proves the IdP accepted the client
// credentials: no retry with the other style, and Basic is remembered.
func TestIdPRefresher_AutoDetectGrantErrorDoesNotRetry(t *testing.T) {
	ep := &tokenEndpoint{t: t, handler: func(w http.ResponseWriter, _ url.Values, _, _ string, _ bool) {
		oauthErrorJSON(w, http.StatusBadRequest, "invalid_grant")
	}}
	srv := httptest.NewServer(ep)
	defer srv.Close()
	r := newTestRefresher(srv.URL, oauth2.AuthStyleAutoDetect, 5*time.Second)

	_, err := r.Refresh(context.Background(), testIdPRefresh)
	var re *idpRefreshError
	if !errors.As(err, &re) || re.Kind != idpRefreshRejected {
		t.Fatalf("err = %v, want a rejected idpRefreshError", err)
	}
	if n := ep.calls.Load(); n != 1 {
		t.Errorf("calls = %d, want 1", n)
	}
	if got := oauth2.AuthStyle(r.detected.Load()); got != oauth2.AuthStyleInHeader {
		t.Errorf("detected style = %v, want InHeader", got)
	}
}

func TestIdPRefresher_AutoDetectTransportErrorNotRemembered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close() // connection refused from here on
	r := newTestRefresher(srv.URL, oauth2.AuthStyleAutoDetect, 2*time.Second)

	if _, err := r.Refresh(context.Background(), testIdPRefresh); err == nil {
		t.Fatal("Refresh against a closed endpoint succeeded")
	}
	if got := r.detected.Load(); got != 0 {
		t.Errorf("detected style = %d after a transport error, want 0 (undecided)", got)
	}
}

func TestIdPRefresher_ErrorClassification(t *testing.T) {
	cases := []struct {
		name       string
		handler    http.HandlerFunc
		wantKind   idpRefreshKind
		wantStatus int
		wantCode   string
	}{
		{name: "invalid_grant", handler: func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 400, "invalid_grant") }, wantKind: idpRefreshRejected, wantStatus: 400, wantCode: "invalid_grant"},
		{name: "interaction_required", handler: func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 400, "interaction_required") }, wantKind: idpRefreshRejected, wantStatus: 400, wantCode: "interaction_required"},
		{name: "invalid_scope", handler: func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 400, "invalid_scope") }, wantKind: idpRefreshRejected, wantStatus: 400, wantCode: "invalid_scope"},
		{name: "invalid_client_keeps_sessions", handler: func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 401, "invalid_client") }, wantKind: idpRefreshUnavailable, wantStatus: 401, wantCode: "invalid_client"},
		{name: "unauthorized_client_on_400", handler: func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 400, "unauthorized_client") }, wantKind: idpRefreshUnavailable, wantStatus: 400, wantCode: "unauthorized_client"},
		{name: "invalid_request_is_permanent", handler: func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 400, "invalid_request") }, wantKind: idpRefreshFailed, wantStatus: 400, wantCode: "invalid_request"},
		{name: "unsupported_grant_type_is_permanent", handler: func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 400, "unsupported_grant_type") }, wantKind: idpRefreshFailed, wantStatus: 400, wantCode: "unsupported_grant_type"},
		{name: "429_is_outage", handler: func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 429, "slow_down") }, wantKind: idpRefreshUnavailable, wantStatus: 429, wantCode: "slow_down"},
		{name: "5xx_with_grant_error_is_outage", handler: func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 500, "invalid_grant") }, wantKind: idpRefreshUnavailable, wantStatus: 500, wantCode: "invalid_grant"},
		{name: "503_html", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(503)
			_, _ = w.Write([]byte("<html>maintenance</html>"))
		}, wantKind: idpRefreshUnavailable, wantStatus: 503},
		{name: "transient_code_on_400", handler: func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 400, "temporarily_unavailable") }, wantKind: idpRefreshUnavailable, wantStatus: 400, wantCode: "temporarily_unavailable"},
		{name: "server_error_on_400", handler: func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 400, "server_error") }, wantKind: idpRefreshUnavailable, wantStatus: 400, wantCode: "server_error"},
		// Answers that never came from a token endpoint: the IdP did
		// not see the grant, so the client's token must stay usable.
		{name: "403_waf_html", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(403)
			_, _ = w.Write([]byte("<html>blocked</html>"))
		}, wantKind: idpRefreshUnavailable, wantStatus: 403},
		{name: "404_plain", handler: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "not found", 404) }, wantKind: idpRefreshUnavailable, wantStatus: 404},
		{name: "400_json_without_error_member", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"message":"bad"}`))
		}, wantKind: idpRefreshUnavailable, wantStatus: 400},
		{name: "200_html_maintenance_page", handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>maintenance</html>")) }, wantKind: idpRefreshUnavailable, wantStatus: 200},
		// A malformed JSON object DID come from the token endpoint: the
		// grant was processed, so the token stays spent.
		{name: "200_malformed_json_object", handler: func(w http.ResponseWriter, _ *http.Request) { okTokenJSON(w, `{"access_token":`) }, wantKind: idpRefreshFailed, wantStatus: 200},
		{name: "200_malformed_object_after_whitespace", handler: func(w http.ResponseWriter, _ *http.Request) { okTokenJSON(w, "\n {\"access_token\":") }, wantKind: idpRefreshFailed, wantStatus: 200},
		{name: "200_json_null", handler: func(w http.ResponseWriter, _ *http.Request) { okTokenJSON(w, `null`) }, wantKind: idpRefreshUnavailable, wantStatus: 200},
		{name: "200_json_array", handler: func(w http.ResponseWriter, _ *http.Request) { okTokenJSON(w, `[]`) }, wantKind: idpRefreshUnavailable, wantStatus: 200},
		{name: "200_mistyped_token_type", handler: func(w http.ResponseWriter, _ *http.Request) {
			okTokenJSON(w, `{"access_token":"x","token_type":5}`)
		}, wantKind: idpRefreshFailed, wantStatus: 200},
		{name: "400_rejected_with_mistyped_sibling", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","access_token":5}`))
		}, wantKind: idpRefreshRejected, wantStatus: 400, wantCode: "invalid_grant"},
		{name: "401_with_unlisted_code", handler: func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 401, "access_denied") }, wantKind: idpRefreshUnavailable, wantStatus: 401, wantCode: "access_denied"},
		{name: "code_is_sanitized", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"bad\ncode"}`))
		}, wantKind: idpRefreshFailed, wantStatus: 400, wantCode: "badcode"},
		{name: "200_expired_on_arrival", handler: func(w http.ResponseWriter, _ *http.Request) {
			okTokenJSON(w, `{"access_token":"x","token_type":"Bearer","expires_in":0}`)
		}, wantKind: idpRefreshFailed, wantStatus: 200},
		{name: "200_negative_expires_in", handler: func(w http.ResponseWriter, _ *http.Request) {
			okTokenJSON(w, `{"access_token":"x","token_type":"Bearer","expires_in":"-5"}`)
		}, wantKind: idpRefreshFailed, wantStatus: 200},
		{name: "200_no_access_token", handler: func(w http.ResponseWriter, _ *http.Request) { okTokenJSON(w, `{"token_type":"Bearer"}`) }, wantKind: idpRefreshFailed, wantStatus: 200},
		{name: "200_dpop_token", handler: func(w http.ResponseWriter, _ *http.Request) {
			okTokenJSON(w, `{"access_token":"x","token_type":"DPoP"}`)
		}, wantKind: idpRefreshFailed, wantStatus: 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			_, err := newTestRefresher(srv.URL, oauth2.AuthStyleInParams, 5*time.Second).Refresh(context.Background(), testIdPRefresh)
			var re *idpRefreshError
			if !errors.As(err, &re) {
				t.Fatalf("err = %v (%T), want *idpRefreshError", err, err)
			}
			if re.Kind != tc.wantKind || re.Status != tc.wantStatus || re.Code != tc.wantCode {
				t.Errorf("got kind=%v status=%d code=%q, want kind=%v status=%d code=%q",
					re.Kind, re.Status, re.Code, tc.wantKind, tc.wantStatus, tc.wantCode)
			}
			if strings.Contains(err.Error(), testIdPRefresh) || strings.Contains(err.Error(), testIdPClientSecret) {
				t.Errorf("error text leaks a credential: %q", err)
			}
		})
	}
}

// Every code in the sets keeps its class: a code dropped from a set
// would silently become "failed".
func TestIdPRefresher_CodeSetsClassify(t *testing.T) {
	classify := func(code string) idpRefreshKind {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 400, code) }))
		defer srv.Close()
		_, err := newTestRefresher(srv.URL, oauth2.AuthStyleInParams, 5*time.Second).Refresh(context.Background(), testIdPRefresh)
		var re *idpRefreshError
		if !errors.As(err, &re) {
			t.Fatalf("%s: err = %v", code, err)
		}
		return re.Kind
	}
	for _, code := range []string{"invalid_grant", "interaction_required", "login_required", "consent_required", "invalid_scope"} {
		if got := classify(code); got != idpRefreshRejected {
			t.Errorf("%s = %v, want rejected", code, got)
		}
	}
	for _, code := range []string{"invalid_client", "unauthorized_client", "temporarily_unavailable", "server_error"} {
		if got := classify(code); got != idpRefreshUnavailable {
			t.Errorf("%s = %v, want unavailable", code, got)
		}
	}
}

// The IdP's error_description is free text it may fill with the grant in
// any encoding: it never reaches the error. The code is redacted.
func TestIdPRefresher_NeverCarriesEchoedSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		rt, secret := r.PostForm.Get("refresh_token"), r.PostForm.Get("client_secret")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "bad_" + rt + "_" + secret,
			"error_description": "token " + rt + " " + url.QueryEscape(rt) + " for secret " + secret + " marker-description",
		})
	}))
	defer srv.Close()

	_, err := newTestRefresher(srv.URL, oauth2.AuthStyleInParams, 5*time.Second).Refresh(context.Background(), testIdPRefresh)
	var re *idpRefreshError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v", err)
	}
	msg := err.Error()
	if strings.Contains(msg, testIdPRefresh) || strings.Contains(msg, testIdPClientSecret) || strings.Contains(msg, "marker-description") {
		t.Errorf("error text carries IdP free text or a credential: %q", msg)
	}
	if re.Code != "bad_[redacted]_[redacted]" {
		t.Errorf("code = %q, want both echoed values redacted", re.Code)
	}
}

// The IdP's own Retry-After is carried, and a refused client credential
// asks for a long wait: only an operator fix clears it.
func TestIdPRefresher_RetryAfter(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		want    time.Duration
	}{
		{name: "429_with_retry_after", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "120")
			oauthErrorJSON(w, 429, "slow_down")
		}, want: 120 * time.Second},
		{name: "503_http_date_ignored", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")
			oauthErrorJSON(w, 503, "temporarily_unavailable")
		}, want: 0},
		{name: "invalid_client", handler: func(w http.ResponseWriter, _ *http.Request) { oauthErrorJSON(w, 401, "invalid_client") }, want: idpClientAuthRetryAfter},
		// A 5xx is an outage whatever its body says: the IdP's own value.
		{name: "503_invalid_client_keeps_idp_value", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "30")
			oauthErrorJSON(w, 503, "invalid_client")
		}, want: 30 * time.Second},
		{name: "huge_value_clamped", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "99999999999")
			oauthErrorJSON(w, 503, "temporarily_unavailable")
		}, want: maxExpiresInSeconds * time.Second},
		{name: "codeless_403_paced_long", handler: func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "blocked", http.StatusForbidden) }, want: idpClientAuthRetryAfter},
		{name: "rejected_carries_none", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "120")
			oauthErrorJSON(w, 400, "invalid_grant")
		}, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			_, err := newTestRefresher(srv.URL, oauth2.AuthStyleInParams, 5*time.Second).Refresh(context.Background(), testIdPRefresh)
			var re *idpRefreshError
			if !errors.As(err, &re) {
				t.Fatalf("err = %v, want *idpRefreshError", err)
			}
			if re.RetryAfter != tc.want {
				t.Errorf("RetryAfter = %v, want %v", re.RetryAfter, tc.want)
			}
		})
	}
}

// A body over the cap is cut off, not buffered whole.
func TestIdPRefresher_ResponseBodyCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"x","token_type":"Bearer","pad":"` + strings.Repeat("a", idpRefreshMaxBody) + `"}`))
	}))
	defer srv.Close()
	_, err := newTestRefresher(srv.URL, oauth2.AuthStyleInParams, 5*time.Second).Refresh(context.Background(), testIdPRefresh)
	var re *idpRefreshError
	if !errors.As(err, &re) || re.Kind != idpRefreshFailed {
		t.Fatalf("err = %v, want failed: the IdP processed the grant", err)
	}
}

// A call over the in-flight bound fails at once and never reaches the
// IdP, so releasing the client's claim for it is always correct.
func TestIdPRefresher_InFlightBounded(t *testing.T) {
	ep := &tokenEndpoint{t: t, handler: func(w http.ResponseWriter, _ url.Values, _, _ string, _ bool) {
		okTokenJSON(w, `{"access_token":"new-at"}`)
	}}
	srv := httptest.NewServer(ep)
	defer srv.Close()
	r := newTestRefresher(srv.URL, oauth2.AuthStyleInParams, 5*time.Second)
	for range idpMaxInFlight {
		r.inFlight <- struct{}{}
	}

	// A deadline, so an implementation that queues fails here instead
	// of hanging the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	_, err := r.Refresh(ctx, testIdPRefresh)
	var re *idpRefreshError
	if !errors.As(err, &re) || re.Kind != idpRefreshUnavailable {
		t.Fatalf("over the bound: err = %v, want unavailable", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("over the bound: answered after %v, want at once (no queueing)", elapsed)
	}
	if n := ep.calls.Load(); n != 0 {
		t.Fatalf("the IdP was called %d times by a call over the bound", n)
	}

	<-r.inFlight
	// token_type is OPTIONAL to check: an IdP that omits it is accepted.
	if _, err := r.Refresh(context.Background(), testIdPRefresh); err != nil {
		t.Fatalf("with a free slot: %v", err)
	}
	if len(r.inFlight) != idpMaxInFlight-1 {
		t.Errorf("slot not given back: %d in flight, want %d", len(r.inFlight), idpMaxInFlight-1)
	}
}

// A transient 5xx on the very first Basic attempt must not pin Basic for
// an IdP that only accepts form credentials.
func TestIdPRefresher_AutoDetectNotPinnedByOutage(t *testing.T) {
	var outage atomic.Bool
	outage.Store(true)
	ep := &tokenEndpoint{t: t, handler: func(w http.ResponseWriter, form url.Values, _, _ string, basic bool) {
		if outage.Load() {
			oauthErrorJSON(w, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		}
		if basic {
			oauthErrorJSON(w, http.StatusUnauthorized, "invalid_client")
			return
		}
		okTokenJSON(w, `{"access_token":"new-at","token_type":"Bearer"}`)
	}}
	srv := httptest.NewServer(ep)
	defer srv.Close()
	r := newTestRefresher(srv.URL, oauth2.AuthStyleAutoDetect, 5*time.Second)

	_, err := r.Refresh(context.Background(), testIdPRefresh)
	var re *idpRefreshError
	if !errors.As(err, &re) || re.Kind != idpRefreshUnavailable {
		t.Fatalf("outage: err = %v, want unavailable", err)
	}
	if n := ep.calls.Load(); n != 1 {
		t.Errorf("outage made %d calls, want 1 (no second attempt on a 5xx)", n)
	}
	if got := r.detected.Load(); got != 0 {
		t.Fatalf("detected style = %d after an outage, want undecided", got)
	}

	outage.Store(false)
	if _, err := r.Refresh(context.Background(), testIdPRefresh); err != nil {
		t.Fatalf("after recovery: %v, want success via the params fallback", err)
	}
	if got := oauth2.AuthStyle(r.detected.Load()); got != oauth2.AuthStyleInParams {
		t.Errorf("detected style = %v, want InParams", got)
	}
}

// A 5xx on the params fallback must not pin params either.
func TestIdPRefresher_AutoDetectNotPinnedByFallbackOutage(t *testing.T) {
	ep := &tokenEndpoint{t: t, handler: func(w http.ResponseWriter, _ url.Values, _, _ string, basic bool) {
		if basic {
			oauthErrorJSON(w, http.StatusUnauthorized, "invalid_client")
			return
		}
		oauthErrorJSON(w, http.StatusServiceUnavailable, "temporarily_unavailable")
	}}
	srv := httptest.NewServer(ep)
	defer srv.Close()
	r := newTestRefresher(srv.URL, oauth2.AuthStyleAutoDetect, 5*time.Second)

	if _, err := r.Refresh(context.Background(), testIdPRefresh); err == nil {
		t.Fatal("Refresh succeeded")
	}
	if got := r.detected.Load(); got != 0 {
		t.Errorf("detected style = %d after a failed fallback, want undecided", got)
	}
}

// An IdP that answers Basic with 400 invalid_request ("client_id
// missing") gets the params fallback, like x/oauth2's own detection.
func TestIdPRefresher_AutoDetectFallsBackOnAny4xx(t *testing.T) {
	ep := &tokenEndpoint{t: t, handler: func(w http.ResponseWriter, form url.Values, _, _ string, _ bool) {
		if form.Get("client_id") == "" {
			oauthErrorJSON(w, http.StatusBadRequest, "invalid_request")
			return
		}
		okTokenJSON(w, `{"access_token":"new-at","token_type":"Bearer"}`)
	}}
	srv := httptest.NewServer(ep)
	defer srv.Close()

	if _, err := newTestRefresher(srv.URL, oauth2.AuthStyleAutoDetect, 5*time.Second).Refresh(context.Background(), testIdPRefresh); err != nil {
		t.Fatalf("Refresh: %v, want success via the params fallback", err)
	}
	if n := ep.calls.Load(); n != 2 {
		t.Errorf("calls = %d, want 2", n)
	}
}

// Without expires_in, a JWT access token's own exp bounds the lifetime;
// with both, the earlier wins.
func TestIdPRefresher_JWTExpiryBound(t *testing.T) {
	jwt := func(exp int64) string {
		payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"aud":"api://upstream-app","exp":%d}`, exp)))
		return "eyJhbGciOiJSUzI1NiJ9." + payload + ".c2ln"
	}
	in10m := time.Now().Add(10 * time.Minute).Unix()
	cases := []struct {
		name string
		body string
		want time.Duration
	}{
		{name: "no_expires_in", body: `{"access_token":"` + jwt(in10m) + `","token_type":"Bearer"}`, want: 10 * time.Minute},
		{name: "jwt_earlier_than_expires_in", body: `{"access_token":"` + jwt(in10m) + `","token_type":"Bearer","expires_in":3600}`, want: 10 * time.Minute},
		{name: "expires_in_earlier_than_jwt", body: `{"access_token":"` + jwt(in10m) + `","token_type":"Bearer","expires_in":300}`, want: 5 * time.Minute},
		{name: "opaque_without_expires_in", body: `{"access_token":"opaque-token","token_type":"Bearer"}`, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { okTokenJSON(w, tc.body) }))
			defer srv.Close()
			tokens, err := newTestRefresher(srv.URL, oauth2.AuthStyleInParams, 5*time.Second).Refresh(context.Background(), testIdPRefresh)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == 0 {
				if !tokens.ExpiresAt.IsZero() {
					t.Errorf("ExpiresAt = %v, want zero", tokens.ExpiresAt)
				}
				return
			}
			if d := time.Until(tokens.ExpiresAt) - tc.want; d < -3*time.Second || d > 3*time.Second {
				t.Errorf("lifetime = %v, want ~%v", time.Until(tokens.ExpiresAt), tc.want)
			}
		})
	}
}

func TestJWTExpiry(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, tc := range []struct {
		token  string
		wantOK bool
	}{
		{token: "a." + enc(`{"exp":1900000000}`) + ".c", wantOK: true},
		{token: "a." + enc(`{"exp":1900000000.5}`) + ".c", wantOK: true},
		{token: "a." + enc(`{"aud":"x"}`) + ".c", wantOK: false},
		{token: "a." + enc(`{"exp":0}`) + ".c", wantOK: false},
		{token: "a." + enc(`{"exp":"soon"}`) + ".c", wantOK: false},
		{token: "a.!!!.c", wantOK: false},
		{token: "a." + enc(`not json`) + ".c", wantOK: false},
		{token: "opaque", wantOK: false},
		// A "never expires" sentinel must not wrap into the past.
		{token: "a." + enc(`{"exp":9223372036854775807}`) + ".c", wantOK: false},
		{token: "a." + enc(`{"exp":1e30}`) + ".c", wantOK: false},
	} {
		if _, ok := jwtExpiry(tc.token); ok != tc.wantOK {
			t.Errorf("jwtExpiry(%q) ok = %v, want %v", tc.token, ok, tc.wantOK)
		}
	}
}

// Following a redirect would re-POST the refresh token and the client
// secret to the Location host.
func TestIdPRefresher_DoesNotFollowRedirects(t *testing.T) {
	var hit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	_, err := newTestRefresher(srv.URL, oauth2.AuthStyleInParams, 5*time.Second).Refresh(context.Background(), testIdPRefresh)
	var re *idpRefreshError
	// Unavailable: the redirect is not followed, so the IdP never saw
	// the grant and the client's token must stay usable.
	if !errors.As(err, &re) || re.Kind != idpRefreshUnavailable || re.Status != http.StatusTemporaryRedirect || re.RetryAfter != idpClientAuthRetryAfter {
		t.Fatalf("err = %v, want unavailable with status 307 and the long Retry-After", err)
	}
	if hit.Load() {
		t.Error("the redirect target received the refresh request")
	}
}

func TestIdPRefresher_Timeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { waitOrGiveUp(release) }))
	defer srv.Close()
	defer close(release)

	start := time.Now()
	_, err := newTestRefresher(srv.URL, oauth2.AuthStyleInParams, 200*time.Millisecond).Refresh(context.Background(), testIdPRefresh)
	var re *idpRefreshError
	if !errors.As(err, &re) || re.Kind != idpRefreshUnavailable || re.Status != 0 {
		t.Fatalf("err = %v, want an unavailable transport error", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("timeout took %v", elapsed)
	}
}

func TestParseExpiresIn(t *testing.T) {
	cases := []struct {
		raw    string
		want   int64
		wantOK bool
	}{
		{raw: ``, wantOK: false},
		{raw: `3600`, want: 3600, wantOK: true},
		{raw: `"3600"`, want: 3600, wantOK: true},
		{raw: `3599.9`, want: 3599, wantOK: true},
		{raw: `0`, want: 0, wantOK: true},
		{raw: `-5`, want: -5, wantOK: true},
		{raw: `"soon"`, wantOK: false},
		{raw: `null`, wantOK: false},
		{raw: `99999999999999`, want: maxExpiresInSeconds, wantOK: true},
		{raw: `1e30`, want: maxExpiresInSeconds, wantOK: true},
		{raw: `-1e30`, want: -1, wantOK: true},
		{raw: `"NaN"`, wantOK: false},
	}
	for _, tc := range cases {
		got, ok := parseExpiresIn([]byte(tc.raw))
		if ok != tc.wantOK || (ok && got != tc.want) {
			t.Errorf("parseExpiresIn(%s) = %d, %v; want %d, %v", tc.raw, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestIdPRefreshError_Message(t *testing.T) {
	e := &idpRefreshError{Kind: idpRefreshRejected, Code: "invalid_grant", Status: 400, Err: errors.New("expired")}
	if got := e.Error(); got != "idp refresh rejected (status 400): invalid_grant: expired" {
		t.Errorf("Error() = %q", got)
	}
	if !errors.Is(e, e.Err) {
		t.Error("Unwrap does not expose the cause")
	}
	if got := (&idpRefreshError{}).Error(); got != "idp refresh unavailable" {
		t.Errorf("empty Error() = %q", got)
	}
	if got := (&idpRefreshError{Kind: idpRefreshFailed}).Error(); got != "idp refresh failed" {
		t.Errorf("failed Error() = %q", got)
	}
}

// A 429 on the Basic attempt is an outage, not an auth-style verdict:
// no second attempt, nothing remembered.
func TestIdPRefresher_AutoDetect429NoFallback(t *testing.T) {
	ep := &tokenEndpoint{t: t, handler: func(w http.ResponseWriter, _ url.Values, _, _ string, _ bool) {
		oauthErrorJSON(w, http.StatusTooManyRequests, "slow_down")
	}}
	srv := httptest.NewServer(ep)
	defer srv.Close()
	r := newTestRefresher(srv.URL, oauth2.AuthStyleAutoDetect, 5*time.Second)

	if _, err := r.Refresh(context.Background(), testIdPRefresh); err == nil {
		t.Fatal("Refresh succeeded")
	}
	if n := ep.calls.Load(); n != 1 {
		t.Errorf("calls = %d, want 1", n)
	}
	if got := r.detected.Load(); got != 0 {
		t.Errorf("detected style = %d, want undecided", got)
	}
}

// A 2xx whose body breaks off: the IdP has processed the grant and
// probably rotated its refresh token, so the token must stay spent.
func TestIdPRefresher_TruncatedSuccessIsFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("no hijacker")
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{\"access_token\":\"partial")
		_ = buf.Flush()
		_ = conn.Close()
	}))
	defer srv.Close()

	_, err := newTestRefresher(srv.URL, oauth2.AuthStyleInParams, 5*time.Second).Refresh(context.Background(), testIdPRefresh)
	var re *idpRefreshError
	if !errors.As(err, &re) || re.Kind != idpRefreshFailed || re.Status != http.StatusOK {
		t.Fatalf("err = %v, want a failed error with status 200", err)
	}
}

// AutoDetect's fallback shares one deadline with the first attempt, so a
// slow IdP cannot double the time a client waits.
func TestIdPRefresher_AutoDetectSingleDeadline(t *testing.T) {
	ep := &tokenEndpoint{t: t, handler: func(w http.ResponseWriter, _ url.Values, _, _ string, basic bool) {
		time.Sleep(300 * time.Millisecond)
		if basic {
			oauthErrorJSON(w, http.StatusUnauthorized, "invalid_client")
			return
		}
		okTokenJSON(w, `{"access_token":"new-at","token_type":"Bearer"}`)
	}}
	srv := httptest.NewServer(ep)
	defer srv.Close()

	start := time.Now()
	_, err := newTestRefresher(srv.URL, oauth2.AuthStyleAutoDetect, 450*time.Millisecond).Refresh(context.Background(), testIdPRefresh)
	elapsed := time.Since(start)
	var re *idpRefreshError
	if !errors.As(err, &re) || re.Kind != idpRefreshUnavailable {
		t.Fatalf("err = %v, want the shared deadline to cut the params attempt short", err)
	}
	if elapsed > 550*time.Millisecond {
		t.Errorf("Refresh took %v, want it bounded by the 450ms budget", elapsed)
	}
}
