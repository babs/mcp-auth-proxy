package handlers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/babs/mcp-auth-proxy/config"
	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/token"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// cimdBodyMarker is planted in document bodies; it must never reach an error message or a log.
const cimdBodyMarker = "SECRET-FROM-BODY"

var cimdAllResults = []cimdResult{cimdOK, cimdURLInvalid, cimdSSRFBlocked, cimdFetchError, cimdTooLarge, cimdDocInvalid, cimdAuthMethodUnsupported}

func cimdFetchTotal() float64 {
	var sum float64
	for _, r := range cimdAllResults {
		sum += testutil.ToFloat64(metrics.CIMDFetch.WithLabelValues(string(r)))
	}
	return sum
}

// MAP-002-AC4
func TestValidateCIMDClientID(t *testing.T) {
	cases := []struct {
		id string
		ok bool
	}{
		{"http://h/x", false},
		{"https://h", false},
		{"https://h/../x", false},
		{"https://h/./x", false},
		{"https://h/%2e%2e/x", false},
		{"https://h/x#f", false},
		{"https://h/x#", false},
		{"https://h/x?y", false},
		{"https://h/x?", false},
		{"https://u@h/x", false},
		{"https://127.0.0.1/x", false},
		{"https://[::1]/x", false},
		{"https://10.0.0.1/x", false},
		{"https:h/x", false},
		{"https:///x", false},
		{"https://h/", true},
		{"https://h/client.json", true},
		{"https://h:8443/c.json", true},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			u, err := validateCIMDClientID(tc.id)
			if tc.ok {
				if err != nil || u == nil {
					t.Fatalf("want accepted, got %v", err)
				}
				return
			}
			if err == nil || err.Result != cimdURLInvalid || u != nil {
				t.Fatalf("want *cimdError{url_invalid}, got %#v (url %v)", err, u)
			}
		})
	}
}

// MAP-002-AC4: the authority is bounded before it reaches a log line.
func TestValidateCIMDClientID_HostLength(t *testing.T) {
	label := strings.Repeat("a", 63)
	longest := strings.Join([]string{label, label, label, strings.Repeat("a", 61)}, ".") // 253 bytes
	if _, err := validateCIMDClientID("https://" + longest + ":65535/c"); err != nil {
		t.Fatalf("253-byte name with the longest port: want accepted, got %v", err)
	}
	if _, err := validateCIMDClientID("https://" + strings.Repeat("a", 300) + "/c"); err == nil || err.Result != cimdURLInvalid {
		t.Fatalf("300-byte host: want url_invalid, got %v", err)
	}
}

func TestNewCIMDResolver_Transport(t *testing.T) {
	tr := NewCIMDResolver(zap.NewNop(), config.RedirectAllowlist{}, config.WebRedirectAllowlist{}, CIMDResolverOptions{}).client.Transport.(*http.Transport)
	if tr.Proxy != nil {
		t.Error("Proxy set: the dial guard would see the proxy, not the destination")
	}
	if tr.MaxResponseHeaderBytes != 16<<10 {
		t.Errorf("MaxResponseHeaderBytes = %d, want %d", tr.MaxResponseHeaderBytes, 16<<10)
	}
}

// MAP-002-AC5
func TestCIMDRejectSpecialPurpose(t *testing.T) {
	cases := []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1", false},
		{"10.0.0.1", false},
		{"169.254.169.254", false},
		{"100.64.0.1", false},
		{"192.0.2.1", false},
		{"198.18.0.1", false},
		{"240.0.0.1", false},
		{"255.255.255.255", false},
		{"0.0.0.0", false},
		{"::", false},
		{"::1", false},
		{"fd00::1", false},
		{"fe80::1", false},
		{"fe80::1%eth0", false},
		{"2001:db8::1", false},
		{"::ffff:127.0.0.1", false},
		{"64:ff9b::a00:1", false},       // NAT64 of 10.0.0.1
		{"64:ff9b:1::a9fe:a9fe", false}, // local-use NAT64 of 169.254.169.254
		{"2002:7f00:1::1", false},       // 6to4 of 127.0.0.1
		{"8.8.8.8", true},
		{"2606:4700::1111", true},
		{"64:ff9b::808:808", true}, // NAT64 of 8.8.8.8
		{"2002:808:808::1", true},  // 6to4 of 8.8.8.8
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			err := cimdRejectSpecialPurpose(netip.MustParseAddr(tc.addr))
			if tc.ok && err != nil {
				t.Fatalf("want accepted, got %v", err)
			}
			if !tc.ok && !errors.Is(err, errCIMDBlockedAddress) {
				t.Fatalf("want errCIMDBlockedAddress, got %v", err)
			}
		})
	}
}

// cimdURL rewrites the httptest address to a hostname: an IP literal
// client_id is refused before any dial, and the guard must see the
// address the name resolves to.
func cimdURL(t *testing.T, srv *httptest.Server, path string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	return "https://localhost:" + port + path
}

// trustTestServer trusts the httptest certificate. It names example.com,
// not localhost, so verification runs against that name while the dial
// still goes to the resolved loopback address.
func trustTestServer(srv *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "example.com"}
}

func allowLoopbackDial(netip.Addr) error { return nil }

// newTestCIMDResolver admits the loopback dial; the production guard is
// exercised by TestCIMDResolve_DefaultGuardBlocksLoopback.
func newTestCIMDResolver(t *testing.T, srv *httptest.Server, allow string) *CIMDResolver {
	t.Helper()
	return NewCIMDResolver(zap.NewNop(), config.RedirectAllowlist{}, mustWebAllowlist(t, allow),
		CIMDResolverOptions{DialGuardOverride: allowLoopbackDial, TLSClientConfigOverride: trustTestServer(srv)})
}

func assertCIMDResult(t *testing.T, ce *cimdError, want cimdResult, before, beforeTotal float64) *cimdError {
	t.Helper()
	if ce == nil {
		t.Fatalf("want *cimdError{%s}, got nil", want)
	}
	if ce.Result != want {
		t.Fatalf("result = %q, want %q (%v)", ce.Result, want, ce)
	}
	if got := testutil.ToFloat64(metrics.CIMDFetch.WithLabelValues(string(want))) - before; got != 1 {
		t.Errorf("cimd_fetch{%s} delta = %v, want 1", want, got)
	}
	if got := cimdFetchTotal() - beforeTotal; got != 1 {
		t.Errorf("cimd_fetch total delta = %v, want 1", got)
	}
	if strings.Contains(ce.Error(), "client.json") {
		t.Errorf("error echoes the client_id URL: %v", ce)
	}
	if strings.Contains(ce.Error(), cimdBodyMarker) {
		t.Errorf("error echoes document content: %v", ce)
	}
	return ce
}

// MAP-002-AC5
func TestCIMDResolve_DefaultGuardBlocksLoopback(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	r := NewCIMDResolver(zap.NewNop(), config.RedirectAllowlist{}, config.WebRedirectAllowlist{}, CIMDResolverOptions{TLSClientConfigOverride: trustTestServer(srv)})
	before, beforeTotal := testutil.ToFloat64(metrics.CIMDFetch.WithLabelValues(string(cimdSSRFBlocked))), cimdFetchTotal()

	client, ce := r.Resolve(context.Background(), cimdURL(t, srv, "/client.json"), "https://proxy.example")
	if client != nil {
		t.Fatalf("want nil client, got %+v", client)
	}
	assertCIMDResult(t, ce, cimdSSRFBlocked, before, beforeTotal)
	if !errors.Is(ce, errCIMDBlockedAddress) {
		t.Errorf("want errCIMDBlockedAddress through the chain, got %v", ce)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("server received %d requests, want 0: the guard must run before the connection", n)
	}
}

// MAP-002-AC3
func TestCIMDResolve(t *testing.T) {
	const audience = "https://proxy.example"
	validDoc := func(id string) string {
		return `{"client_id":` + jsonStr(id) + `,"client_name":"Example","redirect_uris":["https://app.example/cb","http://127.0.0.1:8080/cb"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"unknown_member":1}`
	}
	cases := []struct {
		name        string
		body        func(id string) string
		status      int
		contentType string
		headerPad   int
		allow       string
		want        cimdResult
		wantHits    int32
		wantDescHas string
	}{
		{name: "valid document", body: validDoc, want: cimdOK},
		{name: "document under REDIRECT_URIS_ALLOWLIST", allow: "https://app.example/cb,http://127.0.0.1/cb",
			body: validDoc, want: cimdOK},
		{name: "client_id trailing slash", body: func(id string) string { return validDoc(id + "/") }, want: cimdDocInvalid},
		{name: "client_id host case", body: func(id string) string { return validDoc(strings.Replace(id, "localhost", "LOCALHOST", 1)) }, want: cimdDocInvalid},
		{name: "empty redirect_uris", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":[]}`
		}, want: cimdDocInvalid},
		{name: "missing redirect_uris", body: func(id string) string { return `{"client_id":` + jsonStr(id) + `}` }, want: cimdDocInvalid},
		{name: "six redirect_uris", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://a.example/1","https://a.example/2","https://a.example/3","https://a.example/4","https://a.example/5","https://a.example/6"]}`
		}, want: cimdDocInvalid},
		{name: "redirect_uri http non-loopback", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["http://app.example/cb"]}`
		}, want: cimdDocInvalid},
		{name: "redirect_uri malformed", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://` + cimdBodyMarker + `.example/%zz"]}`
		}, want: cimdDocInvalid},
		{name: "redirect_uri custom scheme without REDIRECT_URIS_EXTRA", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["com.example.app:/cb"]}`
		}, want: cimdDocInvalid},
		{name: "redirect_uri not in REDIRECT_URIS_ALLOWLIST", allow: "https://app.example/cb", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://evil.example/cb"]}`
		}, want: cimdDocInvalid},
		{name: "client_secret_basic", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}`
		}, want: cimdDocInvalid},
		{name: "private_key_jwt", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"private_key_jwt"}`
		}, want: cimdAuthMethodUnsupported},
		{name: "client_secret present", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://app.example/cb"],"client_secret":"s"}`
		}, want: cimdDocInvalid},
		{name: "client_secret_expires_at present", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://app.example/cb"],"client_secret_expires_at":0}`
		}, want: cimdDocInvalid},
		{name: "client_secret null is absent", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://app.example/cb"],"client_secret":null}`
		}, want: cimdOK},
		{name: "grant_types implicit", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://app.example/cb"],"grant_types":["implicit"]}`
		}, want: cimdDocInvalid},
		{name: "grant_types empty", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://app.example/cb"],"grant_types":[]}`
		}, want: cimdDocInvalid},
		{name: "client_name too long", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://app.example/cb"],"client_name":"` + strings.Repeat("a", maxClientNameLength+1) + `"}`
		}, want: cimdDocInvalid},
		{name: "client_name control byte", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://app.example/cb"],"client_name":"a\nb"}`
		}, want: cimdDocInvalid},
		{name: "client_name comma", body: func(id string) string {
			return `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://app.example/cb"],"client_name":"a,b"}`
		}, want: cimdDocInvalid},
		{name: "body one byte over the cap", wantDescHas: "exceeds the size cap", body: func(id string) string {
			head := `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://app.example/cb"],"client_name":"`
			tail := `"}`
			return head + strings.Repeat("a", cimdMaxBodyBytes+1-len(head)-len(tail)) + tail
		}, want: cimdTooLarge},
		{name: "body at the cap is read", body: func(id string) string {
			head := `{"client_id":` + jsonStr(id) + `,"redirect_uris":["https://app.example/cb"],"client_name":"`
			tail := `"}`
			return head + strings.Repeat("a", cimdMaxBodyBytes-len(head)-len(tail)) + tail
		}, want: cimdDocInvalid}, // a name filling the cap fails the length rule, not the size cap
		{name: "20 KiB response header", body: validDoc, headerPad: 20 << 10, want: cimdFetchError},
		{name: "text/html", body: validDoc, contentType: "text/html; charset=utf-8", want: cimdFetchError},
		{name: "application/problem+json accepted", body: validDoc, contentType: "application/problem+json", want: cimdOK},
		{name: "missing content-type", body: validDoc, contentType: "-", want: cimdFetchError},
		{name: "HTTP 301", body: validDoc, status: http.StatusMovedPermanently, want: cimdFetchError, wantHits: 1},
		{name: "HTTP 404", body: validDoc, status: http.StatusNotFound, want: cimdFetchError},
		{name: "trailing JSON data", body: func(id string) string { return validDoc(id) + ` {}` }, want: cimdDocInvalid},
		{name: "not an object", body: func(string) string { return `[]` }, want: cimdDocInvalid},
		{name: "malformed JSON", body: func(string) string { return `{` }, want: cimdDocInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			var clientID, srvURL string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.URL.Path == "/other.json" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(validDoc(clientID)))
					return
				}
				switch tc.contentType {
				case "":
					w.Header().Set("Content-Type", "application/json")
				case "-":
				default:
					w.Header().Set("Content-Type", tc.contentType)
				}
				if tc.headerPad > 0 {
					w.Header().Set("X-Pad", strings.Repeat("a", tc.headerPad))
				}
				if tc.status == http.StatusMovedPermanently {
					// Same server, valid document: a followed redirect shows as 2 hits and ok.
					w.Header().Set("Location", srvURL+"/other.json")
				}
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				_, _ = w.Write([]byte(tc.body(clientID)))
			}))
			defer srv.Close()
			clientID = cimdURL(t, srv, "/client.json")
			srvURL = srv.URL
			r := newTestCIMDResolver(t, srv, tc.allow)
			before, beforeTotal := testutil.ToFloat64(metrics.CIMDFetch.WithLabelValues(string(tc.want))), cimdFetchTotal()

			client, ce := r.Resolve(context.Background(), clientID, audience)

			wantHits := tc.wantHits
			if wantHits == 0 {
				wantHits = 1
			}
			if n := hits.Load(); n != wantHits {
				t.Errorf("server hits = %d, want %d", n, wantHits)
			}
			if tc.want != cimdOK {
				if client != nil {
					t.Errorf("want nil client, got %+v", client)
				}
				assertCIMDResult(t, ce, tc.want, before, beforeTotal)
				if tc.wantDescHas != "" && !strings.Contains(ce.Desc, tc.wantDescHas) {
					t.Errorf("Desc = %q, want it to name %q", ce.Desc, tc.wantDescHas)
				}
				return
			}
			if ce != nil {
				t.Fatalf("Resolve: %v", ce)
			}
			if got := testutil.ToFloat64(metrics.CIMDFetch.WithLabelValues("ok")) - before; got != 1 {
				t.Errorf("cimd_fetch{ok} delta = %v, want 1", got)
			}
			if got := cimdFetchTotal() - beforeTotal; got != 1 {
				t.Errorf("cimd_fetch total delta = %v, want 1", got)
			}
			var doc cimdDocument
			if err := json.Unmarshal([]byte(tc.body(clientID)), &doc); err != nil {
				t.Fatal(err)
			}
			if client.ID != clientID || client.ClientName != doc.ClientName || strings.Join(client.RedirectURIs, " ") != strings.Join(doc.RedirectURIs, " ") {
				t.Errorf("client = %+v, want ID %q name %q redirect_uris %q", client, clientID, doc.ClientName, doc.RedirectURIs)
			}
			if client.Typ != token.PurposeClient || client.Audience != audience || !client.ExpiresAt.IsZero() {
				t.Errorf("client = %+v, want typ %q aud %q and zero ExpiresAt", client, token.PurposeClient, audience)
			}
			if clientExpired(client) {
				t.Error("CIMD client must never expire")
			}
		})
	}
}

// Full semaphore: refused without a request; drained: served.
func TestCIMDResolve_CapacityExhausted(t *testing.T) {
	var hits atomic.Int32
	var clientID string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"client_id":` + jsonStr(clientID) + `,"redirect_uris":["https://app.example/cb"]}`))
	}))
	defer srv.Close()
	clientID = cimdURL(t, srv, "/client.json")
	r := newTestCIMDResolver(t, srv, "")
	for range cap(r.sem) {
		r.sem <- struct{}{}
	}
	before, beforeTotal := testutil.ToFloat64(metrics.CIMDFetch.WithLabelValues(string(cimdFetchError))), cimdFetchTotal()
	_, ce := r.Resolve(context.Background(), clientID, "https://proxy.example")
	assertCIMDResult(t, ce, cimdFetchError, before, beforeTotal)
	if !errors.Is(ce, errCIMDCapacity) {
		t.Errorf("want errCIMDCapacity as the cause, got %v", ce)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("server hits = %d, want 0", n)
	}
	for range cap(r.sem) {
		<-r.sem
	}
	if _, ce := r.Resolve(context.Background(), clientID, "https://proxy.example"); ce != nil {
		t.Fatalf("after drain: %v", ce)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("server hits = %d, want 1", n)
	}
	if n := len(r.sem); n != 0 {
		t.Fatalf("semaphore holds %d slot(s) after a served fetch, want 0: the slot leaked", n)
	}
}

// The failure log names the host through the same byte filter as the
// error page: a non-ASCII name arrives stripped, never raw. The
// semaphore is filled first, so fetch refuses after the host is known
// and before any lookup or dial: no network is involved.
func TestCIMDResolve_LogHostSanitized(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	r := NewCIMDResolver(zap.New(core), config.RedirectAllowlist{}, config.WebRedirectAllowlist{}, CIMDResolverOptions{})
	for range cap(r.sem) {
		r.sem <- struct{}{}
	}
	_, ce := r.Resolve(context.Background(), "https://ex\u00e4mple.invalid/c", "https://proxy.example")
	if ce == nil || !errors.Is(ce, errCIMDCapacity) {
		t.Fatalf("want the capacity refusal, got %v", ce)
	}
	entries := logs.FilterMessage("cimd_resolve_failed").All()
	if len(entries) != 1 {
		t.Fatalf("want 1 cimd_resolve_failed entry, got %d", len(entries))
	}
	if got := entries[0].ContextMap()["client_id_host"]; got != "exmple.invalid" {
		t.Errorf("client_id_host = %q, want %q", got, "exmple.invalid")
	}
}

// The logged cause is clamped: a metadata host answering with a 12 KiB
// Content-Type must not land 12 KiB in the WARN line.
func TestCIMDResolve_LogCauseClamped(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/"+strings.Repeat("a", 12<<10))
	}))
	defer srv.Close()
	core, logs := observer.New(zap.WarnLevel)
	r := newTestCIMDResolver(t, srv, "")
	r.logger = zap.New(core)
	_, ce := r.Resolve(context.Background(), cimdURL(t, srv, "/client.json"), "https://proxy.example")
	if ce == nil || ce.Result != cimdFetchError {
		t.Fatalf("want fetch_error, got %v", ce)
	}
	entries := logs.FilterMessage("cimd_resolve_failed").All()
	if len(entries) != 1 {
		t.Fatalf("want 1 cimd_resolve_failed entry, got %d", len(entries))
	}
	got, _ := entries[0].ContextMap()["error"].(string)
	if got == "" || len(got) > 200 {
		t.Errorf("error field length = %d, want 1..200: %q", len(got), got[:min(len(got), 60)])
	}
}

// TestCIMDResolve_PrivateKeyJWTDescription pins the error_description
// clients are told to act on.
func TestCIMDResolve_PrivateKeyJWTDescription(t *testing.T) {
	_, ce := parseCIMDDocument([]byte(`{"client_id":"https://h/c","redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"private_key_jwt"}`), "https://h/c", config.RedirectAllowlist{}, config.WebRedirectAllowlist{})
	if ce == nil || ce.Result != cimdAuthMethodUnsupported || ce.Desc != "private_key_jwt not supported, use none" {
		t.Fatalf("got %#v", ce)
	}
}

func TestIsCIMDClientID(t *testing.T) {
	for id, want := range map[string]bool{
		"https://h/c":      true,
		"HTTPS://h/c":      false,
		"http://h/c":       false,
		"aHR0cHM6Ly9oL2M=": false,
		"":                 false,
	} {
		if got := isCIMDClientID(id); got != want {
			t.Errorf("isCIMDClientID(%q) = %v, want %v", id, got, want)
		}
	}
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
