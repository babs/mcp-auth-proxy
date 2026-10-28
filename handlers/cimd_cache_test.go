package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/babs/mcp-auth-proxy/config"
	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

func cimdCacheCount(res cimdCacheResult) float64 {
	return testutil.ToFloat64(metrics.CIMDCache.WithLabelValues(string(res)))
}

// cimdCacheServer serves a valid document for /client.json with the given
// Cache-Control and status; /mismatch.json carries another client_id.
func cimdCacheServer(t *testing.T, cacheControl string, status int) (srv *httptest.Server, hits *atomic.Int32, clientID string) {
	t.Helper()
	hits = new(atomic.Int32)
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if cacheControl != "" {
			w.Header().Set(cimdCacheControlHeader, cacheControl)
		}
		if status != 0 {
			w.WriteHeader(status)
		}
		id := clientID
		if r.URL.Path == "/mismatch.json" {
			id += "x"
		}
		_, _ = w.Write([]byte(`{"client_id":` + jsonStr(id) + `,"client_name":"Example","redirect_uris":["https://app.example/cb"]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, hits, cimdURL(t, srv, "/client.json")
}

func newTestCIMDResolverAt(t *testing.T, srv *httptest.Server, now *time.Time) *CIMDResolver {
	t.Helper()
	return NewCIMDResolver(zap.NewNop(), config.RedirectAllowlist{}, config.WebRedirectAllowlist{}, config.CIMDHostAllowlist{},
		CIMDResolverOptions{DialGuardOverride: allowLoopbackDial, TLSClientConfigOverride: trustTestServer(srv), NowOverride: func() time.Time { return *now }})
}

// MAP-002-AC11: a second Resolve within the TTL is served from the cache
// and does not count as a fetch.
func TestCIMDResolve_CacheHit(t *testing.T) {
	srv, hits, clientID := cimdCacheServer(t, "", 0)
	now := time.Now()
	r := newTestCIMDResolverAt(t, srv, &now)
	const audience = "https://proxy.example"

	first, ce := r.Resolve(context.Background(), clientID, audience)
	if ce != nil {
		t.Fatalf("first Resolve: %v", ce)
	}
	fetchBefore, hitBefore := cimdFetchTotal(), cimdCacheCount(cimdCacheHit)
	second, ce := r.Resolve(context.Background(), clientID, audience)
	if ce != nil {
		t.Fatalf("second Resolve: %v", ce)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("server hits = %d, want 1", n)
	}
	if got := cimdCacheCount(cimdCacheHit) - hitBefore; got != 1 {
		t.Errorf("cimd_cache{hit} delta = %v, want 1", got)
	}
	if got := cimdFetchTotal() - fetchBefore; got != 0 {
		t.Errorf("cimd_fetch total delta = %v, want 0: a hit is not a fetch", got)
	}
	if first.ClientName != "Example" || second.ClientName != first.ClientName || second.ID != first.ID || strings.Join(second.RedirectURIs, " ") != strings.Join(first.RedirectURIs, " ") {
		t.Errorf("second = %+v, want %+v", second, first)
	}
}

// MAP-002-AC11: max-age=1 is clamped to 60 s; past it the entry expires
// and the document is fetched again.
func TestCIMDResolve_CacheExpired(t *testing.T) {
	srv, hits, clientID := cimdCacheServer(t, "max-age=1", 0)
	now := time.Now()
	r := newTestCIMDResolverAt(t, srv, &now)
	if _, ce := r.Resolve(context.Background(), clientID, "https://proxy.example"); ce != nil {
		t.Fatal(ce)
	}
	now = now.Add(30 * time.Second)
	if _, ce := r.Resolve(context.Background(), clientID, "https://proxy.example"); ce != nil {
		t.Fatal(ce)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("server hits after 30 s = %d, want 1: max-age=1 is clamped up to 60 s", n)
	}
	expiredBefore, okBefore := cimdCacheCount(cimdCacheExpired), testutil.ToFloat64(metrics.CIMDFetch.WithLabelValues("ok"))
	now = now.Add(31 * time.Second)
	if _, ce := r.Resolve(context.Background(), clientID, "https://proxy.example"); ce != nil {
		t.Fatal(ce)
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("server hits after 61 s = %d, want 2", n)
	}
	if got := cimdCacheCount(cimdCacheExpired) - expiredBefore; got != 1 {
		t.Errorf("cimd_cache{expired} delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.CIMDFetch.WithLabelValues("ok")) - okBefore; got != 1 {
		t.Errorf("cimd_fetch{ok} delta = %v, want 1", got)
	}
}

// MAP-002-AC11: the publisher's no-store is honoured, a failed fetch is
// not cached, an invalid document is not cached.
func TestCIMDResolve_NotCached(t *testing.T) {
	cases := []struct {
		name         string
		cacheControl string
		status       int
		path         string
		want         cimdResult
	}{
		{name: "no-store", cacheControl: "no-store", path: "/client.json", want: cimdOK},
		{name: "HTTP 500", status: http.StatusInternalServerError, path: "/client.json", want: cimdFetchError},
		{name: "client_id mismatch", path: "/mismatch.json", want: cimdDocInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, hits, _ := cimdCacheServer(t, tc.cacheControl, tc.status)
			now := time.Now()
			r := newTestCIMDResolverAt(t, srv, &now)
			id := cimdURL(t, srv, tc.path)
			missBefore := cimdCacheCount(cimdCacheMiss)
			for i := range 2 {
				_, ce := r.Resolve(context.Background(), id, "https://proxy.example")
				if tc.want == cimdOK && ce != nil {
					t.Fatalf("Resolve %d: %v", i, ce)
				}
				if tc.want != cimdOK && (ce == nil || ce.Result != tc.want) {
					t.Fatalf("Resolve %d: got %v, want %s", i, ce, tc.want)
				}
			}
			if n := hits.Load(); n != 2 {
				t.Errorf("server hits = %d, want 2: nothing may be served from the cache", n)
			}
			if got := cimdCacheCount(cimdCacheMiss) - missBefore; got != 2 {
				t.Errorf("cimd_cache{miss} delta = %v, want 2", got)
			}
		})
	}
}

// MAP-002-AC11
func TestCIMDCacheTTL(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return now.Add(d).Format(http.TimeFormat) }
	cases := []struct {
		header string
		other  http.Header
		want   time.Duration
	}{
		{"", nil, 5 * time.Minute},
		{"max-age=1", nil, 60 * time.Second},
		{"max-age=86401", nil, 24 * time.Hour},
		{"s-maxage=120, max-age=10", nil, 120 * time.Second},
		{"max-age=10, s-maxage=120", nil, 120 * time.Second},
		{"no-store", nil, 0},
		{"no-cache", nil, 0},
		{"public, max-age=600, no-store", nil, 0},
		{"private, max-age=300", nil, 0},
		{"public, max-age=300", nil, 300 * time.Second},
		{"max-age=abc", nil, 5 * time.Minute},
		{"max-age=-5", nil, 5 * time.Minute},
		{"max-age=99999999999999999999", nil, 24 * time.Hour},
		{"Max-Age=120", nil, 120 * time.Second},
		{`max-age="120"`, nil, 120 * time.Second},
		{"max-age=600", http.Header{"Age": {"100"}}, 500 * time.Second},
		{"max-age=300", http.Header{"Age": {"290"}}, 60 * time.Second},
		{"max-age=300", http.Header{"Age": {"300"}}, 0},
		{"s-maxage=120, max-age=900", http.Header{"Age": {"60"}}, 60 * time.Second},
		{"max-age=31536000", http.Header{"Age": {"172800"}}, 24 * time.Hour},
		{"max-age=600", http.Header{"Age": {"x"}}, 600 * time.Second},
		{"", http.Header{"Age": {"9999"}}, 5 * time.Minute},
		{"", http.Header{"Expires": {"0"}}, 0},
		{"", http.Header{"Expires": {"garbage"}}, 0},
		{"", http.Header{"Expires": {""}}, 0},
		{"", http.Header{"Expires": {at(-time.Hour)}}, 0},
		{"", http.Header{"Expires": {at(10 * time.Minute)}}, 10 * time.Minute},
		{"", http.Header{"Expires": {at(10 * time.Minute)}, "Date": {at(8 * time.Minute)}}, 2 * time.Minute},
		{"", http.Header{"Expires": {at(10 * time.Minute)}, "Age": {"420"}}, 3 * time.Minute},
		{"max-age=300", http.Header{"Expires": {"0"}}, 300 * time.Second},
		{"", http.Header{"Expires": {at(10 * time.Minute)}, "Date": {at(-time.Hour)}}, 10 * time.Minute},
		{"max-age=900", http.Header{"Date": {at(-300 * time.Second)}}, 600 * time.Second},
		{"max-age=900", http.Header{"Date": {at(-300 * time.Second)}, "Age": {"400"}}, 500 * time.Second},
		{"max-age=900", http.Header{"Date": {at(time.Hour)}}, 900 * time.Second},
		{"", http.Header{"Expires": {"Mon, 01 Jan 1600 00:00:00 GMT"}, "Age": {"1"}}, 0},
		{"", http.Header{"Expires": {at(time.Hour)}, "Date": {"Fri, 31 Dec 9999 23:59:59 GMT"}, "Age": {"1"}}, 0},
		{"", http.Header{"Expires": {"Thu, 01 Jan 1970 00:00:00 GMT"}, "Age": {"99999999999999999999"}}, 0},
		{"max-age=600", http.Header{"Age": {"99999999999999999999"}}, 0},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s|%v", tc.header, tc.other), func(t *testing.T) {
			h := tc.other.Clone()
			if h == nil {
				h = http.Header{}
			}
			if tc.header != "" {
				h.Set(cimdCacheControlHeader, tc.header)
			}
			if got := cimdCacheTTL(h, now); got != tc.want {
				t.Errorf("cimdCacheTTL(%q, %v) = %v, want %v", tc.header, tc.other, got, tc.want)
			}
		})
	}
}

// MAP-002-AC11: a put on a present key replaces the value in place.
func TestCIMDCache_PutReplaces(t *testing.T) {
	c := newCIMDCache(nil)
	a, b := &sealedClient{ID: "a"}, &sealedClient{ID: "b"}
	c.put("k", a, time.Minute)
	c.put("k", b, time.Minute)
	if c.order.Len() != 1 || len(c.entries) != 1 {
		t.Errorf("list %d, map %d, want 1 and 1", c.order.Len(), len(c.entries))
	}
	if got := testutil.ToFloat64(metrics.CIMDCacheEntries); got != 1 {
		t.Errorf("cimd_cache_entries = %v, want 1", got)
	}
	if client, res := c.get("k"); res != cimdCacheHit || client.ID != b.ID {
		t.Errorf("get = %s %+v, want hit on b", res, client)
	}
}

// The cache stores and returns copies: writing through the pointer given
// to put, or the one returned by get, must not reach the cache.
func TestCIMDCache_HitIsACopy(t *testing.T) {
	c := newCIMDCache(nil)
	stored := &sealedClient{ID: "k", ClientName: "Example"}
	c.put("k", stored, time.Minute)
	stored.ClientName = "Tampered"
	stored.ExpiresAt = time.Unix(1, 0)
	got, res := c.get("k")
	if res != cimdCacheHit {
		t.Fatalf("get = %s, want hit", res)
	}
	if got.ClientName != "Example" || !got.ExpiresAt.IsZero() {
		t.Errorf("cached client = %+v: a write through the pointer given to put reached the cache", got)
	}
	got.ClientName = "Tampered"
	got.ExpiresAt = time.Unix(1, 0)
	again, _ := c.get("k")
	if again.ClientName != "Example" || !again.ExpiresAt.IsZero() {
		t.Errorf("cached client = %+v: a write through the returned pointer reached the cache", again)
	}
}

// MAP-002-AC11: capacity evicts the least recently used entry; an expired
// get drops the entry.
func TestCIMDCache_EvictionAndExpiry(t *testing.T) {
	now := time.Now()
	c := newCIMDCache(func() time.Time { return now })
	for i := range cimdCacheMaxEntries + 1 {
		c.put("k"+strconv.Itoa(i), &sealedClient{ID: strconv.Itoa(i)}, time.Minute)
	}
	if n := len(c.entries); n != cimdCacheMaxEntries || c.order.Len() != n {
		t.Fatalf("len = %d (list %d), want %d", n, c.order.Len(), cimdCacheMaxEntries)
	}
	if got := testutil.ToFloat64(metrics.CIMDCacheEntries); got != cimdCacheMaxEntries {
		t.Errorf("cimd_cache_entries = %v, want %d", got, cimdCacheMaxEntries)
	}
	if _, res := c.get("k0"); res != cimdCacheMiss {
		t.Errorf("k0 = %s, want miss: the oldest entry is evicted first", res)
	}
	if client, res := c.get("k1"); res != cimdCacheHit || client.ID != "1" {
		t.Errorf("k1 = %s %+v, want hit", res, client)
	}
	// k1 was just used; k2 is now the back and goes on the next overflow.
	c.put("new", &sealedClient{}, time.Minute)
	if _, res := c.get("k2"); res != cimdCacheMiss {
		t.Errorf("k2 = %s, want miss: a hit moves k1 to the front", res)
	}
	if _, res := c.get("k1"); res != cimdCacheHit {
		t.Errorf("k1 = %s, want hit", res)
	}

	now = now.Add(61 * time.Second)
	if _, res := c.get("k1"); res != cimdCacheExpired {
		t.Errorf("k1 after the TTL = %s, want expired", res)
	}
	if _, ok := c.entries["k1"]; ok {
		t.Error("expired entry still stored")
	}
	if got := testutil.ToFloat64(metrics.CIMDCacheEntries); got != cimdCacheMaxEntries-1 {
		t.Errorf("cimd_cache_entries = %v, want %d", got, cimdCacheMaxEntries-1)
	}
	if _, res := c.get("k1"); res != cimdCacheMiss {
		t.Errorf("k1 after removal = %s, want miss", res)
	}
}
