package handlers

import (
	"container/list"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/babs/mcp-auth-proxy/metrics"
)

const (
	// cimdCacheMaxEntries bounds memory against a caller minting URLs: an
	// entry holds up to 5 KiB of document strings plus the key, about 6 MB
	// at cap.
	cimdCacheMaxEntries = 1000
	cimdCacheDefaultTTL = 5 * time.Minute
	// Clamp: a hostile max-age can neither pin a document past a day nor
	// force a refetch per /authorize.
	cimdCacheMinTTL = 60 * time.Second
	cimdCacheMaxTTL = 24 * time.Hour
)

// cimdCacheResult labels metrics.CIMDCache.
type cimdCacheResult string

const (
	cimdCacheHit     cimdCacheResult = "hit"
	cimdCacheMiss    cimdCacheResult = "miss"
	cimdCacheExpired cimdCacheResult = "expired"
)

type cimdCacheEntry struct {
	key     string
	client  *sealedClient
	expires time.Time
}

// cimdCache is a bounded LRU of validated documents (draft -02 §5.2).
// Only a document that passed parseCIMDDocument is stored; errors and
// invalid documents never are. The cache stores and returns copies, so
// no caller holds the cached struct; the RedirectURIs backing array stays
// shared and has no in-place writers.
type cimdCache struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	// Front is the most recently used entry.
	order *list.List
	now   func() time.Time
}

func newCIMDCache(now func() time.Time) *cimdCache {
	if now == nil {
		now = time.Now
	}
	return &cimdCache{entries: make(map[string]*list.Element), order: list.New(), now: now}
}

// get returns the cached client; an expired entry is dropped and reported
// as expired so the caller refetches.
func (c *cimdCache) get(key string) (*sealedClient, cimdCacheResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[key]
	if !ok {
		return nil, cimdCacheMiss
	}
	e := el.Value.(*cimdCacheEntry)
	if !c.now().Before(e.expires) {
		c.remove(el)
		return nil, cimdCacheExpired
	}
	c.order.MoveToFront(el)
	cp := *e.client
	return &cp, cimdCacheHit
}

// put stores or replaces key at the front and evicts the least recently
// used entries over capacity.
func (c *cimdCache) put(key string, client *sealedClient, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := *client
	e := &cimdCacheEntry{key: key, client: &cp, expires: c.now().Add(ttl)}
	if el, ok := c.entries[key]; ok {
		el.Value = e
		c.order.MoveToFront(el)
	} else {
		c.entries[key] = c.order.PushFront(e)
	}
	for c.order.Len() > cimdCacheMaxEntries {
		c.remove(c.order.Back())
	}
	metrics.CIMDCacheEntries.Set(float64(c.order.Len()))
}

// remove runs under c.mu.
func (c *cimdCache) remove(el *list.Element) {
	delete(c.entries, el.Value.(*cimdCacheEntry).key)
	c.order.Remove(el)
	metrics.CIMDCacheEntries.Set(float64(c.order.Len()))
}

// Hoisted out of the function: TestNoStore_IsTheOnlyCacheHeaderWriter
// forbids the literal in any writer, and this is the one reader.
const cimdCacheControlHeader = "Cache-Control"

// cimdCacheTTL derives the cache lifetime from the response's
// Cache-Control: 0 for no-store, no-cache or private (the proxy is a
// shared cache from the publisher's point of view, RFC 9111 §5.2.2.7),
// else s-maxage over max-age, the default when neither parses, clamped to
// [cimdCacheMinTTL, cimdCacheMaxTTL].
func cimdCacheTTL(h http.Header) time.Duration {
	ttl := cimdCacheDefaultTTL
	var maxAge, sMaxAge time.Duration
	var hasMaxAge, hasSMaxAge bool
	for _, v := range h.Values(cimdCacheControlHeader) {
		for d := range strings.SplitSeq(v, ",") {
			name, val, _ := strings.Cut(strings.TrimSpace(d), "=")
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "no-store", "no-cache", "private":
				return 0
			case "max-age":
				maxAge, hasMaxAge = cimdDeltaSeconds(val)
			case "s-maxage":
				sMaxAge, hasSMaxAge = cimdDeltaSeconds(val)
			}
		}
	}
	switch {
	case hasSMaxAge:
		ttl = sMaxAge
	case hasMaxAge:
		ttl = maxAge
	}
	return max(min(ttl, cimdCacheMaxTTL), cimdCacheMinTTL)
}

// cimdDeltaSeconds parses an RFC 9111 delta-seconds value, already capped
// at cimdCacheMaxTTL so a huge digit string cannot overflow the Duration.
func cimdDeltaSeconds(val string) (time.Duration, bool) {
	n, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(val), `"`), 10, 64)
	// RFC 9111 §1.2.2: a value too large to represent is the largest one.
	if n < 0 || (err != nil && !errors.Is(err, strconv.ErrRange)) {
		return 0, false
	}
	return min(time.Duration(n), cimdCacheMaxTTL/time.Second) * time.Second, true
}
