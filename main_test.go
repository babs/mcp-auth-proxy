package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/babs/mcp-auth-proxy/replay"
)

// fakeStore counts Exists calls so we can assert the readyz cache holds
// consecutive probes to a single Redis round-trip (H4).
type fakeStore struct {
	existsCalls atomic.Int32
	existsErr   error
}

func (f *fakeStore) ClaimOnce(_ context.Context, _ string, _ time.Duration) error {
	return nil
}
func (f *fakeStore) Mark(_ context.Context, _ string, _ time.Duration) error { return nil }
func (f *fakeStore) Exists(_ context.Context, _ string) (bool, error) {
	f.existsCalls.Add(1)
	return false, f.existsErr
}
func (f *fakeStore) ClaimOrCheckFamily(_ context.Context, _, _ string, _ time.Duration) (bool, bool, error) {
	return false, false, nil
}
func (f *fakeStore) Close() error { return nil }

// TestReadyz_NoStore_AlwaysOK: without a replay store, readyz must always
// return 200 without consulting anything.
func TestReadyz_NoStore_AlwaysOK(t *testing.T) {
	h := readyzHandler(nil, zap.NewNop(), nil)
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// TestReadyz_RedisOK_Caches: two probes back-to-back hit Redis once.
func TestReadyz_RedisOK_Caches(t *testing.T) {
	var fs fakeStore
	h := readyzHandler(&fs, zap.NewNop(), nil)

	for i := range 3 {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("probe %d: expected 200, got %d", i, rr.Code)
		}
	}

	if got := fs.existsCalls.Load(); got != 1 {
		t.Errorf("expected 1 Exists call (cached); got %d", got)
	}
}

// TestReadyz_RedisDown_Reports503: when the backing store returns an
// error, readyz flips to 503 so the orchestrator can pull the pod.
func TestReadyz_RedisDown_Reports503(t *testing.T) {
	fs := &fakeStore{existsErr: errors.New("dial: refused")}
	h := readyzHandler(fs, zap.NewNop(), nil)

	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}

// Keep the import set honest even if the test list above changes.
var _ replay.Store = (*fakeStore)(nil)

// TestSubjectLimiter_EvictsIdle: after pruneOnce with a past cutoff, an
// entry with no in-flight work must be removed from the map so memory
// stays bounded to active principals (M1).
func TestSubjectLimiter_EvictsIdle(t *testing.T) {
	l := &subjectLimiter{cap: 4, logger: zap.NewNop()}
	// Warm two subjects with a single Acquire+Release each.
	for _, sub := range []string{"alice", "bob"} {
		se := l.get(sub)
		if !se.sem.TryAcquire(1) {
			t.Fatalf("warm acquire failed for %s", sub)
		}
		se.inFlight.Add(1)
		se.lastUsed.Store(time.Now().Add(-10 * time.Minute).UnixNano())
		se.inFlight.Add(-1)
		se.sem.Release(1)
	}
	before := 0
	l.sems.Range(func(_, _ any) bool { before++; return true })
	if before != 2 {
		t.Fatalf("expected 2 entries before prune, got %d", before)
	}

	l.pruneOnce(time.Now(), 5*time.Minute)

	after := 0
	l.sems.Range(func(_, _ any) bool { after++; return true })
	if after != 0 {
		t.Fatalf("expected 0 entries after prune, got %d", after)
	}
}

// TestReadyz_CacheTTLSplit: the readyz cache TTL differs between the OK
// and failure branches — OK is cached for 250 ms (so a Redis crash right
// after a successful probe is noticed quickly) while failure is cached
// for 1 s (to absorb probe floods against a downed Redis). We pin both
// constants by driving the cache with an explicit clock via last-probe
// timestamp manipulation (not possible with wall-clock without sleeps),
// so the assertion here exercises the conditional directly: after a
// failing probe, a back-to-back probe should reuse the cached 503 and
// NOT hit the store a second time; after an OK probe, same invariant
// holds for the shorter window.
func TestReadyz_CacheTTLSplit(t *testing.T) {
	var fs fakeStore
	h := readyzHandler(&fs, zap.NewNop(), nil)

	// Prime the cache with one OK probe.
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("prime: expected 200, got %d", rr.Code)
	}
	if got := fs.existsCalls.Load(); got != 1 {
		t.Fatalf("prime: expected 1 call, got %d", got)
	}
	// Second probe within the OK TTL window must hit the cache.
	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("cached: expected 200, got %d", rr.Code)
	}
	if got := fs.existsCalls.Load(); got != 1 {
		t.Errorf("cached: expected still 1 call (OK cache hit), got %d", got)
	}

	// Flip the store to error; wait past the 250 ms OK TTL so the next
	// probe actually reaches the store, then confirm the failure branch
	// caches the 503 for the longer 1 s window.
	fs.existsErr = errors.New("dial: refused")
	time.Sleep(270 * time.Millisecond)
	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("after TTL: expected 503, got %d", rr.Code)
	}
	failCalls := fs.existsCalls.Load()
	if failCalls != 2 {
		t.Fatalf("after TTL: expected 2 calls total, got %d", failCalls)
	}
	// Back-to-back probe within the failure TTL window must hit the cache.
	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("fail-cached: expected 503, got %d", rr.Code)
	}
	if got := fs.existsCalls.Load(); got != failCalls {
		t.Errorf("fail-cached: expected still %d calls (failure cache hit), got %d", failCalls, got)
	}
}

// TestSubjectLimiter_KeepsInFlight: an entry with non-zero in-flight must
// not be evicted even if lastUsed is ancient, so releasing the semaphore
// later doesn't touch a map-detached struct (the struct is safe either
// way, but the map must reflect the live in-flight work).
func TestSubjectLimiter_KeepsInFlight(t *testing.T) {
	l := &subjectLimiter{cap: 4, logger: zap.NewNop()}
	se := l.get("alice")
	se.inFlight.Add(1)
	se.lastUsed.Store(time.Now().Add(-1 * time.Hour).UnixNano())
	defer se.inFlight.Add(-1)

	l.pruneOnce(time.Now(), 5*time.Minute)

	if _, ok := l.sems.Load("alice"); !ok {
		t.Fatal("entry with in-flight work was evicted")
	}
}

// TestSubjectLimiter_FreshEntryNotEvicted: a freshly-minted subjectSem
// must survive an immediate prune pass. Without the lastUsed stamp at
// get() time, a fresh entry has lastUsed=0 (Unix epoch) which is always
// < cutoff, so a prune tick landing between LoadOrStore and the
// caller's first Add(1) would evict it — the next concurrent request
// for the same subject would create a second semaphore and the
// per-subject cap would effectively double.
func TestSubjectLimiter_FreshEntryNotEvicted(t *testing.T) {
	l := &subjectLimiter{cap: 4, logger: zap.NewNop()}
	_ = l.get("alice")
	// Run prune immediately; fresh entry has inFlight=0 and (post-fix)
	// lastUsed=now. A 5-minute idle cutoff must keep it.
	l.pruneOnce(time.Now(), 5*time.Minute)
	if _, ok := l.sems.Load("alice"); !ok {
		t.Fatal("fresh entry evicted before first Acquire (prune-race regression)")
	}
}

// TestReadyz_ShuttingDown_Returns503: after the drain sequence flips
// the shuttingDown flag, /readyz must return 503 immediately without
// calling into the (about-to-close) Redis client.
func TestReadyz_ShuttingDown_Returns503(t *testing.T) {
	var fs fakeStore
	var sd atomic.Bool
	sd.Store(true)
	h := readyzHandler(&fs, zap.NewNop(), &sd)

	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 during shutdown, got %d", rr.Code)
	}
	if got := fs.existsCalls.Load(); got != 0 {
		t.Errorf("expected 0 Exists calls during shutdown, got %d", got)
	}
}

// TestReadyz_Singleflight_CoalescesConcurrentMisses: under a burst of
// concurrent probes that all miss the cache (cold start), singleflight
// must collapse them into a single Exists call. Without coalescing a
// kubelet readyz storm amplifies into N Redis round trips per window.
func TestReadyz_Singleflight_CoalescesConcurrentMisses(t *testing.T) {
	var fs fakeStore
	h := readyzHandler(&fs, zap.NewNop(), nil)

	const n = 50
	done := make(chan struct{}, n)
	for range n {
		go func() {
			rr := httptest.NewRecorder()
			h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
			done <- struct{}{}
		}()
	}
	for range n {
		<-done
	}
	// singleflight may allow a small number of in-flight probes if one
	// completes while others are queued at the outer cache check; the
	// coalescing is "at most a handful" rather than "exactly one", but
	// must stay an order of magnitude below N.
	if got := fs.existsCalls.Load(); got > 5 {
		t.Errorf("singleflight did not coalesce: %d Exists calls for %d concurrent probes", got, n)
	}
}
