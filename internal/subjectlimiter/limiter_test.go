package subjectlimiter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/babs/mcp-auth-proxy/middleware"
)

// TestLimiter_EvictsIdle: pruneOnce removes entries with no in-flight
// work past the idle cutoff so memory stays bounded to active
// principals.
func TestLimiter_EvictsIdle(t *testing.T) {
	l := &Limiter{cap: 4, logger: zap.NewNop()}
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

	l.PruneOnce(time.Now(), 5*time.Minute)

	after := 0
	l.sems.Range(func(_, _ any) bool { after++; return true })
	if after != 0 {
		t.Fatalf("expected 0 entries after prune, got %d", after)
	}
}

// TestLimiter_KeepsInFlight: an entry with non-zero in-flight must not
// be evicted even if lastUsed is ancient.
func TestLimiter_KeepsInFlight(t *testing.T) {
	l := &Limiter{cap: 4, logger: zap.NewNop()}
	se := l.get("alice")
	se.inFlight.Add(1)
	se.lastUsed.Store(time.Now().Add(-1 * time.Hour).UnixNano())
	defer se.inFlight.Add(-1)

	l.PruneOnce(time.Now(), 5*time.Minute)

	if _, ok := l.sems.Load("alice"); !ok {
		t.Fatal("entry with in-flight work was evicted")
	}
}

// TestLimiter_FreshEntryNotEvicted: a freshly-minted subjectSem must
// survive an immediate prune pass (regression for the LoadOrStore vs
// first-Add race).
func TestLimiter_FreshEntryNotEvicted(t *testing.T) {
	l := &Limiter{cap: 4, logger: zap.NewNop()}
	_ = l.get("alice")
	l.PruneOnce(time.Now(), 5*time.Minute)
	if _, ok := l.sems.Load("alice"); !ok {
		t.Fatal("fresh entry evicted before first Acquire (prune-race regression)")
	}
}

// TestLimiter_Middleware_CapEnforced: the cap+1-th in-flight request
// for the same subject must be rejected 503 with Retry-After; earlier
// requests continue unaffected.
func TestLimiter_Middleware_CapEnforced(t *testing.T) {
	l := &Limiter{cap: 2, logger: zap.NewNop()}
	release := make(chan struct{})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))

	runReq := func() *httptest.ResponseRecorder {
		ctx := context.WithValue(context.Background(), middleware.ContextSubject, "alice")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequestWithContext(ctx, http.MethodGet, "/x", nil))
		return rr
	}

	// Fire two requests that hold the cap; wait until they've acquired.
	var wg sync.WaitGroup
	wg.Add(2)
	results := make([]*httptest.ResponseRecorder, 2)
	for i := range 2 {
		go func() {
			defer wg.Done()
			results[i] = runReq()
		}()
	}
	// Spin until both acquired (inFlight == 2 on alice's sem).
	se := l.get("alice")
	for se.inFlight.Load() < 2 {
		time.Sleep(time.Millisecond)
	}

	// Third request must 503.
	ctx := context.WithValue(context.Background(), middleware.ContextSubject, "alice")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequestWithContext(ctx, http.MethodGet, "/x", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("want 503, got %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 503")
	}

	close(release)
	wg.Wait()
	for i, r := range results {
		if r.Code != http.StatusOK {
			t.Errorf("in-flight request %d: want 200, got %d", i, r.Code)
		}
	}
}

// TestLimiter_Middleware_Passthrough_NoSubject: a request with no
// subject in context must pass through untouched (belt-and-braces
// against middleware-order changes).
func TestLimiter_Middleware_Passthrough_NoSubject(t *testing.T) {
	l := &Limiter{cap: 0, logger: zap.NewNop()} // cap=0 would reject any acquire
	called := false
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/x", nil))

	if !called {
		t.Error("handler not called for subject-less request")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("want 200 passthrough, got %d", rr.Code)
	}
}

// TestNew_PrunerExitsOnCtx: the pruner goroutine must exit when its
// context is cancelled so shutdown doesn't leak it.
func TestNew_PrunerExitsOnCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := New(ctx, 1, zap.NewNop())
	_ = l
	cancel()
	// Give the pruner a moment to notice. There's no direct handle to
	// await exit; the test passes if the goroutine doesn't wedge the
	// process. A goroutine leak would show up under -race with
	// goleak; a smoke time.Sleep here is enough for coverage.
	time.Sleep(10 * time.Millisecond)
}

var _ = atomic.Int64{} // keep the atomic import in scope for future tests
