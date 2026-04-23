package health

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

// fakeStore counts Exists calls so cache + singleflight behavior can
// be asserted deterministically.
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
func (f *fakeStore) ClaimOrCheckFamily(_ context.Context, _, _ string, _, _ time.Duration) (bool, bool, error) {
	return false, false, nil
}
func (f *fakeStore) Close() error { return nil }

// Compile-time check that fakeStore satisfies replay.Store.
var _ replay.Store = (*fakeStore)(nil)

func TestReadyz_NoStore_AlwaysOK(t *testing.T) {
	h := Readyz(nil, zap.NewNop(), nil)
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestReadyz_RedisOK_Caches(t *testing.T) {
	var fs fakeStore
	h := Readyz(&fs, zap.NewNop(), nil)

	for range 3 {
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
	}
	if got := fs.existsCalls.Load(); got != 1 {
		t.Errorf("expected 1 Exists call (cached); got %d", got)
	}
}

func TestReadyz_RedisDown_Reports503(t *testing.T) {
	fs := &fakeStore{existsErr: errors.New("dial: refused")}
	h := Readyz(fs, zap.NewNop(), nil)

	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}

func TestReadyz_CacheTTLSplit(t *testing.T) {
	var fs fakeStore
	h := Readyz(&fs, zap.NewNop(), nil)

	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("prime: expected 200, got %d", rr.Code)
	}
	if got := fs.existsCalls.Load(); got != 1 {
		t.Fatalf("prime: expected 1 call, got %d", got)
	}
	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("cached: expected 200, got %d", rr.Code)
	}
	if got := fs.existsCalls.Load(); got != 1 {
		t.Errorf("cached: expected still 1 call, got %d", got)
	}

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
	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("fail-cached: expected 503, got %d", rr.Code)
	}
	if got := fs.existsCalls.Load(); got != failCalls {
		t.Errorf("fail-cached: expected still %d calls, got %d", failCalls, got)
	}
}

func TestReadyz_ShuttingDown_Returns503(t *testing.T) {
	var fs fakeStore
	var sd atomic.Bool
	sd.Store(true)
	h := Readyz(&fs, zap.NewNop(), &sd)

	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/readyz", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 during shutdown, got %d", rr.Code)
	}
	if got := fs.existsCalls.Load(); got != 0 {
		t.Errorf("expected 0 Exists calls during shutdown, got %d", got)
	}
}

func TestReadyz_Singleflight_CoalescesConcurrentMisses(t *testing.T) {
	var fs fakeStore
	h := Readyz(&fs, zap.NewNop(), nil)

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
	if got := fs.existsCalls.Load(); got > 5 {
		t.Errorf("singleflight did not coalesce: %d Exists calls for %d concurrent probes", got, n)
	}
}
