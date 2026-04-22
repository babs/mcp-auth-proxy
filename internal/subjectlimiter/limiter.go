// Package subjectlimiter caps in-flight HTTP requests per authenticated
// subject. A single runaway or compromised client identity cannot
// saturate the proxy's goroutine or upstream connection pool at the
// expense of every other caller.
//
// Memory: entries are reclaimed by a pruner goroutine when a subject
// has been idle for IdleEvictAfter, so the map size stays proportional
// to ACTIVE principals, not the lifetime set of ever-seen subjects.
// sync.Map keeps the hot path lock-free except on first-seen subjects.
//
// Correctness: each entry stamps lastUsed at construction time so a
// prune tick landing between LoadOrStore and the caller's first Add
// cannot evict a fresh entry (which would let a concurrent request
// create a second semaphore and effectively double the per-subject
// cap). Entries with in-flight work (inFlight > 0) are never evicted.
package subjectlimiter

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"

	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/middleware"
)

const (
	// IdleEvictAfter is the window past which an entry with no
	// in-flight work is reclaimed by the pruner. 5 minutes covers the
	// longest realistic inter-request gap from a single MCP session
	// without letting orphaned entries linger forever.
	IdleEvictAfter = 5 * time.Minute
	// PruneInterval is the cadence at which the pruner goroutine scans
	// the map. Short enough to keep map size proportional to active
	// principals, long enough to keep the scan cheap.
	PruneInterval = 2 * time.Minute
)

// Limiter caps concurrent requests per subject.
type Limiter struct {
	cap    int64
	sems   sync.Map // map[string]*subjectSem
	logger *zap.Logger
}

type subjectSem struct {
	sem      *semaphore.Weighted
	inFlight atomic.Int64
	lastUsed atomic.Int64 // unix nano
}

// New creates a Limiter and wires a pruner goroutine to ctx so it
// exits on process shutdown. Callers use the Middleware method as an
// http middleware.
func New(ctx context.Context, cap int64, logger *zap.Logger) *Limiter {
	l := &Limiter{cap: cap, logger: logger}
	go l.pruneLoop(ctx)
	return l
}

func (l *Limiter) pruneLoop(ctx context.Context) {
	t := time.NewTicker(PruneInterval)
	defer t.Stop()
	for {
		select {
		case now := <-t.C:
			l.PruneOnce(now, IdleEvictAfter)
		case <-ctx.Done():
			return
		}
	}
}

// PruneOnce performs a single prune pass. Exposed for tests; the
// production pruneLoop drives it on a ticker.
func (l *Limiter) PruneOnce(now time.Time, idleAfter time.Duration) {
	cutoff := now.Add(-idleAfter).UnixNano()
	l.sems.Range(func(k, v any) bool {
		se := v.(*subjectSem)
		// In-flight or recently used → keep. The atomic counter means
		// we never touch the semaphore here, so there is no window
		// where a concurrent Acquire observes a spurious "full" state
		// (contrast with TryAcquire(cap)+Release).
		if se.inFlight.Load() > 0 || se.lastUsed.Load() > cutoff {
			return true
		}
		l.sems.Delete(k)
		return true
	})
}

func (l *Limiter) get(sub string) *subjectSem {
	if v, ok := l.sems.Load(sub); ok {
		return v.(*subjectSem)
	}
	// Stamp lastUsed at construction so the pruner cannot evict a
	// brand-new entry in the window between LoadOrStore and the
	// caller's first Add(1). Without this stamp, fresh entries
	// observe lastUsed=0 (Unix epoch), always below cutoff, so a
	// prune tick landing in that window deletes the entry; a
	// concurrent request from the same subject would then LoadOrStore
	// a second semaphore and effectively double the cap.
	fresh := &subjectSem{sem: semaphore.NewWeighted(l.cap)}
	fresh.lastUsed.Store(time.Now().UnixNano())
	v, _ := l.sems.LoadOrStore(sub, fresh)
	return v.(*subjectSem)
}

// Middleware returns an http.Handler wrapper that rejects the request
// with 503 + Retry-After when the per-subject cap would be exceeded.
// Must run AFTER the auth middleware that sets ContextSubject.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub, _ := r.Context().Value(middleware.ContextSubject).(string)
		if sub == "" {
			// No subject → auth would have rejected already. Belt &
			// braces: pass through so middleware-order changes don't
			// silently DoS unauthenticated paths.
			next.ServeHTTP(w, r)
			return
		}
		se := l.get(sub)
		if !se.sem.TryAcquire(1) {
			metrics.AccessDenied.WithLabelValues("subject_concurrency_exceeded").Inc()
			l.logger.Warn("subject_concurrency_exceeded", zap.String("sub", sub), zap.Int64("cap", l.cap))
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":"temporarily_unavailable","error_description":"per-subject concurrency limit reached"}`)
			return
		}
		se.inFlight.Add(1)
		se.lastUsed.Store(time.Now().UnixNano())
		defer func() {
			se.inFlight.Add(-1)
			se.sem.Release(1)
		}()
		next.ServeHTTP(w, r)
	})
}
