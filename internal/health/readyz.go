// Package health implements the /readyz probe handler.
//
// Split between two cache TTLs: OK cached for 250ms (so a Redis crash
// right after a successful probe is noticed quickly) and failure
// cached for 1s (to absorb probe floods against a downed Redis — if
// kubelet is already hammering /readyz because the pod failed
// readiness, amplifying into a Redis-hammer on top is exactly the
// cascade H4 in the audit flagged).
//
// singleflight coalesces concurrent cache misses (cold start, TTL
// expiry under probe bursts) so a readyz storm amplifies into at
// most one Redis Exists per TTL window instead of one per probe.
//
// During shutdown the drain sequence flips shuttingDown to true
// BEFORE closing the Redis client, so /readyz short-circuits to 503
// and stops probing a soon-to-be-closed pool (eliminating the
// spurious readyz_redis_probe_failed log spam on every shutdown).
package health

import (
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	"github.com/babs/mcp-auth-proxy/replay"
)

const (
	cacheTTLOK   = 250 * time.Millisecond
	cacheTTLFail = 1 * time.Second
	probeTimeout = 1 * time.Second
)

// Readyz returns a /readyz handler backed by the replay store.
//
// When replayStore is nil the handler always returns 200 (no backend
// to probe). When shuttingDown is non-nil and set, the handler
// returns 503 immediately. Pass a zero-valued *atomic.Bool when the
// caller wants shutdown awareness but has not yet flipped the flag.
func Readyz(replayStore replay.Store, logger *zap.Logger, shuttingDown *atomic.Bool) http.HandlerFunc {
	var (
		mu       sync.Mutex
		lastAt   time.Time
		lastOK   bool
		lastBody string
		sf       singleflight.Group
	)
	return func(w http.ResponseWriter, r *http.Request) {
		if shuttingDown != nil && shuttingDown.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"status":"shutting_down"}`)
			return
		}
		if replayStore == nil {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":"ok"}`)
			return
		}
		mu.Lock()
		ttl := cacheTTLFail
		if lastOK {
			ttl = cacheTTLOK
		}
		if !lastAt.IsZero() && time.Since(lastAt) < ttl {
			ok, body := lastOK, lastBody
			mu.Unlock()
			if ok {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			_, _ = io.WriteString(w, body)
			return
		}
		// Capture the cache snapshot under the lock so a concurrent
		// singleflight winner's refresh is detectable inside Do.
		staleAt := lastAt
		mu.Unlock()

		_, _, _ = sf.Do("probe", func() (any, error) {
			mu.Lock()
			// Skip the probe if another Do winner refreshed the
			// cache between our outer read and entry into this
			// critical section. `lastAt` strictly advances, so
			// inequality with the captured snapshot is the atomic
			// freshness signal.
			if lastAt != staleAt {
				mu.Unlock()
				return nil, nil
			}
			mu.Unlock()

			ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
			defer cancel()
			_, err := replayStore.Exists(ctx, "__readyz_probe__")

			mu.Lock()
			lastAt = time.Now()
			if err != nil {
				lastOK = false
				lastBody = `{"status":"redis_unavailable"}`
			} else {
				lastOK = true
				lastBody = `{"status":"ok"}`
			}
			mu.Unlock()
			if err != nil {
				logger.Warn("readyz_redis_probe_failed", zap.Error(err))
			}
			return nil, nil
		})

		mu.Lock()
		ok, body := lastOK, lastBody
		mu.Unlock()
		if ok {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = io.WriteString(w, body)
	}
}
