package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"
	"golang.org/x/term"

	"github.com/babs/mcp-auth-proxy/config"
	"github.com/babs/mcp-auth-proxy/handlers"
	"github.com/babs/mcp-auth-proxy/metrics"
	"github.com/babs/mcp-auth-proxy/middleware"
	"github.com/babs/mcp-auth-proxy/proxy"
	"github.com/babs/mcp-auth-proxy/replay"
	"github.com/babs/mcp-auth-proxy/token"
)

var (
	Version        = "v0.0.0"
	CommitHash     = "0000000"
	BuildTimestamp = "1970-01-01T00:00:00"
	Builder        = "unknown"
	ProjectURL     = "https://github.com/babs/mcp-auth-proxy"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	logger := mustLogger(cfg.LogLevel)
	defer logger.Sync()

	logger.Info("starting",
		zap.String("version", Version),
		zap.String("commit", CommitHash),
		zap.String("built_at", BuildTimestamp),
	)

	// Surface low-entropy secrets as a startup warning so operators notice
	// patterns like "aaaa…" / "0123…" before a real incident forces a
	// post-mortem rotation (L1).
	if w := cfg.SecretWeaknessWarning(); w != "" {
		logger.Warn("token_signing_secret_weak", zap.String("reason", w))
	}

	// OIDC discovery — works with any compliant IdP (Keycloak, Entra, Auth0, Okta...).
	// Retry with capped exponential backoff so a transient IdP blip at pod
	// start doesn't burn a CrashLoopBackoff slot; give up after ~60s total.
	// Ctx-aware: SIGTERM during discovery unwinds immediately instead of
	// wedging the pod in an initial 60s sleep (L7).
	discoveryCtx, discoveryCancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer discoveryCancel()
	oidcProvider, err := discoverOIDC(discoveryCtx, cfg.OIDCIssuerURL, logger)
	if err != nil {
		logger.Fatal("oidc_discovery_failed", zap.String("issuer", cfg.OIDCIssuerURL), zap.Error(err))
	}

	oauth2Cfg := &oauth2.Config{
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  cfg.ProxyBaseURL + "/callback",
		Scopes:       []string{"openid", "email", "profile"},
	}

	idTokenVerifier := oidcProvider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID})

	tm, err := token.NewManager(cfg.TokenSigningSecret)
	if err != nil {
		logger.Fatal("token_manager_init_failed", zap.Error(err))
	}
	// Attach a logger so the one-shot seal-rotation threshold warning
	// fires at 2^28 seals (L6).
	tm.SetLogger(logger)

	// Optional replay protection: when REDIS_URL is set, authorization codes
	// become single-use across all replicas. When unset, behavior is stateless
	// (codes unique + short-lived + PKCE-bound but replayable within TTL).
	//
	// REDIS_REQUIRED=true (default) enforces Redis as a hard dependency —
	// the stateless defaults are vulnerable to code/refresh replay within
	// TTL (C3/C4). Operators must opt out (REDIS_REQUIRED=false) to run
	// without it.
	if cfg.RedisRequired && cfg.RedisURL == "" {
		logger.Fatal("redis_required_but_not_configured",
			zap.String("hint", "set REDIS_URL, or REDIS_REQUIRED=false for dev"),
		)
	}
	var replayStore replay.Store
	// rs is kept separate so shutdown can close it after all in-flight
	// handlers drain, even when srv.Shutdown returns early on deadline.
	var rs *replay.RedisStore
	if cfg.RedisURL != "" {
		var err error
		rs, err = replay.NewRedisStore(cfg.RedisURL, cfg.RedisKeyPrefix)
		if err != nil {
			logger.Fatal("replay_store_init_failed", zap.Error(err))
		}
		replayStore = rs
		logger.Info("replay_store_enabled",
			zap.String("backend", "redis"),
			zap.String("key_prefix", cfg.RedisKeyPrefix),
		)
	} else {
		logger.Info("replay_store_disabled")
	}

	proxyHandler, err := proxy.Handler(cfg.UpstreamMCPURL, logger)
	if err != nil {
		logger.Fatal("proxy_handler_init_failed", zap.Error(err))
	}

	authMW := middleware.NewAuth(tm, logger, cfg.ProxyBaseURL, cfg.RevokeBefore)

	// Signal lifecycle. Three handlers listen for SIGINT/SIGTERM over the
	// process lifetime; Go's signal package fans out each delivery to every
	// registered channel/ctx, so the stages are independent.
	//
	// Construction order (code-wise):
	//   1. discoveryCtx — already built above (line ~70), inside the
	//      OIDC-discovery setup block. Cancels the discovery retry loop so a
	//      crash-loop pod exits fast instead of burning the 60s backoff.
	//      Its `defer discoveryCancel()` is already registered.
	//   2. ctx here (next line) — long-lived; routes the first SIGTERM into
	//      the drain loop AND parents the subject-limiter pruner (and any
	//      other long-lived goroutines) so they exit on shutdown.
	//   3. The hard-exit goroutine is installed later, after `<-ctx.Done()`
	//      fires and the shutdown sequence begins, to catch a SECOND signal
	//      during a stuck drain and fast-fail with os.Exit(2).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Pre-arm the hard-exit channel BEFORE blocking on ctx.Done() so a
	// second SIGTERM arriving during the narrow setup window (between
	// first-signal delivery and the downstream signal.Notify call) is
	// still captured. Go's signal package fans out each delivery to
	// every registered channel, so `hard` also receives the first
	// signal; we drain it after ctx.Done() and only arm the exit
	// goroutine on the NEXT signal.
	hard := make(chan os.Signal, 1)
	signal.Notify(hard, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(hard)

	r := chi.NewRouter()
	// inFlight tracks requests hitting the main router so shutdown can
	// drain them before rs.Close() pulls Redis out from under them (H5).
	// srv.Shutdown waits for handlers too, but returns early on the
	// shutdown-context deadline; the WaitGroup lets us wait up to a
	// bounded grace period past that deadline.
	var inFlight sync.WaitGroup
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inFlight.Add(1)
			defer inFlight.Done()
			next.ServeHTTP(w, r)
		})
	})
	// Strip any inbound X-Request-Id before chi mints one. Without this,
	// clients can inject arbitrary request IDs that propagate into every
	// log line for the request — a trivial log-forgery vector.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Del("X-Request-Id")
			next.ServeHTTP(w, r)
		})
	})
	r.Use(chimw.RequestID)
	r.Use(zapMiddleware(logger))
	r.Use(chimw.Recoverer)

	// Per-IP rate limits. By default the limiter keys on the stripped
	// r.RemoteAddr (httprate.KeyByIP) so a client behind an untrusted frontend
	// cannot spoof X-Forwarded-For / X-Real-IP / True-Client-IP to mint its
	// own bucket. Opt in via TRUST_PROXY_HEADERS=true when the proxy sits
	// behind a trusted L4/L7 that already sanitizes those headers.
	ipKeyFunc := httprate.KeyByIP
	if cfg.TrustProxyHeaders {
		ipKeyFunc = httprate.KeyByRealIP
	}
	registerLimit := passthrough
	authorizeLimit := passthrough
	callbackLimit := passthrough
	tokenLimit := passthrough
	mcpLimit := passthrough
	if cfg.RateLimitEnabled {
		registerLimit = rateLimiter(10, time.Minute, "register", ipKeyFunc)
		authorizeLimit = rateLimiter(30, time.Minute, "authorize", ipKeyFunc)
		callbackLimit = rateLimiter(30, time.Minute, "callback", ipKeyFunc)
		tokenLimit = rateLimiter(60, time.Minute, "token", ipKeyFunc)
		// Authenticated MCP route: per-IP bucket. MCP traffic is all
		// POST /mcp so per-path keying would add no dimension — per-subject
		// concurrency below handles the "one caller hogging one tool" shape.
		mcpLimit = rateLimiter(600, time.Minute, "mcp", ipKeyFunc)
		logger.Info("rate_limit_enabled", zap.Bool("trust_proxy_headers", cfg.TrustProxyHeaders))
	} else {
		logger.Info("rate_limit_disabled")
	}

	// Per-subject concurrency cap (M9 / H10). A single authenticated identity
	// cannot saturate the goroutine or upstream connection pool to the
	// detriment of every other caller. Setting MCP_PER_SUBJECT_CONCURRENCY=0
	// disables the limit entirely. Pruner goroutine tied to the signal ctx
	// so idle-subject entries are reclaimed over time (M1).
	var perSubjectLimiter = passthrough
	if cfg.PerSubjectConcurrency > 0 {
		sl := newSubjectLimiter(ctx, cfg.PerSubjectConcurrency, logger)
		perSubjectLimiter = sl.Middleware
		logger.Info("per_subject_concurrency_enabled", zap.Int64("cap", cfg.PerSubjectConcurrency))
	}

	r.Get("/.well-known/oauth-protected-resource", handlers.ResourceMetadata(cfg.ProxyBaseURL))
	r.Get("/.well-known/oauth-authorization-server", handlers.Discovery(cfg.ProxyBaseURL))
	r.With(registerLimit).Post("/register", handlers.Register(tm, logger, cfg.ProxyBaseURL))
	r.With(authorizeLimit).Get("/authorize", handlers.Authorize(tm, logger, cfg.ProxyBaseURL, oauth2Cfg, handlers.AuthorizeConfig{
		PKCERequired:         cfg.PKCERequired,
		CompatAllowStateless: cfg.CompatAllowStateless,
	}))
	r.With(callbackLimit).Get("/callback", handlers.Callback(tm, logger, cfg.ProxyBaseURL, oauth2Cfg, idTokenVerifier, handlers.CallbackConfig{
		AllowedGroups: cfg.AllowedGroups,
		GroupsClaim:   cfg.GroupsClaim,
	}))
	r.With(tokenLimit).Post("/token", handlers.Token(tm, logger, cfg.ProxyBaseURL, cfg.RevokeBefore, replayStore))

	// Liveness probe: always 200 as long as the process is up.
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// Readiness probe lives on the metrics port only (H4). An
	// unauthenticated readiness probe on the public listener is a
	// Redis-DoS amplifier: a sustained flood saturates go-redis' pool,
	// causes /token calls to fail closed, flips readiness, and drops
	// every pod from the K8s Service simultaneously.

	r.Group(func(r chi.Router) {
		r.Use(authMW.Validate)
		r.Use(middleware.RPCPeek(middleware.RPCPeekConfig{
			MaxBodyBytes: cfg.MCPLogBodyMax,
			Logger:       logger,
		}))
		// Per-subject concurrency must run AFTER Validate (needs claims.Subject
		// in the context) and AFTER RPCPeek (keeps the sub/email fields flowing
		// into the access log even when we 503 a request). Rate limit sits last
		// so a rejected request still counts towards mcp_auth_rate_limited_total.
		r.Use(perSubjectLimiter)
		r.Use(mcpLimit)
		r.Handle("/*", proxyHandler)
	})

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: r,
		// ReadHeaderTimeout caps the headers phase independently of the
		// full-body read so a slowloris on the request line cannot occupy
		// a connection indefinitely. ReadTimeout covers the whole read
		// (headers + body); SSE clients that hold POST bodies open would
		// otherwise exceed it, but MCP POSTs are small JSON-RPC payloads.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout left at 0 — required for SSE/streaming connections
		IdleTimeout: 120 * time.Second,
	}

	// Metrics on a separate port so it's not exposed through the public listener
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.Handle("/readyz", readyzHandler(replayStore, logger))
	metricsSrv := &http.Server{
		Addr:         cfg.MetricsAddr,
		Handler:      metricsMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		logger.Info("metrics_listening", zap.String("addr", cfg.MetricsAddr))
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics_listen_error", zap.Error(err))
		}
	}()

	go func() {
		logger.Info("listening", zap.String("addr", cfg.ListenAddr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("listen_error", zap.Error(err))
		}
	}()

	<-ctx.Done()
	logger.Info("shutting_down", zap.Duration("timeout", cfg.ShutdownTimeout))

	// Drain the first signal the pre-armed `hard` channel received
	// along with ctx (Go fans out every signal to all registered
	// targets). After this, any delivery is by definition a SECOND
	// signal and the goroutine below escalates to os.Exit(2).
	select {
	case <-hard:
	default:
	}
	go func() {
		<-hard
		logger.Warn("shutdown_forced_second_signal")
		os.Exit(2)
	}()

	// Independent shutdown contexts so the metrics server isn't starved when
	// the main server consumes the full budget (M3). Main gets the full
	// timeout; metrics gets the same budget in parallel but drains faster.
	mainShutdownCtx, mainCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer mainCancel()
	metricsShutdownCtx, metricsCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer metricsCancel()

	var shutdownWG sync.WaitGroup
	shutdownWG.Add(2)
	go func() {
		defer shutdownWG.Done()
		if err := srv.Shutdown(mainShutdownCtx); err != nil {
			logger.Error("shutdown_error", zap.Error(err))
		}
	}()
	go func() {
		defer shutdownWG.Done()
		if err := metricsSrv.Shutdown(metricsShutdownCtx); err != nil {
			logger.Error("metrics_shutdown_error", zap.Error(err))
		}
	}()
	shutdownWG.Wait()

	// Drain in-flight main-router handlers before closing Redis (H5).
	// srv.Shutdown already waits for them, but only up to its deadline;
	// the inFlight WaitGroup lets us extend with a bounded grace period
	// so long-lived SSE handlers that need Redis mid-flight don't get
	// yanked. 5s grace is plenty for a handler that already passed
	// Shutdown's ListenerClose; anything still running is a bug.
	if rs != nil {
		drained := make(chan struct{})
		go func() {
			inFlight.Wait()
			close(drained)
		}()
		select {
		case <-drained:
		case <-time.After(5 * time.Second):
			logger.Warn("shutdown_inflight_grace_expired")
		}
		if err := rs.Close(); err != nil {
			logger.Warn("replay_store_close_failed", zap.Error(err))
		}
	}
}

// readyzHandler reflects hard runtime dependencies on the metrics port.
// Redis is probed with a short-timeout EXISTS on a sentinel key (cheap,
// no side effects). The result is cached so a probe flood cannot amplify
// into a Redis DoS (H4) — but we cache OK for a shorter window than fail
// (M3): a Redis crash right after a successful probe is noticed quickly
// (250ms staleness), while a healthy flood is still absorbed (1s cache on
// the failure path gives K8s time to drop the pod from the Service before
// we slam Redis with fresh probes). Without Redis configured, always ready.
func readyzHandler(replayStore replay.Store, logger *zap.Logger) http.HandlerFunc {
	const (
		cacheTTLOK   = 250 * time.Millisecond
		cacheTTLFail = 1 * time.Second
	)
	var (
		mu       sync.Mutex
		lastAt   time.Time
		lastOK   bool
		lastBody string
		sf       singleflight.Group
	)
	return func(w http.ResponseWriter, r *http.Request) {
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
		// singleflight winner's refresh can be detected inside Do.
		staleAt := lastAt
		mu.Unlock()

		// singleflight coalesces concurrent cache misses (cold start,
		// TTL expiry under probe bursts) so a kubelet readyz storm
		// amplifies into at most one Redis Exists per TTL window
		// instead of one per probe. After Do returns, every caller
		// reads the fresh cached value.
		_, _, _ = sf.Do("probe", func() (any, error) {
			mu.Lock()
			// Skip the probe if another Do winner refreshed the cache
			// between our outer read and entry into this critical
			// section. `lastAt` strictly advances, so inequality with
			// the captured snapshot is the atomic freshness signal.
			if lastAt != staleAt {
				mu.Unlock()
				return nil, nil
			}
			mu.Unlock()

			ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
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

func mustLogger(level string) *zap.Logger {
	lvl, err := zapcore.ParseLevel(level)
	if err != nil {
		lvl = zapcore.InfoLevel
	}

	var cfg zap.Config
	if term.IsTerminal(int(os.Stdout.Fd())) {
		cfg = zap.NewDevelopmentConfig()
	} else {
		cfg = zap.NewProductionConfig()
	}

	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, err := cfg.Build()
	if err != nil {
		panic("logger: " + err.Error())
	}
	return logger
}

// passthrough is a no-op middleware used when rate limiting is disabled,
// so the router composition is identical in both modes.
func passthrough(next http.Handler) http.Handler { return next }

// rateLimiter builds an httprate middleware that emits a JSON OAuth error on
// throttle and increments mcp_auth_rate_limited_total so operators can alert
// on abuse patterns per-endpoint. Callers pass the key-func composition
// (IP-only, IP+path, ...) that matches the bucket semantics they want.
func rateLimiter(limit int, window time.Duration, endpoint string, keyFuncs ...httprate.KeyFunc) func(http.Handler) http.Handler {
	return httprate.Limit(
		limit, window,
		httprate.WithKeyFuncs(keyFuncs...),
		httprate.WithLimitHandler(func(w http.ResponseWriter, _ *http.Request) {
			metrics.RateLimited.WithLabelValues(endpoint).Inc()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"temporarily_unavailable","error_description":"rate limit exceeded"}`)
		}),
	)
}

// subjectLimiter caps in-flight requests per authenticated subject.
// Memory-safe: entries are reclaimed by a pruner goroutine when a subject
// has been idle (no in-flight work) for subjectIdleEvictAfter, so the
// map size stays proportional to ACTIVE principals, not the lifetime set
// of ever-seen subjects (M1). sync.Map keeps the hot path lock-free
// except on first-seen subjects (m1).
type subjectLimiter struct {
	cap    int64
	sems   sync.Map // map[string]*subjectSem
	logger *zap.Logger
}

type subjectSem struct {
	sem      *semaphore.Weighted
	inFlight atomic.Int64
	lastUsed atomic.Int64 // unix nano
}

const (
	subjectIdleEvictAfter = 5 * time.Minute
	subjectPruneInterval  = 2 * time.Minute
)

// newSubjectLimiter wires the pruner goroutine to ctx so it exits on
// process shutdown. Callers use the Middleware method as an http mw.
func newSubjectLimiter(ctx context.Context, cap int64, logger *zap.Logger) *subjectLimiter {
	l := &subjectLimiter{cap: cap, logger: logger}
	go l.pruneLoop(ctx)
	return l
}

func (l *subjectLimiter) pruneLoop(ctx context.Context) {
	t := time.NewTicker(subjectPruneInterval)
	defer t.Stop()
	for {
		select {
		case now := <-t.C:
			l.pruneOnce(now, subjectIdleEvictAfter)
		case <-ctx.Done():
			return
		}
	}
}

// pruneOnce performs a single prune pass. Exposed for tests; the
// production pruneLoop drives it on a ticker.
func (l *subjectLimiter) pruneOnce(now time.Time, idleAfter time.Duration) {
	cutoff := now.Add(-idleAfter).UnixNano()
	l.sems.Range(func(k, v any) bool {
		se := v.(*subjectSem)
		// In-flight or recently used → keep. The atomic counter means we
		// never touch the semaphore here, so there is no window where a
		// concurrent Acquire observes a spurious "full" state (contrast
		// with TryAcquire(cap)+Release).
		if se.inFlight.Load() > 0 || se.lastUsed.Load() > cutoff {
			return true
		}
		l.sems.Delete(k)
		return true
	})
}

func (l *subjectLimiter) get(sub string) *subjectSem {
	if v, ok := l.sems.Load(sub); ok {
		return v.(*subjectSem)
	}
	// Stamp lastUsed at construction so the pruner cannot evict a
	// brand-new entry in the window between LoadOrStore and the
	// caller's first Add(1) on the middleware hot path. Without this
	// stamp, fresh entries observe lastUsed=0 (Unix epoch), always
	// below cutoff, so a prune tick landing in that window deletes the
	// entry; a concurrent request from the same subject would then
	// LoadOrStore a second semaphore and effectively double the cap.
	fresh := &subjectSem{sem: semaphore.NewWeighted(l.cap)}
	fresh.lastUsed.Store(time.Now().UnixNano())
	v, _ := l.sems.LoadOrStore(sub, fresh)
	return v.(*subjectSem)
}

func (l *subjectLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub, _ := r.Context().Value(middleware.ContextSubject).(string)
		if sub == "" {
			// No subject → Validate would have rejected already. Belt &
			// braces: pass through so middleware order changes don't
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

// discoverOIDC runs OIDC auto-discovery with bounded retry. A transient IdP
// outage at pod start becomes a short sleep instead of an immediate exit —
// reserves a fatal failure for a persistent misconfiguration. The outer
// ctx cancels the backoff mid-sleep so SIGTERM during discovery unwinds
// immediately rather than stalling out the full retry budget (L7).
func discoverOIDC(ctx context.Context, issuer string, logger *zap.Logger) (*oidc.Provider, error) {
	const (
		maxAttempts = 5
		initial     = 1 * time.Second
		maxBackoff  = 15 * time.Second
	)
	backoff := initial
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		provider, err := oidc.NewProvider(attemptCtx, issuer)
		cancel()
		if err == nil {
			return provider, nil
		}
		lastErr = err
		if attempt == maxAttempts {
			break
		}
		logger.Warn("oidc_discovery_retry",
			zap.Int("attempt", attempt),
			zap.Duration("backoff", backoff),
			zap.Error(err),
		)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	return nil, lastErr
}

func zapMiddleware(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			// Inject a mutable log record into the context so downstream
			// middlewares (RPCPeek) can populate sub/email/rpc_* fields
			// that are only known after auth and body inspection. A pointer
			// survives r.WithContext hops between middleware layers.
			ctx, rec := middleware.InjectLogRecord(r.Context())
			next.ServeHTTP(ww, r.WithContext(ctx))

			fields := []zap.Field{
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", ww.Status()),
				zap.Duration("duration", time.Since(start)),
				zap.String("request_id", chimw.GetReqID(ctx)),
			}
			if rec.Sub != "" {
				fields = append(fields, zap.String("sub", rec.Sub))
			}
			if rec.Email != "" {
				fields = append(fields, zap.String("email", rec.Email))
			}
			if rec.RPCMethod != "" {
				fields = append(fields, zap.String("rpc_method", rec.RPCMethod))
			}
			if rec.RPCTool != "" {
				fields = append(fields, zap.String("rpc_tool", rec.RPCTool))
			}
			if rec.RPCID != "" {
				fields = append(fields, zap.String("rpc_id", rec.RPCID))
			}
			logger.Info("request", fields...)
		})
	}
}
