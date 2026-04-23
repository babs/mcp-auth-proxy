package main

import (
	"context"
	"fmt"
	"io"
	"net"
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
	"golang.org/x/term"

	"github.com/babs/mcp-auth-proxy/config"
	"github.com/babs/mcp-auth-proxy/handlers"
	"github.com/babs/mcp-auth-proxy/internal/health"
	"github.com/babs/mcp-auth-proxy/internal/subjectlimiter"
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

	tm, err := token.NewManagerWithRotation(cfg.TokenSigningSecret, cfg.TokenSigningSecretsPrevious...)
	if err != nil {
		logger.Fatal("token_manager_init_failed", zap.Error(err))
	}
	if n := len(cfg.TokenSigningSecretsPrevious); n > 0 {
		logger.Info("token_signing_rotation_in_progress",
			zap.Int("previous_keys", n),
			zap.String("hint", "remove TOKEN_SIGNING_SECRETS_PREVIOUS after all previous-key-sealed tokens expire"),
		)
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

	proxyHandler, err := proxy.Handler(cfg.UpstreamMCPURL, logger, proxy.Config{
		UpstreamAuthorization: cfg.UpstreamAuthorization,
	})
	if err != nil {
		logger.Fatal("proxy_handler_init_failed", zap.Error(err))
	}
	if cfg.UpstreamAuthorization != "" {
		logger.Info("upstream_authorization_header_configured")
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
	// r.RemoteAddr (httprate.KeyByIP) so a client behind an untrusted
	// frontend cannot spoof XFF/X-Real-IP/True-Client-IP to mint its
	// own bucket.
	//
	// TRUSTED_PROXY_CIDRS (preferred): honor forwarded headers only
	// when the immediate peer is inside one of the listed networks.
	// Everything else falls back to RemoteAddr. This is the strict
	// posture — a client reaching the pod directly (bypassing the
	// ingress controller) cannot spoof a rate-limit key.
	// TRUST_PROXY_HEADERS (legacy, insecure): blanket trust of every
	// peer's forwarded headers. Kept for backward compatibility but
	// CIDR-scoped trust supersedes it whenever both are set.
	ipKeyFunc := httprate.KeyByIP
	switch {
	case len(cfg.TrustedProxyCIDRs) > 0:
		ipKeyFunc = cidrAwareKey(cfg.TrustedProxyCIDRs)
		if cfg.TrustProxyHeaders {
			logger.Warn("trust_proxy_headers_superseded_by_cidrs",
				zap.String("hint", "TRUST_PROXY_HEADERS is ignored when TRUSTED_PROXY_CIDRS is set"),
			)
		}
	case cfg.TrustProxyHeaders:
		ipKeyFunc = httprate.KeyByRealIP
		logger.Warn("trust_proxy_headers_deprecated",
			zap.String("hint", "migrate to TRUSTED_PROXY_CIDRS; TRUST_PROXY_HEADERS trusts every peer"),
		)
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
		sl := subjectlimiter.New(ctx, cfg.PerSubjectConcurrency, logger)
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
	// shuttingDown is flipped by the drain sequence before closing the
	// Redis client so /readyz short-circuits to 503 and stops calling
	// into a soon-to-be-closed pool.
	var shuttingDown atomic.Bool
	metricsMux.Handle("/readyz", health.Readyz(replayStore, logger, &shuttingDown))
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
	//
	// Flip shuttingDown before rs.Close() so /readyz short-circuits
	// instead of probing a pool that's about to close under it.
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
		shuttingDown.Store(true)
		if err := rs.Close(); err != nil {
			logger.Warn("replay_store_close_failed", zap.Error(err))
		}
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

// cidrAwareKey returns an httprate.KeyFunc that honors forwarded
// headers (httprate.KeyByRealIP) only when r.RemoteAddr falls inside
// one of the configured trusted-proxy networks. Everything else
// falls back to the raw RemoteAddr, which prevents a direct-to-pod
// client from spoofing a rate-limit key via X-Forwarded-For.
//
// Kept in main.go — not a package concern; parsing of the CIDR list
// lives in config.Load and the wiring is trivially one place.
func cidrAwareKey(cidrs []*net.IPNet) httprate.KeyFunc {
	return func(r *http.Request) (string, error) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return httprate.KeyByIP(r)
		}
		for _, c := range cidrs {
			if c.Contains(ip) {
				return httprate.KeyByRealIP(r)
			}
		}
		return httprate.KeyByIP(r)
	}
}

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
