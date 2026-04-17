package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
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

	// OIDC discovery — works with any compliant IdP (Keycloak, Entra, Auth0, Okta...).
	// Retry with capped exponential backoff so a transient IdP blip at pod
	// start doesn't burn a CrashLoopBackoff slot; give up after ~60s total.
	oidcProvider, err := discoverOIDC(cfg.OIDCIssuerURL, logger)
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

	// Optional replay protection: when REDIS_URL is set, authorization codes
	// become single-use across all replicas. When unset, behavior is stateless
	// (codes unique + short-lived + PKCE-bound but replayable within TTL).
	var replayStore replay.Store
	if cfg.RedisURL != "" {
		rs, err := replay.NewRedisStore(cfg.RedisURL, cfg.RedisKeyPrefix)
		if err != nil {
			logger.Fatal("replay_store_init_failed", zap.Error(err))
		}
		replayStore = rs
		defer func() {
			if err := rs.Close(); err != nil {
				logger.Warn("replay_store_close_failed", zap.Error(err))
			}
		}()
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

	r := chi.NewRouter()
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

	// Per-IP rate limits on unauthenticated endpoints. httprate keys by
	// X-Forwarded-For / X-Real-IP when present, so deployments behind an
	// untrusted frontend can be bypassed via header spoofing — terminate
	// at a trusted L4/L7 load balancer or disable via RATE_LIMIT_ENABLED=false.
	registerLimit := passthrough
	authorizeLimit := passthrough
	callbackLimit := passthrough
	tokenLimit := passthrough
	if cfg.RateLimitEnabled {
		registerLimit = rateLimiter(10, time.Minute, "register")
		authorizeLimit = rateLimiter(30, time.Minute, "authorize")
		callbackLimit = rateLimiter(30, time.Minute, "callback")
		tokenLimit = rateLimiter(60, time.Minute, "token")
		logger.Info("rate_limit_enabled")
	} else {
		logger.Info("rate_limit_disabled")
	}

	r.Get("/.well-known/oauth-protected-resource", handlers.ResourceMetadata(cfg.ProxyBaseURL))
	r.Get("/.well-known/oauth-authorization-server", handlers.Discovery(cfg.ProxyBaseURL))
	r.With(registerLimit).Post("/register", handlers.Register(tm, logger, cfg.ProxyBaseURL))
	r.With(authorizeLimit).Get("/authorize", handlers.Authorize(tm, logger, cfg.ProxyBaseURL, oauth2Cfg, handlers.AuthorizeConfig{
		PKCERequired: cfg.PKCERequired,
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
	// Readiness probe: reflects hard runtime dependencies. Redis is
	// probed with a short-timeout EXISTS on a sentinel key — cheap, no
	// side effects. Without Redis configured, always ready.
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if replayStore != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
			defer cancel()
			if _, err := replayStore.Exists(ctx, "__readyz_probe__"); err != nil {
				logger.Warn("readyz_redis_probe_failed", zap.Error(err))
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"status":"redis_unavailable"}`)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})

	r.Group(func(r chi.Router) {
		r.Use(authMW.Validate)
		r.Handle("/*", proxyHandler)
	})

	srv := &http.Server{
		Addr:        cfg.ListenAddr,
		Handler:     r,
		ReadTimeout: 30 * time.Second,
		// WriteTimeout left at 0 — required for SSE/streaming connections
		IdleTimeout: 120 * time.Second,
	}

	// Metrics on a separate port so it's not exposed through the public listener
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsSrv := &http.Server{
		Addr:         cfg.MetricsAddr,
		Handler:      metricsMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown_error", zap.Error(err))
	}
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("metrics_shutdown_error", zap.Error(err))
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

// rateLimiter builds a per-IP httprate middleware that emits a JSON OAuth
// error on throttle and increments the mcp_auth_rate_limited_total counter
// so operators can alert on abuse patterns per-endpoint.
func rateLimiter(limit int, window time.Duration, endpoint string) func(http.Handler) http.Handler {
	return httprate.Limit(
		limit, window,
		httprate.WithKeyFuncs(httprate.KeyByIP),
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
// reserves a fatal failure for a persistent misconfiguration.
func discoverOIDC(issuer string, logger *zap.Logger) (*oidc.Provider, error) {
	const (
		maxAttempts = 5
		initial     = 1 * time.Second
		maxBackoff  = 15 * time.Second
	)
	backoff := initial
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		provider, err := oidc.NewProvider(ctx, issuer)
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
		time.Sleep(backoff)
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
			next.ServeHTTP(ww, r)
			logger.Info("request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", ww.Status()),
				zap.Duration("duration", time.Since(start)),
				zap.String("request_id", chimw.GetReqID(r.Context())),
			)
		})
	}
}
