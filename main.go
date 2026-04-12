package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2"
	"golang.org/x/term"

	"github.com/babs/mcp-auth-proxy/config"
	"github.com/babs/mcp-auth-proxy/handlers"
	"github.com/babs/mcp-auth-proxy/middleware"
	"github.com/babs/mcp-auth-proxy/proxy"
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

	// OIDC discovery — works with any compliant IdP (Keycloak, Entra, Auth0, Okta...)
	discoveryCtx, discoveryCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer discoveryCancel()
	oidcProvider, err := oidc.NewProvider(discoveryCtx, cfg.OIDCIssuerURL)
	if err != nil {
		logger.Fatal("oidc discovery failed", zap.String("issuer", cfg.OIDCIssuerURL), zap.Error(err))
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
		logger.Fatal("token manager init failed", zap.Error(err))
	}

	proxyHandler, err := proxy.Handler(cfg.UpstreamMCPURL, logger)
	if err != nil {
		logger.Fatal("proxy handler init failed", zap.Error(err))
	}

	authMW := middleware.NewAuth(tm, logger, cfg.ProxyBaseURL, cfg.RevokeBefore)

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(zapMiddleware(logger))
	r.Use(chimw.Recoverer)

	r.Get("/.well-known/oauth-protected-resource", handlers.ResourceMetadata(cfg.ProxyBaseURL))
	r.Get("/.well-known/oauth-authorization-server", handlers.Discovery(cfg.ProxyBaseURL))
	r.Post("/register", handlers.Register(tm, logger, cfg.ProxyBaseURL))
	r.Get("/authorize", handlers.Authorize(tm, logger, cfg.ProxyBaseURL, oauth2Cfg, handlers.AuthorizeConfig{
		PKCERequired: cfg.PKCERequired,
	}))
	r.Get("/callback", handlers.Callback(tm, logger, cfg.ProxyBaseURL, oauth2Cfg, idTokenVerifier, handlers.CallbackConfig{
		AllowedGroups: cfg.AllowedGroups,
		GroupsClaim:   cfg.GroupsClaim,
	}))
	r.Post("/token", handlers.Token(tm, logger, cfg.ProxyBaseURL, cfg.RevokeBefore))

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
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
		logger.Info("metrics listening", zap.String("addr", cfg.MetricsAddr))
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics listen error", zap.Error(err))
		}
	}()

	go func() {
		logger.Info("listening", zap.String("addr", cfg.ListenAddr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("listen error", zap.Error(err))
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down", zap.Duration("timeout", cfg.ShutdownTimeout))

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", zap.Error(err))
	}
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("metrics shutdown error", zap.Error(err))
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
