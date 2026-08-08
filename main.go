package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
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
	"golang.org/x/time/rate"

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
	// logger.Sync() routinely returns an error when stdout/stderr is the
	// sink (EINVAL on /dev/stdout for non-regular fds). Ignore it — there
	// is nothing meaningful to recover from at the shutdown point anyway.
	defer func() { _ = logger.Sync() }()

	logger.Info("starting",
		zap.String("version", Version),
		zap.String("commit", CommitHash),
		zap.String("built_at", BuildTimestamp),
		zap.String("builder", Builder),
		zap.String("project_url", ProjectURL),
	)

	if len(cfg.CSPFormActionExtra) > 0 {
		logger.Warn("csp_form_action_extra_deprecated",
			zap.String("hint", "ignored since the consent interstitial: form-action is 'self'-only; remove CSP_FORM_ACTION_EXTRA from the deployment"),
		)
	}

	// Single structured line summarising the security-relevant runtime
	// posture. Lets oncall grep one log event per pod start to audit
	// which safety nets are active, without exposing secrets. Booleans
	// are logged as-is; set-ness of sensitive values is reported as a
	// bool (never the value itself).
	logger.Info("startup_config",
		zap.Bool("prod_mode", cfg.ProdMode),
		zap.Bool("pkce_required", cfg.PKCERequired),
		zap.Bool("redis_required", cfg.RedisRequired),
		zap.Bool("rate_limit_enabled", cfg.RateLimitEnabled),
		zap.Bool("trust_proxy_headers", cfg.TrustProxyHeaders),
		zap.Bool("compat_allow_stateless", cfg.CompatAllowStateless),
		zap.Bool("render_consent_page", cfg.RenderConsentPage),
		zap.Int64("per_subject_concurrency", cfg.PerSubjectConcurrency),
		zap.String("groups_claim", cfg.GroupsClaim),
		zap.Bool("allowed_groups_set", len(cfg.AllowedGroups) > 0),
		zap.Bool("revoke_before_set", !cfg.RevokeBefore.IsZero()),
		zap.Bool("upstream_authorization_set", cfg.UpstreamAuthorization != ""),
		zap.String("access_log_skip_re", accessLogSkipPattern(cfg.AccessLogSkipRE)),
		// Surface the per-tool metrics toggle so an operator inspecting
		// startup logs can confirm `MCP_TOOL_METRICS=true` actually took
		// effect. Without this, the new mcp_auth_rpc_*{tool} counters
		// only appear once real RPC traffic flows — there's no visible
		// config evidence in the meantime.
		zap.Bool("tool_metrics_enabled", cfg.ToolMetricsEnabled),
		zap.Int("tool_metrics_max_cardinality", cfg.ToolMetricsMaxCardinality),
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
	// fires at 2^28 seals (L6). The Prometheus seal-counter (M2)
	// observes every seal across replicas — the in-process counter
	// resets on restart, so a frequently-rolled pod would never reach
	// the warning even when fleet-wide cumulative seals do; the metric
	// closes that gap via increase(metric[window]).
	tm.SetLogger(logger)
	tm.SetSealMetric(func(purpose string) {
		metrics.TokenSeals.WithLabelValues(purpose).Inc()
	})

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

	authMW := middleware.NewAuth(tm, logger, cfg.ProxyBaseURL, cfg.UpstreamMCPMountPath, cfg.RevokeBefore)

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
	baseMiddleware(r, logger, cfg)

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
		ipKeyFunc = cidrAwareKey(cfg.TrustedProxyCIDRs, cfg.TrustedProxyHeader)
		if cfg.TrustProxyHeaders {
			logger.Warn("trust_proxy_headers_superseded_by_cidrs",
				zap.String("hint", "TRUST_PROXY_HEADERS is ignored when TRUSTED_PROXY_CIDRS is set"),
			)
		}
	case cfg.TrustProxyHeaders:
		// Legacy blanket-trust path (TRUST_PROXY_HEADERS=true,
		// TRUSTED_PROXY_CIDRS unset). httprate.KeyByRealIP picks the
		// leftmost XFF / True-Client-IP / X-Real-IP without
		// validating the peer; any client can mint an unbounded
		// rate-limit bucket per request. Kept ONLY because removing
		// it would silently regress existing deployments — config
		// rejects this combo under PROD_MODE=true so production
		// pods cannot land here.
		ipKeyFunc = httprate.KeyByRealIP
		logger.Warn("trust_proxy_headers_deprecated",
			zap.String("hint", "migrate to TRUSTED_PROXY_CIDRS; TRUST_PROXY_HEADERS trusts every peer"),
		)
	}
	registerLimit := passthrough
	authorizeLimit := passthrough
	consentLimit := passthrough
	callbackLimit := passthrough
	tokenLimit := passthrough
	mcpLimit := passthrough
	discoveryLimit := passthrough
	if cfg.RateLimitEnabled {
		// /register's 10/min cap is the load-bearing mitigation in
		// docs/threat-model.md row 1 (DCR abuse). Keep this in sync
		// with that document if the value changes.
		registerLimit = rateLimiter(10, time.Minute, "register", ipKeyFunc)
		authorizeLimit = rateLimiter(30, time.Minute, "authorize", ipKeyFunc)
		// /consent has its own bucket so the user-driven approve/deny
		// click doesn't share a budget with /authorize gets — a flow
		// is one /authorize + one /consent and both should fit. Same
		// 30/min ceiling as /authorize keeps the per-flow shape
		// symmetric while letting humans retry without poisoning the
		// /authorize bucket.
		consentLimit = rateLimiter(30, time.Minute, "consent", ipKeyFunc)
		callbackLimit = rateLimiter(30, time.Minute, "callback", ipKeyFunc)
		tokenLimit = rateLimiter(60, time.Minute, "token", ipKeyFunc)
		// Authenticated MCP route: per-IP bucket. MCP traffic is all
		// POST /mcp so per-path keying would add no dimension — per-subject
		// concurrency below handles the "one caller hogging one tool" shape.
		mcpLimit = rateLimiter(600, time.Minute, "mcp", ipKeyFunc)
		// Discovery (RFC 8414 / RFC 9728): legitimate clients hit
		// /.well-known/* once per session. The ceiling here only catches
		// floods. Production MCP servers (Cloudflare/GitHub/Atlassian)
		// limit silently at the edge; same posture here. RFC 8414 §3 and
		// RFC 9728 §3.1 are silent on rate-limit, so 429 is not anti-spec.
		discoveryLimit = rateLimiter(60, time.Minute, "discovery", ipKeyFunc)
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

	registerDiscoveryRoutes(r, cfg.ProxyBaseURL, cfg.UpstreamMCPMountPath, cfg.ResourceName, discoveryLimit)

	var idpExchangeLimiter *rate.Limiter
	if cfg.IdPExchangeRatePerSec > 0 {
		idpExchangeLimiter = rate.NewLimiter(rate.Limit(cfg.IdPExchangeRatePerSec), cfg.IdPExchangeBurst)
		logger.Info("idp_exchange_limiter_enabled",
			zap.Float64("rate_per_sec", cfg.IdPExchangeRatePerSec),
			zap.Int("burst", cfg.IdPExchangeBurst),
		)
	}

	registerOAuthRoutes(r, oauthRoutes{
		Register: handlers.Register(tm, logger, cfg.ProxyBaseURL, cfg.ClientRegistrationTTL),
		Authorize: handlers.Authorize(tm, logger, cfg.ProxyBaseURL, oauth2Cfg, handlers.AuthorizeConfig{
			PKCERequired:         cfg.PKCERequired,
			ResourceURIs:         []string{cfg.ProxyBaseURL + cfg.UpstreamMCPMountPath},
			CanonicalResource:    cfg.ProxyBaseURL + cfg.UpstreamMCPMountPath,
			CompatAllowStateless: cfg.CompatAllowStateless,
			RenderConsentPage:    cfg.RenderConsentPage,
			ResourceName:         cfg.ResourceName,
		}),
		Consent: handlers.Consent(tm, logger, cfg.ProxyBaseURL, oauth2Cfg, handlers.ConsentConfig{
			ReplayStore:  replayStore,
			ResourceName: cfg.ResourceName,
		}),
		Callback: handlers.Callback(tm, logger, cfg.ProxyBaseURL, oauth2Cfg, idTokenVerifier, handlers.CallbackConfig{
			AllowedGroups:      cfg.AllowedGroups,
			GroupsClaim:        cfg.GroupsClaim,
			ReplayStore:        replayStore,
			IdPExchangeLimiter: idpExchangeLimiter,
		}),
		Token: handlers.Token(tm, logger, cfg.ProxyBaseURL, cfg.RevokeBefore, replayStore, handlers.TokenConfig{
			RefreshRaceGrace: cfg.RefreshRaceGrace,
		}, cfg.ProxyBaseURL+cfg.UpstreamMCPMountPath),
		RegisterLimit:  registerLimit,
		AuthorizeLimit: authorizeLimit,
		ConsentLimit:   consentLimit,
		CallbackLimit:  callbackLimit,
		TokenLimit:     tokenLimit,
	})

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
		// MCP mount is the path component of UPSTREAM_MCP_URL. Proxy
		// and upstream share the exact same path literally: client
		// path == upstream path, verbatim, no rewrite. Any path outside
		// the mount is 404 by the router.
		r.Handle(cfg.UpstreamMCPMountPath, proxyHandler)
		r.Handle(cfg.UpstreamMCPMountPath+"/*", proxyHandler)
	})

	installMethodNotAllowed(r)
	installNotFound(r)

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
		// 16 KB, down from net/http's 1 MB default: every header-driven
		// cost on every route (including the pre-auth Accept scan, which
		// the rate limiter by construction does not cover) is bounded by
		// this. Real browsers and MCP clients sit well under 8 KB, the
		// ceiling most reverse proxies already impose.
		MaxHeaderBytes: 16 << 10,
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
		Addr:           cfg.MetricsAddr,
		Handler:        metricsMux,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   30 * time.Second,
		MaxHeaderBytes: 16 << 10,
		IdleTimeout:    120 * time.Second,
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

// cidrAwareKey returns an httprate.KeyFunc that resolves the rate-limit
// bucket key from forwarded headers ONLY when the immediate peer is
// inside one of the configured trusted-proxy networks, and ONLY by
// walking right-to-left through `X-Forwarded-For` (or another
// operator-pinned header) until the first hop NOT covered by the
// trusted-proxy CIDRs is reached. That hop is the closest untrusted
// origin — the actual client from the trusted ingress' perspective.
//
// Why not httprate.KeyByRealIP: that helper picks `True-Client-IP`
// then `X-Real-IP` then leftmost XFF without sanitization. None are
// trusted-proxy gated. Most off-the-shelf ingresses (nginx-ingress
// with `compute-full-forwarded-for=true`, Envoy without
// `xff_num_trusted_hops`, Cloudflare without strict header
// stripping) APPEND to XFF and pass `True-Client-IP` through
// verbatim from the caller. A client that egresses through such an
// ingress can mint an unbounded rate-limit bucket per request just
// by varying the header.
//
// `header` selects which header carries the hop list. Default
// `X-Forwarded-For`. Operator may pin `X-Real-IP` or
// `True-Client-IP` via TRUSTED_PROXY_HEADER when their ingress is
// known to OVERWRITE (not append) that header — in which case the
// header carries exactly one trusted hop and the rightmost-walk
// degenerates to "use the value verbatim".
//
// Falls back to the raw RemoteAddr (httprate.KeyByIP) when the peer
// is not trusted, the header is absent, or every hop in the list is
// itself trusted (legitimate but useless — can't bucket per-client
// without an external client identity).
//
// Kept in main.go — not a package concern; parsing of the CIDR list
// lives in config.Load and the wiring is trivially one place.
func cidrAwareKey(cidrs []*net.IPNet, header string) httprate.KeyFunc {
	if header == "" {
		header = "X-Forwarded-For"
	}
	return func(r *http.Request) (string, error) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !cidrContainsAny(cidrs, ip) {
			return httprate.KeyByIP(r)
		}
		raw := r.Header.Get(header)
		if raw == "" {
			return httprate.KeyByIP(r)
		}
		// Walk right-to-left: the rightmost entry was added by the
		// trusted ingress (its view of the immediate peer); each
		// step left was added by the hop further out. Stop at the
		// first hop NOT in the trusted-proxy set — that is the
		// closest untrusted origin (the actual client per the
		// trusted ingress).
		hops := strings.Split(raw, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(hops[i])
			if candidate == "" {
				continue
			}
			// IPv6 forms in XFF are usually bare (RFC 7239 §6 uses
			// the `Forwarded` header for bracketed forms); strip a
			// stray bracket pair and a trailing :port for both
			// families just in case an upstream synthesizes them.
			candidate = stripPortAndBrackets(candidate)
			hopIP := net.ParseIP(candidate)
			if hopIP == nil {
				return httprate.KeyByIP(r)
			}
			if !cidrContainsAny(cidrs, hopIP) {
				return canonicalIPKey(hopIP), nil
			}
		}
		return httprate.KeyByIP(r)
	}
}

func cidrContainsAny(cidrs []*net.IPNet, ip net.IP) bool {
	for _, c := range cidrs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

// stripPortAndBrackets normalises a hop entry that may carry an
// optional `:port` suffix or `[ipv6]` bracket form. Anything that
// doesn't fit those shapes is returned verbatim so a malformed entry
// trips the net.ParseIP check at the call site.
func stripPortAndBrackets(s string) string {
	if len(s) >= 2 && s[0] == '[' {
		if end := strings.IndexByte(s, ']'); end > 0 {
			return s[1:end]
		}
	}
	if i := strings.LastIndexByte(s, ':'); i > 0 && strings.IndexByte(s, ':') == i {
		return s[:i]
	}
	return s
}

// canonicalIPKey mirrors httprate's internal canonicalisation so the
// trusted-XFF key collates with the direct-RemoteAddr key. Without
// this, a v4-mapped v6 form ("::ffff:1.2.3.4") would bucket
// separately from the bare v4 ("1.2.3.4").
func canonicalIPKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// rateLimiter builds an httprate middleware that emits an OAuth error on
// throttle and increments mcp_auth_rate_limited_total so operators can alert
// on abuse patterns per-endpoint. Callers pass the key-func composition
// (IP-only, IP+path, ...) that matches the bucket semantics they want.
// The response goes through the shared sink, so on a browser-facing route
// a throttled human gets the error page rather than a JSON body.
func rateLimiter(limit int, window time.Duration, endpoint string, keyFuncs ...httprate.KeyFunc) func(http.Handler) http.Handler {
	httprateMW := httprate.Limit(
		limit, window,
		httprate.WithKeyFuncs(keyFuncs...),
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			metrics.RateLimited.WithLabelValues(endpoint).Inc()
			handlers.RateLimitExceeded(w, r)
		}),
	)
	// Wrap with suppression so httprate's X-RateLimit-* headers never
	// reach the client. Production MCP servers (Cloudflare, GitHub
	// Copilot, Atlassian, Notion, Sentry — surveyed in the red-team
	// plan) all keep these silent. The IETF rate-limit-headers draft
	// (security considerations) explicitly notes that disclosing
	// quota state on auth/error paths leaks operational capacity to
	// attackers; suppression is the safer default. Retry-After, which
	// httprate sets on the 429, is preserved: it states when to retry,
	// which the error page also promises, and the window alone does not
	// disclose the per-window quota that X-RateLimit-* would.
	return func(next http.Handler) http.Handler {
		return suppressRateLimitHeaders(httprateMW(next))
	}
}

// suppressRateLimitHeaders removes the X-RateLimit-* headers httprate
// sets on every response. Wrap with a small ResponseWriter so the
// strip happens at WriteHeader time (before the headers are flushed
// to the client).
func suppressRateLimitHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&rateLimitHeaderStripper{ResponseWriter: w}, r)
	})
}

type rateLimitHeaderStripper struct {
	http.ResponseWriter
	stripped bool
}

func (s *rateLimitHeaderStripper) WriteHeader(code int) {
	if !s.stripped {
		h := s.Header()
		h.Del("X-RateLimit-Limit")
		h.Del("X-RateLimit-Remaining")
		h.Del("X-RateLimit-Reset")
		s.stripped = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *rateLimitHeaderStripper) Write(b []byte) (int, error) {
	if !s.stripped {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

// Flush forwards to the underlying writer so SSE / chunked streaming
// keeps working — chi's WrapResponseWriter does the same dance.
func (s *rateLimitHeaderStripper) Flush() {
	if !s.stripped {
		s.WriteHeader(http.StatusOK)
	}
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
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

// accessLogSkipPattern returns the configured regex source for the
// startup_config audit log, or "" when no filter is set.
//
// Load-bearing nil check: (*regexp.Regexp).String() dereferences re.expr,
// which panics on a nil receiver. Do NOT inline this as cfg.AccessLogSkipRE.String()
// — the unset-filter path (the default) would crash startup_config.
func accessLogSkipPattern(re *regexp.Regexp) string {
	if re == nil {
		return ""
	}
	return re.String()
}

// rpcMetrics bundles the per-request hooks that record both the
// per-tool counter family and the disjoint batch-shape family. nil
// when MCP_TOOL_METRICS is disabled — keeps the hot path branch-only
// when the operator hasn't opted in. Bundling the two callbacks lets
// the test layer intercept both axes through one wiring point.
type rpcMetrics struct {
	perTool func(tool string, status int, reqBytes int64, respBytes int)
	batch   func(status int, reqBytes int64, respBytes int)
}

// buildRPCMetrics returns the rpc-metrics callbacks when
// MCP_TOOL_METRICS=true and nil otherwise. The per-tool closure
// closes over a single ToolCardinality instance so the cap state is
// shared across every request. The batch closure has no cardinality
// guard — it has no labels.
func buildRPCMetrics(cfg *config.Config, logger *zap.Logger) *rpcMetrics {
	if !cfg.ToolMetricsEnabled {
		return nil
	}
	card := &metrics.ToolCardinality{MaxCardinality: cfg.ToolMetricsMaxCardinality}
	// Defense in depth: a panic in metrics.WithLabelValues / .Inc /
	// .Add is not expected (Prometheus stdlib is robust for valid
	// label-arity calls), but by the time these run the response is
	// already on the wire — chimw.Recoverer would catch an escaping
	// panic but cannot rewrite the already-flushed status. Recover
	// locally and log as Warn so a future metric mis-wiring is
	// visible in operator logs without taking down in-flight requests.
	recoverWarn := func(where string, fields ...zap.Field) {
		if rec := recover(); rec != nil {
			logger.Warn("rpc_metrics_observer_panicked",
				append(fields, zap.String("where", where), zap.Any("recovered", rec))...,
			)
		}
	}
	return &rpcMetrics{
		perTool: func(tool string, status int, reqBytes int64, respBytes int) {
			defer recoverWarn("perTool", zap.String("tool", tool), zap.Int("status", status))
			label := card.ToolLabel(tool)
			metrics.RPCCalls.WithLabelValues(label).Inc()
			if status >= 400 {
				metrics.RPCCallsFailed.WithLabelValues(label).Inc()
			}
			// Skip both chunked (Content-Length == -1) and explicitly-
			// empty (== 0) bodies: nothing useful to add to the byte
			// counter and dashboards would otherwise see a true-zero
			// contribution mixed with the unknown-size signal.
			if reqBytes > 0 {
				metrics.RPCRequestBytes.WithLabelValues(label).Add(float64(reqBytes))
			}
			if respBytes > 0 {
				metrics.RPCResponseBytes.WithLabelValues(label).Add(float64(respBytes))
			}
		},
		batch: func(status int, reqBytes int64, respBytes int) {
			defer recoverWarn("batch", zap.Int("status", status))
			metrics.RPCBatches.Inc()
			if status >= 400 {
				metrics.RPCBatchesFailed.Inc()
			}
			if reqBytes > 0 {
				metrics.RPCBatchBytes.WithLabelValues("request").Add(float64(reqBytes))
			}
			if respBytes > 0 {
				metrics.RPCBatchBytes.WithLabelValues("response").Add(float64(respBytes))
			}
		},
	}
}

// securityHeaders applies the public-listener-baseline response headers.
// Set before the handler runs so they land on every status code,
// including upstream pass-through 5xx and rate-limiter 429s.
//
// Header rationale:
//   - Strict-Transport-Security: RFC 6797 SHOULD; production MCP
//     servers (GitHub Copilot, Atlassian, Notion, Sentry) all carry
//     it. 2-year max-age + includeSubDomains assumes the operator's
//     parent zone is all-HTTPS — flag in deployment docs.
//   - X-Content-Type-Options: nosniff — defense-in-depth against
//     MIME-sniffing of error bodies (JSON, or HTML on the
//     browser-negotiated error page).
//   - X-Frame-Options: DENY — supplements CSP frame-ancestors for
//     pre-CSP-2 browsers.
//   - Referrer-Policy: no-referrer — RFC 9700 §4.2.4 RECOMMENDED for
//     OAuth ASes (defends against authorization-code leakage via
//     Referer header to a downstream resource).
//   - Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
//     — JSON / redirect responses do not need any subresource; the
//     stricter CSP is honest about that. The three proxy-rendered pages
//     (handlers/pages.go) override this baseline with their own
//     self-contained headers: style-src names each page's own style
//     hash, and form-action is 'self' on the consent page and 'none' on
//     the other two — no origin enumeration, because the interstitial
//     terminates Chromium's form-action chain enforcement at the proxy.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func zapMiddleware(logger *zap.Logger, skipRE *regexp.Regexp, rpcObs *rpcMetrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Operator-configured path filter. Skip early to avoid the
			// response-writer wrap and log-record injection; upstream
			// inFlight/RequestID middlewares still run so shutdown drain
			// and panic recovery remain correct. Handler response and
			// Prometheus counters are unaffected.
			if skipRE != nil && skipRE.MatchString(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			// Inject a mutable log record into the context so downstream
			// middlewares (RPCPeek) can populate sub/email/rpc_* fields
			// that are only known after auth and body inspection. A pointer
			// survives r.WithContext hops between middleware layers.
			ctx, rec := middleware.InjectLogRecord(r.Context())
			next.ServeHTTP(ww, r.WithContext(ctx))

			// req_bytes: Content-Length of the inbound request. -1 when
			// the client used chunked encoding or omitted the header — kept
			// as-is so the field is unambiguous rather than conflated with
			// a true zero-byte body.
			// resp_bytes: cumulative bytes the handler wrote through the
			// chi response wrapper. For SSE / streaming responses this is
			// the whole stream size (only finalized when the handler
			// returns), which is the intended signal for volume auditing.
			fields := []zap.Field{
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", ww.Status()),
				zap.Duration("duration", time.Since(start)),
				zap.Int64("req_bytes", r.ContentLength),
				zap.Int("resp_bytes", ww.BytesWritten()),
				// Distinguishes the negotiated HTML error page from the
				// JSON body on the same status and path — resp_bytes
				// stopped being that fingerprint when the page landed
				// (see the client-registration-expired runbook).
				zap.String("resp_content_type", ww.Header().Get("Content-Type")),
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

			// RPC metrics observed AFTER the log line so a panic in the
			// observer cannot lose the access-log entry. Two axes:
			//
			//  - per-tool counters (mcp_auth_rpc_calls_total{tool}, …):
			//    single-call tools/call fires once with extracted tool
			//    name + actual bytes; a batch fires PER tools/call entry
			//    with that entry's tool name and 0/0 bytes (no honest
			//    per-call attribution inside a batch).
			//  - batch counters (mcp_auth_rpc_batches_total +
			//    rpc_batch_bytes_total{direction}, no tool label): one
			//    increment per batch HTTP request that contained at
			//    least one tools/call entry, carrying the request's
			//    actual Content-Length / BytesWritten.
			//
			// Protocol-level methods (initialize, notifications/*,
			// tools/list, prompts/*, …) and batches without any
			// tools/call entry are skipped entirely so the `_unknown`
			// bucket reliably means "tools/call with malformed
			// params.name".
			if rpcObs != nil {
				if rec.RPCMethod == "tools/call" {
					rpcObs.perTool(rec.RPCTool, ww.Status(), r.ContentLength, ww.BytesWritten())
				} else {
					var hadToolsCall bool
					for _, call := range rec.RPCBatch {
						if call.Method == "tools/call" {
							rpcObs.perTool(call.Tool, ww.Status(), 0, 0)
							hadToolsCall = true
						}
					}
					if hadToolsCall {
						rpcObs.batch(ww.Status(), r.ContentLength, ww.BytesWritten())
					}
				}
			}
		})
	}
}

// baseMiddleware installs the middleware every public response passes
// through, in order. Extracted so the e2e harness runs the same chain
// as production: the error page's own CSP has to override the
// securityHeaders baseline, which a router without it cannot exercise.
func baseMiddleware(r chi.Router, logger *zap.Logger, cfg *config.Config) {
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Del("X-Request-Id")
			next.ServeHTTP(w, r)
		})
	})
	r.Use(chimw.RequestID)
	r.Use(zapMiddleware(logger, cfg.AccessLogSkipRE, buildRPCMetrics(cfg, logger)))
	r.Use(chimw.Recoverer)
	// Security-headers baseline applied to every response on the
	// public listener. Set BEFORE the handler runs so the headers
	// land on every status code (including upstream 5xx pass-through
	// from the MCP proxy and the rate-limiter's 429s). Headers chosen
	// per RFC 9700 §4.2.4 (Referrer-Policy: no-referrer is RECOMMENDED
	// for OAuth ASes), RFC 6797 (HSTS), and production-MCP parity
	// (GitHub Copilot / Atlassian / Notion / Sentry all carry HSTS;
	// surveyed in the red-team plan). Not applied to the metrics
	// listener — Prometheus scrape is in-cluster only and HSTS over
	// loopback is meaningless.
	r.Use(securityHeaders)
}

// oauthRoutes carries the OAuth control-plane handlers and their
// per-endpoint limiters. Grouping them lets registerOAuthRoutes own the
// middleware wiring — the part a test can pin.
type oauthRoutes struct {
	Register  http.HandlerFunc
	Authorize http.HandlerFunc
	Consent   http.HandlerFunc
	Callback  http.HandlerFunc
	Token     http.HandlerFunc

	RegisterLimit  func(http.Handler) http.Handler
	AuthorizeLimit func(http.Handler) http.Handler
	ConsentLimit   func(http.Handler) http.Handler
	CallbackLimit  func(http.Handler) http.Handler
	TokenLimit     func(http.Handler) http.Handler
}

// registerOAuthRoutes wires the OAuth control plane onto r.
//
// BrowserFacing marks the three routes that terminate in a user's
// browser, and sits OUTSIDE their limiter so a throttled human still
// gets the error page instead of a JSON body. /register and /token
// deliberately carry no marker: that is what keeps them on
// application/json as RFC 6749 §5.2 and RFC 7591 §3.2.2 require, no
// matter what a caller puts in Accept.
//
// /consent gets its own bucket: a single user-driven flow is
// /authorize GET + /consent POST, and independent buckets stop a human
// who clicks Approve quickly from halving the per-IP budget for either.
func registerOAuthRoutes(r chi.Router, rt oauthRoutes) {
	// Fail at wiring time, not at the first request and not silently: a
	// missing limiter leaves the route unthrottled, which is the one
	// failure mode worth crashing a deploy over. Callers pass
	// passthrough explicitly when they mean "no limit".
	// Slice, not map: with several nil limiters the panic must name the
	// first one in route order, not a randomized pick.
	for _, l := range []struct {
		name string
		mw   func(http.Handler) http.Handler
	}{
		{"register", rt.RegisterLimit}, {"authorize", rt.AuthorizeLimit},
		{"consent", rt.ConsentLimit}, {"callback", rt.CallbackLimit}, {"token", rt.TokenLimit},
	} {
		if l.mw == nil {
			panic("registerOAuthRoutes: nil limiter for /" + l.name)
		}
	}
	r.With(rt.RegisterLimit).Post("/register", rt.Register)
	r.With(handlers.BrowserFacing, rt.AuthorizeLimit).Get("/authorize", rt.Authorize)
	r.With(handlers.BrowserFacing, rt.ConsentLimit).Post("/consent", rt.Consent)
	r.With(handlers.BrowserFacing, rt.CallbackLimit).Get("/callback", rt.Callback)
	r.With(rt.TokenLimit).Post("/token", rt.Token)
}

// browserFacingPaths lists the routes that terminate in a user's
// browser. registerOAuthRoutes wires the marker onto them directly;
// this list is what installMethodNotAllowed reads, so the two are
// separate statements of the same fact and would drift silently.
// TestBrowserFacingPaths_MatchesTheWiring derives the marked set from
// the live router and fails on any difference.
var browserFacingPaths = []string{"/authorize", "/consent", "/callback"}

// installMethodNotAllowed replaces chi's 405 responder.
//
// Two things the default handler gets wrong for this proxy, and one it
// gets right:
//   - it writes an empty body, which on /consent or /authorize is a
//     blank page for a user arriving from a bookmark or a stale form —
//     so the response goes through the shared error sink instead;
//   - negotiation is per path, NOT router-wide: a wrong method on
//     /token or /register must stay application/json like every other
//     error on those routes (RFC 6749 §5.2, RFC 7591 §3.2.2);
//   - it sets Allow, which RFC 9110 §15.5.6 makes a MUST on 405, so a
//     replacement has to keep setting it.
func installMethodNotAllowed(r chi.Router) {
	// Built on the first 405, not at wiring time: the routing table is
	// complete by then whatever order the caller registered things in,
	// so no route can be added "after" this and silently lose its Allow.
	// Cached rather than per-request — a 405 flood on an unlimited route
	// (/healthz) must not buy a tree walk each time.
	//
	// atomic.Pointer, not sync.Once: Once latches done even when its
	// function panics, which would strip the RFC 9110 §15.5.6 Allow
	// header from every later 405 with Recoverer swallowing the cause.
	// A racing double-build is cheap and idempotent.
	var allowCache atomic.Pointer[map[string]string]
	plain := http.HandlerFunc(handlers.MethodNotAllowed)
	browser := handlers.BrowserFacing(plain)
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		allow := allowCache.Load()
		if allow == nil {
			built := allowedMethods(r)
			allowCache.Store(&built)
			allow = &built
		}
		if a := (*allow)[req.URL.Path]; a != "" {
			w.Header().Set("Allow", a)
		}
		if slices.Contains(browserFacingPaths, req.URL.Path) {
			browser.ServeHTTP(w, req)
			return
		}
		plain.ServeHTTP(w, req)
	})
}

// installNotFound routes a 404 through the same responder as the 405,
// for the same reason: /authorize/ and a mistyped bookmark land here
// rather than on MethodNotAllowed, and chi's default answers a bare
// text/plain body.
//
// One body for every 404 in the proxy — handlers.NotFound emits the
// RFC 6749 envelope on an unmarked route and negotiates only on a
// marked one, so the discovery carve-outs, stray probes and browser
// bookmarks all carry the same JSON. The marker is applied per path
// exactly as the 405's is: it decides representation, never content.
func installNotFound(r chi.Router) {
	notFound := http.HandlerFunc(handlers.NotFound)
	browser := handlers.BrowserFacing(notFound)
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		if slices.Contains(browserFacingPaths, strings.TrimSuffix(req.URL.Path, "/")) {
			browser.ServeHTTP(w, req)
			return
		}
		notFound.ServeHTTP(w, req)
	})
}

// allowedMethods maps each literal route pattern to its Allow header
// value. Wildcard patterns are skipped: they are registered with
// Handle (every method), so they never reach a 405, and their pattern
// would not equal a request path anyway — chi leaves RoutePattern empty
// on the method-not-allowed branch, so the lookup has to key on the
// path itself.
func allowedMethods(r chi.Router) map[string]string {
	allow := map[string]string{}
	for _, route := range r.Routes() {
		if strings.ContainsAny(route.Pattern, "*{") {
			continue
		}
		methods := make([]string, 0, len(route.Handlers))
		for m := range route.Handlers {
			// chi keys an all-methods route under "*", which is not a
			// method token (RFC 9110 §10.2.1) and must not reach Allow.
			if m == "*" {
				continue
			}
			methods = append(methods, m)
		}
		if len(methods) == 0 {
			continue
		}
		slices.Sort(methods)
		allow[route.Pattern] = strings.Join(methods, ", ")
	}
	return allow
}

// registerDiscoveryRoutes wires all /.well-known/* and related
// discovery routes onto r. Kept separate from main so the routing
// decisions are testable in isolation (TestRegisterDiscoveryRoutes).
//
// baseURL must be origin-only (no trailing slash, no path) — enforced
// by config.validateProxyBaseURL. Violating that invariant silently
// produces wrong "resource" fields in the PRM.
//
// mountPath is the MCP mount extracted from UPSTREAM_MCP_URL
// (cfg.UpstreamMCPMountPath): the literal URL path shared by client
// and upstream (e.g. "/mcp", "/api/v1/mcp"). The per-resource PRM
// and AS-meta compat routes are published at <mountPath>-suffixed
// paths so MCP clients that probe the resource URL variant find them.
// limiter is the rate-limit middleware applied to every served well-
// known path. Pass `passthrough` when rate limiting is disabled, or
// `nil` (treated as identity) when callers don't need a limiter at
// all (tests).
func registerDiscoveryRoutes(r chi.Router, baseURL, mountPath, resourceName string, limiter func(http.Handler) http.Handler) {
	if limiter == nil {
		limiter = func(h http.Handler) http.Handler { return h }
	}
	// OAuth Protected Resource Metadata (RFC 9728).
	// - Root "/"-suffixed resource: Claude.ai canonicalizes RFC 8707
	//   resource indicators with a trailing slash, so this document
	//   must advertise the "/"-terminated form or `resource`
	//   comparisons fail.
	// - Per-resource path per RFC 9728 §3.1: a protected resource at
	//   https://host<mountPath> publishes PRM at
	//   /.well-known/oauth-protected-resource<mountPath> with
	//   resource=https://host<mountPath>.
	r.With(limiter).Get("/.well-known/oauth-protected-resource", handlers.ResourceMetadata(baseURL+"/", baseURL, resourceName))
	r.With(limiter).Get("/.well-known/oauth-protected-resource"+mountPath, handlers.ResourceMetadata(baseURL+mountPath, baseURL, resourceName))

	// OAuth 2.0 Authorization Server Metadata (RFC 8414).
	// Canonical location is the root well-known path. The mountPath-
	// suffixed variant is a non-spec compat path that some MCP clients
	// (Claude.ai web) probe alongside the canonical URL; serving the
	// same document there avoids a confusing 401 from the downstream
	// auth-gated catch-all.
	asMeta := handlers.Discovery(baseURL)
	r.With(limiter).Get("/.well-known/oauth-authorization-server", asMeta)
	r.With(limiter).Get("/.well-known/oauth-authorization-server"+mountPath, asMeta)

	// We are not an OIDC provider and we do not mirror upstream OIDC
	// discovery. Clients that probe these paths should get 404 so
	// they fall back to the OAuth metadata above. The 404 path is
	// also rate-limited — otherwise it becomes the cheapest flood
	// surface (smallest body, no JSON build).
	nf := http.HandlerFunc(handlers.NotFound)
	r.With(limiter).Handle("/.well-known/openid-configuration", nf)
	r.With(limiter).Handle("/.well-known/openid-configuration"+mountPath, nf)
	// Non-spec probes: some clients look for well-known paths under
	// the resource URL (<mountPath>/.well-known/...). RFC 8414/9728
	// put these at the origin root. Return 404 so the client falls
	// back to the canonical locations above instead of being
	// auth-gated by the MCP mount itself.
	r.With(limiter).Handle(mountPath+"/.well-known/*", nf)
}
