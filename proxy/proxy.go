package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/babs/mcp-auth-proxy/middleware"
	"go.uber.org/zap"
)

const (
	maxRedirects = 10
	// Cap proxied request bodies to 16 MiB. Anything larger is almost
	// certainly an abuse pattern — MCP JSON-RPC payloads are small, and
	// the redirect-following transport buffers the whole body in memory.
	maxProxiedBodyBytes = 16 * 1024 * 1024
	// Fail fast when an upstream stops sending headers. Stream bodies
	// (SSE) are unaffected because this timeout only covers the headers
	// phase of the response.
	upstreamResponseHeaderTimeout = 30 * time.Second
)

// sanitizeRequestHeaders strips inbound headers that must not reach the
// upstream: forwarding/IP headers that could spoof client identity at the
// upstream ACL layer, and any X-User-* headers the caller may have injected
// to impersonate a different user. Must be called before injectIdentityHeaders
// so the proxy-owned values are never accidentally deleted. Also called on
// every redirect hop to prevent smuggling across path transitions (H2, H9).
func sanitizeRequestHeaders(req *http.Request) {
	for _, h := range []string{
		"Cookie",
		"Proxy-Authorization",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"X-Forwarded-Port",
		"Forwarded",
		"X-Real-IP",
		"True-Client-IP",
		"X-Original-URI",
		"X-Original-Host",
	} {
		req.Header.Del(h)
	}
	// Delete any X-User-* the caller injected — including non-standard ones
	// not in the explicit list above (e.g. X-User-Admin). Keys are already in
	// canonical form (textproto.CanonicalMIMEHeaderKey), so the prefix check
	// is correct without further normalisation.
	for k := range req.Header {
		if strings.HasPrefix(k, "X-User-") {
			delete(req.Header, k)
		}
	}
}

// injectIdentityHeaders sets the proxy-owned X-User-* headers from the
// validated auth context. Must be called after sanitizeRequestHeaders.
func injectIdentityHeaders(req *http.Request) {
	if sub, ok := req.Context().Value(middleware.ContextSubject).(string); ok {
		req.Header.Set("X-User-Sub", sub)
	}
	if email, ok := req.Context().Value(middleware.ContextEmail).(string); ok {
		req.Header.Set("X-User-Email", email)
	}
	if groups, ok := req.Context().Value(middleware.ContextGroups).([]string); ok && len(groups) > 0 {
		req.Header.Set("X-User-Groups", strings.Join(groups, ","))
	}
}

// sameHost reports whether two URLs target the same host:port once
// implicit default ports (http=80, https=443) and letter case are
// normalized away. Used by the redirect-follow transport so a Location:
// that differs from the original request only in default-port form is
// recognized as same-origin (M8).
func sameHost(a, b *url.URL) bool {
	return normalizedHostPort(a) == normalizedHostPort(b)
}

func normalizedHostPort(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return host + ":" + port
}

// redirectFollowingTransport follows 307/308 redirects server-side.
// Python MCP backends (FastAPI/Starlette) redirect /mcp → /mcp/ with 307.
// MCP clients can't follow 307 on POST per HTTP spec, so the proxy handles it.
//
// upstreamAuthorization mirrors Config.UpstreamAuthorization so each
// redirect hop re-applies the operator-configured Authorization after
// sanitizeRequestHeaders runs (sanitize does not strip Authorization
// today, but re-applying keeps the Director and the redirect hop on
// identical header shapes regardless of future sanitize changes).
type redirectFollowingTransport struct {
	base                  http.RoundTripper
	upstreamAuthorization string
}

func (t *redirectFollowingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// H10: first hop streams the body straight through to the upstream.
	// A bounded copy is tee'd into buf so a subsequent 307/308 can replay
	// it without re-reading req.Body (which the base transport has since
	// drained). For the common no-redirect path this avoids any up-front
	// io.ReadAll and keeps baseline memory proportional to what the
	// upstream actually consumes.
	var (
		buf       *bytes.Buffer
		teeSrc    io.Reader
		bodyBytes []byte
	)
	if req.Body != nil && req.Body != http.NoBody {
		buf = &bytes.Buffer{}
		teeSrc = io.TeeReader(req.Body, buf)
		req.Body = io.NopCloser(teeSrc)
	}

	var lastResp *http.Response
	for i := 0; i < maxRedirects; i++ {
		// Honor client cancellation between hops so a caller that gave
		// up during a 307/308 chain doesn't cost one extra upstream RT
		// per remaining hop. The first hop is covered by the base
		// transport's own ctx check; this guard catches subsequent ones.
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		resp, err := t.base.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusPermanentRedirect {
			return resp, nil
		}

		loc := resp.Header.Get("Location")
		if loc == "" {
			return resp, nil
		}

		nextURL, err := req.URL.Parse(loc)
		if err != nil {
			return resp, nil
		}

		// Security: only follow redirects to the same host (M8 normalized).
		if !sameHost(nextURL, req.URL) {
			return resp, nil
		}

		// Security: reject scheme changes on redirect (H1). An https→http
		// downgrade would replay identity headers over cleartext.
		if nextURL.Scheme != req.URL.Scheme {
			return resp, nil
		}

		// On the last hop, drop the upstream redirect response and
		// synthesize a 502 below (L9). Returning the 307/308 verbatim
		// would push a `Location:` header to the MCP client that points
		// into an upstream redirect loop, which is worse than admitting
		// the upstream is misbehaving.
		if i == maxRedirects-1 {
			_ = resp.Body.Close()
			lastResp = resp
			break
		}

		// First 307/308: materialize the body for replay. H10 defers this
		// allocation until we actually need it; the common no-redirect
		// path never hits this branch. Drain any bytes the upstream
		// didn't consume so the buffer has the full request body.
		if bodyBytes == nil && buf != nil {
			if teeSrc != nil {
				if _, err := io.Copy(io.Discard, teeSrc); err != nil {
					_ = resp.Body.Close()
					return nil, fmt.Errorf("proxy: read request body for replay: %w", err)
				}
			}
			// Defensive: MaxBytesReader at the http.Handler boundary already
			// caps incoming bodies at maxProxiedBodyBytes, so this branch
			// should be unreachable. Keep as belt-and-braces against future
			// wiring changes that bypass the handler-level cap.
			if buf.Len() > maxProxiedBodyBytes {
				_ = resp.Body.Close()
				return nil, fmt.Errorf("proxy: request body exceeds %d bytes; cannot follow redirect", maxProxiedBodyBytes)
			}
			bodyBytes = buf.Bytes()
		}

		_ = resp.Body.Close()
		req = req.Clone(req.Context())
		req.URL = nextURL
		// Re-sanitize and re-inject on every hop so a compromised upstream
		// cannot smuggle forwarding headers or inject X-User-* across path
		// transitions via redirect chains (H9).
		sanitizeRequestHeaders(req)
		injectIdentityHeaders(req)
		// Re-apply the operator-configured upstream Authorization on
		// every hop. The Director's Del("Authorization") + Set pair
		// runs only on the first hop; without this, a future change
		// to sanitizeRequestHeaders that starts stripping
		// Authorization would silently drop the upstream credential
		// on redirect.
		if t.upstreamAuthorization != "" {
			req.Header.Set("Authorization", t.upstreamAuthorization)
		}
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
		}
	}

	// Exhausted the hop budget (L9). Synthesize a 502 with a generic
	// JSON body. The prior behavior of echoing the last 307/308 leaked
	// upstream internals (Location: into a redirect loop) to the MCP
	// client; a plain 502 tells the client "upstream is broken, give up"
	// which matches what an observer-safe reverse proxy should say.
	if lastResp != nil {
		body := []byte(`{"error":"bad_gateway","error_description":"too many upstream redirects"}`)
		hdr := http.Header{}
		hdr.Set("Content-Type", "application/json")
		hdr.Set("Content-Length", strconv.Itoa(len(body)))
		return &http.Response{
			Status:        "502 Bad Gateway",
			StatusCode:    http.StatusBadGateway,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        hdr,
			Body:          io.NopCloser(bytes.NewReader(body)),
			ContentLength: int64(len(body)),
			Request:       req,
		}, nil
	}
	return nil, fmt.Errorf("proxy: too many redirects (max %d)", maxRedirects)
}

// Config holds optional settings for the reverse-proxy Handler.
type Config struct {
	// UpstreamAuthorization, when non-empty, is set verbatim as the
	// Authorization header on every request forwarded to the upstream
	// MCP backend (and re-applied on every 307/308 redirect hop). The
	// operator provides the full header value including the scheme,
	// e.g. "Bearer s3cr3t" or "Basic dXNlcjpwYXNz". When empty, no
	// Authorization header is sent — the MCP client's own token is
	// already stripped by the Director, so the upstream sees the
	// request un-authenticated at the HTTP layer and must rely on the
	// proxy-injected X-User-* identity headers.
	UpstreamAuthorization string

	// ResponseHeaderTimeoutOverride, when non-zero, replaces the
	// 30s upstreamResponseHeaderTimeout default. Test-only knob —
	// production callers leave this at zero. Documented on the
	// Config struct rather than via a package-level variable so
	// the override is scoped to a single Handler instance and
	// cannot leak into another test running in parallel.
	ResponseHeaderTimeoutOverride time.Duration
}

// Handler returns a reverse proxy to the upstream MCP server.
// It strips the Authorization header and injects user identity headers.
// FlushInterval=-1 ensures SSE and chunked streaming work correctly.
func Handler(upstreamURL string, logger *zap.Logger, cfg Config) (http.Handler, error) {
	target, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	// Clone DefaultTransport so ResponseHeaderTimeout is applied without
	// mutating the package-level default. Header timeout fails fast on a
	// wedged upstream; it does NOT cover the response body, so SSE and
	// chunked streams remain uncapped.
	//
	// Two-value assert: a future caller (or test harness) may have
	// swapped DefaultTransport for a non-*http.Transport. Falling back
	// to a fresh *http.Transport keeps startup loud-but-functional
	// instead of panicking.
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		baseTransport = baseTransport.Clone()
	} else {
		baseTransport = &http.Transport{}
	}
	baseTransport.ResponseHeaderTimeout = upstreamResponseHeaderTimeout
	if cfg.ResponseHeaderTimeoutOverride > 0 {
		baseTransport.ResponseHeaderTimeout = cfg.ResponseHeaderTimeoutOverride
	}

	rp := &httputil.ReverseProxy{
		// Rewrite (vs Director) is used intentionally: Director causes
		// httputil.ReverseProxy to append X-Forwarded-For with the client IP
		// after the Director returns, undermining our header sanitisation.
		// Rewrite does not add any forwarding headers automatically.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = target.Scheme
			pr.Out.URL.Host = target.Host
			pr.Out.Host = target.Host
			// Path is forwarded verbatim: the router ensures the inbound
			// path sits under the UPSTREAM_MCP_URL mount (path on
			// upstream ≡ path on proxy). The upstream and the client
			// see the same URL path.

			// Strip forwarding and caller-supplied identity headers before
			// injecting the proxy-owned values from the validated auth context.
			sanitizeRequestHeaders(pr.Out)
			injectIdentityHeaders(pr.Out)

			// Security: don't leak the MCP client's internal token to
			// upstream. The Del must happen BEFORE the optional
			// UPSTREAM_AUTHORIZATION injection below so the operator-
			// configured value is not accidentally clobbered.
			pr.Out.Header.Del("Authorization")
			if cfg.UpstreamAuthorization != "" {
				pr.Out.Header.Set("Authorization", cfg.UpstreamAuthorization)
			}
		},
		// Python backends redirect /mcp → /mcp/ with 307; follow it server-side
		Transport:     &redirectFollowingTransport{base: baseTransport, upstreamAuthorization: cfg.UpstreamAuthorization},
		FlushInterval: -1, // Immediate flush for SSE/streaming
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("proxy_error", zap.Error(err))
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// Cap proxied request bodies. Applies only when a body is present;
	// GET/SSE requests pass through untouched. Prevents an authenticated
	// client from forcing the redirect-follow transport to buffer an
	// unbounded amount of memory during body replay.
	capped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, maxProxiedBodyBytes)
		}
		rp.ServeHTTP(w, r)
	})

	return capped, nil
}
