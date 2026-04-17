package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/babs/mcp-auth-proxy/middleware"
	"go.uber.org/zap"
)

// singleJoiningSlash joins two URL path segments with exactly one slash.
// Mirrors the helper from net/http/httputil.
func singleJoiningSlash(a, b string) string {
	aSlash := strings.HasSuffix(a, "/")
	bSlash := strings.HasPrefix(b, "/")
	switch {
	case aSlash && bSlash:
		return a + b[1:]
	case !aSlash && !bSlash:
		return a + "/" + b
	}
	return a + b
}

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

// redirectFollowingTransport follows 307/308 redirects server-side.
// Python MCP backends (FastAPI/Starlette) redirect /mcp → /mcp/ with 307.
// MCP clients can't follow 307 on POST per HTTP spec, so the proxy handles it.
type redirectFollowingTransport struct {
	base http.RoundTripper
}

func (t *redirectFollowingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Buffer body for replay on redirect (MCP JSON-RPC payloads are small)
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	var lastResp *http.Response
	for i := 0; i < maxRedirects; i++ {
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

		// Security: only follow redirects to the same host
		if nextURL.Host != req.URL.Host {
			return resp, nil
		}

		// Hand the redirect response back only if it's the last hop.
		// Draining+closing here before issuing the next request.
		if i == maxRedirects-1 {
			lastResp = resp
			break
		}

		resp.Body.Close()
		req = req.Clone(req.Context())
		req.URL = nextURL
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
		}
	}

	// Exhausted the hop budget. Return the last redirect response rather
	// than re-issuing the request, which would double side effects on the
	// upstream and still not produce a usable response for the client.
	if lastResp != nil {
		return lastResp, nil
	}
	return nil, fmt.Errorf("proxy: too many redirects (max %d)", maxRedirects)
}

// Handler returns a reverse proxy to the upstream MCP server.
// It strips the Authorization header and injects user identity headers.
// FlushInterval=-1 ensures SSE and chunked streaming work correctly.
func Handler(upstreamURL string, logger *zap.Logger) (http.Handler, error) {
	target, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	// Clone DefaultTransport so ResponseHeaderTimeout is applied without
	// mutating the package-level default. Header timeout fails fast on a
	// wedged upstream; it does NOT cover the response body, so SSE and
	// chunked streams remain uncapped.
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.ResponseHeaderTimeout = upstreamResponseHeaderTimeout

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			// Preserve path prefix from UPSTREAM_MCP_URL (e.g. /api)
			req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)

			// Drop any caller-supplied identity headers before injecting trusted
			// values from the validated auth context.
			req.Header.Del("X-User-Sub")
			req.Header.Del("X-User-Email")
			req.Header.Del("X-User-Groups")

			if sub, ok := req.Context().Value(middleware.ContextSubject).(string); ok {
				req.Header.Set("X-User-Sub", sub)
			}
			if email, ok := req.Context().Value(middleware.ContextEmail).(string); ok {
				req.Header.Set("X-User-Email", email)
			}
			if groups, ok := req.Context().Value(middleware.ContextGroups).([]string); ok && len(groups) > 0 {
				req.Header.Set("X-User-Groups", strings.Join(groups, ","))
			}

			// Security: don't leak internal token to upstream
			req.Header.Del("Authorization")
		},
		// Python backends redirect /mcp → /mcp/ with 307; follow it server-side
		Transport:     &redirectFollowingTransport{base: baseTransport},
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
