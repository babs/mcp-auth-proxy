package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

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

const maxRedirects = 10

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

		resp.Body.Close()
		req = req.Clone(req.Context())
		req.URL = nextURL
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
		}
	}

	// Exhausted redirects — return last response via a final round-trip
	return t.base.RoundTrip(req)
}

// Handler returns a reverse proxy to the upstream MCP server.
// It strips the Authorization header and injects user identity headers.
// FlushInterval=-1 ensures SSE and chunked streaming work correctly.
func Handler(upstreamURL string, logger *zap.Logger) (http.Handler, error) {
	target, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			// Preserve path prefix from UPSTREAM_MCP_URL (e.g. /api)
			req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)

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
		Transport:     &redirectFollowingTransport{base: http.DefaultTransport},
		FlushInterval: -1, // Immediate flush for SSE/streaming
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("proxy_error", zap.Error(err))
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	return rp, nil
}
