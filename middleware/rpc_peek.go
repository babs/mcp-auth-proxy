package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// RPCPeekConfig configures the RPC body peek middleware.
type RPCPeekConfig struct {
	// MaxBodyBytes caps how many bytes are buffered per request for JSON-RPC
	// method extraction. 0 disables the peek entirely (no buffering, no
	// method logging).
	MaxBodyBytes int64
	Logger       *zap.Logger
}

// RequestLogRecord is a mutable bag that RPCPeek populates after auth has
// run. zapMiddleware injects a fresh record via InjectLogRecord before the
// handler chain; RPCPeek writes into it; zapMiddleware reads it back after
// ServeHTTP returns. A pointer is used so the reference survives all
// r.WithContext hops across middleware layers.
type RequestLogRecord struct {
	Sub, Email, RPCMethod, RPCTool, RPCID string
}

const contextLogRecord contextKey = "log_record"

// InjectLogRecord adds a fresh *RequestLogRecord to ctx. Returns the enriched
// context and the pointer. Called by zapMiddleware; the pointer is read back
// after ServeHTTP to emit the structured access-log line.
func InjectLogRecord(ctx context.Context) (context.Context, *RequestLogRecord) {
	rec := &RequestLogRecord{}
	return context.WithValue(ctx, contextLogRecord, rec), rec
}

// RPCPeek returns middleware that buffers small JSON-RPC request bodies,
// extracts method / params.name / id, stashes them in the request context
// (ContextRPCMethod / ContextRPCTool / ContextRPCID) and in the
// *RequestLogRecord for access logging. The body is replayed byte-for-byte
// to the downstream handler. Any error is swallowed; the request is never
// failed.
func RPCPeek(cfg RPCPeekConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Sub/email are set by auth, which runs before us; copy them into
			// the log record now so even passthrough requests (non-JSON, large
			// bodies) still emit the principal in the access log.
			rec, _ := r.Context().Value(contextLogRecord).(*RequestLogRecord)
			if rec != nil {
				rec.Sub, _ = r.Context().Value(ContextSubject).(string)
				rec.Email, _ = r.Context().Value(ContextEmail).(string)
			}

			// Conditions under which we skip body inspection entirely.
			if cfg.MaxBodyBytes == 0 ||
				!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") ||
				r.ContentLength < 0 || r.ContentLength > cfg.MaxBodyBytes {
				next.ServeHTTP(w, r)
				return
			}

			buf, err := io.ReadAll(io.LimitReader(r.Body, cfg.MaxBodyBytes+1))
			// Always replay so downstream always sees a complete reader.
			r.Body = io.NopCloser(bytes.NewReader(buf))

			if err != nil || int64(len(buf)) > cfg.MaxBodyBytes {
				// Oversized or read error — pass through without parsing.
				// Body is replayed with whatever was read (partial is fine; the
				// real defense is the Content-Length pre-check above).
				next.ServeHTTP(w, r)
				return
			}

			// Strict peek: decode only the fields we care about.
			type peekParams struct {
				Name string `json:"name"`
			}
			type peek struct {
				Method string          `json:"method"`
				Params peekParams      `json:"params"`
				ID     json.RawMessage `json:"id"`
			}

			ctx := r.Context()
			trim := bytes.TrimLeft(buf, " \t\r\n")
			if len(trim) > 0 && trim[0] == '[' {
				// Batch request: collect all method names.
				var batch []peek
				if json.Unmarshal(buf, &batch) == nil {
					methods := make([]string, 0, len(batch))
					for _, p := range batch {
						if p.Method != "" {
							methods = append(methods, sanitize(p.Method, 128))
						}
					}
					if len(methods) > 0 {
						joined := strings.Join(methods, ",")
						if rec != nil {
							rec.RPCMethod = joined
						}
						ctx = context.WithValue(ctx, ContextRPCMethod, joined)
					}
				}
			} else {
				var one peek
				if json.Unmarshal(buf, &one) == nil {
					if one.Method != "" {
						m := sanitize(one.Method, 128)
						if rec != nil {
							rec.RPCMethod = m
						}
						ctx = context.WithValue(ctx, ContextRPCMethod, m)
					}
					if one.Params.Name != "" {
						t := sanitize(one.Params.Name, 128)
						if rec != nil {
							rec.RPCTool = t
						}
						ctx = context.WithValue(ctx, ContextRPCTool, t)
					}
					if len(one.ID) > 0 {
						// JSON-RPC ids are typically a small number or a UUID.
						// Cap aggressively to keep log lines bounded — a
						// pathological 64 KiB id within Content-Length would
						// otherwise bloat every access log line.
						id := sanitize(string(one.ID), 64)
						if id != "" {
							if rec != nil {
								rec.RPCID = id
							}
							ctx = context.WithValue(ctx, ContextRPCID, id)
						}
					}
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// sanitize caps s at maxLen runes and keeps only a narrow allowlist
// (ASCII alnum plus `._:/-+`) typical of MCP method names like
// "tools/call", resource URI schemes and tool slugs. Rejecting everything
// else defends log aggregators against BiDi/ZWJ homograph confusion and
// keeps noise out of the access log when a client sends unusual payloads.
func sanitize(s string, maxLen int) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count >= maxLen {
			break
		}
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == ':', r == '/', r == '-', r == '+':
			b.WriteRune(r)
			count++
		}
	}
	return b.String()
}
