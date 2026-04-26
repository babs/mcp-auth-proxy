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
// RPCCall captures one entry inside a JSON-RPC batch (or, by way of a
// degenerate single-element view, a single-call request) with the
// per-call method and the extracted tool name when the method is
// "tools/call". Used by the metrics observer to fan a batch out into
// one Prometheus increment per tool invocation rather than collapsing
// the whole batch into a single label.
type RPCCall struct {
	Method, Tool string
}

type RequestLogRecord struct {
	Sub, Email, RPCMethod, RPCTool, RPCID string
	// RPCBatch is non-nil ONLY for JSON-RPC batch requests. Each entry
	// is one call inside the batch with its method + extracted tool
	// name (or empty Tool when the method is not tools/call or
	// params.name was absent / unparseable). RPCMethod still carries
	// the comma-joined methods for log convenience; RPCBatch is the
	// structured form for metrics fan-out.
	RPCBatch []RPCCall
}

const contextLogRecord contextKey = "log_record"

// InjectLogRecord adds a fresh *RequestLogRecord to ctx and returns both the
// enriched context and the pointer.
//
// Why a pointer-through-context, not a direct field on the handler:
// zapMiddleware wraps the whole chain — it computes status/duration and
// emits the access log AFTER next.ServeHTTP returns. The fields we want
// on that log line (sub, email, rpc_method, rpc_tool, rpc_id) are
// populated by LATER middlewares — auth fills sub/email, RPCPeek
// parses the JSON-RPC envelope. Those middlewares run in their own
// handlers with their own request copies (r.WithContext hops create
// fresh *http.Request values), so a direct field write would be lost
// when ServeHTTP returns. A pointer stored in the root context
// survives every WithContext hop; both the enricher and the emitter
// look it up by key and see the same struct. Alternatives considered
// and rejected: (1) wrapping http.ResponseWriter — conflicts with
// chi's own WrapResponseWriter and needs care for Hijack/Flush;
// (2) sync.Map keyed by request id — extra allocation per request
// and exposes a GC lifecycle we'd have to manage explicitly.
func InjectLogRecord(ctx context.Context) (context.Context, *RequestLogRecord) {
	rec := &RequestLogRecord{}
	return context.WithValue(ctx, contextLogRecord, rec), rec
}

// LogRecordFromContext returns the per-request RequestLogRecord
// pointer if one was injected by InjectLogRecord, or nil if the
// context never carried one. Exported so handlers and tests can
// observe / mutate the record by the same key the enricher uses,
// without having to re-export the contextKey itself.
func LogRecordFromContext(ctx context.Context) *RequestLogRecord {
	rec, _ := ctx.Value(contextLogRecord).(*RequestLogRecord)
	return rec
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
				// Batch request: collect both the joined method list
				// (log line shape, unchanged) AND the structured per-
				// call view (metrics fan-out). Each batch entry's
				// params.name is captured at the SAME time we see its
				// method — losing it here would be the bug the metrics
				// observer just papered over by skipping batches.
				var batch []peek
				if json.Unmarshal(buf, &batch) == nil {
					methods := make([]string, 0, len(batch))
					calls := make([]RPCCall, 0, len(batch))
					for _, p := range batch {
						if p.Method == "" {
							continue
						}
						method := sanitize(p.Method, 128)
						methods = append(methods, method)
						call := RPCCall{Method: method}
						if method == "tools/call" && p.Params.Name != "" {
							call.Tool = sanitize(p.Params.Name, 128)
						}
						calls = append(calls, call)
					}
					if len(methods) > 0 {
						joined := strings.Join(methods, ",")
						if rec != nil {
							rec.RPCMethod = joined
							rec.RPCBatch = calls
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
