// Package metrics exposes Prometheus counters for the security-relevant
// events the proxy performs. Counters are registered with the default
// prometheus registry via promauto, so the existing promhttp.Handler() on
// the metrics listener picks them up without additional wiring.
package metrics

import (
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ToolLabelOverflow is the label value substituted for any tool name
// observed AFTER the cardinality cap is reached. Operators can detect
// runaway labels by alerting on this single bucket instead of facing
// unbounded series creation.
const ToolLabelOverflow = "_overflow"

// ToolLabelUnknown is the label value used when a request reached the
// MCP route but RPCPeek did not extract a tool name (non-JSON-RPC
// shape, oversized body, parse miss). Counted into a single bucket
// rather than dropped so operators see the volume of non-tool calls.
const ToolLabelUnknown = "_unknown"

// ToolCardinality bounds the number of distinct tool labels observed
// to MaxCardinality. Once the cap is reached, additional unique tool
// names route to the ToolLabelOverflow bucket. Adversarial clients
// that probe non-existent tools to inflate Prometheus cardinality
// only ever produce one extra series (the overflow bucket).
//
// Concurrency: ToolLabel is safe under contention. The seen-count
// uses an atomic.Int64 and the deduplication uses sync.Map; under
// burst contention the counter can briefly overshoot MaxCardinality
// by the number of concurrent goroutines, which is acceptable —
// the cap is a soft budget, not a security boundary.
type ToolCardinality struct {
	MaxCardinality int
	seen           sync.Map // map[string]struct{}
	seenCount      atomic.Int64
}

// ToolLabel returns the bucket name to use for the given tool. Empty
// names are folded into ToolLabelUnknown (RPC peek miss, non-JSON
// body); names past the cap go to ToolLabelOverflow.
func (c *ToolCardinality) ToolLabel(tool string) string {
	if tool == "" {
		return ToolLabelUnknown
	}
	if _, ok := c.seen.Load(tool); ok {
		return tool
	}
	if c.MaxCardinality > 0 && c.seenCount.Load() >= int64(c.MaxCardinality) {
		return ToolLabelOverflow
	}
	if _, loaded := c.seen.LoadOrStore(tool, struct{}{}); !loaded {
		c.seenCount.Add(1)
	}
	return tool
}

var (
	// TokensIssued counts successfully-minted access tokens, labelled by
	// the grant that produced them (authorization_code / refresh_token).
	TokensIssued = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcp_auth_tokens_issued_total",
		Help: "Access tokens successfully issued, by grant type.",
	}, []string{"grant_type"})

	// AccessDenied counts rejected authentications, labelled by reason
	// (group, email_unverified, audience, ...). Useful for spotting
	// misconfigured IdP claims or abuse patterns.
	AccessDenied = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcp_auth_access_denied_total",
		Help: "Access denied counts, by reason.",
	}, []string{"reason"})

	// ReplayDetected counts replay attempts caught by the replay store
	// (requires REDIS_URL). Labelled by kind (code / refresh).
	ReplayDetected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcp_auth_replay_detected_total",
		Help: "Replay attempts detected by the replay store, by kind.",
	}, []string{"kind"})

	// ClientsRegistered counts dynamic client registrations (RFC 7591).
	ClientsRegistered = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mcp_auth_clients_registered_total",
		Help: "Dynamic client registrations accepted.",
	})

	// RateLimited counts requests that were throttled at the pre-auth
	// httprate layer. Labelled by endpoint.
	RateLimited = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcp_auth_rate_limited_total",
		Help: "Requests rejected by the per-IP rate limiter, by endpoint.",
	}, []string{"endpoint"})

	// GroupsClaimShapeMismatch counts id_tokens whose `groups` claim
	// did not decode as []string. Distinct from AccessDenied because
	// the request is NOT denied on this path — the proxy admits with
	// an empty groups list. Operators alert on this independently to
	// catch IdP schema migrations / claim-shape regressions before
	// they cascade into a real `group` denial spike.
	GroupsClaimShapeMismatch = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mcp_auth_groups_claim_shape_mismatch_total",
		Help: "ID-token groups claim failed to decode as []string; user was admitted with empty groups.",
	})

	// TokenSeals counts successful AES-GCM seal operations, labelled by
	// purpose (client / session / code / access / refresh). Aggregating
	// across replicas via Prometheus solves the per-process seal-counter
	// blind spot: the in-process counter resets on every restart, so a
	// pod that rolls daily never approaches its 2^28 one-replica
	// threshold even when fleet-wide cumulative seals do. Alert example:
	//   sum(increase(mcp_auth_token_seals_total[7d])) > 2^28
	// Crossing this is the operator signal to rotate
	// TOKEN_SIGNING_SECRET via the rolling-rotation runbook —
	// AES-GCM with random 96-bit nonces approaches collision risk
	// around 2^32 messages per key.
	TokenSeals = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcp_auth_token_seals_total",
		Help: "AES-GCM seal operations on the primary signing secret, by purpose. Aggregate across replicas to track cumulative seals per key.",
	}, []string{"purpose"})

	// Per-tool RPC observability — opt-in via MCP_TOOL_METRICS=true so
	// the cardinality cost is a deliberate operator decision. Tool name
	// is sourced from RPCPeek's `rpc_tool` extraction (the JSON-RPC
	// `params.name` field; see middleware/rpc_peek.go); names that
	// did not parse are folded into ToolLabelUnknown. Past the
	// MCP_TOOL_METRICS_MAX_CARDINALITY cap (default 256), additional
	// distinct names are folded into ToolLabelOverflow so adversarial
	// clients calling non-existent tools cannot inflate the series count.
	RPCCalls = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcp_auth_rpc_calls_total",
		Help: "MCP JSON-RPC tool invocations seen by the proxy, by tool name. Disabled by default; enable via MCP_TOOL_METRICS=true.",
	}, []string{"tool"})

	RPCCallsFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcp_auth_rpc_calls_failed_total",
		Help: "MCP JSON-RPC invocations that returned a 4xx/5xx response status, by tool name.",
	}, []string{"tool"})

	RPCRequestBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcp_auth_rpc_request_bytes_total",
		Help: "Cumulative request body bytes for MCP JSON-RPC invocations, by tool name. Sourced from Content-Length; chunked / unknown-length requests do not contribute.",
	}, []string{"tool"})

	RPCResponseBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "mcp_auth_rpc_response_bytes_total",
		Help: "Cumulative response body bytes for MCP JSON-RPC invocations, by tool name. Includes SSE / streaming body bytes finalised when the handler returns.",
	}, []string{"tool"})
)
