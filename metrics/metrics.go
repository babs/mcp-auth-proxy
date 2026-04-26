// Package metrics exposes Prometheus counters for the security-relevant
// events the proxy performs. Counters are registered with the default
// prometheus registry via promauto, so the existing promhttp.Handler() on
// the metrics listener picks them up without additional wiring.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

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
)
