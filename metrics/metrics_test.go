package metrics

import (
	"sync"
	"testing"
)

// TestToolCardinality_BelowCap verifies the happy path: tools observed
// before the cap is hit are returned verbatim. The seen-set is the
// dedup primitive — re-observing the same tool does not reduce
// remaining headroom.
func TestToolCardinality_BelowCap(t *testing.T) {
	c := &ToolCardinality{MaxCardinality: 3}

	for _, tool := range []string{"weather", "search", "weather", "calendar", "search"} {
		got := c.ToolLabel(tool)
		if got != tool {
			t.Errorf("ToolLabel(%q) = %q, want verbatim", tool, got)
		}
	}
	if got := c.seenCount.Load(); got != 3 {
		t.Errorf("seenCount = %d, want 3 (deduplicated unique entries)", got)
	}
}

// TestToolCardinality_OverflowBucket pins the cardinality bound: the
// (cap+1)-th distinct tool — and every subsequent one — must collapse
// into the _overflow label so a malicious client cannot inflate the
// Prometheus series count by probing fictional tool names.
func TestToolCardinality_OverflowBucket(t *testing.T) {
	c := &ToolCardinality{MaxCardinality: 2}

	if got := c.ToolLabel("weather"); got != "weather" {
		t.Errorf("first tool: got %q, want %q", got, "weather")
	}
	if got := c.ToolLabel("search"); got != "search" {
		t.Errorf("second tool: got %q, want %q", got, "search")
	}
	// At cap. Every new distinct tool routes to overflow.
	for _, tool := range []string{"calendar", "stocks", "another-tool"} {
		if got := c.ToolLabel(tool); got != ToolLabelOverflow {
			t.Errorf("over-cap tool %q: got %q, want %q", tool, got, ToolLabelOverflow)
		}
	}
	// Already-seen tools are still served from the seen set.
	if got := c.ToolLabel("weather"); got != "weather" {
		t.Errorf("seen tool after cap: got %q, want %q", got, "weather")
	}
}

// TestToolCardinality_EmptyToolUnknown — RPCPeek may have failed to
// extract a tool name (non-JSON body, oversized payload, parse miss).
// Empty string folds into _unknown rather than producing a series
// labelled with the empty string (Prometheus would accept it but it's
// confusing in dashboards).
func TestToolCardinality_EmptyToolUnknown(t *testing.T) {
	c := &ToolCardinality{MaxCardinality: 256}
	if got := c.ToolLabel(""); got != ToolLabelUnknown {
		t.Errorf("ToolLabel(\"\") = %q, want %q", got, ToolLabelUnknown)
	}
	// _unknown does NOT consume a cardinality slot — it is a
	// constant bucket independent of the observed-tool set.
	if got := c.seenCount.Load(); got != 0 {
		t.Errorf("seenCount after empty tool = %d, want 0", got)
	}
}

// TestToolCardinality_ConcurrentSafety exercises the lock-free path
// under contention. Race detector + the simple correctness check
// (every legitimate tool either resolves to itself or to overflow,
// never to a corrupted string) is enough — exact tool/overflow
// distribution is non-deterministic by design under the soft cap.
func TestToolCardinality_ConcurrentSafety(t *testing.T) {
	c := &ToolCardinality{MaxCardinality: 5}
	tools := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, tool := range tools {
				got := c.ToolLabel(tool)
				if got != tool && got != ToolLabelOverflow {
					t.Errorf("ToolLabel(%q) = %q (neither verbatim nor overflow)", tool, got)
				}
			}
		}()
	}
	wg.Wait()
}

// TestToolCardinality_ZeroCapDisablesGuard — a non-positive
// MaxCardinality skips the cap check entirely, so every tool goes
// to its own bucket. Useful for deployments where the upstream
// already enforces a tool allowlist and operators want raw
// per-tool data without overflow folding.
func TestToolCardinality_ZeroCapDisablesGuard(t *testing.T) {
	c := &ToolCardinality{MaxCardinality: 0}
	for i := range 100 {
		tool := "tool-" + string(rune('a'+(i%26)))
		if got := c.ToolLabel(tool); got != tool {
			t.Errorf("zero cap should accept every tool, got %q for %q", got, tool)
		}
	}
}
