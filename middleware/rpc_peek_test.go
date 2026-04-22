package middleware

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// helpers

func makeJSONRequest(body string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(body))
	return r
}

func withLogRec(r *http.Request) (*http.Request, *RequestLogRecord) {
	ctx, rec := InjectLogRecord(r.Context())
	return r.WithContext(ctx), rec
}

func withSubEmail(r *http.Request, sub, email string) *http.Request {
	ctx := context.WithValue(r.Context(), ContextSubject, sub)
	ctx = context.WithValue(ctx, ContextEmail, email)
	return r.WithContext(ctx)
}

func defaultCfg() RPCPeekConfig {
	return RPCPeekConfig{MaxBodyBytes: 65536, Logger: zap.NewNop()}
}

func smallCfg(max int64) RPCPeekConfig {
	return RPCPeekConfig{MaxBodyBytes: max, Logger: zap.NewNop()}
}

// Test 1: single JSON-RPC populates method, tool, id in record and context.
func TestRPCPeek_Single(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell"}}`
	r := makeJSONRequest(body)
	r = withSubEmail(r, "user-123", "user@example.com")
	r, rec := withLogRec(r)

	var downstreamCtx context.Context
	mw := RPCPeek(defaultCfg())(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		downstreamCtx = req.Context()
		w.WriteHeader(http.StatusOK)
	}))
	mw.ServeHTTP(httptest.NewRecorder(), r)

	if rec.Sub != "user-123" {
		t.Errorf("rec.Sub = %q, want %q", rec.Sub, "user-123")
	}
	if rec.Email != "user@example.com" {
		t.Errorf("rec.Email = %q, want %q", rec.Email, "user@example.com")
	}
	if rec.RPCMethod != "tools/call" {
		t.Errorf("rec.RPCMethod = %q, want %q", rec.RPCMethod, "tools/call")
	}
	if rec.RPCTool != "shell" {
		t.Errorf("rec.RPCTool = %q, want %q", rec.RPCTool, "shell")
	}
	if rec.RPCID != "1" {
		t.Errorf("rec.RPCID = %q, want %q", rec.RPCID, "1")
	}
	// Context keys must also be set for downstream code.
	if v, _ := downstreamCtx.Value(ContextRPCMethod).(string); v != "tools/call" {
		t.Errorf("ContextRPCMethod = %q, want %q", v, "tools/call")
	}
	if v, _ := downstreamCtx.Value(ContextRPCTool).(string); v != "shell" {
		t.Errorf("ContextRPCTool = %q, want %q", v, "shell")
	}
	if v, _ := downstreamCtx.Value(ContextRPCID).(string); v != "1" {
		t.Errorf("ContextRPCID = %q, want %q", v, "1")
	}
}

// Test 2: batch JSON-RPC joins all method names with comma.
func TestRPCPeek_Batch(t *testing.T) {
	body := `[{"method":"a"},{"method":"b"}]`
	r := makeJSONRequest(body)
	r, rec := withLogRec(r)

	mw := RPCPeek(defaultCfg())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mw.ServeHTTP(httptest.NewRecorder(), r)

	if rec.RPCMethod != "a,b" {
		t.Errorf("rec.RPCMethod = %q, want %q", rec.RPCMethod, "a,b")
	}
}

// Test 3: non-JSON content type is a passthrough — no rpc fields set.
func TestRPCPeek_NonJSON(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(`{"method":"tools/call"}`))
	r.Header.Set("Content-Type", "text/plain")
	r.ContentLength = 23
	r, rec := withLogRec(r)

	called := false
	mw := RPCPeek(defaultCfg())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	mw.ServeHTTP(httptest.NewRecorder(), r)

	if !called {
		t.Fatal("next handler should be called on non-JSON")
	}
	if rec.RPCMethod != "" {
		t.Errorf("expected no RPCMethod for non-JSON, got %q", rec.RPCMethod)
	}
}

// Test 4: Content-Length > max is a passthrough — no rpc fields set.
func TestRPCPeek_ContentLengthExceedsMax(t *testing.T) {
	body := `{"method":"tools/call"}`
	r := makeJSONRequest(body)
	r.ContentLength = 1000 // claims 1000 bytes; max = 10
	r, rec := withLogRec(r)

	called := false
	mw := RPCPeek(smallCfg(10))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	mw.ServeHTTP(httptest.NewRecorder(), r)

	if !called {
		t.Fatal("next handler should be called when Content-Length > max")
	}
	if rec.RPCMethod != "" {
		t.Errorf("expected no RPCMethod when CL > max, got %q", rec.RPCMethod)
	}
}

// Test 5: malformed JSON → next is still called, no rpc fields, no panic.
func TestRPCPeek_MalformedJSON(t *testing.T) {
	body := `{not valid json at all`
	r := makeJSONRequest(body)
	r, rec := withLogRec(r)

	called := false
	mw := RPCPeek(defaultCfg())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	mw.ServeHTTP(httptest.NewRecorder(), r)

	if !called {
		t.Fatal("next handler should be called even on malformed JSON")
	}
	if rec.RPCMethod != "" || rec.RPCTool != "" || rec.RPCID != "" {
		t.Errorf("expected no rpc fields on malformed JSON, got method=%q tool=%q id=%q",
			rec.RPCMethod, rec.RPCTool, rec.RPCID)
	}
}

// Test 6: empty method field → no RPCMethod context key or record field.
func TestRPCPeek_EmptyMethod(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"","params":{"name":"tool"}}`
	r := makeJSONRequest(body)
	r, rec := withLogRec(r)

	mw := RPCPeek(defaultCfg())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mw.ServeHTTP(httptest.NewRecorder(), r)

	if rec.RPCMethod != "" {
		t.Errorf("expected no RPCMethod for empty method field, got %q", rec.RPCMethod)
	}
}

// Test 7: downstream handler receives the full original body byte-for-byte.
func TestRPCPeek_BodyReplay(t *testing.T) {
	original := `{"jsonrpc":"2.0","method":"tools/list","id":42}`
	r := makeJSONRequest(original)
	r, _ = withLogRec(r)

	var got []byte
	mw := RPCPeek(defaultCfg())(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got, _ = io.ReadAll(req.Body)
		w.WriteHeader(http.StatusOK)
	}))
	mw.ServeHTTP(httptest.NewRecorder(), r)

	if !bytes.Equal(got, []byte(original)) {
		t.Errorf("body not replayed correctly\ngot:  %q\nwant: %q", got, original)
	}
}

// Test 8: Content-Length within max but actual body is larger → ReadAll hits
// the max+1 limit, request passes through without rpc fields.
func TestRPCPeek_BodyLargerThanMaxDespiteSmallCL(t *testing.T) {
	const max = 10
	actual := strings.Repeat("x", max+2) // 12 bytes; CL claims 10

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(actual))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = max // lie: claim exactly max bytes

	r, rec := withLogRec(r)

	called := false
	mw := RPCPeek(smallCfg(max))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	mw.ServeHTTP(httptest.NewRecorder(), r)

	if !called {
		t.Fatal("next handler should be called even when actual body > CL")
	}
	if rec.RPCMethod != "" {
		t.Errorf("expected no RPCMethod when body overflows, got %q", rec.RPCMethod)
	}
}

// Test: MaxBodyBytes=0 disables peek entirely; body is untouched.
func TestRPCPeek_DisabledWhenMaxZero(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"tools/call"}`
	r := makeJSONRequest(body)
	r, rec := withLogRec(r)

	var got []byte
	mw := RPCPeek(RPCPeekConfig{MaxBodyBytes: 0, Logger: zap.NewNop()})(
		http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			got, _ = io.ReadAll(req.Body)
			w.WriteHeader(http.StatusOK)
		}),
	)
	mw.ServeHTTP(httptest.NewRecorder(), r)

	if rec.RPCMethod != "" {
		t.Errorf("expected no RPCMethod when disabled, got %q", rec.RPCMethod)
	}
	// Body must still reach downstream unchanged.
	if !bytes.Equal(got, []byte(body)) {
		t.Errorf("body not preserved when peek disabled\ngot:  %q\nwant: %q", got, body)
	}
}
