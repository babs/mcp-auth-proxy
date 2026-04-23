package handlers

import (
	"net/http"
)

// ResourceMetadata returns the OAuth 2.0 Protected Resource Metadata (RFC 9728)
// for a specific resource URI. MCP clients use this to discover which
// authorization server protects the resource.
//
// resourceURI is what the handler advertises under the "resource" field — it
// must match exactly what clients send back in RFC 8707 resource indicators.
// Callers are responsible for picking the form (root "/"-suffixed for
// Claude.ai compat, path-scoped "/mcp" for the RFC 9728 §3.1 per-resource
// path, etc.). baseURL stays as the issuer identifier in
// "authorization_servers".
func ResourceMetadata(resourceURI, baseURL string) http.HandlerFunc {
	meta := map[string]any{
		"resource":                 resourceURI,
		"authorization_servers":    []string{baseURL},
		"bearer_methods_supported": []string{"header"},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, meta)
	}
}
