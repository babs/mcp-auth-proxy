package handlers

import (
	"net/http"
	"strings"
)

// ResourceMetadata returns the OAuth 2.0 Protected Resource Metadata (RFC 9728).
// MCP clients use this to discover which authorization server protects this resource.
func ResourceMetadata(baseURL string) http.HandlerFunc {
	// Claude.ai normalizes resource URIs with trailing slash (RFC 8707).
	// Ensure the resource field matches what clients will send back.
	resourceURI := strings.TrimRight(baseURL, "/") + "/"
	meta := map[string]any{
		"resource":                 resourceURI,
		"authorization_servers":    []string{baseURL},
		"bearer_methods_supported": []string{"header"},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, meta)
	}
}
