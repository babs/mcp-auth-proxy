package handlers

import "net/http"

// Discovery returns the OAuth 2.0 Authorization Server Metadata.
func Discovery(baseURL string) http.HandlerFunc {
	meta := map[string]any{
		"issuer":                           baseURL,
		"authorization_endpoint":           baseURL + "/authorize",
		"token_endpoint":                   baseURL + "/token",
		"registration_endpoint":            baseURL + "/register",
		"response_types_supported":         []string{"code"},
		"grant_types_supported":            []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported": []string{"S256"},
		// PKCE-only proxy: no client secrets are validated
		"token_endpoint_auth_methods_supported": []string{"none"},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, meta)
	}
}
