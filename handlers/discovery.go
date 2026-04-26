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
		// RFC 8414 §2 (RECOMMENDED). Explicit empty array — the proxy
		// carries no scope model of its own (scopes are not parsed at
		// /authorize, not encoded in access tokens, not checked by the
		// RS middleware). Publishing `[]` is more informative than
		// omitting the field: a client that auto-configures least-
		// privilege requests sees a concrete "no scopes" answer rather
		// than having to probe.
		"scopes_supported": []string{},
		// RFC 9207 §3 / RFC 9700 §2.1.4 (mix-up defense). The /callback
		// redirect emits the `iss` parameter on every authorization
		// response (success AND error). Strict clients gate the check
		// on this metadata flag — if it's missing, they ignore `iss`
		// and the defense is silently disabled. We always emit it.
		"authorization_response_iss_parameter_supported": true,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, meta)
	}
}
