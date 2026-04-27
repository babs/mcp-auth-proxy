# Conformance

This document records what the proxy implements, what is intentionally
not implemented, and what is covered by automated tests.

## Implemented profile

The project targets the MCP Authorization 2025-06-18 profile, which
pins OAuth 2.1 draft-13 behavior for the MCP flow. Later OAuth 2.1
drafts are not claimed as the active profile until this document and
the implementation are updated together.

| Spec | Implemented behavior | Evidence |
|---|---|---|
| OAuth 2.1 draft-13 | Authorization code grant, public clients, PKCE-first behavior, refresh token rotation with Redis-backed reuse detection | `handlers/authorize.go`, `handlers/token.go`, `e2e_test.go` |
| RFC 8414 | Authorization server metadata at `/.well-known/oauth-authorization-server` and per-mount compatibility path | `handlers/discovery.go`, `discovery_routes_test.go` |
| RFC 9728 | Protected resource metadata and `WWW-Authenticate` `resource_metadata` challenge | `handlers/resource_metadata.go`, `middleware/auth.go` |
| RFC 7591 | Dynamic client registration with public-client-only `token_endpoint_auth_method=none` | `handlers/register.go`, `handlers/handlers_test.go` |
| RFC 7636 | S256 PKCE, verifier/challenge length and charset validation | `handlers/authorize.go`, `handlers/token.go` |
| RFC 8707 | `resource` validation on `/authorize` and `/token`; resource binding sealed into issued tokens | `handlers/authorize.go`, `handlers/token.go`, `middleware/auth.go` |
| OIDC Core | Upstream OIDC discovery, authorization-code exchange, ID token verification, nonce validation, `email_verified` enforcement when present | `main.go`, `handlers/callback.go` |

## Intentional compatibility behavior

| Area | Behavior | Reason |
|---|---|---|
| Root protected-resource metadata | The root PRM advertises `{PROXY_BASE_URL}/` with a trailing slash | Claude.ai compatibility for RFC 8707 resource matching |
| Per-resource metadata | The path-scoped PRM advertises `{PROXY_BASE_URL}<mount>` exactly | Strict RFC 9728 clients can fetch the path-specific document |
| Per-resource AS metadata path | `/.well-known/oauth-authorization-server<mount>` returns the same AS document as the root path | Some MCP clients probe the per-resource suffix even though RFC 8414 uses the issuer path |
| Scope model | `scopes_supported` is an empty array and scopes are not parsed or enforced | The proxy delegates identity to OIDC and enforces groups, not OAuth scopes |
| Public clients only | Dynamic registration accepts `token_endpoint_auth_method=none`; `/token` rejects Authorization headers | MCP clients are public clients in this deployment model |
| Compatibility flags | `PKCE_REQUIRED=false`, `COMPAT_ALLOW_STATELESS=true`, `REDIS_REQUIRED=false`, and legacy proxy-header trust exist | Dev and legacy-client support; `PROD_MODE=true` rejects unsafe production combinations |

## Not implemented

- Client-secret authentication at `/token`.
- OAuth scope authorization or consent by scope.
- Multi-resource authorization beyond the single configured MCP mount.
- Token introspection or revocation endpoints.
- Userinfo proxying.
- OIDC back-channel logout.

## Automated evidence

The regular test suite covers:

- sealed payload purpose separation,
- audience and resource binding,
- dynamic registration validation,
- PKCE validation,
- authorization-code and refresh-token replay behavior,
- OIDC callback nonce and claim enforcement,
- protected MCP proxy header sanitization,
- Redis replay-store behavior,
- end-to-end mock OIDC flow.

Current CI runs `go vet`, `go test -race`, coverage reporting,
`golangci-lint`, fuzz smoke tests for token parsing, and
`govulncheck`.

## Interoperability status

| IdP | Status | Notes |
|---|---|---|
| Mock OIDC provider | Automated | In-process e2e test exercises the full flow |
| Keycloak | Automated | CI starts the Docker Compose demo stack and runs the tagged real-IdP e2e test |
| Entra ID | Manual | Validated against a real tenant on 2026-04-27 |
