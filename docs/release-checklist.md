# Release checklist

Use this checklist before publishing a tag and after the image is
available in GHCR.

## Before tagging

Run locally from a clean worktree:

```bash
go test ./...
go test -race -count=1 ./...
go vet ./...
golangci-lint run
govulncheck ./...
kubectl kustomize manifests/overlays/production
```

Check the rendered production overlay:

- image is pinned and does not use `:latest`,
- `PROD_MODE=true`,
- `REDIS_REQUIRED=true`,
- `PKCE_REQUIRED=true`,
- `RENDER_CONSENT_PAGE=true` (default; explicit in the overlay so a prior `=false` override is loud at release time),
- metrics port is reachable only through NetworkPolicy,
- Redis egress points at the intended managed/operator Redis endpoint,
- pod security context remains nonroot with dropped capabilities.

## Tagging

Use a semver tag with a leading `v`:

```bash
git tag v1.2.3
git push origin v1.2.3
```

The release workflow publishes image tags without the leading `v`
(`ghcr.io/babs/mcp-auth-proxy:1.2.3`).

## After publish

Verify the published image signature:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/babs/mcp-auth-proxy/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/babs/mcp-auth-proxy:1.2.3
```

Inspect provenance and SBOM:

```bash
docker buildx imagetools inspect ghcr.io/babs/mcp-auth-proxy:1.2.3 \
  --format '{{json .Provenance}}' | jq

docker buildx imagetools inspect ghcr.io/babs/mcp-auth-proxy:1.2.3 \
  --format '{{json .SBOM}}' | jq
```

Record any manually run IdP compatibility checks in
`docs/conformance.md`.
