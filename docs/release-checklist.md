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

Exercise the error page against a running instance — a page that stops
rendering is invisible to the checks above. The status is printed too:
without it, an ingress or WAF serving its own HTML error page is
indistinguishable from a working proxy:

```bash
BASE=https://mcp.example.com   # the running instance under test

# error page: expect "400 text/html; charset=utf-8"
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' -H 'Accept: text/html' "$BASE/callback?state=bogus"
# machine contract: a */* caller (curl's default) must stay JSON — expect "400 application/json"
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' "$BASE/callback?state=bogus"
# and so must a caller sending no Accept header at all — expect "400 application/json"
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' -H 'Accept:' "$BASE/callback?state=bogus"
# /token must stay JSON even when asked for HTML — expect "400 application/json"
curl -sS -o /dev/null -w '%{http_code} %{content_type}\n' -X POST -H 'Accept: text/html' "$BASE/token"
```

`-S` so a bad `$BASE` fails loudly instead of printing an empty line. No
`-f`: the endpoints answer 400 by design, and `-f` would turn every one
of these into a curl exit 22.

Status and `Content-Type` do not prove the page is *styled*: a wrong
`style-src` sha256 renders a page every browser strips the CSS from,
which on the consent page is the Approve/Deny distinction. CI pins the
hash against the rendered bytes (`TestPageCSPHashMatchesRenderedStyle`),
so this is a spot-check rather than the gate:

```bash
curl -sS -D- -o /dev/null -H 'Accept: text/html' "$BASE/callback?state=bogus" | grep -i content-security-policy
```

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
