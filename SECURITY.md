# Security Policy

`mcp-auth-proxy` sits on the authorization path between MCP clients
and a private MCP server. Vulnerabilities here can let an attacker
mint tokens, impersonate users, exfiltrate identity material, or
deny service. We take reports seriously and want to make it as easy
as possible to disclose responsibly.

## Reporting a vulnerability

**Please do not open public GitHub issues for security problems.**

Report privately via **GitHub Security Advisory**:
<https://github.com/babs/mcp-auth-proxy/security/advisories/new>

This opens a confidential thread with the maintainers and gives us
a place to coordinate the fix, CVE assignment, and the eventual
public advisory.

We acknowledge new reports within **3 business days**. If you do not
hear back within that window, please post a brief, *non-sensitive*
nudge on the advisory thread — GitHub notification settings
occasionally lose the initial ping.

### What to include

A useful report typically contains:

- Affected version or commit hash (`git rev-parse HEAD` from your
  local checkout, or the image digest if you deployed a release).
- Reproduction steps or a minimal proof-of-concept. Curl commands
  are ideal; screenshots are acceptable.
- The configuration that triggers the issue — env vars, IdP type,
  whether Redis is enabled, `PROD_MODE`, `RENDER_CONSENT_PAGE`,
  `PKCE_REQUIRED`, `TRUSTED_PROXY_CIDRS`, etc.
- Expected vs. observed behavior, and the security impact you
  believe this enables (e.g. token theft, account takeover, SSRF,
  bypass of `ALLOWED_GROUPS`).
- Any relevant log snippets (redact bearer tokens, authorization
  codes, refresh tokens, and `id_token` values before sending).

If you are not sure whether something is a vulnerability, send the
report anyway — we would rather triage a non-issue than miss a real
one.

## Supported versions

Security fixes are issued against the latest released minor version
on `master`. Older versions do not receive backports.

| Version | Supported |
|---------|-----------|
| `v1.x` (latest minor)  | ✅ |
| `< v1.0` (pre-release) | ❌ |

The container images at
`ghcr.io/babs/mcp-auth-proxy` follow the same support window. When a
security fix lands, we publish a new patch tag (`v1.x.y`) and update
the `:v1` floating tag.

## Coordinated disclosure timeline

Our default disclosure model is a **90-day** window from the date we
acknowledge the report:

- **Day 0** — report received, acknowledgement sent.
- **Day 0–7** — triage, severity scoring (CVSS v3.1), reproduction.
- **Day 7–60** — fix developed in a private branch or security
  advisory fork; reviewed; tests added under `handlers/*_test.go`,
  `replay/*_test.go`, or a new e2e case.
- **Day 60–90** — coordinated release: patch tag, image rebuild,
  public advisory, credit, optional CVE.

We are willing to extend the window if a fix requires upstream
changes (Go stdlib, IdP, Redis client) or if you ask us to hold for
your own coordinated rollout.

If the issue is already being actively exploited in the wild, we
will accelerate the timeline and may publish the fix and advisory
together.

## Scope

In scope — anything that can be reached by traffic going through the
proxy:

- OAuth 2.1 endpoints: `/authorize`, `/token`, `/register`,
  `/consent`, `/callback`.
- Discovery: `/.well-known/oauth-authorization-server`,
  `/.well-known/oauth-protected-resource[/<mount>]`.
- The MCP pass-through path: `/mcp` (and any configured mount).
- Token sealing / verification in the `token/` package.
- Replay / single-use enforcement in the `replay/` package.
- Authorization middleware in `middleware/auth.go`.
- Configuration validation in `config/config.go`, especially flags
  that can weaken a control when set (`PROD_MODE`,
  `TRUSTED_PROXY_CIDRS`, `PKCE_REQUIRED`, `RENDER_CONSENT_PAGE`,
  `REDIS_REQUIRED`).
- Container image hygiene (`Dockerfile`), supply chain (`go.sum`).
- Metrics endpoint information disclosure (`/metrics`).

The [threat model](docs/threat-model.md) lists the specific threats
we already mitigate and which code, tests, and runbooks back them.

Out of scope — documented, accepted residual risk (see the
"Out of scope" section in `docs/threat-model.md` for the full
discussion):

- **IdP compromise.** If the configured OIDC IdP is compromised, the
  proxy trusts what the IdP says. Bug reports about Keycloak, Entra,
  Auth0, Okta, etc. belong with those vendors.
- **Backend MCP server vulnerabilities.** The proxy forwards
  authenticated traffic; it does not sanitize JSON-RPC payloads to
  the upstream MCP server beyond what is required for transport.
- **Browser-engine bugs.** The consent page is JS-free and
  CSP-locked (`default-src 'none'`); we do not separately defend
  against escapes of the browser's contextual HTML escaping.
- **Denial of service via raw network capacity.** Per-IP rate limits
  protect specific endpoints; absorbing volumetric L3/L4 floods is
  the deployment operator's responsibility (CDN, WAF, k8s ingress).
- **Misconfiguration where the operator explicitly opted out** of a
  control (e.g. `RENDER_CONSENT_PAGE=false`, `PKCE_REQUIRED=false`,
  `REDIS_REQUIRED=false`). These flags exist for compatibility; the
  associated weakening is intentional. We will still accept reports
  about additional weaknesses they expose beyond the documented
  trade-off.
- **Social engineering and physical attacks** against operators,
  maintainers, or end users.

If you are unsure whether a finding is in scope, send it anyway — we
will tell you, and we will treat the conversation as confidential.

## Safe harbor

We will not pursue or support legal action against researchers who:

- Make a good-faith effort to comply with this policy.
- Avoid privacy violations, destruction of data, or interruption of
  service for users other than themselves.
- Do not exploit a discovered vulnerability beyond the minimum
  necessary to demonstrate impact.
- Give us reasonable time to fix the issue before public disclosure.
- Do not extort, threaten, or attempt to monetize the finding
  outside of the recognition described below.

Testing against your own deployment of the proxy is always allowed.
Testing against deployments you do not control requires the
operator's permission — the demo stack at `docker-compose.yml` and
the Keycloak fixtures are explicitly available for this purpose.

## Recognition

We are happy to credit reporters in:

- The public GitHub Security Advisory.
- The CHANGELOG entry for the fix release.
- An optional "Security acknowledgements" section in the README,
  added when the first credited report ships.

If you prefer to stay anonymous, we will honor that.

There is no monetary bounty program at this time.

## Cryptographic verification (optional)

The container images at `ghcr.io/babs/mcp-auth-proxy` are built by
GitHub Actions; the build is reproducible from the tagged commit
(`docs/release-checklist.md` documents the procedure). If you need
to verify a binary against the source, build from the same tag with
the same Go toolchain and compare hashes.

We do not currently sign releases with a long-lived PGP key. The
GitHub Security Advisory channel is already an encrypted,
authenticated transport — please use it for sensitive material
rather than email.

## Companion documents

- [`docs/threat-model.md`](docs/threat-model.md) — STRIDE coverage
  matrix mapping threats to code, tests, and runbooks. The
  authoritative list of what we already defend against.
- [`docs/conformance.md`](docs/conformance.md) — RFCs the proxy
  claims to implement, with code and test evidence. Useful when
  scoping whether a report is a spec deviation or a vulnerability.
- [`docs/configuration.md`](docs/configuration.md) — every
  configuration flag, its default, and the security trade-off if
  changed.
- [`docs/runbooks/`](docs/runbooks/) — operational responses to
  security-relevant incidents (Redis outage, IdP outage, key
  rotation, consent-denial spikes, bulk revocation).
