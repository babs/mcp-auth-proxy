#!/usr/bin/env bash
# Smoke-test the two OAuth discovery endpoints exposed by the proxy.
#
# Checks:
#   1. GET /.well-known/oauth-protected-resource → 200 JSON
#   2. GET /.well-known/oauth-authorization-server → 200 JSON
#
# Exits non-zero with a descriptive message on any failure.
# Does NOT attempt the full browser OAuth flow (requires user interaction).
set -euo pipefail

readonly BASE="${PROXY_BASE_URL:-http://localhost:8080}"
BODY_FILE="$(mktemp)"
readonly BODY_FILE
trap 'rm -f "$BODY_FILE"' EXIT

PASS=0
FAIL=0

check() {
  local label="$1"
  local url="$2"
  local expected_key="$3"
  local http_code

  echo -n "  Checking $label ... "

  http_code="$(curl -s -o "$BODY_FILE" -w '%{http_code}' "$url")"

  if [[ "$http_code" != "200" ]]; then
    echo "FAIL (HTTP $http_code)"
    echo "    URL: $url"
    echo "    Body: $(cat "$BODY_FILE" 2>/dev/null || echo '<empty>')"
    FAIL=$(( FAIL + 1 ))
    return
  fi

  if ! grep -q "\"$expected_key\"" "$BODY_FILE" 2>/dev/null; then
    echo "FAIL (200 but missing key '$expected_key' in response)"
    echo "    URL: $url"
    echo "    Body: $(cat "$BODY_FILE")"
    FAIL=$(( FAIL + 1 ))
    return
  fi

  echo "OK (HTTP 200, key '$expected_key' present)"
  PASS=$(( PASS + 1 ))
}

echo ""
echo "=== mcp-auth-proxy smoke test (base: $BASE) ==="
echo ""

check "Protected Resource Metadata (RFC 9728)" \
  "$BASE/.well-known/oauth-protected-resource" \
  "authorization_servers"

check "Authorization Server Metadata (RFC 8414)" \
  "$BASE/.well-known/oauth-authorization-server" \
  "authorization_endpoint"

echo ""
echo "Results: $PASS passed, $FAIL failed"

if [[ $FAIL -gt 0 ]]; then
  echo ""
  echo "ERROR: $FAIL check(s) failed. Is the proxy running?"
  echo "  docker compose -f manifests/docker-compose/compose.yaml logs mcp-auth-proxy"
  exit 1
fi

echo ""
echo "Smoke test passed. Next step: run"
echo "  go test -tags=keycloak_e2e -run TestKeycloakE2EFullOAuthFlow -count=1 ."
echo "or use Claude.ai / Claude Code against http://localhost:8080"
