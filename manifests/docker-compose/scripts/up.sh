#!/usr/bin/env bash
# Start the mcp-auth-proxy demo stack.
#
# Steps:
#   1. Verify prerequisites (/etc/hosts entry, .env file)
#   2. docker compose up -d --build
#   3. Poll http://localhost:8080/healthz until the proxy is ready
#   4. Print next steps
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
COMPOSE_DIR="$(dirname "$SCRIPT_DIR")"
readonly COMPOSE_DIR
readonly COMPOSE_FILE="$COMPOSE_DIR/compose.yaml"
readonly ENV_FILE="$COMPOSE_DIR/.env"

# ---------------------------------------------------------------------------
# 1. Prerequisites
# ---------------------------------------------------------------------------

# /etc/hosts: the proxy redirects the browser to http://keycloak:8080/...
# during the OAuth flow. Without this entry the browser cannot resolve the
# keycloak hostname.
if ! grep -qE '^[[:space:]]*127\.0\.0\.1[[:space:]]+keycloak' /etc/hosts 2>/dev/null; then
  echo ""
  echo "WARNING: 'keycloak' is not mapped to 127.0.0.1 in /etc/hosts."
  echo "The OAuth browser redirect will fail without it."
  echo ""
  echo "Run this once to add the entry (requires sudo):"
  echo "  echo '127.0.0.1 keycloak' | sudo tee -a /etc/hosts"
  echo ""
  read -r -p "Add it automatically now? [y/N] " answer
  if [[ "${answer,,}" == "y" ]]; then
    echo '127.0.0.1 keycloak' | sudo tee -a /etc/hosts
    echo "Added."
  else
    echo "Continuing without the entry — browser-based OAuth will not work."
  fi
fi

# .env must exist
if [[ ! -f "$ENV_FILE" ]]; then
  echo ""
  echo "ERROR: $ENV_FILE not found."
  echo "Run:  bash scripts/generate-secrets.sh"
  exit 1
fi

# Warn if TOKEN_SIGNING_SECRET is empty
if grep -qE '^TOKEN_SIGNING_SECRET=$' "$ENV_FILE"; then
  echo ""
  echo "ERROR: TOKEN_SIGNING_SECRET is empty in $ENV_FILE."
  echo "Run:  bash scripts/generate-secrets.sh"
  exit 1
fi

# ---------------------------------------------------------------------------
# 2. Start the stack
# ---------------------------------------------------------------------------

echo ""
echo "==> Building and starting the demo stack..."
docker compose -f "$COMPOSE_FILE" up -d --build

# ---------------------------------------------------------------------------
# 3. Wait for the proxy to be ready
# ---------------------------------------------------------------------------

PROXY_HEALTHZ="http://localhost:8080/healthz"
MAX_WAIT=120
WAITED=0
INTERVAL=3

echo ""
echo "==> Waiting for mcp-auth-proxy to be ready (max ${MAX_WAIT}s)..."
until curl -fs "$PROXY_HEALTHZ" > /dev/null 2>&1; do
  if [[ $WAITED -ge $MAX_WAIT ]]; then
    echo ""
    echo "ERROR: Proxy did not become healthy within ${MAX_WAIT}s."
    echo "Check logs:  docker compose -f $COMPOSE_FILE logs mcp-auth-proxy"
    exit 1
  fi
  printf '.'
  sleep "$INTERVAL"
  WAITED=$(( WAITED + INTERVAL ))
done
echo ""
echo "==> Proxy is ready (${WAITED}s)."

# ---------------------------------------------------------------------------
# 4. Next steps
# ---------------------------------------------------------------------------

cat <<'EOF'

============================================================
  mcp-auth-proxy demo is running
============================================================

  Proxy (MCP + OAuth):  http://localhost:8080
  Keycloak admin:       http://localhost:8180  (admin / admin)
  MCP server (direct):  http://localhost:3000/mcp
  Metrics:              http://localhost:9090/metrics

  Discovery endpoints:
    http://localhost:8080/.well-known/oauth-protected-resource
    http://localhost:8080/.well-known/oauth-authorization-server

  Test credentials:  alice / changeme   (DEMO ONLY)

  To run the smoke test:
    bash scripts/smoke-test.sh

  Add to Claude.ai (Settings → Integrations → Add custom integration):
    MCP server URL: http://localhost:8080

  Teardown:
    bash scripts/down.sh

============================================================
EOF
