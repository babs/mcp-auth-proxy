#!/usr/bin/env bash
# Stop and remove all containers, networks, and volumes for the demo stack.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
COMPOSE_DIR="$(dirname "$SCRIPT_DIR")"
readonly COMPOSE_DIR
readonly COMPOSE_FILE="$COMPOSE_DIR/compose.yaml"

echo "==> Stopping and removing the demo stack (volumes included)..."
docker compose -f "$COMPOSE_FILE" down -v
echo "Done."
