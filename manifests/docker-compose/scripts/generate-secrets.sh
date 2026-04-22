#!/usr/bin/env bash
# Idempotent .env generator for the Docker Compose demo.
#
# - Copies .env.example → .env (does NOT overwrite an existing .env).
# - Substitutes TOKEN_SIGNING_SECRET with a fresh random value.
# - Leaves all other REPLACE_ME_* / blank values for the operator to fill.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
COMPOSE_DIR="$(dirname "$SCRIPT_DIR")"
readonly COMPOSE_DIR
readonly HELPER="$COMPOSE_DIR/../scripts/generate-signing-secret.sh"
readonly ENV_FILE="$COMPOSE_DIR/.env"
readonly EXAMPLE_FILE="$COMPOSE_DIR/.env.example"

if [[ -f "$ENV_FILE" ]]; then
  echo ".env already exists — skipping to avoid overwrite."
  echo "Delete $ENV_FILE and re-run to regenerate."
  exit 0
fi

if [[ ! -f "$EXAMPLE_FILE" ]]; then
  echo "ERROR: .env.example not found at $EXAMPLE_FILE" >&2
  exit 1
fi

# Generate a 64-char URL-safe base64 signing secret.
TOKEN_SECRET="$("$HELPER")"

# Write .env with the generated secret, preserving all other lines verbatim.
while IFS= read -r line; do
  if [[ "$line" == TOKEN_SIGNING_SECRET=* ]]; then
    printf 'TOKEN_SIGNING_SECRET=%s\n' "$TOKEN_SECRET"
  else
    printf '%s\n' "$line"
  fi
done < "$EXAMPLE_FILE" > "$ENV_FILE"

echo "Generated $ENV_FILE with a fresh TOKEN_SIGNING_SECRET."
echo ""
echo "Review the file and fill in any remaining blank or REPLACE_ME_* values"
echo "before running:  bash up.sh"
