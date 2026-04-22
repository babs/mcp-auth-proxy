#!/usr/bin/env bash
# Emit a cryptographically-random 64-character base64 secret to stdout.
# Used by docker-compose/scripts/generate-secrets.sh and anywhere a fresh
# TOKEN_SIGNING_SECRET is needed.
set -euo pipefail

openssl rand -base64 48 | tr -d '\n=' | head -c 64
printf '\n'
