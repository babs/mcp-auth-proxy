#!/usr/bin/env bash
# Asserts the rendered production overlay matches the posture
# documented in manifests/overlays/production/README.md. Run on
# every PR that touches manifests/. Failure means the overlay
# drifted from the documented production defaults.
#
# Requires: kubectl (with embedded kustomize >= v5), yq (mikefarah).
set -euo pipefail

# Resolve the script's own directory through symlinks so the script
# remains invokable from anywhere (CI, operator shell, IDE task).
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
cd "$SCRIPT_DIR/../../.."

rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT

kubectl kustomize manifests/overlays/production >"$rendered"

fail=0

check() {
  # Two-step assignment: `local got=$(...)` masks command failures
  # under `set -e` because `local` itself returns 0. Splitting lets
  # a yq error propagate and fail the script loudly.
  local name="$1" expr="$2" want="$3"
  local got
  got="$(yq eval-all "$expr" "$rendered")"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $name — want=$want got=$got"
    fail=1
  else
    echo "ok:   $name"
  fi
}

# Image must carry an explicit version, never :latest. A floating tag
# in production breaks rollback determinism and SBOM correlation.
img=
img="$(yq eval-all 'select(.kind == "Deployment" and .metadata.name == "mcp-auth-proxy") | .spec.template.spec.containers[].image' "$rendered")"
if [[ -z "$img" ]]; then
  echo "FAIL: deployment image — empty"
  fail=1
elif [[ "$img" == *:latest ]]; then
  echo "FAIL: deployment image — pinned to :latest ($img)"
  fail=1
else
  echo "ok:   deployment image pinned ($img)"
fi

cm='select(.kind == "ConfigMap" and .metadata.name == "mcp-auth-proxy-config") | .data'

check "PROD_MODE=true"               "$cm.PROD_MODE"               'true'
check "RENDER_CONSENT_PAGE=true"     "$cm.RENDER_CONSENT_PAGE"     'true'
check "REDIS_REQUIRED=true"          "$cm.REDIS_REQUIRED"          'true'
check "PKCE_REQUIRED=true"           "$cm.PKCE_REQUIRED"           'true'
check "RATE_LIMIT_ENABLED=true"      "$cm.RATE_LIMIT_ENABLED"      'true'
check "COMPAT_ALLOW_STATELESS=false" "$cm.COMPAT_ALLOW_STATELESS"  'false'

redis_url=
redis_url="$(yq eval-all "$cm.REDIS_URL" "$rendered")"
if [[ -z "$redis_url" || "$redis_url" == "null" ]]; then
  echo "FAIL: REDIS_URL — unset"
  fail=1
else
  echo "ok:   REDIS_URL set ($redis_url)"
fi

# TRUSTED_PROXY_CIDRS is the load-bearing input for XFF spoof
# defense (PR #16). Empty means the proxy trusts no upstream hop,
# which silently breaks per-IP rate limiting behind any ingress.
trusted=
trusted="$(yq eval-all "$cm.TRUSTED_PROXY_CIDRS" "$rendered")"
if [[ -z "$trusted" || "$trusted" == "null" ]]; then
  echo "FAIL: TRUSTED_PROXY_CIDRS — unset"
  fail=1
else
  echo "ok:   TRUSTED_PROXY_CIDRS set ($trusted)"
fi

# Pod-level security context must enforce non-root + RuntimeDefault
# seccomp. Any container in the deployment running as root in prod
# is an automatic finding from CIS / PSS audits.
sec='select(.kind == "Deployment" and .metadata.name == "mcp-auth-proxy") | .spec.template.spec.securityContext'

check "runAsNonRoot=true"             "$sec.runAsNonRoot"          'true'
check "seccompProfile=RuntimeDefault" "$sec.seccompProfile.type"   'RuntimeDefault'

# HA assumption baked into the PodDisruptionBudget — single-replica
# deployments break PDB minAvailable=1 during voluntary disruptions.
replicas=
replicas="$(yq eval-all 'select(.kind == "Deployment" and .metadata.name == "mcp-auth-proxy") | .spec.replicas' "$rendered")"
if [[ -z "$replicas" || "$replicas" == "null" || "$replicas" -lt 2 ]]; then
  echo "FAIL: deployment replicas — want >=2, got=$replicas"
  fail=1
else
  echo "ok:   deployment replicas ($replicas)"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "production overlay check FAILED"
  exit 1
fi
echo "production overlay check OK"
