#!/usr/bin/env bash
# Tear down Aegis Project resources. ALWAYS run this when you finish a session.
# Usage: ./scripts/destroy.sh [core | scenarios/NN-name]
# With no argument it destroys all scenarios then core.
set -euo pipefail

destroy_dir() {
  local dir="$1"
  if [[ -d "$dir" && -f "$dir/main.tf" ]] || ls "$dir"/*.tf >/dev/null 2>&1; then
    echo "==> Destroying $dir"
    ( cd "$dir" && terraform destroy -auto-approve ) || true
  fi
}

if [[ -n "${1:-}" ]]; then
  if [[ "$1" == "core" ]]; then destroy_dir "infra/core"; else destroy_dir "${1%/}/infra"; fi
else
  for s in scenarios/*/infra; do destroy_dir "$s"; done
  destroy_dir "infra/core"
fi
echo "==> Teardown complete. Verify in the AWS console that nothing is left running."
