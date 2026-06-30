#!/usr/bin/env bash
# Tear down Aegis Project resources. ALWAYS run this when you finish a session.
# Usage: ./scripts/destroy.sh [core | NN-scenario-name]
# With no argument it destroys all scenarios then core.
set -euo pipefail

destroy_dir() {
  local dir="$1"
  if ls "$dir"/*.tf >/dev/null 2>&1; then
    echo "==> Destroying $dir"
    ( cd "$dir" && terraform destroy -auto-approve ) || true
  fi
}

destroy_scenario() {
  # Reverse of deploy: remediation subscribes to detection's topic via a data
  # source, so it must go first; infra goes last.
  local scen="$1"
  for layer in remediation detection infra; do
    destroy_dir "scenarios/${scen}/${layer}"
  done
}

if [[ -n "${1:-}" ]]; then
  if [[ "$1" == "core" ]]; then
    destroy_dir "infra/core"
  else
    destroy_scenario "$1"
  fi
else
  for path in scenarios/*/; do
    destroy_scenario "$(basename "$path")"
  done
  destroy_dir "infra/core"
fi

echo "==> Teardown complete. Verify in the AWS console that nothing is left running."
