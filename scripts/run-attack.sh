#!/usr/bin/env bash
# Launch a scenario's attack script.
# Usage: ./scripts/run-attack.sh 01-public-s3-bucket
set -euo pipefail
SCEN="${1:-}"
[[ -z "$SCEN" ]] && { echo "Usage: $0 <NN-scenario-name>"; exit 1; }
ATTACK_DIR="scenarios/${SCEN}/attack"
echo "==> Running attack for $SCEN"
# Each attack script defines its own args; pass the bucket/target as needed.
python "${ATTACK_DIR}"/*.py "${@:2}"
