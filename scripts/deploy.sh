#!/usr/bin/env bash
# Deploy a component of the Aegis Project range.
# Usage:
#   ./scripts/deploy.sh core
#   ./scripts/deploy.sh 01-public-s3-bucket
set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <core | NN-scenario-name>"
  exit 1
fi

echo "==> SAFETY CHECK: make sure you are pointed at your SANDBOX account!"
aws sts get-caller-identity || { echo "AWS CLI not configured"; exit 1; }

apply_dir() {
  echo "==> Deploying $1"
  ( cd "$1" && terraform init -input=false && terraform apply -auto-approve )
}

if [[ "$TARGET" == "core" ]]; then
  apply_dir "infra/core"
else
  # A scenario is a full pipeline: the reactive layers depend on the infra, and
  # remediation subscribes to the topic detection creates, so order matters.
  for layer in infra detection remediation; do
    apply_dir "scenarios/${TARGET}/${layer}"
  done
fi

echo "==> Done. Remember to ./scripts/destroy.sh ${TARGET} when finished."