#!/usr/bin/env bash
# Deploy a component of the Aegis Project range.
# Usage:
#   ./scripts/deploy.sh core
#   ./scripts/deploy.sh scenarios/01-public-s3-bucket
set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <core | scenarios/NN-name>"
  exit 1
fi

# Resolve the terraform directory for the target.
if [[ "$TARGET" == "core" ]]; then
  DIR="infra/core"
else
  DIR="${TARGET%/}/infra"
fi

echo "==> Deploying $TARGET (terraform dir: $DIR)"
echo "==> SAFETY CHECK: make sure you are pointed at your SANDBOX account!"
aws sts get-caller-identity || { echo "AWS CLI not configured"; exit 1; }

cd "$DIR"
terraform init
terraform plan -out=tfplan
terraform apply tfplan
echo "==> Done. Remember to ./scripts/destroy.sh when finished."
