#!/usr/bin/env bash
# Launch a scenario's attack with targets resolved from its Terraform outputs.
# Usage: ./scripts/run-attack.sh 03-exposed-ssh
set -euo pipefail

SCEN="${1:-}"
[[ -z "$SCEN" ]] && { echo "Usage: $0 <NN-scenario-name>"; exit 1; }

INFRA="scenarios/${SCEN}/infra"
PY=$(ls "scenarios/${SCEN}/attack"/*.py | head -n1)
tf_out() { terraform -chdir="$INFRA" output -raw "$1"; }

echo "==> Running attack for $SCEN"

case "$SCEN" in
  01-*)
    # Detection triggers on PutBucketPolicy, so re-apply a public policy with the
    # pipeline already live, then run the anonymous-read demo.
    bucket=$(tf_out bucket_name)
    tmp=$(mktemp)
    printf '{"Version":"2012-10-17","Statement":[{"Sid":"PublicRead","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}]}' "$bucket" > "$tmp"
    aws s3api put-bucket-policy --bucket "$bucket" --policy "file://$tmp" --region eu-west-1
    rm -f "$tmp"
    python "$PY" --bucket "$bucket"
    ;;
  02-*)
    python "$PY" \
      --access-key-id "$(tf_out lowpriv_access_key_id)" \
      --secret-access-key "$(tf_out lowpriv_secret_access_key)"
    ;;
  03-*)
    python "$PY" \
      --security-group-id "$(tf_out security_group_id)" \
      --public-ip "$(tf_out instance_public_ip)"
    ;;
  *)
    echo "Unknown scenario: $SCEN"; exit 1
    ;;
esac