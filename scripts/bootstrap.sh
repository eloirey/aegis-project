#!/usr/bin/env bash
# One-time local setup.
set -euo pipefail
python -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "==> Done. Activate with: source .venv/bin/activate"
echo "==> Next: configure AWS CLI for your SANDBOX account and set a Budget alert."
