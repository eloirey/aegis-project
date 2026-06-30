#!/usr/bin/env bash
# One-time local setup.
set -euo pipefail

python -m venv .venv
# Windows venvs expose activate under Scripts/, not bin/ (Git Bash on Windows).
# shellcheck disable=SC1091
source .venv/Scripts/activate
pip install --upgrade pip
pip install -r requirements.txt

echo "==> Done. Activate with: source .venv/Scripts/activate"
echo "==> Next: configure AWS CLI for your SANDBOX account and set a Budget alert."
