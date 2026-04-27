#!/usr/bin/env bash
set -euo pipefail
ENV_NAME="${1:-s3-radar}"
if ! command -v conda >/dev/null 2>&1; then
  echo "conda not found" >&2
  exit 1
fi
source "$(conda info --base)/etc/profile.d/conda.sh"
if ! conda env list | awk '{print $1}' | grep -qx "$ENV_NAME"; then
  conda create -y -n "$ENV_NAME" python=3.11
fi
conda activate "$ENV_NAME"
pip install -r requirements.txt
