#!/usr/bin/env bash
set -euo pipefail
CONFIG_PATH="${1:-config/probe_cd.yaml}"
PORT=$(python -c 'import sys, yaml; print(yaml.safe_load(open(sys.argv[1], encoding="utf-8"))["listen_port"])' "$CONFIG_PATH")
export S3_PROBE_CONFIG="$CONFIG_PATH"
uvicorn probe.app:app --host 0.0.0.0 --port "$PORT"
