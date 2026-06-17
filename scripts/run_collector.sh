#!/usr/bin/env bash
set -euo pipefail
CONFIG_PATH="${1:-config/collector.yaml}"
export S3_COLLECTOR_CONFIG="$CONFIG_PATH"
uvicorn collector.app:app --host 0.0.0.0 --port 28081
