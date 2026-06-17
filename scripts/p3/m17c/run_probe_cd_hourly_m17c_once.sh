#!/usr/bin/env bash
set -euo pipefail

cd ~/s3_stage3_v3_code
# --- Shared conda init for cron / non-interactive shell ---
source scripts/p3/m17c/conda_bootstrap.sh
# --- End shared conda init ---
export PYTHONNOUSERSITE=1
export PYTHONPATH="$PWD:${PYTHONPATH:-}"

source ~/.s3_m245_ingest.env

export PROBE_ID="probe-cd"
export COLLECTOR_URL="http://47.108.137.128:28117/upload"
export RAW_SIDECAR_URL="http://47.108.137.128:28116/upload"

TARGET_STAMP="$(date -u +%Y%m%dT%H0000Z)"
export TARGET_WINDOW_ID="win_${TARGET_STAMP}_10m"

mkdir -p data/probe/m17c_hourly/logs

echo "===== PROBE-CD HOURLY M17C START ====="
echo "created_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "PROBE_ID=$PROBE_ID"
echo "TARGET_WINDOW_ID=$TARGET_WINDOW_ID"
echo "COLLECTOR_URL=$COLLECTOR_URL"
echo "RAW_SIDECAR_URL=$RAW_SIDECAR_URL"
echo "TOKEN_LENGTH=${#TOKEN}"
echo "M245_INGEST_TOKEN_LENGTH=${#M245_INGEST_TOKEN}"

bash scripts/p3/m17c/run_probe_m17c_once.sh

echo "===== PROBE-CD HOURLY M17C DONE ====="
echo "finished_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
