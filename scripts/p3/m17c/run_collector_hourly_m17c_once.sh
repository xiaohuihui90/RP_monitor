#!/usr/bin/env bash
set -euo pipefail

cd ~/s3_stage3_v3_code
# --- Shared conda init for cron / non-interactive shell ---
source scripts/p3/m17c/conda_bootstrap.sh
# --- End shared conda init ---
export PYTHONNOUSERSITE=1
export PYTHONPATH="$PWD:${PYTHONPATH:-}"

source ~/.s3_m245_ingest.env

TARGET_STAMP="$(date -u +%Y%m%dT%H0000Z)"
TARGET_WINDOW_ID="win_${TARGET_STAMP}_10m"
RUN_ID="m17c_2h_${TARGET_WINDOW_ID}_$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p ~/s3_runtime

echo "===== COLLECTOR 2H M17C START ====="
echo "created_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "TARGET_WINDOW_ID=$TARGET_WINDOW_ID"
echo "RUN_ID=$RUN_ID"
echo "TOKEN_LENGTH=${#TOKEN}"
echo "M245_INGEST_TOKEN_LENGTH=${#M245_INGEST_TOKEN}"

scripts/p3/m17c/run_m17c_hourly_incremental_once.sh \
  --target-window-id "$TARGET_WINDOW_ID" \
  --run-id "$RUN_ID"

echo "===== COLLECTOR 2H M17C DONE ====="
echo "finished_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
