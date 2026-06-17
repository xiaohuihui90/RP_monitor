#!/usr/bin/env bash
set -u

PROJECT_DIR="${PROJECT_DIR:-$HOME/s3_stage3_v3_code}"
INTERVAL_SEC="${INTERVAL_SEC:-60}"
OUT_ROOT="${OUT_ROOT:-$PROJECT_DIR/data/p3_collector/m245_three_layer_baseline/mapping_context_runs}"
LOG_DIR="${LOG_DIR:-$HOME/s3_runtime}"

mkdir -p "$OUT_ROOT" "$LOG_DIR"

cd "$PROJECT_DIR" || exit 1

export PYTHONNOUSERSITE=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$PROJECT_DIR:${PYTHONPATH:-}"

echo "[START] m245 mapping context backfill loop"
echo "PROJECT_DIR=$PROJECT_DIR"
echo "INTERVAL_SEC=$INTERVAL_SEC"
echo "OUT_ROOT=$OUT_ROOT"

while true; do
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  RUN_DIR="$OUT_ROOT/h3b_mapping_context_backfill_$TS"
  mkdir -p "$RUN_DIR"

  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] mapping backfill once: $RUN_DIR"

  python -m scripts.p3.m245.collector.layer_mapping_context_backfill_once \
    --project-dir "$PROJECT_DIR" \
    --out-dir "$RUN_DIR" \
    --limit 50 \
    --update-existing-summaries \
    > "$RUN_DIR/backfill.stdout" \
    2> "$RUN_DIR/backfill.stderr"

  RC=$?
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] mapping backfill rc=$RC"

  sleep "$INTERVAL_SEC"
done
