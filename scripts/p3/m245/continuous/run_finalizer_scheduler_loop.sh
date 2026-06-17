#!/usr/bin/env bash
set -u

PROJECT_DIR="${PROJECT_DIR:-$HOME/s3_stage3_v3_code}"
INTERVAL_SEC="${INTERVAL_SEC:-60}"
OUT_ROOT="${OUT_ROOT:-$PROJECT_DIR/data/p3_collector/m245_three_layer_baseline/scheduler_runs}"
LOG_DIR="${LOG_DIR:-$HOME/s3_runtime}"

mkdir -p "$OUT_ROOT" "$LOG_DIR"

cd "$PROJECT_DIR" || exit 1

export PYTHONNOUSERSITE=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$PROJECT_DIR:${PYTHONPATH:-}"

echo "[START] m245 finalizer scheduler loop"
echo "PROJECT_DIR=$PROJECT_DIR"
echo "INTERVAL_SEC=$INTERVAL_SEC"
echo "OUT_ROOT=$OUT_ROOT"

while true; do
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  RUN_DIR="$OUT_ROOT/g3c_scheduler_loop_$TS"
  mkdir -p "$RUN_DIR"

  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] scheduler once: $RUN_DIR"

  python -m scripts.p3.m245.continuous.window_finalizer_scheduler \
    --project-dir "$PROJECT_DIR" \
    --out-dir "$RUN_DIR" \
    --once \
    > "$RUN_DIR/scheduler.stdout" \
    2> "$RUN_DIR/scheduler.stderr"

  RC=$?
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] scheduler rc=$RC"

  sleep "$INTERVAL_SEC"
done
