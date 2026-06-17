#!/usr/bin/env bash
set -u

PROJECT_DIR="${PROJECT_DIR:-$HOME/s3_stage3_v3_code}"
PROBE_ID="${PROBE_ID:?PROBE_ID is required, e.g. probe-cd/probe-bj/probe-sg}"
INTERVAL_SEC="${INTERVAL_SEC:-7200}"
TIMEOUT_SEC="${TIMEOUT_SEC:-2400}"
LOW_THRESHOLD="${LOW_THRESHOLD:-500000}"
OUT_ROOT="${OUT_ROOT:-$PROJECT_DIR/data/probe/m245_three_layer_baseline/validator_refresh_runs}"
LOG_DIR="${LOG_DIR:-$HOME/s3_runtime}"
LOCK_FILE="${LOCK_FILE:-/tmp/m245_validator_refresh_${PROBE_ID}.lock}"

mkdir -p "$OUT_ROOT" "$LOG_DIR"

cd "$PROJECT_DIR" || exit 1

export PYTHONNOUSERSITE=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$PROJECT_DIR:${PYTHONPATH:-}"

echo "[START] m245 validator refresh loop"
echo "PROJECT_DIR=$PROJECT_DIR"
echo "PROBE_ID=$PROBE_ID"
echo "INTERVAL_SEC=$INTERVAL_SEC"
echo "OUT_ROOT=$OUT_ROOT"
echo "LOCK_FILE=$LOCK_FILE"

while true; do
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  RUN_DIR="$OUT_ROOT/validator_refresh_${PROBE_ID}_${TS}"
  mkdir -p "$RUN_DIR"

  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] refresh start: $RUN_DIR"

  (
    flock -n 9 || {
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] skip: refresh lock busy"
      exit 0
    }

    python -m scripts.p3.m245.continuous.validator_refresh_runner \
      --project-dir "$PROJECT_DIR" \
      --probe-id "$PROBE_ID" \
      --refresh-mode "scheduled_refresh" \
      --out-dir "$RUN_DIR" \
      --timeout-sec "$TIMEOUT_SEC" \
      --vrp-count-low-threshold "$LOW_THRESHOLD" \
      > "$RUN_DIR/validator_refresh.stdout" \
      2> "$RUN_DIR/validator_refresh.stderr"
  ) 9>"$LOCK_FILE"

  RC=$?
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] refresh rc=$RC"

  sleep "$INTERVAL_SEC"
done
