#!/usr/bin/env bash
set -eo pipefail

cd ~/s3_stage3_v3_code

source ~/.bashrc || true
conda activate s3-radar || true

export PYTHONNOUSERSITE=1
export PYTHONPATH="$PWD:${PYTHONPATH:-}"

PROBE_ID="${PROBE_ID:?PROBE_ID required}"
REFRESH_BEFORE_EXPORT="${REFRESH_BEFORE_EXPORT:-false}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-900}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-1800}"
MAX_ROUNDS="${MAX_ROUNDS:-20}"

M20_5_ROOT="$PWD/data/probe/m20_5_vrp_summary"
SESSION_TAG="${SESSION_TAG:-m20_5f_night_${PROBE_ID}_$(date -u +%Y%m%dT%H%M%SZ)}"
SESSION_DIR="$M20_5_ROOT/night_runs/$SESSION_TAG"

mkdir -p "$M20_5_ROOT"/{latest,records,exports,checks,logs}
mkdir -p "$SESSION_DIR"/{logs,checks,manifests}

END_EPOCH="$(python - <<'PY'
from datetime import datetime, timedelta
now = datetime.now()
target = now.replace(hour=9, minute=0, second=0, microsecond=0)
if now >= target:
    target += timedelta(days=1)
print(int(target.timestamp()))
PY
)"

START_EPOCH="$(date +%s)"

cat > "$SESSION_DIR/session_env.sh" <<EOF
export PROBE_ID="$PROBE_ID"
export REFRESH_BEFORE_EXPORT="$REFRESH_BEFORE_EXPORT"
export TIMEOUT_SECONDS="$TIMEOUT_SECONDS"
export INTERVAL_SECONDS="$INTERVAL_SECONDS"
export MAX_ROUNDS="$MAX_ROUNDS"
export SESSION_TAG="$SESSION_TAG"
export SESSION_DIR="$SESSION_DIR"
export END_EPOCH="$END_EPOCH"
EOF

echo "========== M20.5-F NIGHT LOOP START ==========" | tee -a "$SESSION_DIR/logs/session.log"
echo "probe_id=$PROBE_ID" | tee -a "$SESSION_DIR/logs/session.log"
echo "refresh_before_export=$REFRESH_BEFORE_EXPORT" | tee -a "$SESSION_DIR/logs/session.log"
echo "timeout_seconds=$TIMEOUT_SECONDS" | tee -a "$SESSION_DIR/logs/session.log"
echo "interval_seconds=$INTERVAL_SECONDS" | tee -a "$SESSION_DIR/logs/session.log"
echo "max_rounds=$MAX_ROUNDS" | tee -a "$SESSION_DIR/logs/session.log"
echo "session_dir=$SESSION_DIR" | tee -a "$SESSION_DIR/logs/session.log"
echo "end_local=$(date -d "@$END_EPOCH" '+%F %T %Z')" | tee -a "$SESSION_DIR/logs/session.log"
echo | tee -a "$SESSION_DIR/logs/session.log"

ROUND=1

while true; do
  NOW_EPOCH="$(date +%s)"

  if [ "$NOW_EPOCH" -ge "$END_EPOCH" ]; then
    echo "stop_reason=reached_end_time" | tee -a "$SESSION_DIR/logs/session.log"
    break
  fi

  if [ "$ROUND" -gt "$MAX_ROUNDS" ]; then
    echo "stop_reason=reached_max_rounds" | tee -a "$SESSION_DIR/logs/session.log"
    break
  fi

  ROUND_LABEL="$(printf 'round%02d' "$ROUND")"
  ROUND_STARTED_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  echo "========== $ROUND_LABEL START $ROUND_STARTED_UTC ==========" | tee -a "$SESSION_DIR/logs/session.log"

  CMD=(
    python scripts/p3/m20_5/cli/probe_collect_vrp_summary.py
    --probe-id "$PROBE_ID"
    --out-dir "$M20_5_ROOT"
    --validator-id routinator
    --routinator-bin routinator
    --status-url "http://127.0.0.1:8323/api/v1/status"
    --mode summary_only
    --timeout-seconds "$TIMEOUT_SECONDS"
  )

  if [ "$REFRESH_BEFORE_EXPORT" = "true" ]; then
    CMD+=(--refresh-before-export)
  fi

  set +e
  "${CMD[@]}" | tee "$SESSION_DIR/logs/${ROUND_LABEL}_${PROBE_ID}.log"
  CMD_STATUS="${PIPESTATUS[0]}"
  set -e

  ARCHIVE="$(ls -1t "$M20_5_ROOT/exports"/m20_5a_vrp_summary_${PROBE_ID}_*.tar.gz 2>/dev/null | head -n 1 || true)"
  SUMMARY="$M20_5_ROOT/latest/probe_vrp_summary.json"

  python - <<PY
import json
from pathlib import Path
from datetime import datetime, timezone

session_dir = Path("$SESSION_DIR")
summary_path = Path("$SUMMARY")
archive_path = Path("$ARCHIVE") if "$ARCHIVE" else None

row = {
    "schema": "s3.m20_5f.probe_loop_manifest.v1",
    "created_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "round_label": "$ROUND_LABEL",
    "probe_id": "$PROBE_ID",
    "cmd_status": int("$CMD_STATUS"),
    "summary_path": str(summary_path),
    "archive_path": str(archive_path) if archive_path else None,
}

if summary_path.exists():
    obj = json.loads(summary_path.read_text(encoding="utf-8"))
    for k in [
        "run_id",
        "export_status",
        "vrp_count",
        "vrp_digest",
        "last_update_done",
        "latency_ms",
        "refresh_before_export",
        "cli_export_policy",
        "warnings",
        "errors",
    ]:
        row[k] = obj.get(k)

with (session_dir / "manifests" / "probe_loop_manifest.jsonl").open("a", encoding="utf-8") as f:
    f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\\n")

print(json.dumps(row, ensure_ascii=False, indent=2))
PY

  if [ "$CMD_STATUS" -ne 0 ]; then
    echo "$ROUND_LABEL status=FAILED cmd_status=$CMD_STATUS" | tee -a "$SESSION_DIR/logs/session.log"
  else
    echo "$ROUND_LABEL status=DONE" | tee -a "$SESSION_DIR/logs/session.log"
  fi

  NEXT_EPOCH="$((START_EPOCH + ROUND * INTERVAL_SECONDS))"
  NOW_EPOCH="$(date +%s)"
  SLEEP_SECONDS="$((NEXT_EPOCH - NOW_EPOCH))"

  if [ "$SLEEP_SECONDS" -gt 0 ]; then
    echo "$ROUND_LABEL sleep_seconds=$SLEEP_SECONDS" | tee -a "$SESSION_DIR/logs/session.log"
    sleep "$SLEEP_SECONDS"
  fi

  ROUND="$((ROUND + 1))"
done

echo "========== M20.5-F NIGHT LOOP END ==========" | tee -a "$SESSION_DIR/logs/session.log"
echo "M20_5F_NIGHT_LOOP_DONE=PASS" | tee -a "$SESSION_DIR/logs/session.log"
