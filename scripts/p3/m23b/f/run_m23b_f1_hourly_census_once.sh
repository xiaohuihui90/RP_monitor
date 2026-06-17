#!/usr/bin/env bash
set -u

cd "$HOME/s3_stage3_v3_code" || exit 1
source "$HOME/.bashrc" >/dev/null 2>&1 || true
conda activate s3-radar >/dev/null 2>&1 || true

export PYTHONNOUSERSITE=1
export PYTHONPATH="$PWD:${PYTHONPATH:-}"

export M21_RUN_DIR="${M21_RUN_DIR:-data/p3_collector/m21_manifest_pp_alignment/history/m21_a1_roa_repository_listing_20260607T144706Z}"
export M23B_OUT="${M23B_OUT:-$M21_RUN_DIR/outputs/m23b_five_tal_candidate_aware_live_capture}"
export M23B_D_OUT="${M23B_D_OUT:-$M23B_OUT/m23b_d_high_impact_same_window_capture}"
export M23B_F_OUT="${M23B_F_OUT:-$M23B_OUT/m23b_f_longitudinal_scheduler}"

mkdir -p "$M23B_F_OUT/state/locks" "$M23B_F_OUT/hourly_census" "$M23B_F_OUT/logs/hourly_census"

LOCKDIR="$M23B_F_OUT/state/locks/hourly_census.lock"
if ! mkdir "$LOCKDIR" 2>/dev/null; then
  echo "M23B_F1_HOURLY_CENSUS=SKIP_LOCK_HELD"
  echo "lockdir = $LOCKDIR"
  exit 0
fi
trap 'rm -rf "$LOCKDIR"' EXIT

RUN_ID="m23b_f_hourly_census_$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$M23B_F_OUT/hourly_census/$RUN_ID"
TARGET_CSV="$M23B_OUT/m23b_pp_census_target_set.csv"

mkdir -p "$RUN_DIR"
LOG="$RUN_DIR/run.log"

echo "run_id=$RUN_ID" | tee "$LOG"
echo "target_csv=$TARGET_CSV" | tee -a "$LOG"
echo "run_dir=$RUN_DIR" | tee -a "$LOG"

python scripts/p3/m23b/run_m23b_lightweight_pp_census.py \
  --target-set-csv "$TARGET_CSV" \
  --out-dir "$RUN_DIR" \
  --max-targets 40 \
  >> "$LOG" 2>&1

RC=$?

# 兼容不同输出文件名，复制成 records.csv。
REC="$(find "$RUN_DIR" -maxdepth 1 -type f \( -name "*records.csv" -o -name "records.csv" \) | head -n 1 || true)"
if [ -n "$REC" ] && [ "$REC" != "$RUN_DIR/records.csv" ]; then
  cp "$REC" "$RUN_DIR/records.csv"
fi

SUMMARY="$(find "$RUN_DIR" -maxdepth 1 -type f \( -name "*summary.md" -o -name "summary.md" \) | head -n 1 || true)"
if [ -n "$SUMMARY" ] && [ "$SUMMARY" != "$RUN_DIR/summary.md" ]; then
  cp "$SUMMARY" "$RUN_DIR/summary.md"
fi

python - <<PY > "$RUN_DIR/M23B_F1_HOURLY_CENSUS_CHECK.txt"
import csv
from pathlib import Path

run_id = "$RUN_ID"
run_dir = Path("$RUN_DIR")
target_csv = Path("$TARGET_CSV")
records_csv = run_dir / "records.csv"

def count_csv(p):
    if not p.exists():
        return 0
    with p.open("r", encoding="utf-8", newline="") as f:
        return sum(1 for _ in csv.DictReader(f))

target_count = count_csv(target_csv)
record_count = count_csv(records_csv)
status = "PASS" if $RC == 0 and record_count > 0 else "FAIL"

print(f"M23B_F1_HOURLY_CENSUS={status}")
print(f"run_id = {run_id}")
print(f"target_count = {target_count}")
print(f"record_count = {record_count}")
print(f"return_code = {$RC}")
print(f"run_dir = {run_dir}")
print(f"records_csv = {records_csv}")
print("semantic_boundary = single_probe_lightweight_census_not_multi_probe_same_window_attribution")
print("next_stage = M23B_F2_HIGH_IMPACT_CAPTURE")
PY

cat > "$M23B_F_OUT/state/current_hourly_census.env" <<EOF
export LAST_M23B_F1_RUN_ID="$RUN_ID"
export LAST_M23B_F1_RUN_DIR="$RUN_DIR"
EOF

cat "$RUN_DIR/M23B_F1_HOURLY_CENSUS_CHECK.txt"
