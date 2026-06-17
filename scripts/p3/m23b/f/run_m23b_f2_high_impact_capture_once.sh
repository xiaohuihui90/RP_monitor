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

mkdir -p "$M23B_F_OUT/state/locks" "$M23B_F_OUT/high_impact_capture" "$M23B_F_OUT/logs/high_impact_capture"

LOCKDIR="$M23B_F_OUT/state/locks/high_impact_capture.lock"
if ! mkdir "$LOCKDIR" 2>/dev/null; then
  echo "M23B_F2_HIGH_IMPACT_CAPTURE=SKIP_LOCK_HELD"
  echo "lockdir = $LOCKDIR"
  exit 0
fi
trap 'rm -rf "$LOCKDIR"' EXIT

CAPTURE_ID="m23b_d_capture_$(date -u +%Y%m%dT%H%M%SZ)"
CAPTURE_F_DIR="$M23B_F_OUT/high_impact_capture/$CAPTURE_ID"
TARGET_CSV="$M23B_D_OUT/m23b_d_same_window_target_list.csv"

mkdir -p "$CAPTURE_F_DIR"
LOG="$CAPTURE_F_DIR/run.log"

echo "capture_id=$CAPTURE_ID" | tee "$LOG"
echo "target_csv=$TARGET_CSV" | tee -a "$LOG"
echo "m23b_d_out=$M23B_D_OUT" | tee -a "$LOG"

python scripts/p3/m23b/run_m23b_d_same_window_capture_once.py \
  --target-list-csv "$TARGET_CSV" \
  --out-dir "$M23B_D_OUT" \
  --capture-id "$CAPTURE_ID" \
  >> "$LOG" 2>&1

RC_CAPTURE=$?

if [ -f scripts/p3/m23b/analyze_m23b_d_longitudinal_features.py ]; then
  python scripts/p3/m23b/analyze_m23b_d_longitudinal_features.py >> "$LOG" 2>&1
  RC_ANALYZE=$?
else
  RC_ANALYZE=99
fi

[ -f "$M23B_D_OUT/${CAPTURE_ID}_summary.md" ] && cp "$M23B_D_OUT/${CAPTURE_ID}_summary.md" "$CAPTURE_F_DIR/capture_summary.md"
[ -f "$M23B_D_OUT/${CAPTURE_ID}_summary.json" ] && cp "$M23B_D_OUT/${CAPTURE_ID}_summary.json" "$CAPTURE_F_DIR/capture_summary.json"
[ -f "$M23B_D_OUT/M23B_D_SAME_WINDOW_CAPTURE_ONCE_CHECK.txt" ] && cp "$M23B_D_OUT/M23B_D_SAME_WINDOW_CAPTURE_ONCE_CHECK.txt" "$CAPTURE_F_DIR/capture_check.txt"
[ -f "$M23B_D_OUT/m23b_d_longitudinal_feature_summary.md" ] && cp "$M23B_D_OUT/m23b_d_longitudinal_feature_summary.md" "$CAPTURE_F_DIR/longitudinal_feature_summary.md"
[ -f "$M23B_D_OUT/m23b_d_longitudinal_target_feature_table.csv" ] && cp "$M23B_D_OUT/m23b_d_longitudinal_target_feature_table.csv" "$CAPTURE_F_DIR/longitudinal_target_feature_table.csv"
[ -f "$M23B_D_OUT/m23b_d_longitudinal_host_feature_table.csv" ] && cp "$M23B_D_OUT/m23b_d_longitudinal_host_feature_table.csv" "$CAPTURE_F_DIR/longitudinal_host_feature_table.csv"

python - <<PY > "$CAPTURE_F_DIR/M23B_F2_HIGH_IMPACT_CAPTURE_CHECK.txt"
import csv
from pathlib import Path

capture_id = "$CAPTURE_ID"
target_csv = Path("$TARGET_CSV")
records_csv = Path("$M23B_D_OUT") / "m23b_d_same_window_capture_records.csv"

def count_csv(p):
    if not p.exists():
        return 0
    with p.open("r", encoding="utf-8", newline="") as f:
        return sum(1 for _ in csv.DictReader(f))

target_count = count_csv(target_csv)
record_total = count_csv(records_csv)
status = "PASS" if $RC_CAPTURE == 0 and target_count > 0 else "FAIL"

print(f"M23B_F2_HIGH_IMPACT_CAPTURE={status}")
print(f"capture_id = {capture_id}")
print(f"target_count = {target_count}")
print(f"capture_return_code = {$RC_CAPTURE}")
print(f"analyze_return_code = {$RC_ANALYZE}")
print(f"global_record_total = {record_total}")
print(f"capture_dir = $CAPTURE_F_DIR")
print(f"records_csv = {records_csv}")
print("semantic_boundary = repeated_single_node_live_capture_not_multi_probe_same_window_attribution")
print("next_stage = M23B_F21_PIPELINE")
PY

cat > "$M23B_F_OUT/state/current_high_impact_capture.env" <<EOF
export LAST_M23B_F2_CAPTURE_ID="$CAPTURE_ID"
export LAST_M23B_F2_CAPTURE_DIR="$CAPTURE_F_DIR"
EOF

cat "$CAPTURE_F_DIR/M23B_F2_HIGH_IMPACT_CAPTURE_CHECK.txt"
