#!/usr/bin/env bash
set -euo pipefail

cd ~/s3_stage3_v3_code
export PYTHONNOUSERSITE=1
export PYTHONPATH="$PWD:${PYTHONPATH:-}"

export M17_TARGET_WINDOW_ID="win_20260528T054000Z_10m"
export M17_SELECTED_WINDOWS="data/p3_collector/m245_three_layer_baseline/m17_vrp_entry_diff_inputs/selected_windows.json"
export M17_INPUT_WINDOW_DIR="data/p3_collector/m245_three_layer_baseline/history/m245_window_${M17_TARGET_WINDOW_ID}"

OUT_DIR="data/p3_collector/m17_vrp_entry_diff/debug"
mkdir -p "$OUT_DIR"

{
  echo "M17_BATCH0_PRECHECK=START"
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "target_window_id=$M17_TARGET_WINDOW_ID"
  echo

  echo "===== selected_windows ====="
  test -f "$M17_SELECTED_WINDOWS"
  python -m json.tool "$M17_SELECTED_WINDOWS" | head -n 120
  echo

  echo "===== target window dir ====="
  ls -ld "$M17_INPUT_WINDOW_DIR"
  echo

  echo "===== required files ====="
  for f in \
    "$M17_INPUT_WINDOW_DIR/outputs/M245_three_layer_status_matrix.json" \
    "$M17_INPUT_WINDOW_DIR/outputs/M245_layer_mapping_context.json" \
    "$M17_INPUT_WINDOW_DIR/outputs/M245_layer_mapping_context_h7_overlay.json" \
    "$M17_INPUT_WINDOW_DIR/outputs/validator_runtime_metadata.json" \
    "$M17_INPUT_WINDOW_DIR/outputs/raw_vrp_import_manifest.json" \
    "data/p3_collector/m245_three_layer_baseline/evidence_packs/${M17_TARGET_WINDOW_ID}/evidence_pack.json"
  do
    echo "----- $f -----"
    test -f "$f"
    ls -lh "$f"
  done
  echo

  echo "===== raw vrp files ====="
  find "$M17_INPUT_WINDOW_DIR/outputs/raw_vrp" \
    -maxdepth 3 \
    -type f \
    -name '*_raw_vrp.json' \
    -ls

  echo
  echo "===== raw schema probe ====="
  python -m json.tool "data/p3_collector/m17_vrp_entry_diff/debug/raw_vrp_schema_probe.json" | head -n 240

  echo
  echo "M17_BATCH0_PRECHECK=PASS"
} | tee "$OUT_DIR/M17_batch0_precheck.txt"
