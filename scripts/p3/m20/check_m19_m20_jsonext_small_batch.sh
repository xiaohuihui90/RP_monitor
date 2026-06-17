#!/usr/bin/env bash
set -u

cd ~/s3_stage3_v3_code

export M19_RUN_DIR="${M19_RUN_DIR:-data/p3_collector/m19_roa_to_vrp/history/m19_top200_20260607T082859Z}"
export M20_RUN_DIR="${M20_RUN_DIR:-data/p3_collector/m20_targeted_backfill/history/m20_jsonext_uri_top20_20260607T081406Z}"

echo "M19_RUN_DIR=$M19_RUN_DIR"
echo "M20_RUN_DIR=$M20_RUN_DIR"

check_file() {
  local title="$1"
  local path="$2"
  echo
  echo "========== $title =========="
  if [ -f "$path" ]; then
    cat "$path"
  else
    echo "MISSING: $path"
  fi
}

check_file "M19 B1" "$M19_RUN_DIR/checks/M19_B1_SOURCE_URI_DIAG_CHECK.txt"
check_file "M19 B7" "$M19_RUN_DIR/checks/M19_B7_JSONEXT_SOURCE_BRIDGE_CHECK.txt"
check_file "M19 B8" "$M19_RUN_DIR/checks/M19_B8_JSONEXT_ENRICHED_MAPPING_CHECK.txt"
check_file "M19 B9" "$M19_RUN_DIR/checks/M19_B9_MANIFEST_PP_HINT_CHECK.txt"

check_file "M20 B0" "$M20_RUN_DIR/checks/M20_B0_TARGET_PRECHECK.txt"
check_file "M20 B1" "$M20_RUN_DIR/checks/M20_B1_JSONEXT_URI_FETCH_CHECK.txt"
check_file "M20 B2" "$M20_RUN_DIR/checks/M20_B2_BACKFILLED_OBJECT_INDEX_CHECK.txt"
check_file "M20 B3" "$M20_RUN_DIR/checks/M20_B3_JOIN_BACKFILLED_OBJECTS_CHECK.txt"
check_file "M20 B4" "$M20_RUN_DIR/checks/M20_B4_EVIDENCE_PACK_AND_RESEARCH_SUMMARY_CHECK.txt"

echo
echo "========== key outputs =========="
wc -l "$M19_RUN_DIR/outputs/m20_jsonext_uri_backfill_candidates.jsonl" 2>/dev/null || true
wc -l "$M20_RUN_DIR/outputs/m20_jsonext_uri_fetch_records.jsonl" 2>/dev/null || true
wc -l "$M20_RUN_DIR/outputs/m20_case_success_examples.jsonl" 2>/dev/null || true
wc -l "$M20_RUN_DIR/outputs/m20_case_failure_examples.jsonl" 2>/dev/null || true

echo
echo "========== success sample =========="
head -n 3 "$M20_RUN_DIR/outputs/m20_case_success_examples.jsonl" 2>/dev/null || true

echo
echo "========== failure sample =========="
head -n 3 "$M20_RUN_DIR/outputs/m20_case_failure_examples.jsonl" 2>/dev/null || true
