#!/usr/bin/env bash
set -euo pipefail

cd ~/s3_stage3_v3_code

export PYTHONNOUSERSITE=1
export PYTHONPATH="$PWD"
export PATH="/home/zhangxiaohui/.cargo/bin:$PATH"

PYTHON_BIN="${PYTHON_BIN:-/home/zhangxiaohui/installers/ENTER/envs/s3-radar/bin/python}"

SRC_PP="data/p3_analysis/sec27/coverage_candidate/source_pp_coverage.jsonl"
L2B="data/p3_analysis/sec27/l2b_effective_input_r2/l2b_candidate_effective_input.jsonl"
SUPPORTED="data/p3_analysis/sec27/b5_paper_stats/object_or_manifest_supported_subset.jsonl"
B4C="data/p3_analysis/sec27/b4c_candidate_evidence_table/candidate_evidence_table.jsonl"
B6="data/p3_analysis/sec27/b6_final_paper_tables/selected_persistent_cases.jsonl"

RUN_ID="hourly_$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="data/probe/e2e_msal_cycles/probe-cd/${RUN_ID}"
mkdir -p "$RUN_DIR" logs

"$PYTHON_BIN" probe/run_probe_live_msal_cycle.py \
  --probe-id probe-cd \
  --snapshot-root data/probe/live_vrp_snapshots \
  --out-dir "$RUN_DIR" \
  --routinator-bin /home/zhangxiaohui/.cargo/bin/routinator \
  --command-format json \
  --command-timeout-sec 1200 \
  --source-pp-coverage "$SRC_PP" \
  --l2-object-index "$L2B" \
  --manifest-filelist-index "$SUPPORTED" \
  --hash-evidence-index "$B6" \
  --candidate-evidence-table "$B4C" \
  --allow-empty-events \
  --dump-index-stats

SNAP_ROOT="data/probe/live_vrp_snapshots/probe-cd/history"
find "$SNAP_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | head -n -4 | xargs -r rm -rf

RUN_ROOT="data/probe/e2e_msal_cycles/probe-cd"
find "$RUN_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | head -n -12 | xargs -r rm -rf
