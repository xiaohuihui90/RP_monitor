#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR_RAW="${SCRIPT_PATH%/*}"
if [[ "${SCRIPT_DIR_RAW}" == "${SCRIPT_PATH}" ]]; then
  SCRIPT_DIR_RAW="."
fi
SCRIPT_DIR="$(cd "${SCRIPT_DIR_RAW}" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PYTHON_BIN="${PYTHON_BIN:-/home/zhangxiaohui/installers/ENTER/envs/s3-radar/bin/python}"

usage() {
  printf '%s\n' \
'Usage: run_p11b_vrp_object_mapper_once.sh --p11a-run-dir PATH --p8-input-vrp-manifest PATH --out-dir PATH [options]' \
'' \
'P11-B maps P11-A candidate VRPs to ROA, manifest, publication point, CA, and TAL evidence context.' \
'' \
'Options:' \
'  --mapping-index PATH' \
'  --object-evidence-root PATH' \
'  --max-candidates N' \
'' \
'Example:' \
'  bash scripts/runtime/run_p11b_vrp_object_mapper_once.sh \' \
'    --p11a-run-dir data/probe/p11a_impact_vrp_explainer/<P11A_RUN> \' \
'    --p8-input-vrp-manifest data/probe/p8_input_vrps/window_id=<WINDOW_ID>/p8_input_vrp_manifest.json \' \
'    --mapping-index data/p3_analysis/sec27/b4c_candidate_evidence_table/candidate_evidence_table.jsonl \' \
'    --out-dir data/probe/p11b_vrp_object_mapping/<RUN_ID>'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

cd "${REPO_ROOT}"
exec "${PYTHON_BIN}" -m probe.rov.map_candidate_vrps_to_objects "$@"
