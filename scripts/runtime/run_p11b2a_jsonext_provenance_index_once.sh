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
'Usage: run_p11b2a_jsonext_provenance_index_once.sh --p11a-run-dir PATH --p8-input-vrp-manifest PATH --out-dir PATH [options]' \
'' \
'P11-B2A builds a P11-B-compatible candidate VRP provenance index from Routinator jsonext.' \
'' \
'Options:' \
'  --routinator-bin PATH' \
'  --jsonext-file PATH' \
'  --probe-id PROBE' \
'  --max-candidates N' \
'  --use-window-bound-jsonext-if-available true|false' \
'' \
'Example:' \
'  bash scripts/runtime/run_p11b2a_jsonext_provenance_index_once.sh \' \
'    --p11a-run-dir data/probe/p11a_impact_vrp_explainer/<P11A_RUN> \' \
'    --p8-input-vrp-manifest data/probe/p8_input_vrps/window_id=<WINDOW_ID>/p8_input_vrp_manifest.json \' \
'    --jsonext-file data/probe/p8_input_vrps/window_id=<WINDOW_ID>/latest_vrps_jsonext.json \' \
'    --out-dir data/probe/p11b2a_jsonext_provenance/<RUN_ID>'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

cd "${REPO_ROOT}"
exec "${PYTHON_BIN}" -m probe.rov.build_jsonext_vrp_provenance_index "$@"
