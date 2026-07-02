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
'Usage: run_p11a_impact_vrp_explainer_once.sh --p10a-run-dir PATH --p8-input-vrp-manifest PATH --out-dir PATH [options]' \
'' \
'P11-A explains P10-A impact-bearing ROV transition events with candidate VRPs from a window-bound P8 input manifest.' \
'' \
'Options:' \
'  --max-events N' \
'  --probe-ids probe-cd,probe-sg,probe-k02' \
'' \
'Example:' \
'  bash scripts/runtime/run_p11a_impact_vrp_explainer_once.sh \' \
'    --p10a-run-dir data/probe/p10_rov_impact/<P10A_RUN> \' \
'    --p8-input-vrp-manifest data/probe/p8_input_vrps/window_id=<WINDOW_ID>/p8_input_vrp_manifest.json \' \
'    --out-dir data/probe/p11a_impact_vrp_explainer/<RUN_ID>'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

cd "${REPO_ROOT}"
exec "${PYTHON_BIN}" -m probe.rov.explain_impact_events_to_vrps "$@"
