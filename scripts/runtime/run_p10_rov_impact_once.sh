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
'Usage: run_p10_rov_impact_once.sh --mode rib_snapshot --routes PATH --vrp PROBE=PATH --metadata PROBE=PATH --out-dir PATH [options]' \
'' \
'This wrapper forwards all arguments to probe.rov.analyze_rov_impact.' \
'' \
'Common example:' \
'  bash scripts/runtime/run_p10_rov_impact_once.sh \' \
'    --mode rib_snapshot \' \
'    --routes data/bgp/latest_prefix_origin.csv \' \
'    --vrp probe-cd=data/probe/live_vrp_snapshots/probe-cd/latest_normalized_vrp.jsonl \' \
'    --metadata probe-cd=data/probe/live_vrp_snapshots/probe-cd/latest_metadata.json \' \
'    --out-dir data/probe/p10_rov_impact/manual_run'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

cd "${REPO_ROOT}"
exec "${PYTHON_BIN}" -m probe.rov.analyze_rov_impact "$@"
