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
'Usage: run_p10c_time_aligned_rov_once.sh --p8-run-dir PATH [options]' \
'' \
'P10-C selects a time-aligned RouteViews/RIS RIB for a P8 PASS window,' \
'optionally downloads it, runs P10-B route-table build, then runs P10-A ROV impact.' \
'' \
'Common options:' \
'  --collector routeviews2' \
'  --source routeviews|ris' \
'  --rib-time-policy nearest_leq|nearest|nearest_geq' \
'  --align-to window_center|window_start' \
'  --download true|false' \
'  --out-dir PATH' \
'  --bgpdump-bin PATH' \
'  --max-routes N' \
'  --max-route-time-skew-sec N' \
'  --vrp-input-mode latest|window_bound' \
'  --p8-input-vrp-manifest PATH' \
'' \
'Example:' \
'  bash scripts/runtime/run_p10c_time_aligned_rov_once.sh \' \
'    --p8-run-dir data/probe/cross_probe_pipeline/<P8_PASS_RUN> \' \
'    --collector routeviews2 \' \
'    --source routeviews \' \
'    --download true \' \
'    --max-routes 100000'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

cd "${REPO_ROOT}"
exec "${PYTHON_BIN}" -m probe.rov.select_bgp_rib_for_window "$@"
