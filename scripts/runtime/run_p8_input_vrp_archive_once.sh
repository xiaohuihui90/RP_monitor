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
'Usage: run_p8_input_vrp_archive_once.sh --p8-run-dir PATH --out-dir PATH [options]' \
'' \
'Archive the exact VRP inputs for a P8 PASS window so P10 historical replay can use window-bound VRPs.' \
'' \
'Options:' \
'  --upload-minio true|false' \
'  --compress gzip|none' \
'  --minio-prefix PREFIX' \
'  --mc-bin mc' \
'  --metadata PROBE=PATH' \
'  --vrp PROBE=PATH' \
'' \
'Example:' \
'  bash scripts/runtime/run_p8_input_vrp_archive_once.sh \' \
'    --p8-run-dir data/probe/cross_probe_pipeline/<P8_PASS_RUN> \' \
'    --out-dir data/probe/p8_input_vrps \' \
'    --upload-minio false'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

cd "${REPO_ROOT}"
exec "${PYTHON_BIN}" probe/archive_p8_input_vrps.py "$@"
