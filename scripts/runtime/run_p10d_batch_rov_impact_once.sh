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
'Usage: run_p10d_batch_rov_impact_once.sh --p8-root PATH --latest-n N --out-dir PATH [options]' \
'' \
'Batch replay P10-C over multiple P8 PASS windows and merge P10-A impact tables.' \
'' \
'Common options:' \
'  --collector routeviews2' \
'  --source routeviews|ris' \
'  --rib-time-policy nearest_leq|nearest|nearest_geq' \
'  --download true|false' \
'  --bgpdump-bin PATH' \
'  --max-routes N' \
'  --continue-on-error true|false' \
'  --skip-existing' \
'  --min-p8-skew-ok true|false' \
'' \
'Example:' \
'  bash scripts/runtime/run_p10d_batch_rov_impact_once.sh \' \
'    --p8-root data/probe/cross_probe_pipeline \' \
'    --latest-n 6 \' \
'    --collector routeviews2 \' \
'    --source routeviews \' \
'    --rib-time-policy nearest_leq \' \
'    --download false \' \
'    --bgpdump-bin "$(command -v bgpdump)" \' \
'    --max-routes 100000 \' \
'    --out-dir data/probe/p10d_batch_rov_impact/p10d_latest6_routeviews2'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

cd "${REPO_ROOT}"
exec "${PYTHON_BIN}" -m probe.rov.run_batch_rov_impact "$@"
