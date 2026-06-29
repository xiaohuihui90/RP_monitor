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
'Usage: run_p10_build_route_table_once.sh --rib PATH --collector ID --rib-time-utc YYYY-MM-DDTHH:MM:SSZ --out-dir PATH [options]' \
'' \
'Build P10 routes.jsonl from a local RouteViews/RIPE RIS MRT RIB via bgpdump -m.' \
'' \
'Options are forwarded to probe.rov.build_bgp_route_table:' \
'  --bgpdump-bin PATH' \
'  --max-routes N' \
'  --include-ipv6 | --no-include-ipv6' \
'  --as-set-policy skip|mark_uncertain' \
'  --dedupe-key prefix_origin_collector|prefix_origin|none' \
'' \
'Example:' \
'  bash scripts/runtime/run_p10_build_route_table_once.sh \' \
'    --rib data/bgp/routeviews/ribs/rib.20260101.0000.bz2 \' \
'    --collector routeviews2 \' \
'    --rib-time-utc 2026-01-01T00:00:00Z \' \
'    --out-dir data/bgp/p10_route_tables/routeviews2_20260101T000000Z \' \
'    --max-routes 100000'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

cd "${REPO_ROOT}"
exec "${PYTHON_BIN}" -m probe.rov.build_bgp_route_table "$@"
