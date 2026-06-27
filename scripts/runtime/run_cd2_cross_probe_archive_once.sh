#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PYTHON_BIN="${PYTHON_BIN:-/home/zhangxiaohui/installers/ENTER/envs/s3-radar/bin/python}"
PROBE_ID_LIST="${PROBE_ID_LIST:-probe-cd,probe-sg,probe-k02}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/data/probe/cross_probe_pipeline}"
MODE="${MODE:-dry-run}"
MAX_SKEW_SEC="${MAX_SKEW_SEC:-600}"
MIN_CONSECUTIVE="${MIN_CONSECUTIVE:-2}"
WINDOW_SIZE_SEC="${WINDOW_SIZE_SEC:-3600}"
MINIO_ENDPOINT="${MINIO_ENDPOINT:-}"
MINIO_BUCKET="${MINIO_BUCKET:-rpki-probe-artifacts}"
MINIO_PREFIX="${MINIO_PREFIX:-rp-monitor}"
MC_BIN="${MC_BIN:-mc}"
RSYNC_BIN="${RSYNC_BIN:-rsync}"
SSH_COMMAND="${SSH_COMMAND:-}"
SAMPLE_DOWNLOAD="${SAMPLE_DOWNLOAD:-0}"

cd "${REPO_ROOT}"

exec "${PYTHON_BIN}" "${REPO_ROOT}/probe/run_cross_probe_archive_once.py" \
  --probe-id-list "${PROBE_ID_LIST}" \
  --snapshot "probe-cd=${REPO_ROOT}/data/probe/live_vrp_snapshots/probe-cd/latest_normalized_vrp.jsonl" \
  --metadata "probe-cd=${REPO_ROOT}/data/probe/live_vrp_snapshots/probe-cd/latest_metadata.json" \
  --snapshot "probe-sg=${REPO_ROOT}/data/probe/remote_snapshots/probe-sg/latest_normalized_vrp.jsonl" \
  --metadata "probe-sg=${REPO_ROOT}/data/probe/remote_snapshots/probe-sg/latest_metadata.json" \
  --snapshot "probe-k02=${REPO_ROOT}/data/probe/remote_snapshots/probe-k02/latest_normalized_vrp.jsonl" \
  --metadata "probe-k02=${REPO_ROOT}/data/probe/remote_snapshots/probe-k02/latest_metadata.json" \
  --out-root "${OUT_ROOT}" \
  --mode "${MODE}" \
  --max-skew-sec "${MAX_SKEW_SEC}" \
  --window-size-sec "${WINDOW_SIZE_SEC}" \
  --min-consecutive "${MIN_CONSECUTIVE}" \
  --minio-endpoint "${MINIO_ENDPOINT}" \
  --minio-bucket "${MINIO_BUCKET}" \
  --minio-prefix "${MINIO_PREFIX}" \
  --python-bin "${PYTHON_BIN}" \
  --rsync-bin "${RSYNC_BIN}" \
  --ssh-command "${SSH_COMMAND}" \
  --mc-bin "${MC_BIN}" \
  --sample-download "${SAMPLE_DOWNLOAD}" \
  "$@"
