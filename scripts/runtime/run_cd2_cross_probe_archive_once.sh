#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PYTHON_BIN="${PYTHON_BIN:-/home/zhangxiaohui/installers/ENTER/envs/s3-radar/bin/python}"
PROBE_ID_LIST="${PROBE_ID_LIST:-probe-cd,probe-sg,probe-k02}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/data/probe/cross_probe_pipeline}"
P8_MODE="${P8_MODE:-${MODE:-dry-run}}"
P8_MAX_SKEW_SEC="${P8_MAX_SKEW_SEC:-${MAX_SKEW_SEC:-600}}"
MIN_CONSECUTIVE="${MIN_CONSECUTIVE:-2}"
WINDOW_SIZE_SEC="${WINDOW_SIZE_SEC:-3600}"
MINIO_ENDPOINT="${MINIO_ENDPOINT:-}"
MINIO_BUCKET="${MINIO_BUCKET:-rpki-probe-artifacts}"
P8_MINIO_PREFIX="${P8_MINIO_PREFIX:-${MINIO_PREFIX:-rp-monitor}}"
MC_BIN="${MC_BIN:-mc}"
RSYNC_BIN="${RSYNC_BIN:-rsync}"
SSH_COMMAND="${SSH_COMMAND:-}"
P8_SAMPLE_DOWNLOAD="${P8_SAMPLE_DOWNLOAD:-${SAMPLE_DOWNLOAD:-0}}"
P8_COMPRESS_JSONL="${P8_COMPRESS_JSONL:-1}"

cd "${REPO_ROOT}"

case "${P8_MODE}" in
  dry-run|upload|verify) ;;
  *) echo "invalid P8_MODE=${P8_MODE}; expected dry-run, upload, or verify" >&2; exit 2 ;;
esac

case "${P8_COMPRESS_JSONL}" in
  1|true|TRUE|yes|YES|on|ON) COMPRESS_ARGS=(--compress-jsonl) ;;
  0|false|FALSE|no|NO|off|OFF) COMPRESS_ARGS=() ;;
  *) echo "invalid P8_COMPRESS_JSONL=${P8_COMPRESS_JSONL}; expected 1/0, true/false, yes/no, or on/off" >&2; exit 2 ;;
esac

P8_ARGS=(
  "${PYTHON_BIN}" "${REPO_ROOT}/probe/run_cross_probe_archive_once.py"
  --probe-id-list "${PROBE_ID_LIST}" \
  --snapshot "probe-cd=${REPO_ROOT}/data/probe/live_vrp_snapshots/probe-cd/latest_normalized_vrp.jsonl" \
  --metadata "probe-cd=${REPO_ROOT}/data/probe/live_vrp_snapshots/probe-cd/latest_metadata.json" \
  --snapshot "probe-sg=${REPO_ROOT}/data/probe/remote_snapshots/probe-sg/latest_normalized_vrp.jsonl" \
  --metadata "probe-sg=${REPO_ROOT}/data/probe/remote_snapshots/probe-sg/latest_metadata.json" \
  --snapshot "probe-k02=${REPO_ROOT}/data/probe/remote_snapshots/probe-k02/latest_normalized_vrp.jsonl" \
  --metadata "probe-k02=${REPO_ROOT}/data/probe/remote_snapshots/probe-k02/latest_metadata.json" \
  --out-root "${OUT_ROOT}" \
  --mode "${P8_MODE}" \
  --max-skew-sec "${P8_MAX_SKEW_SEC}" \
  --window-size-sec "${WINDOW_SIZE_SEC}" \
  --min-consecutive "${MIN_CONSECUTIVE}" \
  --minio-endpoint "${MINIO_ENDPOINT}" \
  --minio-bucket "${MINIO_BUCKET}" \
  --minio-prefix "${P8_MINIO_PREFIX}" \
  --python-bin "${PYTHON_BIN}" \
  --rsync-bin "${RSYNC_BIN}" \
  --ssh-command "${SSH_COMMAND}" \
  --mc-bin "${MC_BIN}" \
  --sample-download "${P8_SAMPLE_DOWNLOAD}"
)

P8_ARGS+=("${COMPRESS_ARGS[@]}")

exec "${P8_ARGS[@]}" "$@"
