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
P9_PROBE_IDS="${P9_PROBE_IDS:-${PROBE_ID:-probe-cd}}"
P9_OUT_ROOT="${P9_OUT_ROOT:-${REPO_ROOT}/data/probe/runtime_retention}"
P9_P8_ROOT="${P9_P8_ROOT:-${REPO_ROOT}/data/probe/cross_probe_pipeline}"
P9_SNAPSHOT_ROOT="${P9_SNAPSHOT_ROOT:-${REPO_ROOT}/data/probe/live_vrp_snapshots}"
P9_REMOTE_SNAPSHOT_ROOT="${P9_REMOTE_SNAPSHOT_ROOT:-${REPO_ROOT}/data/probe/remote_snapshots}"
P9_SNAPSHOT_ROOT_MAP="${P9_SNAPSHOT_ROOT_MAP:-}"
P9_CYCLE_ROOT="${P9_CYCLE_ROOT:-${REPO_ROOT}/data/probe/e2e_msal_cycles}"
P9_KEEP_P8_RUNS="${P9_KEEP_P8_RUNS:-12}"
P9_KEEP_SNAPSHOTS="${P9_KEEP_SNAPSHOTS:-6}"
P9_KEEP_CYCLES="${P9_KEEP_CYCLES:-24}"
P9_APPLY="${P9_APPLY:-0}"
P9_UPLOAD_MINIO="${P9_UPLOAD_MINIO:-1}"
P9_CHECKPOINT="${P9_CHECKPOINT:-0}"
P9_CHECKPOINT_GZIP="${P9_CHECKPOINT_GZIP:-1}"
P9_ALLOW_LARGE_SNAPSHOT_UPLOAD="${P9_ALLOW_LARGE_SNAPSHOT_UPLOAD:-0}"
P9_DELETE_FAILED_BEFORE_DAYS="${P9_DELETE_FAILED_BEFORE_DAYS:-}"
P9_ROLLUP_LIMIT="${P9_ROLLUP_LIMIT:-0}"
MC_BIN="${MC_BIN:-mc}"

usage() {
  printf '%s\n' \
'Usage: run_runtime_retention_once.sh [options]' \
'' \
'Options:' \
'  --repo-root PATH' \
'  --python-bin PATH' \
'  --probe-ids ID[,ID...]' \
'  --out-root PATH' \
'  --p8-root PATH' \
'  --snapshot-root PATH' \
'  --remote-snapshot-root PATH' \
'  --snapshot-root-map probe=PATH[,probe=PATH...]' \
'  --cycle-root PATH' \
'  --keep-p8-runs N' \
'  --keep-snapshots N' \
'  --keep-cycles N' \
'  --apply' \
'  --no-upload-minio' \
'  --checkpoint' \
'  --checkpoint-gzip' \
'  --no-checkpoint-gzip' \
'  --allow-large-snapshot-upload' \
'  --delete-failed-before-days N' \
'  --rollup-limit N' \
'  --mc-bin PATH'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root) REPO_ROOT="$2"; shift 2 ;;
    --python-bin) PYTHON_BIN="$2"; shift 2 ;;
    --probe-ids) P9_PROBE_IDS="$2"; shift 2 ;;
    --out-root) P9_OUT_ROOT="$2"; shift 2 ;;
    --p8-root) P9_P8_ROOT="$2"; shift 2 ;;
    --snapshot-root) P9_SNAPSHOT_ROOT="$2"; shift 2 ;;
    --remote-snapshot-root) P9_REMOTE_SNAPSHOT_ROOT="$2"; shift 2 ;;
    --snapshot-root-map) P9_SNAPSHOT_ROOT_MAP="$2"; shift 2 ;;
    --cycle-root) P9_CYCLE_ROOT="$2"; shift 2 ;;
    --keep-p8-runs) P9_KEEP_P8_RUNS="$2"; shift 2 ;;
    --keep-snapshots) P9_KEEP_SNAPSHOTS="$2"; shift 2 ;;
    --keep-cycles) P9_KEEP_CYCLES="$2"; shift 2 ;;
    --apply) P9_APPLY=1; shift ;;
    --no-upload-minio) P9_UPLOAD_MINIO=0; shift ;;
    --checkpoint) P9_CHECKPOINT=1; shift ;;
    --checkpoint-gzip) P9_CHECKPOINT_GZIP=1; shift ;;
    --no-checkpoint-gzip) P9_CHECKPOINT_GZIP=0; shift ;;
    --allow-large-snapshot-upload) P9_ALLOW_LARGE_SNAPSHOT_UPLOAD=1; shift ;;
    --delete-failed-before-days) P9_DELETE_FAILED_BEFORE_DAYS="$2"; shift 2 ;;
    --rollup-limit) P9_ROLLUP_LIMIT="$2"; shift 2 ;;
    --mc-bin) MC_BIN="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

snapshot_root_for_probe() {
  local probe_id="$1"
  local assignment key value
  if [[ -n "${P9_SNAPSHOT_ROOT_MAP}" ]]; then
    IFS=',' read -r -a SNAPSHOT_ROOT_MAP_ARRAY <<< "${P9_SNAPSHOT_ROOT_MAP}"
    for assignment in "${SNAPSHOT_ROOT_MAP_ARRAY[@]}"; do
      key="${assignment%%=*}"
      value="${assignment#*=}"
      key="${key//[[:space:]]/}"
      if [[ "${key}" == "${probe_id}" && "${assignment}" == *"="* && -n "${value}" ]]; then
        printf '%s\n' "${value}"
        return 0
      fi
    done
  fi

  if [[ "${probe_id}" == "probe-cd" ]]; then
    printf '%s\n' "${P9_SNAPSHOT_ROOT}/${probe_id}"
    return 0
  fi

  if [[ "${probe_id}" == "probe-sg" || "${probe_id}" == "probe-k02" ]]; then
    printf '%s\n' "${P9_REMOTE_SNAPSHOT_ROOT}/${probe_id}"
    return 0
  fi

  if [[ -d "${P9_SNAPSHOT_ROOT}/${probe_id}" ]]; then
    printf '%s\n' "${P9_SNAPSHOT_ROOT}/${probe_id}"
  elif [[ -d "${P9_REMOTE_SNAPSHOT_ROOT}/${probe_id}" ]]; then
    printf '%s\n' "${P9_REMOTE_SNAPSHOT_ROOT}/${probe_id}"
  else
    printf '%s\n' "${P9_SNAPSHOT_ROOT}/${probe_id}"
  fi
}

RUN_ID="p9_runtime_retention_$("${PYTHON_BIN}" -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))')"
RUN_DIR="${P9_OUT_ROOT}/${RUN_ID}"
ROLLUP_DIR="${RUN_DIR}/p8_rollup"
RETENTION_DIR="${RUN_DIR}/retention"
CHECKPOINT_REPORT_ARGS=()

cd "${REPO_ROOT}"

ROLLUP_ARGS=(
  "${PYTHON_BIN}" "${REPO_ROOT}/probe/build_p8_rollup.py"
  --p8-root "${P9_P8_ROOT}"
  --out-dir "${ROLLUP_DIR}"
  --limit "${P9_ROLLUP_LIMIT}"
  --mc-bin "${MC_BIN}"
)
if [[ "${P9_UPLOAD_MINIO}" == "1" ]]; then
  ROLLUP_ARGS+=(--upload-minio)
fi
"${ROLLUP_ARGS[@]}"

if [[ "${P9_CHECKPOINT}" == "1" ]]; then
  IFS=',' read -r -a PROBE_ARRAY <<< "${P9_PROBE_IDS}"
  for probe_id_raw in "${PROBE_ARRAY[@]}"; do
    probe_id="${probe_id_raw//[[:space:]]/}"
    if [[ -z "${probe_id}" ]]; then
      continue
    fi
    checkpoint_dir="${RUN_DIR}/snapshot_checkpoint/${probe_id}"
    checkpoint_snapshot_root="$(snapshot_root_for_probe "${probe_id}")"
    CHECKPOINT_ARGS=(
      "${PYTHON_BIN}" "${REPO_ROOT}/probe/archive_snapshot_checkpoint.py"
      --probe-id "${probe_id}"
      --snapshot-root "${checkpoint_snapshot_root}"
      --out-dir "${checkpoint_dir}"
      --checkpoint
      --mc-bin "${MC_BIN}"
    )
    if [[ "${P9_CHECKPOINT_GZIP}" == "1" ]]; then
      CHECKPOINT_ARGS+=(--gzip)
    fi
    if [[ "${P9_UPLOAD_MINIO}" == "1" ]]; then
      CHECKPOINT_ARGS+=(--upload-minio)
    fi
    if [[ "${P9_ALLOW_LARGE_SNAPSHOT_UPLOAD}" == "1" ]]; then
      CHECKPOINT_ARGS+=(--allow-large-snapshot-upload)
    fi
    "${CHECKPOINT_ARGS[@]}"
    CHECKPOINT_REPORT_ARGS+=(--checkpoint-report "${checkpoint_dir}/checkpoint_archive_report.json")
  done
fi

RETENTION_ARGS=(
  "${PYTHON_BIN}" "${REPO_ROOT}/probe/manage_runtime_retention.py"
  --p8-root "${P9_P8_ROOT}"
  --snapshot-root "${P9_SNAPSHOT_ROOT}"
  --cycle-root "${P9_CYCLE_ROOT}"
  --keep-p8-runs "${P9_KEEP_P8_RUNS}"
  --keep-snapshots "${P9_KEEP_SNAPSHOTS}"
  --keep-cycles "${P9_KEEP_CYCLES}"
  --out-dir "${RETENTION_DIR}"
  --p8-rollup-summary "${ROLLUP_DIR}/p8_rollup_summary.json"
)
if [[ "${P9_UPLOAD_MINIO}" == "1" ]]; then
  RETENTION_ARGS+=(--rollup-upload-requested)
fi
if [[ "${P9_APPLY}" == "1" ]]; then
  RETENTION_ARGS+=(--apply)
fi
if [[ -n "${P9_DELETE_FAILED_BEFORE_DAYS}" ]]; then
  RETENTION_ARGS+=(--delete-failed-before-days "${P9_DELETE_FAILED_BEFORE_DAYS}")
fi
IFS=',' read -r -a PROBE_ARRAY <<< "${P9_PROBE_IDS}"
for probe_id_raw in "${PROBE_ARRAY[@]}"; do
  probe_id="${probe_id_raw//[[:space:]]/}"
  if [[ -n "${probe_id}" ]]; then
    RETENTION_ARGS+=(--probe-id "${probe_id}")
  fi
done
RETENTION_ARGS+=("${CHECKPOINT_REPORT_ARGS[@]}")

"${RETENTION_ARGS[@]}"

echo "${RUN_DIR}"
