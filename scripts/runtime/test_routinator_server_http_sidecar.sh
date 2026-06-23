#!/usr/bin/env bash
set -Eeuo pipefail

PYTHON_BIN="/home/zhangxiaohui/installers/ENTER/envs/s3-radar/bin/python"
ROUTINATOR_BIN="/home/zhangxiaohui/.cargo/bin/routinator"

HTTP_PORT="28114"
REFRESH_SEC="600"
MAX_WAIT_SEC="2400"
POLL_SEC="15"
PROBE_ID="probe-cd"
BASE_DIR="data/probe/a2_routinator_server"
EXPORT_HTTP_TIMEOUT_SEC="300"
STOP_AFTER_TEST="false"
PID_FILE=""
LOG_FILE=""

usage() {
  printf '%s\n' \
    "Usage:" \
    "  scripts/runtime/test_routinator_server_http_sidecar.sh [options]" \
    "" \
    "Options:" \
    "  --http-port PORT       Local HTTP port bound on 127.0.0.1. Default: 28114" \
    "  --refresh SEC          Routinator refresh interval. Default: 600" \
    "  --max-wait-sec SEC     Max wait for /api/v1/status readiness. Default: 2400" \
    "  --poll-sec SEC         Status polling interval. Default: 15" \
    "  --probe-id ID          Probe id for exporter validation. Default: probe-cd" \
    "  --pid-file PATH        PID file. Default: data/probe/a2_routinator_server/routinator_http_sidecar_<port>.pid" \
    "  --log PATH             Log file. Default: data/probe/a2_routinator_server/routinator_http_sidecar_<port>.log" \
    "  --stop-after-test      Stop the sidecar process after the exporter test" \
    "  -h, --help             Show this help" \
    "" \
    "The script starts Routinator as a local HTTP sidecar on 127.0.0.1 only," \
    "waits until /api/v1/status is no longer 'Initial validation ongoing', and" \
    "validates probe/export_routinator_live_snapshot.py --capture-mode http."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --http-port|--port)
      HTTP_PORT="${2:?missing value for --http-port}"
      shift 2
      ;;
    --refresh)
      REFRESH_SEC="${2:?missing value for --refresh}"
      shift 2
      ;;
    --max-wait-sec)
      MAX_WAIT_SEC="${2:?missing value for --max-wait-sec}"
      shift 2
      ;;
    --poll-sec)
      POLL_SEC="${2:?missing value for --poll-sec}"
      shift 2
      ;;
    --probe-id)
      PROBE_ID="${2:?missing value for --probe-id}"
      shift 2
      ;;
    --pid-file)
      PID_FILE="${2:?missing value for --pid-file}"
      shift 2
      ;;
    --log)
      LOG_FILE="${2:?missing value for --log}"
      shift 2
      ;;
    --stop-after-test)
      STOP_AFTER_TEST="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

HTTP_ADDR="127.0.0.1:${HTTP_PORT}"
HTTP_URL="http://${HTTP_ADDR}"
STATUS_URL="${HTTP_URL}/api/v1/status"
EXPORT_OUT_ROOT="${BASE_DIR}/live_vrp_snapshots"
CHECK_FILE="${BASE_DIR}/checks/A2_ROUTINATOR_SERVER_HTTP_ACCEPTANCE.txt"

if [[ -z "$PID_FILE" ]]; then
  PID_FILE="${BASE_DIR}/routinator_http_sidecar_${HTTP_PORT}.pid"
fi
if [[ -z "$LOG_FILE" ]]; then
  LOG_FILE="${BASE_DIR}/routinator_http_sidecar_${HTTP_PORT}.log"
fi

STATUS="FAIL"
STARTED_PID=""
ROUTINATOR_VERSION=""
VALIDATOR_HEALTH=""
CAPTURE_METHOD=""
VRP_COUNT=""
RAW_VRP_FILE=""
NORMALIZED_VRP_FILE=""
STATUS_READY="false"
EXPORTER_EXIT_ZERO="false"
VRP_COUNT_GT_ZERO="false"
PORT_FREE_BEFORE="false"
PID_FILE_CLEAR="false"
SERVER_STARTED="false"
LISTEN_READY="false"
LAST_STATUS_HTTP_CODE=""
LAST_STATUS_BODY=""
FAIL_REASONS=()

bool_text() {
  if [[ "${1:-false}" == "true" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

sanitize_value() {
  printf '%s' "${1:-}" | tr '\r\n' '  ' | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//' | cut -c 1-400
}

record_fail() {
  FAIL_REASONS+=("$1")
}

port_is_listening() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${HTTP_PORT}$"
    return $?
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${HTTP_PORT}$"
    return $?
  fi
  return 2
}

write_acceptance() {
  local tmp="${CHECK_FILE}.tmp.$$"
  mkdir -p "$(dirname "$CHECK_FILE")"
  {
    echo "A2_ROUTINATOR_SERVER_HTTP=${STATUS}"
    echo "probe_id=${PROBE_ID}"
    echo "http_port=${HTTP_PORT}"
    echo "pid=${STARTED_PID}"
    echo "capture_method=${CAPTURE_METHOD}"
    echo "routinator_version=$(sanitize_value "$ROUTINATOR_VERSION")"
    echo "validator_health=$(sanitize_value "$VALIDATOR_HEALTH")"
    echo "vrp_count=${VRP_COUNT}"
    echo "raw_vrp_file=${RAW_VRP_FILE}"
    echo "normalized_vrp_file=${NORMALIZED_VRP_FILE}"
    echo "status_ready=${STATUS_READY}"
    echo "exporter_exit_zero=${EXPORTER_EXIT_ZERO}"
    echo "vrp_count_gt_zero=${VRP_COUNT_GT_ZERO}"
    echo
    echo "[checks]"
    echo "routinator_version_ok=$(bool_text "${ROUTINATOR_VERSION:+true}")"
    echo "python_bin_exists=$(bool_text "$([[ -x "$PYTHON_BIN" ]] && echo true || echo false)")"
    echo "routinator_bin_exists=$(bool_text "$([[ -x "$ROUTINATOR_BIN" ]] && echo true || echo false)")"
    echo "pid_file_clear=${PID_FILE_CLEAR}"
    echo "port_free_before=${PORT_FREE_BEFORE}"
    echo "server_started=${SERVER_STARTED}"
    echo "listen_ready=${LISTEN_READY}"
    echo "status_ready=${STATUS_READY}"
    echo "exporter_exit_zero=${EXPORTER_EXIT_ZERO}"
    echo "vrp_count_gt_zero=${VRP_COUNT_GT_ZERO}"
    echo
    echo "[paths]"
    echo "pid_file=${PID_FILE}"
    echo "log_file=${LOG_FILE}"
    echo "export_out_root=${EXPORT_OUT_ROOT}"
    echo "status_url=${STATUS_URL}"
    echo "last_status_http_code=${LAST_STATUS_HTTP_CODE}"
    if [[ ${#FAIL_REASONS[@]} -gt 0 ]]; then
      echo
      echo "[fail_reasons]"
      printf '%s\n' "${FAIL_REASONS[@]}"
    fi
  } > "$tmp"
  mv "$tmp" "$CHECK_FILE"
}

compute_status() {
  STATUS="PASS"
  local required=(
    "${ROUTINATOR_VERSION:+true}"
    "$PID_FILE_CLEAR"
    "$PORT_FREE_BEFORE"
    "$SERVER_STARTED"
    "$LISTEN_READY"
    "$STATUS_READY"
    "$EXPORTER_EXIT_ZERO"
    "$VRP_COUNT_GT_ZERO"
  )
  for item in "${required[@]}"; do
    if [[ "$item" != "true" ]]; then
      STATUS="FAIL"
      break
    fi
  done
}

stop_sidecar_if_requested() {
  if [[ "$STOP_AFTER_TEST" != "true" || -z "$STARTED_PID" ]]; then
    return
  fi
  if kill -0 "$STARTED_PID" >/dev/null 2>&1; then
    kill "$STARTED_PID" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      if ! kill -0 "$STARTED_PID" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
  fi
}

on_exit() {
  local original_exit=$?
  trap - EXIT
  stop_sidecar_if_requested
  compute_status
  write_acceptance
  if [[ "$STATUS" == "PASS" ]]; then
    echo "A2 Routinator HTTP sidecar PASS"
    echo "check_file=${CHECK_FILE}"
    if [[ "$STOP_AFTER_TEST" != "true" ]]; then
      echo "sidecar_pid=${STARTED_PID}"
      echo "stop_with: kill \$(cat ${PID_FILE})"
    fi
    exit 0
  fi
  echo "A2 Routinator HTTP sidecar FAIL" >&2
  echo "check_file=${CHECK_FILE}" >&2
  exit "$original_exit"
}

trap on_exit EXIT

mkdir -p "$BASE_DIR" "$(dirname "$CHECK_FILE")" "$(dirname "$PID_FILE")" "$(dirname "$LOG_FILE")" "$EXPORT_OUT_ROOT"

if [[ ! "$HTTP_PORT" =~ ^[0-9]+$ ]] || (( HTTP_PORT < 1 || HTTP_PORT > 65535 )); then
  record_fail "invalid_http_port:${HTTP_PORT}"
  exit 1
fi

if [[ ! -x "$PYTHON_BIN" ]]; then
  record_fail "python_bin_not_executable:${PYTHON_BIN}"
  exit 1
fi

if [[ ! -x "$ROUTINATOR_BIN" ]]; then
  record_fail "routinator_bin_not_executable:${ROUTINATOR_BIN}"
  exit 1
fi

if ROUTINATOR_VERSION="$("$ROUTINATOR_BIN" --version 2>&1 | sed -n '1p')"; then
  :
else
  record_fail "routinator_version_failed"
  exit 1
fi

if [[ -f "$PID_FILE" ]]; then
  old_pid="$(tr -dc '0-9' < "$PID_FILE" || true)"
  if [[ -n "$old_pid" ]] && kill -0 "$old_pid" >/dev/null 2>&1; then
    record_fail "pid_file_points_to_running_process:${old_pid}"
    exit 1
  fi
fi
PID_FILE_CLEAR="true"

port_check_rc=0
port_is_listening || port_check_rc=$?
if [[ "$port_check_rc" == "0" ]]; then
  record_fail "http_port_already_listening:${HTTP_PORT}"
  exit 1
elif [[ "$port_check_rc" == "2" ]]; then
  record_fail "ss_or_netstat_not_found"
  exit 1
else
  PORT_FREE_BEFORE="true"
fi

NO_RTR_ARGS=()
SERVER_HELP="$("$ROUTINATOR_BIN" server --help 2>&1 || true)"
if printf '%s\n' "$SERVER_HELP" | grep -Eq -- '(^|[[:space:]])--no-rtr([,[:space:]]|$)'; then
  NO_RTR_ARGS=(--no-rtr)
fi

{
  echo "==== $(date -u +%Y-%m-%dT%H:%M:%SZ) starting Routinator HTTP sidecar ===="
  echo "repo_root=${REPO_ROOT}"
  echo "python_bin=${PYTHON_BIN}"
  echo "routinator_bin=${ROUTINATOR_BIN}"
  echo "routinator_version=${ROUTINATOR_VERSION}"
  echo "http_addr=${HTTP_ADDR}"
  echo "refresh_sec=${REFRESH_SEC}"
  echo "max_wait_sec=${MAX_WAIT_SEC}"
  echo "no_rtr_args=${NO_RTR_ARGS[*]:-}"
} >> "$LOG_FILE"

START_CMD=("$ROUTINATOR_BIN" server --http "$HTTP_ADDR" --refresh "$REFRESH_SEC")
if [[ ${#NO_RTR_ARGS[@]} -gt 0 ]]; then
  START_CMD+=("${NO_RTR_ARGS[@]}")
fi

nohup "${START_CMD[@]}" >> "$LOG_FILE" 2>&1 &
STARTED_PID="$!"
echo "$STARTED_PID" > "$PID_FILE"
SERVER_STARTED="true"

for _ in $(seq 1 120); do
  if ! kill -0 "$STARTED_PID" >/dev/null 2>&1; then
    record_fail "routinator_server_exited_early"
    exit 1
  fi
  if port_is_listening; then
    LISTEN_READY="true"
    break
  fi
  sleep 1
done

if [[ "$LISTEN_READY" != "true" ]]; then
  record_fail "http_listener_not_ready:${HTTP_ADDR}"
  exit 1
fi

{
  echo "---- listener check for ${HTTP_PORT} ----"
  if command -v ss >/dev/null 2>&1; then
    ss -ltnp 2>/dev/null | grep -E "(:|\\])${HTTP_PORT}\\b" || true
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltnp 2>/dev/null | grep -E "(:|\\])${HTTP_PORT}\\b" || true
  fi
} >> "$LOG_FILE"

deadline=$(( "$(date +%s)" + MAX_WAIT_SEC ))
while (( "$(date +%s)" <= deadline )); do
  if ! kill -0 "$STARTED_PID" >/dev/null 2>&1; then
    record_fail "routinator_server_exited_during_validation"
    exit 1
  fi

  tmp_status="$(mktemp)"
  LAST_STATUS_HTTP_CODE="$(curl -sS --max-time 30 -o "$tmp_status" -w "%{http_code}" "$STATUS_URL" 2>>"$LOG_FILE" || true)"
  LAST_STATUS_BODY="$(cat "$tmp_status" 2>/dev/null || true)"
  rm -f "$tmp_status"

  if [[ "$LAST_STATUS_BODY" == *"Initial validation ongoing"* ]]; then
    VALIDATOR_HEALTH="Initial validation ongoing"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) status=${LAST_STATUS_HTTP_CODE} Initial validation ongoing" >> "$LOG_FILE"
    sleep "$POLL_SEC"
    continue
  fi

  if [[ "$LAST_STATUS_HTTP_CODE" =~ ^2[0-9][0-9]$ || "$LAST_STATUS_HTTP_CODE" =~ ^3[0-9][0-9]$ ]]; then
    STATUS_READY="true"
    VALIDATOR_HEALTH="status_ready:http_${LAST_STATUS_HTTP_CODE}"
    break
  fi

  VALIDATOR_HEALTH="status_not_ready:http_${LAST_STATUS_HTTP_CODE}"
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) status=${LAST_STATUS_HTTP_CODE} waiting for readiness" >> "$LOG_FILE"
  sleep "$POLL_SEC"
done

if [[ "$STATUS_READY" != "true" ]]; then
  record_fail "status_not_ready_before_timeout:http_${LAST_STATUS_HTTP_CODE}"
  exit 1
fi

EXPORT_CMD=(
  "$PYTHON_BIN" probe/export_routinator_live_snapshot.py
  --probe-id "$PROBE_ID"
  --out-root "$EXPORT_OUT_ROOT"
  --capture-mode http
  --routinator-url "$HTTP_URL"
  --status-path "/api/v1/status"
  --http-timeout-sec "$EXPORT_HTTP_TIMEOUT_SEC"
)

if "${EXPORT_CMD[@]}" >> "$LOG_FILE" 2>&1; then
  EXPORTER_EXIT_ZERO="true"
else
  record_fail "exporter_http_mode_failed"
fi

LATEST_METADATA="${EXPORT_OUT_ROOT}/${PROBE_ID}/latest_metadata.json"
if [[ "$EXPORTER_EXIT_ZERO" == "true" && -s "$LATEST_METADATA" ]]; then
  CAPTURE_METHOD="$("$PYTHON_BIN" -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8-sig")); print(d.get("capture_method") or "")' "$LATEST_METADATA")"
  metadata_health="$("$PYTHON_BIN" -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8-sig")); print(d.get("validator_health") or "")' "$LATEST_METADATA")"
  if [[ -n "$metadata_health" ]]; then
    VALIDATOR_HEALTH="$metadata_health"
  fi
  VRP_COUNT="$("$PYTHON_BIN" -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8-sig")); print(d.get("vrp_count") if d.get("vrp_count") is not None else "")' "$LATEST_METADATA")"
  RAW_VRP_FILE="$("$PYTHON_BIN" -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8-sig")); print(d.get("raw_vrp_file") or "")' "$LATEST_METADATA")"
  NORMALIZED_VRP_FILE="$("$PYTHON_BIN" -c 'import json,sys; d=json.load(open(sys.argv[1], encoding="utf-8-sig")); print(d.get("normalized_vrp_file") or "")' "$LATEST_METADATA")"
  if [[ "$VRP_COUNT" =~ ^[0-9]+$ ]] && (( VRP_COUNT > 0 )); then
    VRP_COUNT_GT_ZERO="true"
  else
    record_fail "vrp_count_not_gt_zero:${VRP_COUNT}"
  fi
else
  if [[ "$EXPORTER_EXIT_ZERO" == "true" ]]; then
    record_fail "latest_metadata_missing:${LATEST_METADATA}"
  fi
fi
