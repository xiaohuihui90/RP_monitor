#!/usr/bin/env bash
set -Eeuo pipefail

PYTHON_BIN="${PYTHON_BIN:-/home/zhangxiaohui/installers/ENTER/envs/s3-radar/bin/python}"
ROUTINATOR_BIN="${ROUTINATOR_BIN:-/home/zhangxiaohui/.cargo/bin/routinator}"
MIN_FREE_GB="10"
REPO_ROOT=""

usage() {
  printf '%s\n' \
    "Usage:" \
    "  scripts/runtime/probe_env_preflight.sh [options]" \
    "" \
    "Options:" \
    "  --repo-root PATH       Repository root. Default: auto-detect from this script" \
    "  --python-bin PATH      Python binary. Default: ${PYTHON_BIN}" \
    "  --routinator-bin PATH  Routinator binary. Default: ${ROUTINATOR_BIN}" \
    "  --min-free-gb GB       Minimum free disk space. Default: ${MIN_FREE_GB}" \
    "  -h, --help             Show this help" \
    "" \
    "Checks Python, Routinator, git hash, PYTHONPATH, disk, cron, required" \
    "scripts, data/probe writability, and routinator --version."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root)
      REPO_ROOT="${2:?missing value for --repo-root}"
      shift 2
      ;;
    --python-bin)
      PYTHON_BIN="${2:?missing value for --python-bin}"
      shift 2
      ;;
    --routinator-bin)
      ROUTINATOR_BIN="${2:?missing value for --routinator-bin}"
      shift 2
      ;;
    --min-free-gb)
      MIN_FREE_GB="${2:?missing value for --min-free-gb}"
      shift 2
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
if [[ -z "$REPO_ROOT" ]]; then
  REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
else
  REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
fi

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

print_result() {
  local level="$1"
  local name="$2"
  local detail="${3:-}"
  printf '%-5s %s' "$level" "$name"
  if [[ -n "$detail" ]]; then
    printf ' :: %s' "$detail"
  fi
  printf '\n'
  case "$level" in
    PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
    FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    WARN) WARN_COUNT=$((WARN_COUNT + 1)) ;;
  esac
}

check_file_executable() {
  local name="$1"
  local path="$2"
  if [[ -x "$path" ]]; then
    print_result PASS "$name" "$path"
  elif [[ -e "$path" ]]; then
    print_result FAIL "$name" "exists but is not executable: $path"
  else
    print_result FAIL "$name" "missing: $path"
  fi
}

check_required_file() {
  local rel="$1"
  local path="$REPO_ROOT/$rel"
  if [[ -f "$path" ]]; then
    print_result PASS "required_script:$rel"
  else
    print_result FAIL "required_script:$rel" "missing"
  fi
}

printf 'P1 probe environment preflight\n'
printf 'repo_root=%s\n' "$REPO_ROOT"
printf 'python_bin=%s\n' "$PYTHON_BIN"
printf 'routinator_bin=%s\n' "$ROUTINATOR_BIN"
printf 'min_free_gb=%s\n' "$MIN_FREE_GB"
printf '\n[checks]\n'

if [[ -d "$REPO_ROOT/.git" ]]; then
  if git_hash="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null)"; then
    print_result PASS "git_commit_hash" "$git_hash"
  else
    print_result FAIL "git_commit_hash" "git rev-parse failed"
  fi
else
  print_result FAIL "git_commit_hash" ".git directory not found"
fi

check_file_executable "python_path" "$PYTHON_BIN"
if [[ -x "$PYTHON_BIN" ]]; then
  if python_version="$("$PYTHON_BIN" --version 2>&1 | head -n 1)"; then
    print_result PASS "python_version" "$python_version"
  else
    print_result FAIL "python_version" "python --version failed"
  fi
fi

check_file_executable "routinator_path" "$ROUTINATOR_BIN"
if [[ -x "$ROUTINATOR_BIN" ]]; then
  if routinator_version="$("$ROUTINATOR_BIN" --version 2>&1 | head -n 1)"; then
    print_result PASS "routinator_version" "$routinator_version"
  else
    print_result FAIL "routinator_version" "routinator --version failed"
  fi
fi

pythonpath_value="${PYTHONPATH:-}"
if [[ -z "$pythonpath_value" ]]; then
  print_result WARN "PYTHONPATH" "unset; cron installer will export repo root"
elif [[ ":$pythonpath_value:" == *":$REPO_ROOT:"* ]]; then
  print_result PASS "PYTHONPATH" "$pythonpath_value"
else
  print_result WARN "PYTHONPATH" "does not include repo root: $pythonpath_value"
fi

if command -v df >/dev/null 2>&1; then
  available_kb="$(df -Pk "$REPO_ROOT" | awk 'NR==2 {print $4}')"
  threshold_kb=$((MIN_FREE_GB * 1024 * 1024))
  if [[ "$available_kb" =~ ^[0-9]+$ ]] && (( available_kb >= threshold_kb )); then
    free_gb="$(awk -v kb="$available_kb" 'BEGIN {printf "%.2f", kb / 1024 / 1024}')"
    print_result PASS "disk_free" "${free_gb}GB available"
  else
    free_gb="$(awk -v kb="${available_kb:-0}" 'BEGIN {printf "%.2f", kb / 1024 / 1024}')"
    print_result FAIL "disk_free" "${free_gb}GB available, need >= ${MIN_FREE_GB}GB"
  fi
else
  print_result FAIL "disk_free" "df command not found"
fi

if command -v crontab >/dev/null 2>&1; then
  print_result PASS "cron_available" "$(command -v crontab)"
  if crontab -l >/dev/null 2>&1; then
    print_result PASS "cron_readable" "current crontab readable"
  else
    print_result WARN "cron_readable" "no crontab installed or crontab -l returned non-zero"
  fi
else
  print_result FAIL "cron_available" "crontab command not found"
fi

required_scripts=(
  "probe/export_routinator_live_snapshot.py"
  "probe/diff_live_vrp_snapshots.py"
  "probe/msal_minimal_attribution.py"
  "probe/run_live_vrp_msal_once.py"
  "probe/run_probe_live_msal_cycle.py"
  "probe/summarize_live_msal_cycles.py"
  "probe/check_live_msal_cron_health.py"
  "probe/build_cycle_artifact_manifest.py"
  "probe/archive_cycle_artifacts.py"
  "scripts/runtime/install_probe_cron.sh"
)

for rel in "${required_scripts[@]}"; do
  check_required_file "$rel"
done

data_probe_dir="$REPO_ROOT/data/probe"
if mkdir -p "$data_probe_dir" 2>/dev/null; then
  test_file="$data_probe_dir/.p1_preflight_write_test.$$"
  if printf 'ok\n' > "$test_file" 2>/dev/null; then
    rm -f "$test_file"
    print_result PASS "data_probe_writable" "$data_probe_dir"
  else
    print_result FAIL "data_probe_writable" "cannot write to $data_probe_dir"
  fi
else
  print_result FAIL "data_probe_writable" "cannot create $data_probe_dir"
fi

printf '\n[summary]\n'
printf 'pass_count=%s\n' "$PASS_COUNT"
printf 'warn_count=%s\n' "$WARN_COUNT"
printf 'fail_count=%s\n' "$FAIL_COUNT"

if (( FAIL_COUNT == 0 )); then
  printf 'P1_PROBE_ENV_PREFLIGHT=PASS\n'
  exit 0
fi

printf 'P1_PROBE_ENV_PREFLIGHT=FAIL\n'
exit 1