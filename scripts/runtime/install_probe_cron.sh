#!/usr/bin/env bash
set -Eeuo pipefail

PROBE_ID=""
REPO_ROOT=""
PYTHON_BIN="/home/zhangxiaohui/installers/ENTER/envs/s3-radar/bin/python"
ROUTINATOR_BIN="/home/zhangxiaohui/.cargo/bin/routinator"
CRON_MINUTE="7"
ENABLE="false"
DRY_RUN="false"

usage() {
  printf '%s\n' \
    "Usage:" \
    "  scripts/runtime/install_probe_cron.sh --probe-id PROBE_ID [options]" \
    "" \
    "Options:" \
    "  --probe-id ID          Probe id, for example probe-cd or probe-bj" \
    "  --repo-root PATH       Repository root. Default: auto-detect from this script" \
    "  --python-bin PATH      Python binary. Default: ${PYTHON_BIN}" \
    "  --routinator-bin PATH  Routinator binary. Default: ${ROUTINATOR_BIN}" \
    "  --cron-minute MIN      Minute field for hourly E2 cycle. Default: ${CRON_MINUTE}" \
    "  --enable               Install the planned managed crontab block" \
    "  --dry-run              Print planned crontab and wrapper only; never install" \
    "  -h, --help             Show this help" \
    "" \
    "The script prints the planned crontab first. It preserves existing crontab" \
    "content and only replaces the RP Monitor managed block for this probe." \
    "The managed cron line calls a short generated wrapper at:" \
    "  scripts/runtime/run_<probe_id>_live_msal_cycle_once.sh"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --probe-id)
      PROBE_ID="${2:?missing value for --probe-id}"
      shift 2
      ;;
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
    --cron-minute)
      CRON_MINUTE="${2:?missing value for --cron-minute}"
      shift 2
      ;;
    --enable)
      ENABLE="true"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
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

if [[ -z "$PROBE_ID" ]]; then
  echo "ERROR: --probe-id is required" >&2
  usage >&2
  exit 2
fi

if [[ ! "$CRON_MINUTE" =~ ^[0-9]+$ ]] || (( CRON_MINUTE < 0 || CRON_MINUTE > 59 )); then
  echo "ERROR: --cron-minute must be an integer between 0 and 59" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "$REPO_ROOT" ]]; then
  REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
else
  REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
fi

if [[ ! -f "$REPO_ROOT/probe/run_probe_live_msal_cycle.py" ]]; then
  echo "ERROR: required script missing: $REPO_ROOT/probe/run_probe_live_msal_cycle.py" >&2
  exit 1
fi

shell_quote() {
  local value="$1"
  printf "'%s'" "$(printf '%s' "$value" | sed "s/'/'\\\\''/g")"
}

safe_probe_id="$(printf '%s' "$PROBE_ID" | sed 's/[^A-Za-z0-9_.-]/_/g')"
wrapper_rel="scripts/runtime/run_${safe_probe_id}_live_msal_cycle_once.sh"
wrapper_path="$REPO_ROOT/$wrapper_rel"
mark_begin="# BEGIN RP_MONITOR_LIVE_MSAL_${safe_probe_id}"
mark_end="# END RP_MONITOR_LIVE_MSAL_${safe_probe_id}"

render_wrapper() {
  cat <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail

PROBE_ID=$(shell_quote "$PROBE_ID")
SAFE_PROBE_ID=$(shell_quote "$safe_probe_id")
REPO_ROOT=$(shell_quote "$REPO_ROOT")
PYTHON_BIN=$(shell_quote "$PYTHON_BIN")
ROUTINATOR_BIN=$(shell_quote "$ROUTINATOR_BIN")

cd "\$REPO_ROOT"
export PYTHONNOUSERSITE=1
export PYTHONPATH="\$REPO_ROOT:\${PYTHONPATH:-}"

LOG_PATH="logs/\${SAFE_PROBE_ID}_live_msal_cycle_cron.log"
mkdir -p logs "data/probe/e2e_msal_cycles/\$PROBE_ID"
exec >> "\$LOG_PATH" 2>&1

run_id="hourly_\$(date -u +%Y%m%dT%H%M%SZ)"
out_dir="data/probe/e2e_msal_cycles/\$PROBE_ID/\$run_id"

echo "[\$(date -u +%Y-%m-%dT%H:%M:%SZ)] starting E2 live MSAL cycle probe_id=\$PROBE_ID out_dir=\$out_dir"
set +e
"\$PYTHON_BIN" probe/run_probe_live_msal_cycle.py \\
  --probe-id "\$PROBE_ID" \\
  --snapshot-root data/probe/live_vrp_snapshots \\
  --out-dir "\$out_dir" \\
  --routinator-bin "\$ROUTINATOR_BIN" \\
  --allow-empty-events \\
  --source-pp-coverage data/p3_analysis/sec27/coverage_candidate/source_pp_coverage.jsonl \\
  --l2-object-index data/p3_analysis/sec27/l2b_effective_input_r2/l2b_candidate_effective_input.jsonl \\
  --manifest-filelist-index data/p3_analysis/sec27/b5_paper_stats/object_or_manifest_supported_subset.jsonl \\
  --candidate-evidence-table data/p3_analysis/sec27/b4c_candidate_evidence_table/candidate_evidence_table.jsonl \\
  --hash-evidence-index data/p3_analysis/sec27/b6_final_paper_tables/selected_persistent_cases.jsonl
status=\$?
set -e
echo "[\$(date -u +%Y-%m-%dT%H:%M:%SZ)] finished E2 live MSAL cycle probe_id=\$PROBE_ID status=\$status out_dir=\$out_dir"
exit "\$status"
EOF
}

write_wrapper() {
  local tmp_wrapper
  tmp_wrapper="$(mktemp "${wrapper_path}.tmp.XXXXXX")"
  render_wrapper > "$tmp_wrapper"
  chmod 0755 "$tmp_wrapper"
  mv -f "$tmp_wrapper" "$wrapper_path"
}

cycle_cron_line="${CRON_MINUTE} * * * * /bin/bash $(shell_quote "$wrapper_path")"

current_cron="$(mktemp)"
planned_cron="$(mktemp)"
cleanup() {
  rm -f "$current_cron" "$planned_cron"
}
trap cleanup EXIT

if command -v crontab >/dev/null 2>&1; then
  crontab -l > "$current_cron" 2>/dev/null || true
else
  if [[ "$ENABLE" == "true" && "$DRY_RUN" != "true" ]]; then
    echo "ERROR: crontab command not found" >&2
    exit 1
  fi
  printf '%s\n' "# WARNING: crontab command not found; dry-run planned block only." > "$current_cron"
fi
awk -v begin="$mark_begin" -v end="$mark_end" '
  $0 == begin {skip=1; next}
  $0 == end {skip=0; next}
  skip != 1 {print}
' "$current_cron" > "$planned_cron"

if [[ -s "$planned_cron" ]] && [[ "$(tail -c 1 "$planned_cron" | wc -l | tr -d ' ')" == "0" ]]; then
  printf '\n' >> "$planned_cron"
fi

{
  echo "$mark_begin"
  echo "# Probe: $PROBE_ID"
  echo "# Installed by scripts/runtime/install_probe_cron.sh"
  echo "# Wrapper: $wrapper_rel"
  echo "# Runs one E2 live MSAL cycle per hour. E3/E4/E5 remain explicit acceptance steps."
  echo "$cycle_cron_line"
  echo "$mark_end"
} >> "$planned_cron"

printf '%s\n' "----- planned crontab begin -----"
cat "$planned_cron"
printf '%s\n' "----- planned crontab end -----"
printf '%s\n' "----- planned wrapper path -----"
printf '%s\n' "$wrapper_path"
printf '%s\n' "----- planned wrapper begin -----"
render_wrapper
printf '%s\n' "----- planned wrapper end -----"

if [[ "$ENABLE" != "true" || "$DRY_RUN" == "true" ]]; then
  printf 'P1_INSTALL_PROBE_CRON=DRY_RUN\n'
  printf 'enable=%s\n' "$ENABLE"
  printf 'dry_run=%s\n' "$DRY_RUN"
  printf 'wrapper_path=%s\n' "$wrapper_path"
  exit 0
fi

write_wrapper
crontab "$planned_cron"
printf 'P1_INSTALL_PROBE_CRON=INSTALLED\n'
printf 'probe_id=%s\n' "$PROBE_ID"
printf 'cron_minute=%s\n' "$CRON_MINUTE"
printf 'wrapper_path=%s\n' "$wrapper_path"
