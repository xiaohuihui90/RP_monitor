#!/usr/bin/env bash
set -euo pipefail

: "${PROBE_ID:?missing PROBE_ID}"
: "${TARGET_WINDOW_ID:?missing TARGET_WINDOW_ID}"
: "${COLLECTOR_URL:?missing COLLECTOR_URL}"
: "${RAW_SIDECAR_URL:?missing RAW_SIDECAR_URL}"
: "${TOKEN:?missing TOKEN}"

cd ~/s3_stage3_v3_code
export PYTHONNOUSERSITE=1
export PYTHONPATH="$PWD:${PYTHONPATH:-}"

utc_now() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

epoch_now() {
  date -u +%s
}

duration_or_null() {
  local s="${1:-}"
  local e="${2:-}"
  if [ -n "$s" ] && [ -n "$e" ]; then
    python - <<PY
try:
    print(float("$e") - float("$s"))
except Exception:
    print("null")
PY
  else
    echo "null"
  fi
}

write_timing_json() {
  local timing_path="$1"
  local status="$2"

  python - "$timing_path" "$status" <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

timing_path = Path(sys.argv[1])
status = sys.argv[2]

def env(name, default=None):
    return os.environ.get(name, default)

def duration(start, end):
    try:
        if start and end:
            return float(end) - float(start)
    except Exception:
        pass
    return None

def get_timedatectl():
    try:
        p = subprocess.run(
            ["timedatectl"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        if p.returncode != 0:
            return {
                "timedatectl_available": False,
                "ntp_sync_status": "unknown",
                "ntp_service_status": "unknown",
                "clock_offset_hint_sec": None,
                "timedatectl_error": p.stderr[:500],
            }

        raw = p.stdout
        sync = "unknown"
        ntp_service = "unknown"

        for line in raw.splitlines():
            s = line.strip()
            if s.startswith("System clock synchronized:"):
                v = s.split(":", 1)[1].strip().lower()
                sync = "synchronized" if v == "yes" else "unsynchronized"
            elif s.startswith("NTP service:"):
                ntp_service = s.split(":", 1)[1].strip()

        return {
            "timedatectl_available": True,
            "ntp_sync_status": sync,
            "ntp_service_status": ntp_service,
            "clock_offset_hint_sec": None,
            "timedatectl_raw": raw[:2000],
        }
    except Exception as e:
        return {
            "timedatectl_available": False,
            "ntp_sync_status": "unknown",
            "ntp_service_status": "unknown",
            "clock_offset_hint_sec": None,
            "timedatectl_error": str(e),
        }

td = get_timedatectl()

obj = {
    "schema": "s3.m17c.probe_once_timing.v1",
    "status": status,
    "generated_at_utc": env("TIMING_GENERATED_AT_UTC"),

    "window_id": env("TARGET_WINDOW_ID"),
    "probe_id": env("PROBE_ID"),

    "probe_once_started_at_utc": env("PROBE_ONCE_STARTED_AT_UTC"),
    "probe_once_finished_at_utc": env("PROBE_ONCE_FINISHED_AT_UTC"),
    "probe_once_duration_sec": duration(env("PROBE_ONCE_STARTED_EPOCH"), env("PROBE_ONCE_FINISHED_EPOCH")),

    "m245_collect_started_at_utc": env("M245_COLLECT_STARTED_AT_UTC"),
    "m245_collect_finished_at_utc": env("M245_COLLECT_FINISHED_AT_UTC"),
    "m245_collect_duration_sec": duration(env("M245_COLLECT_STARTED_EPOCH"), env("M245_COLLECT_FINISHED_EPOCH")),

    "raw_vrp_export_started_at_utc": env("RAW_VRP_EXPORT_STARTED_AT_UTC"),
    "raw_vrp_export_finished_at_utc": env("RAW_VRP_EXPORT_FINISHED_AT_UTC"),
    "raw_vrp_export_duration_sec": duration(env("RAW_VRP_EXPORT_STARTED_EPOCH"), env("RAW_VRP_EXPORT_FINISHED_EPOCH")),

    "raw_vrp_upload_started_at_utc": env("RAW_VRP_UPLOAD_STARTED_AT_UTC"),
    "raw_vrp_upload_finished_at_utc": env("RAW_VRP_UPLOAD_FINISHED_AT_UTC"),
    "raw_vrp_upload_duration_sec": duration(env("RAW_VRP_UPLOAD_STARTED_EPOCH"), env("RAW_VRP_UPLOAD_FINISHED_EPOCH")),

    "probe_date_utc_at_start": env("PROBE_DATE_UTC_AT_START"),
    "probe_date_utc_at_finish": env("PROBE_DATE_UTC_AT_FINISH"),

    "validator_update_mode": "noupdate",
    "routinator_service_mode": "cli_cache_export",

    "timedatectl_available": td.get("timedatectl_available"),
    "ntp_sync_status": td.get("ntp_sync_status"),
    "ntp_service_status": td.get("ntp_service_status"),
    "clock_offset_hint_sec": td.get("clock_offset_hint_sec"),

    "notes": [
        "raw VRP export uses routinator vrps --format json --noupdate through export_raw_vrp_sidecar.py",
        "timing fields are measured on the probe host",
        "tar package includes timing metadata written before upload; collector-side receipt time should be used as server-side upload received time"
    ],
}

if "timedatectl_raw" in td:
    obj["timedatectl_raw"] = td["timedatectl_raw"]
if "timedatectl_error" in td:
    obj["timedatectl_error"] = td["timedatectl_error"]

timing_path.parent.mkdir(parents=True, exist_ok=True)
timing_path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

echo "===== M17C PROBE ONCE START ====="
echo "PROBE_ID=$PROBE_ID"
echo "TARGET_WINDOW_ID=$TARGET_WINDOW_ID"
echo "COLLECTOR_URL=$COLLECTOR_URL"
echo "RAW_SIDECAR_URL=$RAW_SIDECAR_URL"
echo "TOKEN_LENGTH=${#TOKEN}"
date -u

export PROBE_ONCE_STARTED_AT_UTC="$(utc_now)"
export PROBE_ONCE_STARTED_EPOCH="$(epoch_now)"
export PROBE_DATE_UTC_AT_START="$(date -u)"

SIDECAR_DIR="data/probe/m245_three_layer_baseline/raw_vrp_sidecar/${TARGET_WINDOW_ID}/${PROBE_ID}"
TIMING_PATH="${SIDECAR_DIR}/probe_m17c_once_timing.json"
mkdir -p "$SIDECAR_DIR"

echo
echo "===== STEP 1: M245 collect/upload ====="
export M245_COLLECT_STARTED_AT_UTC="$(utc_now)"
export M245_COLLECT_STARTED_EPOCH="$(epoch_now)"

python scripts/p3/m245/continuous/probe_collect_upload_once.py \
  --project-dir ~/s3_stage3_v3_code \
  --probe-id "$PROBE_ID" \
  --collector-url "$COLLECTOR_URL" \
  --token "$TOKEN" \
  --out-dir "data/probe/m245_three_layer_baseline/h1_runs/${TARGET_WINDOW_ID}/${PROBE_ID}" \
  --window-id "$TARGET_WINDOW_ID" \
  --timeout-sec 1800 \
  --vrp-timeout-sec 1200 \
  --validator-update-mode noupdate \
  --vrp-count-low-threshold 100000 \
  --window-quality late

export M245_COLLECT_FINISHED_AT_UTC="$(utc_now)"
export M245_COLLECT_FINISHED_EPOCH="$(epoch_now)"

echo
echo "===== STEP 2: raw VRP sidecar export ====="
export RAW_VRP_EXPORT_STARTED_AT_UTC="$(utc_now)"
export RAW_VRP_EXPORT_STARTED_EPOCH="$(epoch_now)"

python scripts/p3/m245/continuous/export_raw_vrp_sidecar.py \
  --probe-id "$PROBE_ID" \
  --window-id "$TARGET_WINDOW_ID" \
  --format json \
  --timeout-sec 1200

export RAW_VRP_EXPORT_FINISHED_AT_UTC="$(utc_now)"
export RAW_VRP_EXPORT_FINISHED_EPOCH="$(epoch_now)"

# 写入“上传前版本”的 timing.json，使其被 sidecar tar.gz 打包上传到 collector。
export RAW_VRP_UPLOAD_STARTED_AT_UTC="$(utc_now)"
export RAW_VRP_UPLOAD_STARTED_EPOCH="$(epoch_now)"
export RAW_VRP_UPLOAD_FINISHED_AT_UTC=""
export RAW_VRP_UPLOAD_FINISHED_EPOCH=""
export PROBE_ONCE_FINISHED_AT_UTC=""
export PROBE_ONCE_FINISHED_EPOCH=""
export PROBE_DATE_UTC_AT_FINISH=""
export TIMING_GENERATED_AT_UTC="$(utc_now)"

write_timing_json "$TIMING_PATH" "upload_started"

echo
echo "===== STEP 3: raw VRP sidecar upload ====="

python -m scripts.p3.m17c.raw_vrp_sidecar_uploader \
  --project-dir ~/s3_stage3_v3_code \
  --probe-id "$PROBE_ID" \
  --window-id "$TARGET_WINDOW_ID" \
  --collector-url "$RAW_SIDECAR_URL" \
  --token "$TOKEN" \
  --out-dir /tmp

export RAW_VRP_UPLOAD_FINISHED_AT_UTC="$(utc_now)"
export RAW_VRP_UPLOAD_FINISHED_EPOCH="$(epoch_now)"
export PROBE_ONCE_FINISHED_AT_UTC="$(utc_now)"
export PROBE_ONCE_FINISHED_EPOCH="$(epoch_now)"
export PROBE_DATE_UTC_AT_FINISH="$(date -u)"
export TIMING_GENERATED_AT_UTC="$(utc_now)"

# 本地最终版包含 upload_finished；collector 端 tar 内版本至少包含 export timing 和 upload_started。
write_timing_json "$TIMING_PATH" "PASS"

echo
echo "===== STEP 4: local checks ====="

H1_CHECK="data/probe/m245_three_layer_baseline/h1_runs/${TARGET_WINDOW_ID}/${PROBE_ID}/H1_probe_collect_upload_once_check_${PROBE_ID}_${TARGET_WINDOW_ID}.txt"
SIDECAR_CHECK="data/probe/m245_three_layer_baseline/raw_vrp_sidecar/${TARGET_WINDOW_ID}/${PROBE_ID}/raw_vrp_export_check.txt"
UPLOAD_RESULT="/tmp/raw_vrp_sidecar_upload_result_${PROBE_ID}_${TARGET_WINDOW_ID}.json"

echo
echo "----- H1 check -----"
cat "$H1_CHECK"

echo
echo "----- raw sidecar check -----"
cat "$SIDECAR_CHECK"

echo
echo "----- timing metadata -----"
python -m json.tool "$TIMING_PATH" | head -n 160

echo
echo "----- upload result -----"
python -m json.tool "$UPLOAD_RESULT" | head -n 120

echo
echo "M17C_PROBE_ONCE=PASS"
