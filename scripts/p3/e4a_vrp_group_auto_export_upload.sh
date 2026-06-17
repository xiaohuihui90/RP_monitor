#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

export PYTHONNOUSERSITE=1
export PYTHONPATH="$PWD:${PYTHONPATH:-}"

CONFIG_FILE="${1:-config/p3/e4a_vrp_group_auto_upload.env}"

if [ ! -f "$CONFIG_FILE" ]; then
  echo "[ERROR] config file not found: $CONFIG_FILE" >&2
  exit 2
fi

# shellcheck disable=SC1090
source "$CONFIG_FILE"

: "${P8_VRP_PROBE_ID:?missing P8_VRP_PROBE_ID}"
: "${P8_VRP_LOCATION:?missing P8_VRP_LOCATION}"
: "${P8_VRP_GROUP_ID:?missing P8_VRP_GROUP_ID}"
: "${P8_VRP_COLLECTOR_URL:?missing P8_VRP_COLLECTOR_URL}"

P8_VRP_OUT_ROOT="${P8_VRP_OUT_ROOT:-data/probe/e4a_vrp_group_auto}"
P8_VRP_USE_NOUPDATE="${P8_VRP_USE_NOUPDATE:-true}"
P8_VRP_LOCK_FILE="${P8_VRP_LOCK_FILE:-data/probe/e4a_vrp_group_auto.lock}"
: "${P8_VRP_ROUTINATOR_BIN:?missing P8_VRP_ROUTINATOR_BIN; use absolute path, do not rely on PATH}"

mkdir -p "$P8_VRP_OUT_ROOT"/{latest,history} "$(dirname "$P8_VRP_LOCK_FILE")" logs/p3

exec 9>"$P8_VRP_LOCK_FILE"
if ! flock -n 9; then
  echo "[SKIP] previous VRP export/upload still running"
  exit 0
fi

EXPORT_ID="$(date -u +%Y%m%dT%H%M%SZ)"
START_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HIST_DIR="$P8_VRP_OUT_ROOT/history/$EXPORT_ID"
LATEST_DIR="$P8_VRP_OUT_ROOT/latest"
RESP_DIR="$LATEST_DIR/upload_responses"

mkdir -p "$HIST_DIR" "$LATEST_DIR" "$RESP_DIR"

RAW="$HIST_DIR/${P8_VRP_PROBE_ID}_vrps.raw.json"
GZIP="$HIST_DIR/${P8_VRP_PROBE_ID}_vrps.raw.json.gz"
MANIFEST="$HIST_DIR/manifest.json"
SHA="$HIST_DIR/sha256.txt"
RESP="$RESP_DIR/${P8_VRP_PROBE_ID}_${P8_VRP_GROUP_ID}_vrp_upload_response.json"

VALIDATOR_VERSION="$("$P8_VRP_ROUTINATOR_BIN" --version 2>/dev/null | head -n 1 || echo 'Routinator unknown')"

echo "========== E4A VRP GROUP_AUTO EXPORT/UPLOAD =========="
echo "probe_id=$P8_VRP_PROBE_ID"
echo "location=$P8_VRP_LOCATION"
echo "snapshot_group_id=$P8_VRP_GROUP_ID"
echo "export_id=$EXPORT_ID"
echo "collector_url=$P8_VRP_COLLECTOR_URL"
echo "validator_version=$VALIDATOR_VERSION"
echo "routinator_bin=$P8_VRP_ROUTINATOR_BIN"
echo "start_at=$START_AT"

if [ "$P8_VRP_USE_NOUPDATE" = "true" ]; then
  "$P8_VRP_ROUTINATOR_BIN" vrps --format json --noupdate --output "$RAW"
else
  "$P8_VRP_ROUTINATOR_BIN" vrps --format json --output "$RAW"
fi

FINISH_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python - <<PY
import json
from pathlib import Path

raw = Path("$RAW")
obj = json.loads(raw.read_text(encoding="utf-8"))

roa_count = 0
router_key_count = 0
aspa_count = 0

if isinstance(obj, list):
    roa_count = len(obj)
elif isinstance(obj, dict):
    for k in ["roas", "vrps", "validated_roa_payloads", "validatedRoas"]:
        v = obj.get(k)
        if isinstance(v, list):
            roa_count = len(v)
            break
    for k in ["routerKeys", "router_keys", "routerkeys"]:
        v = obj.get(k)
        if isinstance(v, list):
            router_key_count = len(v)
            break
    for k in ["aspas", "aspa"]:
        v = obj.get(k)
        if isinstance(v, list):
            aspa_count = len(v)
            break

manifest = {
    "schema": "s3.stage3.e4a.vrp_group_auto_export_manifest.v1",
    "probe_id": "$P8_VRP_PROBE_ID",
    "location": "$P8_VRP_LOCATION",
    "snapshot_group_id": "$P8_VRP_GROUP_ID",
    "export_id": "$EXPORT_ID",
    "validator": "routinator",
    "validator_version": "$VALIDATOR_VERSION",
    "generatedTime": "$START_AT",
    "export_started_at": "$START_AT",
    "export_finished_at": "$FINISH_AT",
    "roa_count": roa_count,
    "router_key_count": router_key_count,
    "aspa_count": aspa_count,
    "raw_json_size_bytes": raw.stat().st_size,
    "used_noupdate": "$P8_VRP_USE_NOUPDATE" == "true",
    "upload_ready": True
}

Path("$MANIFEST").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(manifest, ensure_ascii=False, indent=2))
PY

gzip -c "$RAW" > "$GZIP"

GZIP_BASENAME="$(basename "$GZIP")"
sha256sum "$GZIP" | sed "s#  .*#  ${GZIP_BASENAME}#" > "$SHA"

cp "$RAW" "$LATEST_DIR/${P8_VRP_PROBE_ID}_vrps.raw.json"
cp "$GZIP" "$LATEST_DIR/${P8_VRP_PROBE_ID}_vrps.raw.json.gz"
cp "$MANIFEST" "$LATEST_DIR/manifest.json"
cp "$SHA" "$LATEST_DIR/sha256.txt"

curl -sS \
  --connect-timeout "${P8_VRP_CONNECT_TIMEOUT_SECONDS:-10}" \
  --max-time "${P8_VRP_MAX_TIME_SECONDS:-900}" \
  --retry "${P8_VRP_CURL_RETRY:-2}" \
  --retry-delay "${P8_VRP_CURL_RETRY_DELAY:-5}" \
  -X POST "$P8_VRP_COLLECTOR_URL" \
  -F "probe_id=${P8_VRP_PROBE_ID}" \
  -F "validator=routinator" \
  -F "validator_version=${VALIDATOR_VERSION}" \
  -F "generatedTime=${START_AT}" \
  -F "snapshot_group_id=${P8_VRP_GROUP_ID}" \
  -F "manifest=@${MANIFEST};type=application/json" \
  -F "file=@${GZIP};type=application/gzip" \
  -F "sha256=@${SHA};type=text/plain" \
  | tee "$RESP" \
  | python -m json.tool

python - <<PY
import json
from pathlib import Path

resp = Path("$RESP")
obj = json.loads(resp.read_text(encoding="utf-8"))

expected = "$P8_VRP_GROUP_ID"
record = obj.get("snapshot_record", {})
group = obj.get("group", {})

ok = (
    obj.get("status") == "ok"
    and record.get("snapshot_group_id") == expected
    and group.get("snapshot_group_id") == expected
    and record.get("sha256_gzip_ok") is True
    and record.get("gzip_valid") is True
)

print("expected_group_id =", expected)
print("record_group_id =", record.get("snapshot_group_id"))
print("group_id =", group.get("snapshot_group_id"))
print("sha256_gzip_ok =", record.get("sha256_gzip_ok"))
print("gzip_valid =", record.get("gzip_valid"))
print("upload_ok =", ok)

if not ok:
    raise SystemExit("[ERROR] VRP group_auto upload failed")
PY

cat > "$LATEST_DIR/P8_vrp_group_auto_upload_acceptance.txt" <<EOF
P8_VRP_GROUP_AUTO_UPLOAD_ONCE=DONE

probe_id = $P8_VRP_PROBE_ID
location = $P8_VRP_LOCATION
snapshot_group_id = $P8_VRP_GROUP_ID
export_id = $EXPORT_ID

collector_url = $P8_VRP_COLLECTOR_URL
validator = routinator
validator_version = $VALIDATOR_VERSION

generatedTime = $START_AT
export_started_at = $START_AT
export_finished_at = $FINISH_AT

upload_response = $RESP
upload_status = success

P8_vrp_upload_acceptance = True
EOF

cat "$LATEST_DIR/P8_vrp_group_auto_upload_acceptance.txt"

echo "[DONE] VRP group_auto export/upload success"
