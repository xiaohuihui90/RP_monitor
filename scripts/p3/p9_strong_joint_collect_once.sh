#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:?usage: p9_strong_joint_collect_once.sh <env-file>}"
source "$ENV_FILE"

: "${P9_PROBE_ID:?missing P9_PROBE_ID}"
: "${P9_LOCATION:?missing P9_LOCATION}"
: "${P9_STRONG_GROUP_ID:?missing P9_STRONG_GROUP_ID}"
: "${P9_STRONG_TARGET_UTC:?missing P9_STRONG_TARGET_UTC}"
: "${P9_OBJECT_COLLECTOR_URL:?missing P9_OBJECT_COLLECTOR_URL}"
: "${P9_VRP_COLLECTOR_URL:?missing P9_VRP_COLLECTOR_URL}"
: "${P9_ROUTINATOR_BIN:?missing P9_ROUTINATOR_BIN}"

mkdir -p logs/p3 config/p3

echo "========== P9 STRONG JOINT COLLECT =========="
echo "probe_id=$P9_PROBE_ID"
echo "location=$P9_LOCATION"
echo "group_id=$P9_STRONG_GROUP_ID"
echo "target_utc=$P9_STRONG_TARGET_UTC"
echo "routinator_bin=$P9_ROUTINATOR_BIN"

python - <<'PY'
import os
import time
from datetime import datetime, timezone

target = os.environ["P9_STRONG_TARGET_UTC"].replace("Z", "+00:00")
target_dt = datetime.fromisoformat(target)
now = datetime.now(timezone.utc)
sleep_s = (target_dt - now).total_seconds()

print("now_utc =", now.isoformat())
print("target_utc =", target_dt.isoformat())
print("sleep_seconds =", sleep_s)

if sleep_s > 0:
    time.sleep(sleep_s)
else:
    print("[WARN] target time has already passed; running immediately")
PY

cat > config/p3/p9_strong_object_upload.env <<EOF
P5A_PROBE_ID=$P9_PROBE_ID
P5A_LOCATION=$P9_LOCATION
P5A_GROUP_ID=$P9_STRONG_GROUP_ID
P5A_COLLECTOR_OBJECT_URL=$P9_OBJECT_COLLECTOR_URL
P5A_PERIOD_MINUTES=10
P5A_CONNECT_TIMEOUT_SECONDS=10
P5A_MAX_TIME_SECONDS=900
P5A_CURL_RETRY=2
P5A_CURL_RETRY_DELAY=5
EOF

cat > config/p3/p9_strong_vrp_upload.env <<EOF
P8_VRP_PROBE_ID=$P9_PROBE_ID
P8_VRP_LOCATION=$P9_LOCATION
P8_VRP_GROUP_ID=$P9_STRONG_GROUP_ID
P8_VRP_COLLECTOR_URL=$P9_VRP_COLLECTOR_URL
P8_VRP_ROUTINATOR_BIN=$P9_ROUTINATOR_BIN
P8_VRP_USE_NOUPDATE=true
P8_VRP_CONNECT_TIMEOUT_SECONDS=10
P8_VRP_MAX_TIME_SECONDS=900
P8_VRP_CURL_RETRY=2
P8_VRP_CURL_RETRY_DELAY=5
EOF

echo "========== OBJECT ENV =========="
cat config/p3/p9_strong_object_upload.env

echo "========== VRP ENV =========="
cat config/p3/p9_strong_vrp_upload.env

echo "========== RUN OBJECT UPLOAD =========="
bash scripts/p3/e4a_object_auto_export_upload.sh config/p3/p9_strong_object_upload.env \
  | tee "logs/p3/p9_strong_object_${P9_PROBE_ID}_${P9_STRONG_GROUP_ID}.log"

echo "========== RUN VRP UPLOAD =========="
bash scripts/p3/e4a_vrp_group_auto_export_upload.sh config/p3/p9_strong_vrp_upload.env \
  | tee "logs/p3/p9_strong_vrp_${P9_PROBE_ID}_${P9_STRONG_GROUP_ID}.log"

echo "[DONE] P9 strong joint collect finished for $P9_PROBE_ID"
