import json
from collections import defaultdict
import glob

files = glob.glob(
    "data/p3_collector/m18_diff_lifetime/**/vrp_diff_lifetime_records.jsonl",
    recursive=True
)

print("WINDOWS FOUND:", len(files))

window_stats = {}

for f in files:
    window_id = f.split("/")[-2]

    total = 0
    divergence = 0
    impact_proxy = 0

    with open(f) as fp:
        for line in fp:
            r = json.loads(line)

            total += 1

            if r.get("divergence") != "NONE":
                divergence += 1

            # proxy impact rule (no control-plane yet)
            if r.get("vrp_state") == "VALID" and r.get("divergence") != "NONE":
                impact_proxy += 1

    window_stats[window_id] = {
        "total": total,
        "divergence": divergence,
        "impact_proxy": impact_proxy
    }

print("\n=== LONGITUDINAL SUMMARY ===")
for k, v in window_stats.items():
    print(k, v)
