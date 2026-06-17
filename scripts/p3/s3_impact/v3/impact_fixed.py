import json
import glob
from window_index import build

windows = build()

files = glob.glob(
    "data/p3_collector/m18_diff_lifetime/**/vrp_diff_lifetime_records.jsonl",
    recursive=True
)

total = 0
impact = 0

for f in files:
    with open(f) as fp:
        for line in fp:
            try:
                r = json.loads(line)

                window = r.get("window_id", None)
                divergence = r.get("divergence", "NONE")

                total += 1

                # ✔ 真正join
                if window in windows and divergence != "NONE":
                    impact += 1

            except:
                continue

print("TOTAL =", total)
print("IMPACT =", impact)
print("WINDOWS =", len(windows))
