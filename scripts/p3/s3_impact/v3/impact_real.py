import json
import glob
from scripts.p3.s3_impact.v3.rov_bridge import compute_rov_transition

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

                before, after = compute_rov_transition(r)

                total += 1

                if before != after:
                    impact += 1

            except:
                continue

print("TOTAL =", total)
print("REAL_IMPACT =", impact)
