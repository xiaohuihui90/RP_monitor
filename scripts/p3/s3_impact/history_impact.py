import json
import glob
from scripts.p3.control_adapter.rov import rov_check

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

                prefix = r.get("prefix")
                asn = r.get("asn")
                vrp_state = r.get("vrp_state", "VALID")
                divergence = r.get("divergence", "NONE")

                rov_before = rov_check(prefix, asn, vrp_state)
                rov_after  = rov_check(prefix, asn, vrp_state)

                is_impact = (rov_before != rov_after) or (divergence != "NONE")

                total += 1
                if is_impact:
                    impact += 1

            except:
                continue

print("TOTAL =", total)
print("IMPACT =", impact)
