import json
from collections import defaultdict

inp = "data/p3_control_plane_input/vrp_diff_lifetime_records.jsonl"

print("LOADING VRP DIFF...")

data = defaultdict(list)

with open(inp) as f:
    for line in f:
        try:
            r = json.loads(line)
            key = (r.get("prefix"), r.get("asn"))
            data[key].append(r)
        except:
            continue

total = 0
impact = 0

for (prefix, asn), events in data.items():

    total += 1

    vrp_div = any(e.get("divergence") != "NONE" for e in events)

    # control-plane impact rule (S3 baseline)
    is_impact = vrp_div and len(events) > 3

    if is_impact:
        impact += 1

    print({
        "prefix": prefix,
        "asn": asn,
        "vrp_divergence": vrp_div,
        "impact": is_impact
    })

print("TOTAL PREFIXES:", total)
print("IMPACT CANDIDATES:", impact)
