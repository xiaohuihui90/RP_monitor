import json

vrp_file = "data/p3_impact_engine/m18_fusion/vrp_diff_lifetime_records.jsonl"
div_file = "data/p3_impact_engine/m18_fusion/persistent_divergence_candidates.jsonl"

# load divergence map
div_map = {}

with open(div_file) as f:
    for line in f:
        r = json.loads(line)
        key = (r.get("prefix"), r.get("asn"))
        div_map[key] = r

total = 0
impact = 0

with open(vrp_file) as f:
    for line in f:
        r = json.loads(line)

        key = (r.get("prefix"), r.get("asn"))

        divergence = div_map.get(key, {}).get("divergence_type", "NONE")

        # =========================
        # CONTROL PLANE IMPACT RULE
        # =========================
        if divergence != "NONE":
            impact += 1

        total += 1

print("TOTAL VRP EVENTS:", total)
print("CONTROL-PLANE IMPACT CANDIDATES:", impact)
