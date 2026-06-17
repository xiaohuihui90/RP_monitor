import json

vrp_file = "data/p3_impact_engine/m18_input/vrp_diff_lifetime_records.jsonl"
div_file = "data/p3_impact_engine/m18_input/persistent_divergence_candidates.jsonl"

print("LOADING M18 VRP LIFETIME DIFF...")

div_map = {}

# load persistent divergence
with open(div_file) as f:
    for line in f:
        try:
            r = json.loads(line)
            key = r.get("prefix","unknown") + "_" + str(r.get("asn","unknown"))
            div_map[key] = r
        except:
            continue

impact_count = 0
total = 0

with open(vrp_file) as f:
    for line in f:
        try:
            r = json.loads(line)

            prefix = r.get("prefix","unknown")
            asn = r.get("asn","unknown")

            key = prefix + "_" + str(asn)

            div = div_map.get(key, {})

            vrp_state = r.get("vrp_state","VALID")
            divergence = div.get("divergence_type","NONE")

            # =========================
            # IMPACT LOGIC (core)
            # =========================
            impact = (divergence != "NONE")

            total += 1
            if impact:
                impact_count += 1

            print({
                "prefix": prefix,
                "asn": asn,
                "vrp_state": vrp_state,
                "divergence": divergence,
                "impact": impact
            })

        except:
            continue

print("TOTAL:", total)
print("IMPACT:", impact_count)
