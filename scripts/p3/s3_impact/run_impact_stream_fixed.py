import csv

inp = "data/p3_impact_engine/classified_records_v21.csv"

rows = list(csv.DictReader(open(inp)))

print("records =", len(rows))

for r in rows[:50]:

    # ✔ 正确字段（关键修复）
    prefix = r.get("prefix")
    asn = r.get("asn")
    tal = r.get("tal")

    root_cause = r.get("root_cause_primary")

    # ✔ 模拟ROV（先保证可跑）
    if root_cause == "C4_PP_REACHABILITY":
        rov_before = "VALID"
        rov_after = "INVALID"
    else:
        rov_before = "VALID"
        rov_after = "VALID"

    impact = (rov_before != rov_after)

    print({
        "prefix": prefix,
        "asn": asn,
        "tal": tal,
        "rov_before": rov_before,
        "rov_after": rov_after,
        "impact": impact,
        "root_cause": root_cause
    })

print("IMPACT STREAM FIXED DONE")
