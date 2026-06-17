from scripts.p3.s3_impact.input_adapter.classification_adapter import (
    load_classification,
    to_control_plane_signal
)

INPUT_FILE = "data/p3_control_plane_input/classification.csv"

print("loading classification...")

cls = load_classification(INPUT_FILE)

print("converting to control-plane signal...")

signals = to_control_plane_signal(cls)

total = 0
impact = 0

for k, v in signals.items():

    total += 1

    if v["impact"]:
        impact += 1

    print({
        "prefix": k[0],
        "asn": k[1],
        "cd": v["cd"],
        "bj": v["bj"],
        "sg": v["sg"],
        "impact_score": v["impact_score"],
        "impact": v["impact"]
    })

print("TOTAL =", total)
print("IMPACT =", impact)
