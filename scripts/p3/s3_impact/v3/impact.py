import csv

FILE = "data/p3_control_plane_input/classification.csv"

rows = list(csv.DictReader(open(FILE)))

total = 0
impact = 0

for r in rows:

    cd = r["status_cd"]
    bj = r["status_bj"]
    sg = r["status_sg"]

    # === ROV proxy logic ===
    valid_count = [cd,bj,sg].count("Valid")
    invalid_count = [cd,bj,sg].count("Invalid")

    # === control-plane impact rule ===
    # 关键：多数不一致 + Invalid传播
    if invalid_count >= 2 or valid_count == 1:
        impact += 1

    total += 1

print("TOTAL =", total)
print("CONTROL_PLANE_IMPACT =", impact)
