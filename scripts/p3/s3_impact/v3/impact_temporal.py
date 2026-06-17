import json
import glob

files = glob.glob(
    "data/p3_collector/m18_diff_lifetime/**/vrp_diff_lifetime_records.jsonl",
    recursive=True
)

history = []

for f in files:
    with open(f) as fp:
        for line in fp:
            try:
                r = json.loads(line)
                history.append(r)
            except:
                continue


total = 0
impact = 0

for i in range(1, len(history)):

    prev = history[i-1]
    curr = history[i]

    # ❗时间差分（关键）
    if prev.get("vrp_valid") != curr.get("vrp_valid"):
        impact += 1

    total += 1

print("TOTAL =", total)
print("TEMPORAL_IMPACT =", impact)
