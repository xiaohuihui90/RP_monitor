import json
import glob

# load windows
def load_windows():
    try:
        return json.load(open("/tmp/m17_window_registry.json"))
    except:
        return []


# load VRP diff
def load_diffs():
    files = glob.glob(
        "data/p3_collector/m18_diff_lifetime/**/vrp_diff_lifetime_records.jsonl",
        recursive=True
    )

    records = []
    for f in files:
        with open(f) as fp:
            for line in fp:
                try:
                    records.append(json.loads(line))
                except:
                    pass
    return records


windows = load_windows()
diffs = load_diffs()

total = len(diffs)
impact = 0

for d in diffs:

    divergence = d.get("divergence", "NONE")

    # ❗关键：必须 window存在才算impact
    if windows and divergence != "NONE":
        impact += 1

print("TOTAL =", total)
print("IMPACT =", impact)
print("WINDOWS =", len(windows))
