import json
import glob
from state_reconstruction import build_state_machine, detect_transition

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
                continue


state = build_state_machine(records)
transitions = detect_transition(state)

print("TOTAL =", len(records))
print("ROV_TRANSITIONS =", transitions)
