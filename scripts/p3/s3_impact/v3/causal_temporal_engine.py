from scripts.p3.timeline.rrdp_loader import load_rrdp_snapshots, extract_state
from scripts.p3.timeline.validator_stream import simulate_validator
from scripts.p3.timeline.bgp_stream import detect_bgp

def run():

    timeline = load_rrdp_snapshots()

    states = []
    for t in timeline:
        states.append(extract_state(t["file"]))

    rov_history = simulate_validator(states)

    impact = 0

    for i in range(1, len(states)):

        bgp_delta = detect_bgp(states[i-1], states[i])

        if rov_history[i]["rov"] == "INVALID" and bgp_delta > 0:
            impact += 1

    print("TOTAL =", len(states))
    print("REAL_IMPACT =", impact)

if __name__ == "__main__":
    run()
