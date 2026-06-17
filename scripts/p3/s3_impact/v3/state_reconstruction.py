from collections import defaultdict

def build_state_machine(records):

    state = defaultdict(list)

    for r in records:

        key = (r.get("prefix"), r.get("asn"))
        state[key].append(r.get("vrp_valid", True))

    return state


def detect_transition(state):

    transitions = 0

    for k, v in state.items():

        for i in range(1, len(v)):
            if v[i] != v[i-1]:
                transitions += 1

    return transitions
