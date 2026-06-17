def extract_events(states):

    events = []

    for i in range(1, len(states)):

        prev = states[i-1]
        curr = states[i]

        if prev["roas"] != curr["roas"]:

            events.append({
                "type": "VRP_CHANGE",
                "t": i
            })

    return events
