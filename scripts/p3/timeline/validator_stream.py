def simulate_validator(states):

    history = []

    for i, s in enumerate(states):

        history.append({
            "t": i,
            "rov": "VALID" if s["roas"] > 0 else "INVALID"
        })

    return history
