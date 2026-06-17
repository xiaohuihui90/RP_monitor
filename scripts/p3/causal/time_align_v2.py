def bucket(ts):
    return int(ts) // 3600

def align(vrp_events, bgp_events):

    aligned = []

    for v in vrp_events:
        vt = bucket(v.get("timestamp", 0))

        for b in bgp_events:

            bt = bucket(b.get("timestamp", 0))

            if vt == bt:

                aligned.append({
                    "vrp": v,
                    "bgp": b
                })

    return aligned
