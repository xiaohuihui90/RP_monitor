def bucket(t):
    return int(t) // 3600

def align(vrp, bgp):

    matched = []

    for v in vrp:
        vt = bucket(v["timestamp"])

        for b in bgp:
            bt = bucket(b["timestamp"])

            if vt == bt:
                matched.append({
                    "vrp": v,
                    "bgp": b
                })

    return matched
