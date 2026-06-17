def bucket(t):

    # RRDP字符串时间 → hash桶
    if isinstance(t, str):
        return hash(t) % 10000

    return int(t) // 3600


def align(vrp, bgp):

    aligned = []

    for v in vrp:

        for b in bgp:

            if bucket(v["timestamp"]) == bucket(b["timestamp"]):

                aligned.append({
                    "vrp": v,
                    "bgp": b
                })

    return aligned
