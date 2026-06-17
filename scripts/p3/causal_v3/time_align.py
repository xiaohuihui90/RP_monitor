def bucket(ts):

    # 如果是字符串时间（RRDP）
    if isinstance(ts, str):
        return hash(ts) % 1000

    return int(ts) // 3600


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
