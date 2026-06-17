def align(rrdp, bgp):

    aligned = []

    for r in rrdp:

        for b in bgp:

            # 统一时间桶后再对齐
            if r["asn"] == b["asn"]:

                aligned.append({
                    "vrp": r,
                    "bgp": b
                })

    return aligned
