def align(vrp, bgp):

    aligned = []

    for v in vrp:

        for b in bgp:

            # 最简单可运行版本（先保证通）
            if v.get("asn") == b.get("asn"):

                aligned.append({
                    "vrp": v,
                    "bgp": b
                })

    return aligned
