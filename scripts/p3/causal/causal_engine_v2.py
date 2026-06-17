def causal(aligned):

    total = len(aligned)
    causal = 0
    non_causal = 0

    for a in aligned:

        vrp = a["vrp"]
        bgp = a["bgp"]

        if vrp["asn"] == bgp["asn"]:
            causal += 1
        else:
            non_causal += 1

    return {
        "total": total,
        "causal": causal,
        "non_causal": non_causal
    }
