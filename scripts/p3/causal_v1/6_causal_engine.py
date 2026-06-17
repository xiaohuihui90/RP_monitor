def causal_analysis(aligned):

    total = 0
    causal = 0
    non_causal = 0

    for a in aligned:

        total += 1

        if a["match"] and a["aligned"]:
            causal += 1
        else:
            non_causal += 1

    return {
        "total": total,
        "causal": causal,
        "non_causal": non_causal
    }
