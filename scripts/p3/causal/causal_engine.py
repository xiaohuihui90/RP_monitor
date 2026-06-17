def causal(joined):

    total = 0
    causal = 0
    non_causal = 0

    for j in joined:

        total += 1

        if j["match"] and j["aligned"]:
            causal += 1
        else:
            non_causal += 1

    return {
        "total": total,
        "causal": causal,
        "non_causal": non_causal
    }
