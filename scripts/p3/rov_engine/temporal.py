def detect_temporal_impact(history):
    """
    检测 VRP → ROV → BGP 时间变化
    """

    impacts = []

    for i in range(1, len(history)):

        prev = history[i-1]["state"]
        curr = history[i]["state"]

        change = {}

        for k in curr:
            if prev.get(k) != curr.get(k):
                change[k] = (prev[k], curr[k])

        if change:
            impacts.append({
                "step": i,
                "changes": change
            })

    return impacts
