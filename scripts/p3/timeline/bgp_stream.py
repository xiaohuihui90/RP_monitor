def detect_bgp(prev, curr):

    changes = 0

    for k in curr:
        if prev.get(k) != curr.get(k):
            changes += 1

    return changes
