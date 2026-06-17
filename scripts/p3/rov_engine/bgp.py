def bgp_update(prev_state, current_state):
    """
    模拟BGP route withdraw/announce
    """

    changes = []

    for k in current_state:
        if prev_state.get(k) != current_state.get(k):
            changes.append(k)

    return {
        "withdrawals": changes,
        "impact": len(changes) > 0
    }
