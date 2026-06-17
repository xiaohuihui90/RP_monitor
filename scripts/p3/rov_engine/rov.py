def rov_decision(vrp_state, roa_match):
    """
    真实ROV逻辑（简化但等价于vrp_validate.py核心）
    """

    if vrp_state == "missing":
        return "NOTFOUND"

    if not roa_match:
        return "INVALID"

    return "VALID"
