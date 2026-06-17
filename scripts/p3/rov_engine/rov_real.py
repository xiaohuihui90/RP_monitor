def rov_eval(vrp_valid, roa_match):
    """
    真实ROV逻辑（不是mock）
    """

    if not vrp_valid:
        return "NOTFOUND"

    if roa_match:
        return "VALID"

    return "INVALID"
