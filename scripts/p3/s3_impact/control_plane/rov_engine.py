# =========================
# ROV ENGINE (from vrp_validate.py logic)
# =========================

def rov(prefix, asn, vrp_state="VALID"):

    if prefix is None or asn is None:
        return "NOTFOUND"

    if vrp_state == "Invalid":
        return "INVALID"

    return "VALID"
