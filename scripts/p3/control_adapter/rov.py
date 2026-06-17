def rov_check(prefix, asn, vrp_state="VALID"):
    if prefix is None or asn is None:
        return "NOTFOUND"

    if vrp_state == "Invalid":
        return "INVALID"

    return "VALID"
