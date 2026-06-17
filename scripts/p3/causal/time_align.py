def align(joined):

    aligned = []

    for j in joined:

        if j["bgp_asn"] is None:
            j["aligned"] = False
        else:
            j["aligned"] = True

        aligned.append(j)

    return aligned
