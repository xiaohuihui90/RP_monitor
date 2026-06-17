def join(vrp_events, bgp_table):

    results = []

    for e in vrp_events:

        prefix = e.get("prefix")
        vrp_asn = e.get("asn")

        bgp_asn = bgp_table.get(prefix)

        results.append({
            "prefix": prefix,
            "vrp_asn": vrp_asn,
            "bgp_asn": bgp_asn,
            "match": vrp_asn == bgp_asn if bgp_asn else False
        })

    return results
