def classify(e):

    prefix = e.get("prefix", "")
    asn = e.get("asn", "")

    if not prefix or not asn:
        return "benign"

    if len(prefix) < 8:
        return "structural"

    return "propagation_capable"


def run(events):

    for e in events:
        e["type"] = classify(e)

    return events
