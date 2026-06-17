def classify(vrp_event):

    # propagation-capable（关键）
    if vrp_event["asn"] is None:
        return "benign"

    if len(vrp_event["prefix"]) < 5:
        return "structural"

    return "propagation_capable"


def run(events):
    out = []

    for e in events:
        e["type"] = classify(e)
        out.append(e)

    return out
