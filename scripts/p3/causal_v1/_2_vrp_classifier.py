def classify(event):

    prefix = event.get("prefix", "")
    asn = event.get("asn", "")

    # 简化但稳定的三分类模型
    if not prefix or not asn:
        return "benign"

    if len(prefix) < 8:
        return "structural"

    return "propagation_capable"


def run(events):

    out = []

    for e in events:
        e["type"] = classify(e)
        out.append(e)

    return out
