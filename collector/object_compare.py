from __future__ import annotations
def compare_inventory_lists(items_a: list[dict], items_b: list[dict]) -> dict:
    a = {x["uri"]: x["hash"] for x in items_a}
    b = {x["uri"]: x["hash"] for x in items_b}
    uris = sorted(set(a) | set(b))
    diffs = []
    for uri in uris:
        ha = a.get(uri)
        hb = b.get(uri)
        if ha is None:
            diffs.append({"uri": uri, "hash_a": None, "hash_b": hb, "diff_type": "missing_in_a"})
        elif hb is None:
            diffs.append({"uri": uri, "hash_a": ha, "hash_b": None, "diff_type": "missing_in_b"})
        elif ha != hb:
            diffs.append({"uri": uri, "hash_a": ha, "hash_b": hb, "diff_type": "hash_mismatch"})
    return {
        "compare_status": "same" if not diffs else "different",
        "diff_item_count": len(diffs),
        "diff_items": diffs,
    }
