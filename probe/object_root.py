from __future__ import annotations
import hashlib
import json
from typing import Iterable

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def build_leaf(uri: str, object_hash: str) -> str:
    return _sha256_bytes(f"{uri}\n{object_hash}".encode())

def build_object_root(items: Iterable[dict]) -> dict:
    normalized = []
    for x in items:
        uri = x["uri"]
        h = x["hash"]
        normalized.append({"uri": uri, "hash": h, "leaf": build_leaf(uri, h)})
    normalized.sort(key=lambda x: x["uri"])
    leaves = [x["leaf"] for x in normalized]
    if not leaves:
        empty = _sha256_bytes(b"")
        return {"object_set_root": empty, "inventory_digest": empty, "bucket_roots": {}, "object_count": 0}

    inventory_digest = _sha256_bytes(
        json.dumps([{"uri": x["uri"], "hash": x["hash"]} for x in normalized], separators=(",", ":"), ensure_ascii=False).encode()
    )

    level = leaves[:]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(_sha256_bytes(f"{left}{right}".encode()))
        level = nxt

    return {
        "object_set_root": level[0],
        "inventory_digest": inventory_digest,
        "bucket_roots": {},
        "object_count": len(normalized),
    }
