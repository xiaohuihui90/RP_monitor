from __future__ import annotations
import base64
import hashlib
import xml.etree.ElementTree as ET
from pathlib import Path


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def build_inventory_from_snapshot(snapshot_path: str) -> tuple[list[dict], dict]:
    p = Path(snapshot_path)
    root = ET.parse(p).getroot()

    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    items = []
    publish_count = 0
    invalid_count = 0

    for elem in root.findall(f".//{ns}publish"):
        uri = elem.attrib.get("uri")
        body = (elem.text or "").strip()

        if not uri or not body:
            invalid_count += 1
            continue

        try:
            obj_bytes = base64.b64decode(body, validate=True)
        except Exception:
            invalid_count += 1
            continue

        obj_hash = hashlib.sha256(obj_bytes).hexdigest()

        items.append({
            "uri": uri,
            "hash": obj_hash,
            "source": "snapshot",
            "op": "present",
            "object_type": None,
            "origin_ref": str(p),
        })
        publish_count += 1

    stats = {
        "total_objects": len(items),
        "publish_count": publish_count,
        "withdraw_count": 0,
        "invalid_item_count": invalid_count,
    }
    return items, stats
