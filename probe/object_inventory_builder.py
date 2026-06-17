from __future__ import annotations
from datetime import datetime, timezone
from probe.inventory_builder import build_inventory_from_snapshot
from probe.object_root import build_object_root

def build_object_inventory_record(*, probe_id: str, pp_id: str, session_id: str, serial: int, base_notif_digest: str, snapshot_artifact_path: str) -> tuple[dict, list[dict], dict]:
    items, stats = build_inventory_from_snapshot(snapshot_artifact_path)
    root = build_object_root(items)
    rec = {
        "schema_version": "2.0",
        "probe_id": probe_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pp_id": pp_id,
        "session_id": session_id,
        "serial": serial,
        "base_notif_digest": base_notif_digest,
        "inventory_source": "rrdp",
        "inventory_type": "snapshot",
        "object_count": root["object_count"],
        "object_set_root": root["object_set_root"],
        "inventory_digest": root["inventory_digest"],
        "bucket_roots_ref": None,
        "artifact_ref": snapshot_artifact_path,
        "inventory_build_stats": stats,
    }
    return rec, items, root
