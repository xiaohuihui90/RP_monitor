#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--joint-dir", default="data/probe/e4a_joint/latest")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    joint_dir = Path(args.joint_dir)
    obj_path = joint_dir / "object/object_snapshot_record.json"
    joint_path = joint_dir / "joint_snapshot_manifest.json"

    blockers = []
    warnings = []

    obj = load_json(obj_path) if obj_path.exists() else {}
    joint = load_json(joint_path) if joint_path.exists() else {}

    object_inventory_count = obj.get("object_inventory_count")
    active_manifest_count = obj.get("active_manifest_count")
    object_set_root = obj.get("object_set_root")
    effective_object_root = obj.get("effective_object_root")

    if not obj_path.exists():
        blockers.append("object_snapshot_record_missing")
    if not joint_path.exists():
        blockers.append("joint_snapshot_manifest_missing")

    if not object_set_root:
        blockers.append("object_set_root_missing")
    if not effective_object_root:
        blockers.append("effective_object_root_missing")
    if not isinstance(object_inventory_count, int) or object_inventory_count <= 0:
        blockers.append("object_inventory_empty")

    if not isinstance(active_manifest_count, int) or active_manifest_count <= 0:
        warnings.append("active_manifest_records_empty")

    vrp_skew = joint.get("joint_timing", {}).get("vrp_object_time_skew_seconds")
    mapping_level = joint.get("joint_timing", {}).get("mapping_level")

    if vrp_skew is None:
        warnings.append("vrp_object_time_skew_unknown")
    elif vrp_skew > 600:
        warnings.append("vrp_object_time_skew_above_600_seconds")

    semantic_ok = not blockers
    strict_ok = semantic_ok and active_manifest_count and active_manifest_count > 0 and mapping_level in {"strong", "acceptable"}

    result = {
        "schema": "s3.stage3.e4a_joint.object_snapshot_quality.v1",
        "probe_id": obj.get("probe_id") or joint.get("probe_id"),
        "location": obj.get("location") or joint.get("location"),
        "snapshot_group_id": obj.get("snapshot_group_id") or joint.get("snapshot_group_id"),
        "joint_snapshot_id": obj.get("joint_snapshot_id") or joint.get("joint_snapshot_id"),
        "object_inventory_count": object_inventory_count,
        "active_manifest_count": active_manifest_count,
        "object_set_root_exists": bool(object_set_root),
        "effective_object_root_exists": bool(effective_object_root),
        "vrp_object_time_skew_seconds": vrp_skew,
        "window_mapping_level": mapping_level,
        "semantic_object_snapshot_ok": semantic_ok,
        "strict_same_window_object_snapshot_ok": bool(strict_ok),
        "warnings": warnings,
        "blockers": blockers,
        "interpretation": (
            "Object snapshot has enough semantic roots for lightweight object context."
            if semantic_ok else
            "Object snapshot is not semantically valid because root/inventory evidence is missing."
        )
    }

    out = joint_dir / "object/object_snapshot_quality_check.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    text = f"""P3R_OBJECT_SNAPSHOT_QUALITY_CHECK=DONE

probe_id = {result.get("probe_id")}
location = {result.get("location")}
snapshot_group_id = {result.get("snapshot_group_id")}
joint_snapshot_id = {result.get("joint_snapshot_id")}

object_inventory_count = {object_inventory_count}
active_manifest_count = {active_manifest_count}
object_set_root_exists = {bool(object_set_root)}
effective_object_root_exists = {bool(effective_object_root)}

vrp_object_time_skew_seconds = {vrp_skew}
window_mapping_level = {mapping_level}

semantic_object_snapshot_ok = {semantic_ok}
strict_same_window_object_snapshot_ok = {bool(strict_ok)}

warnings = {warnings}
blockers = {blockers}

P3R_acceptance = {semantic_ok}
"""
    acc = joint_dir / "object/P3R_object_snapshot_quality_check.txt"
    acc.write_text(text, encoding="utf-8")

    print(text)


if __name__ == "__main__":
    main()
