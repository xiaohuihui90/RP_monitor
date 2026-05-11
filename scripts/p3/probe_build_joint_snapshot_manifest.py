#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_ts(s: str | None):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def find_vrp_gzip(vrp_dir: Path, probe_id: str) -> Path | None:
    candidates = [
        vrp_dir / f"{probe_id}_vrps.raw.json.gz",
        vrp_dir / "vrps.raw.json.gz",
    ]
    for c in candidates:
        if c.exists():
            return c

    found = sorted(vrp_dir.glob("*vrps*.json.gz"))
    return found[0] if found else None


def main() -> None:
    ap = argparse.ArgumentParser(description="Build E4-A joint snapshot manifest from VRP latest and Object snapshot latest")
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--location", required=True)
    ap.add_argument("--snapshot-group-id", required=True)
    ap.add_argument("--export-id", required=True)
    ap.add_argument("--vrp-dir", required=True)
    ap.add_argument("--object-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    probe_id = args.probe_id
    location = args.location
    snapshot_group_id = args.snapshot_group_id
    export_id = args.export_id

    vrp_dir = Path(args.vrp_dir)
    object_dir = Path(args.object_dir)
    out_dir = Path(args.out_dir)

    out_dir.mkdir(parents=True, exist_ok=True)

    vrp_manifest_path = vrp_dir / "manifest.json"
    vrp_sha_path = vrp_dir / "sha256.txt"
    vrp_gzip_path = find_vrp_gzip(vrp_dir, probe_id)

    object_record_path = object_dir / "object_snapshot_record.json"
    object_tar_path = object_dir / "object_snapshot.tar.gz"
    object_sha_path = object_dir / "sha256.txt"
    active_manifest_path = object_dir / "active_manifest_records.jsonl"
    object_inventory_path = object_dir / "object_inventory.jsonl"

    blockers = []
    warnings = []

    if not vrp_manifest_path.exists():
        blockers.append("vrp_manifest_missing")
        vrp_manifest = {}
    else:
        vrp_manifest = read_json(vrp_manifest_path)

    if not vrp_gzip_path or not vrp_gzip_path.exists():
        blockers.append("vrp_gzip_missing")

    if not vrp_sha_path.exists():
        blockers.append("vrp_sha256_txt_missing")

    if not object_record_path.exists():
        blockers.append("object_snapshot_record_missing")
        object_record = {}
    else:
        object_record = read_json(object_record_path)

    if not object_tar_path.exists():
        blockers.append("object_snapshot_tar_gz_missing")

    if not object_sha_path.exists():
        blockers.append("object_sha256_txt_missing")

    if not active_manifest_path.exists():
        blockers.append("active_manifest_records_missing")
    elif active_manifest_path.stat().st_size == 0:
        warnings.append("active_manifest_records_empty")

    if not object_inventory_path.exists():
        blockers.append("object_inventory_missing")

    object_export_started = object_record.get("object_export_started_at")
    object_export_finished = object_record.get("object_export_finished_at")
    vrp_generated_time = vrp_manifest.get("generatedTime")

    t_vrp = parse_ts(vrp_generated_time)
    t_obj = parse_ts(object_export_started)
    vrp_object_time_skew_seconds = None
    if t_vrp and t_obj:
        vrp_object_time_skew_seconds = abs(int((t_obj - t_vrp).total_seconds()))
        if vrp_object_time_skew_seconds > 600:
            warnings.append("vrp_object_time_skew_above_600_seconds")

    vrp_sha256_gzip = None
    if vrp_gzip_path and vrp_gzip_path.exists():
        vrp_sha256_gzip = sha256_file(vrp_gzip_path)

    object_sha256_tar_gz = None
    if object_tar_path.exists():
        object_sha256_tar_gz = sha256_file(object_tar_path)

    joint_snapshot_id = f"{probe_id}_{export_id}"

    manifest = {
        "schema": "s3.stage3.joint_snapshot_manifest.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": snapshot_group_id,
        "joint_snapshot_id": joint_snapshot_id,
        "probe_id": probe_id,
        "location": location,
        "export_id": export_id,
        "generated_time": object_record.get("object_export_started_at") or vrp_generated_time,

        "vrp_snapshot": {
            "available": vrp_manifest_path.exists() and vrp_gzip_path is not None and vrp_gzip_path.exists(),
            "validator": vrp_manifest.get("validator", "routinator"),
            "validator_version": vrp_manifest.get("validator_version"),
            "generatedTime": vrp_generated_time,
            "export_started_at": vrp_manifest.get("export_started_at"),
            "export_finished_at": vrp_manifest.get("export_finished_at"),
            "vrp_count": vrp_manifest.get("roa_count") or vrp_manifest.get("vrp_count"),
            "unique_vrp_count": vrp_manifest.get("unique_vrp_count") or vrp_manifest.get("roa_count"),
            "vrp_root_v1": vrp_manifest.get("vrp_root_v1"),
            "vrp_digest": vrp_manifest.get("vrp_digest") or vrp_manifest.get("vrp_root_v1"),
            "raw_json_size_bytes": vrp_manifest.get("raw_json_size_bytes"),
            "gzip_size_bytes": vrp_manifest.get("gzip_size_bytes") or (vrp_gzip_path.stat().st_size if vrp_gzip_path and vrp_gzip_path.exists() else None),
            "vrp_gzip_path": str(vrp_gzip_path.relative_to(out_dir)) if vrp_gzip_path and vrp_gzip_path.exists() and vrp_gzip_path.is_relative_to(out_dir) else str(vrp_gzip_path) if vrp_gzip_path else None,
            "sha256_gzip": vrp_manifest.get("sha256_gzip") or vrp_sha256_gzip,
        },

        "object_snapshot": {
            "available": object_record_path.exists() and object_tar_path.exists(),
            "object_set_root": object_record.get("object_set_root"),
            "effective_object_root": object_record.get("effective_object_root"),
            "object_inventory_count": object_record.get("object_inventory_count"),
            "active_manifest_count": object_record.get("active_manifest_count"),
            "active_manifest_records_path": "object/active_manifest_records.jsonl",
            "object_inventory_path": "object/object_inventory.jsonl",
            "object_snapshot_tar_gz": "object/object_snapshot.tar.gz",
            "sha256_tar_gz": object_sha256_tar_gz,
            "object_export_started_at": object_export_started,
            "object_export_finished_at": object_export_finished,
            "warnings": object_record.get("warnings", []),
            "blockers": object_record.get("blockers", []),
        },

        "joint_timing": {
            "vrp_generatedTime": vrp_generated_time,
            "object_export_started_at": object_export_started,
            "object_export_finished_at": object_export_finished,
            "vrp_object_time_skew_seconds": vrp_object_time_skew_seconds,
            "mapping_level": (
                "strong" if vrp_object_time_skew_seconds is not None and vrp_object_time_skew_seconds <= 300
                else "acceptable" if vrp_object_time_skew_seconds is not None and vrp_object_time_skew_seconds <= 600
                else "weak_or_unknown"
            ),
        },

        "validator_context": {
            "validator_name": "routinator",
            "validator_version": vrp_manifest.get("validator_version"),
            "fingerprint_level": "partial",
            "config_hash": None,
            "tal_set_hash": None,
            "runtime_process_fingerprint": None,
        },

        "reserved_interfaces": {
            "e4b_cross_validator": "reserved_only",
            "control_plane_impact": "reserved_only",
        },

        "warnings": warnings,
        "blockers": blockers,
        "upload_ready": len(blockers) == 0,
    }

    # Organize latest joint directory. Copy object files into out_dir/object.
    out_object_dir = out_dir / "object"
    out_object_dir.mkdir(parents=True, exist_ok=True)
    for src in [object_record_path, object_tar_path, object_sha_path, active_manifest_path, object_inventory_path]:
        if src.exists() and src.parent != out_object_dir:
            shutil.copy2(src, out_object_dir / src.name)

    # Copy light VRP metadata only; do not duplicate 70MB raw json here.
    out_vrp_dir = out_dir / "vrp"
    out_vrp_dir.mkdir(parents=True, exist_ok=True)
    for src in [vrp_manifest_path, vrp_sha_path]:
        if src.exists():
            shutil.copy2(src, out_vrp_dir / src.name)

    joint_path = out_dir / "joint_snapshot_manifest.json"
    write_json(joint_path, manifest)

    sha_path = out_dir / "sha256.txt"
    rows = [f"{sha256_file(joint_path)}  joint_snapshot_manifest.json\n"]
    for rel in [
        "object/object_snapshot_record.json",
        "object/object_snapshot.tar.gz",
        "object/active_manifest_records.jsonl",
        "object/object_inventory.jsonl",
        "vrp/manifest.json",
        "vrp/sha256.txt",
    ]:
        p = out_dir / rel
        if p.exists():
            rows.append(f"{sha256_file(p)}  {rel}\n")
    sha_path.write_text("".join(rows), encoding="utf-8")

    acceptance_ok = manifest["upload_ready"] and manifest["vrp_snapshot"]["available"] and manifest["object_snapshot"]["available"]

    acceptance = f"""P2_JOINT_SNAPSHOT_MANIFEST=DONE

probe_id = {probe_id}
location = {location}
snapshot_group_id = {snapshot_group_id}
joint_snapshot_id = {joint_snapshot_id}
export_id = {export_id}

vrp_snapshot_available = {manifest["vrp_snapshot"]["available"]}
object_snapshot_available = {manifest["object_snapshot"]["available"]}
joint_snapshot_manifest_exists = {joint_path.exists()}
joint_snapshot_upload_ready = {manifest["upload_ready"]}

vrp_generatedTime = {vrp_generated_time}
object_export_started_at = {object_export_started}
vrp_object_time_skew_seconds = {vrp_object_time_skew_seconds}
window_mapping_level = {manifest["joint_timing"]["mapping_level"]}

object_inventory_count = {manifest["object_snapshot"]["object_inventory_count"]}
active_manifest_count = {manifest["object_snapshot"]["active_manifest_count"]}
object_set_root = {manifest["object_snapshot"]["object_set_root"]}
effective_object_root = {manifest["object_snapshot"]["effective_object_root"]}

warnings = {warnings}
blockers = {blockers}

reserved_interfaces:
  e4b_cross_validator = reserved_only
  control_plane_impact = reserved_only

runtime_service_changed = False
collector_restarted = False
probe_restarted = False
new_validator_installed = False
bgp_data_loaded = False

P2_acceptance = {acceptance_ok}
"""
    acc_path = out_dir / "P2_joint_manifest_acceptance_check.txt"
    acc_path.write_text(acceptance, encoding="utf-8")

    print(acceptance)


if __name__ == "__main__":
    main()
