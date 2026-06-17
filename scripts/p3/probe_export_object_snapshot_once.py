#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


URI_KEYS = [
    "uri", "object_uri", "url", "href", "path", "file", "filename",
    "relative_path", "manifest_uri", "mft_uri", "rpki_uri"
]

HASH_KEYS = [
    "sha256", "hash", "object_hash", "file_hash", "digest",
    "manifest_hash", "mft_hash", "content_hash"
]

TYPE_KEYS = [
    "object_type", "type", "kind", "rpki_object_type"
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_hash(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    if s.startswith("sha256:"):
        s = s[len("sha256:"):]
    s = s.lower()
    if len(s) >= 32 and all(c in "0123456789abcdef" for c in s[:32]):
        return s
    return None


def infer_type(uri: str, explicit: str | None = None) -> str:
    if explicit:
        e = str(explicit).lower()
        if "manifest" in e or e == "mft":
            return "mft"
        if "roa" in e:
            return "roa"
        if "cer" in e or "cert" in e:
            return "cer"
        if "crl" in e:
            return "crl"
        if "aspa" in e:
            return "aspa"
        if "gbr" in e:
            return "gbr"
        return e

    u = uri.lower()
    for suffix, typ in [
        (".mft", "mft"),
        (".roa", "roa"),
        (".cer", "cer"),
        (".crl", "crl"),
        (".asa", "aspa"),
        (".gbr", "gbr"),
    ]:
        if u.endswith(suffix) or suffix in u:
            return typ
    return "unknown"


def first_str(d: dict[str, Any], keys: list[str]) -> str | None:
    for k in keys:
        if k in d and d[k] is not None:
            return str(d[k])
    return None


def first_hash(d: dict[str, Any], keys: list[str]) -> str | None:
    for k in keys:
        if k in d:
            h = normalize_hash(d[k])
            if h:
                return h
    return None


def make_record(uri: str, h: str, object_type: str, source_file: Path, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    rec = {
        "uri": uri,
        "sha256": h,
        "object_type": object_type,
        "source_file": str(source_file),
    }
    if extra:
        for k, v in extra.items():
            if v is not None and k not in rec:
                rec[k] = v
    return rec


def extract_records_from_obj(obj: Any, source_file: Path, out: list[dict[str, Any]]) -> None:
    if isinstance(obj, dict):
        uri = first_str(obj, URI_KEYS)
        h = first_hash(obj, HASH_KEYS)
        typ = first_str(obj, TYPE_KEYS)

        if uri and h:
            out.append(make_record(
                uri=uri,
                h=h,
                object_type=infer_type(uri, typ),
                source_file=source_file,
                extra={
                    "manifest_number": obj.get("manifest_number") or obj.get("manifestNumber"),
                    "pp_id": obj.get("pp_id") or obj.get("tal") or obj.get("ta"),
                },
            ))

        # 常见结构：对象记录里带 manifest_uri + manifest_hash
        m_uri = obj.get("manifest_uri") or obj.get("mft_uri")
        m_hash = normalize_hash(obj.get("manifest_hash") or obj.get("mft_hash"))
        if m_uri and m_hash:
            out.append(make_record(
                uri=str(m_uri),
                h=m_hash,
                object_type="mft",
                source_file=source_file,
                extra={
                    "manifest_number": obj.get("manifest_number") or obj.get("manifestNumber"),
                    "pp_id": obj.get("pp_id") or obj.get("tal") or obj.get("ta"),
                },
            ))

        for v in obj.values():
            if isinstance(v, (dict, list)):
                extract_records_from_obj(v, source_file, out)

    elif isinstance(obj, list):
        for v in obj:
            extract_records_from_obj(v, source_file, out)


def parse_json_or_jsonl(path: Path, max_bytes: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    if path.stat().st_size > max_bytes:
        return records

    name = path.name.lower()

    try:
        if name.endswith(".jsonl"):
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    extract_records_from_obj(obj, path, records)
        elif name.endswith(".json"):
            text = path.read_text(encoding="utf-8", errors="ignore").strip()
            if text:
                obj = json.loads(text)
                extract_records_from_obj(obj, path, records)
    except Exception:
        return records

    return records


def canonicalize_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    dedup: dict[tuple[str, str, str], dict[str, Any]] = {}
    for r in records:
        uri = str(r.get("uri", "")).strip()
        h = normalize_hash(r.get("sha256"))
        typ = infer_type(uri, r.get("object_type"))
        if not uri or not h:
            continue
        key = (uri, h, typ)
        if key not in dedup:
            rr = dict(r)
            rr["uri"] = uri
            rr["sha256"] = h
            rr["object_type"] = typ
            dedup[key] = rr
    return [dedup[k] for k in sorted(dedup)]


def merkle_root(records: list[dict[str, Any]], fields: list[str]) -> str | None:
    if not records:
        return None
    leaves = []
    for r in records:
        s = "|".join(str(r.get(f, "")) for f in fields)
        leaves.append(sha256_bytes(s.encode("utf-8")))
    payload = "\n".join(sorted(leaves)).encode("utf-8")
    return "sha256:" + sha256_bytes(payload)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def copy_to_latest(history_dir: Path, latest_dir: Path) -> None:
    latest_dir.mkdir(parents=True, exist_ok=True)
    for rel in [
        "object/object_snapshot_record.json",
        "object/active_manifest_records.jsonl",
        "object/object_inventory.jsonl",
        "object/object_snapshot.tar.gz",
        "object/sha256.txt",
        "object/P1_object_export_acceptance_check.txt",
    ]:
        src = history_dir / rel
        dst = latest_dir / rel
        if src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(src.read_bytes())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--location", required=True)
    ap.add_argument("--snapshot-group-id", required=True)
    ap.add_argument("--export-id", required=True)
    ap.add_argument("--out-root", default="data/probe/e4a_joint")
    ap.add_argument("--source-root", action="append", default=[])
    ap.add_argument("--include-active-manifest-records", action="store_true")
    ap.add_argument("--include-object-inventory-summary", action="store_true")
    ap.add_argument("--max-file-mb", type=int, default=200)
    args = ap.parse_args()

    source_roots = [Path(x) for x in args.source_root]
    if not source_roots:
        source_roots = [
            Path("data/probe"),
            Path("data/p3_collector/object_gate_v5_runs"),
            Path("data/p3_collector/stage3_final_archive"),
            Path("data/p3_collector/m14_vrp_runs"),
        ]

    out_root = Path(args.out_root)
    history_dir = out_root / "history" / args.export_id
    latest_dir = out_root / "latest"
    object_dir = history_dir / "object"
    object_dir.mkdir(parents=True, exist_ok=True)

    started = utc_now()
    max_bytes = args.max_file_mb * 1024 * 1024

    candidate_files: list[Path] = []
    for root in source_roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            low = str(p).lower()
            if not (low.endswith(".json") or low.endswith(".jsonl")):
                continue
            if any(x in low for x in ["object", "manifest", "mft", "inventory", "verdict", "evidence"]):
                candidate_files.append(p)

    raw_records: list[dict[str, Any]] = []
    for p in sorted(set(candidate_files)):
        raw_records.extend(parse_json_or_jsonl(p, max_bytes=max_bytes))

    inventory = canonicalize_records(raw_records)
    active_manifests = [
        r for r in inventory
        if r.get("object_type") == "mft" or str(r.get("uri", "")).lower().endswith(".mft")
    ]

    object_set_root = merkle_root(inventory, ["uri", "sha256", "object_type"])
    effective_object_root = merkle_root(active_manifests, ["uri", "sha256", "object_type"]) or object_set_root

    inventory_path = object_dir / "object_inventory.jsonl"
    manifests_path = object_dir / "active_manifest_records.jsonl"
    write_jsonl(inventory_path, inventory)
    write_jsonl(manifests_path, active_manifests)

    finished = utc_now()

    record = {
        "schema": "s3.stage3.object_snapshot_record.v1",
        "snapshot_group_id": args.snapshot_group_id,
        "joint_snapshot_id": f"{args.probe_id}_{args.export_id}",
        "probe_id": args.probe_id,
        "location": args.location,
        "export_id": args.export_id,
        "object_export_started_at": started,
        "object_export_finished_at": finished,
        "source_roots": [str(x) for x in source_roots],
        "candidate_file_count": len(set(candidate_files)),
        "object_set_root": object_set_root,
        "effective_object_root": effective_object_root,
        "object_inventory_count": len(inventory),
        "active_manifest_count": len(active_manifests),
        "active_manifest_records_path": "active_manifest_records.jsonl",
        "object_inventory_path": "object_inventory.jsonl",
        "manifest_parse_error_count": None,
        "expired_manifest_count": None,
        "fetch_completeness": {
            "all_target_pp_success": None,
            "failed_pp_count": None,
            "timeout_count": None,
            "non_timeout_error_count": None,
            "source": "local_object_artifact_discovery"
        },
        "warnings": [],
        "blockers": []
    }

    if not inventory:
        record["blockers"].append("no_object_inventory_records_extracted")
    if not active_manifests:
        record["warnings"].append("no_active_manifest_records_extracted")
    if not object_set_root:
        record["blockers"].append("object_set_root_missing")
    if not effective_object_root:
        record["blockers"].append("effective_object_root_missing")

    record_path = object_dir / "object_snapshot_record.json"
    record_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")

    tar_path = object_dir / "object_snapshot.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(record_path, arcname="object_snapshot_record.json")
        tar.add(manifests_path, arcname="active_manifest_records.jsonl")
        tar.add(inventory_path, arcname="object_inventory.jsonl")

    sha_path = object_dir / "sha256.txt"
    rows = []
    for p in [record_path, manifests_path, inventory_path, tar_path]:
        rows.append(f"{sha256_file(p)}  {p.name}\n")
    sha_path.write_text("".join(rows), encoding="utf-8")

    sha_ok = sha256_file(tar_path) in sha_path.read_text(encoding="utf-8")

    acceptance_ok = (
        object_set_root is not None
        and effective_object_root is not None
        and inventory_path.exists()
        and manifests_path.exists()
        and tar_path.exists()
        and sha_path.exists()
        and not record["blockers"]
    )

    acceptance = f"""P1_OBJECT_SNAPSHOT_EXPORT=DONE

probe_id = {args.probe_id}
location = {args.location}
snapshot_group_id = {args.snapshot_group_id}
joint_snapshot_id = {args.probe_id}_{args.export_id}
export_id = {args.export_id}

object_snapshot_export_success = {acceptance_ok}
candidate_file_count = {len(set(candidate_files))}
object_inventory_count = {len(inventory)}
active_manifest_count = {len(active_manifests)}

object_set_root_exists = {object_set_root is not None}
effective_object_root_exists = {effective_object_root is not None}
active_manifest_records_exists = {manifests_path.exists()}
object_inventory_exists = {inventory_path.exists()}
object_snapshot_tar_gz_exists = {tar_path.exists()}
sha256_txt_exists = {sha_path.exists()}

object_set_root = {object_set_root}
effective_object_root = {effective_object_root}

warnings = {record["warnings"]}
blockers = {record["blockers"]}

outputs:
  {record_path}
  {manifests_path}
  {inventory_path}
  {tar_path}
  {sha_path}

runtime_service_changed = False
collector_restarted = False
probe_restarted = False
new_validator_installed = False
bgp_data_loaded = False

P1_acceptance = {acceptance_ok}
"""
    acc_path = object_dir / "P1_object_export_acceptance_check.txt"
    acc_path.write_text(acceptance, encoding="utf-8")

    copy_to_latest(history_dir, latest_dir)

    print(acceptance)


if __name__ == "__main__":
    main()
