#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RPKI_SUFFIX_TO_TYPE = {
    ".cer": "cer",
    ".roa": "roa",
    ".mft": "mft",
    ".crl": "crl",
    ".asa": "aspa",
    ".gbr": "gbr",
}


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


def object_type(path: Path) -> str:
    return RPKI_SUFFIX_TO_TYPE.get(path.suffix.lower(), "unknown")


def discover_source_roots() -> list[Path]:
    home = Path.home()
    candidates = [
        home / ".rpki-cache",
        home / ".cache/routinator",
        home / ".local/share/routinator",
        home / ".routinator",
        home / "rpki-cache",
        home / "routinator",
        home / "s3_runtime",
        Path("data/probe"),
        Path("data/routinator"),
        Path("/var/lib/routinator"),
        Path("/var/cache/routinator"),
    ]

    # Try to extract cache-like paths from ~/.routinator.conf.
    conf = home / ".routinator.conf"
    if conf.exists():
        try:
            for line in conf.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if any(k in s.lower() for k in ["repository-dir", "cache-dir", "rrdp-root", "rsync-root", "base-dir"]):
                    for sep in ["=", ":"]:
                        if sep in s:
                            v = s.split(sep, 1)[1].strip().strip('"').strip("'")
                            if v:
                                p = Path(v).expanduser()
                                candidates.append(p)
        except Exception:
            pass

    out = []
    seen = set()
    for p in candidates:
        try:
            rp = p.expanduser().resolve()
        except Exception:
            continue
        if rp.exists() and rp.is_dir() and str(rp) not in seen:
            seen.add(str(rp))
            out.append(rp)
    return out


def scan_objects(source_roots: list[Path], max_file_mb: int, max_files: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    max_bytes = max_file_mb * 1024 * 1024
    rows = []
    scanned_files = 0
    skipped_large = 0
    skipped_error = 0

    for root in source_roots:
        if not root.exists():
            continue

        for p in root.rglob("*"):
            if not p.is_file():
                continue

            suf = p.suffix.lower()
            if suf not in RPKI_SUFFIX_TO_TYPE:
                continue

            scanned_files += 1
            if scanned_files > max_files:
                break

            try:
                size = p.stat().st_size
                if size <= 0:
                    continue
                if size > max_bytes:
                    skipped_large += 1
                    continue

                try:
                    rel = p.relative_to(root).as_posix()
                except Exception:
                    rel = p.name

                rows.append({
                    "uri": f"cache://{root.name}/{rel}",
                    "relative_path": rel,
                    "sha256": sha256_file(p),
                    "object_type": object_type(p),
                    "size_bytes": size,
                    "source_root": str(root),
                    "source_file": str(p),
                    "evidence_level": "cache_file_inventory",
                })
            except Exception:
                skipped_error += 1

        if scanned_files > max_files:
            break

    rows.sort(key=lambda x: (x["uri"], x["sha256"], x["object_type"]))

    summary = {
        "source_roots": [str(x) for x in source_roots],
        "scanned_files": scanned_files,
        "skipped_large": skipped_large,
        "skipped_error": skipped_error,
        "max_file_mb": max_file_mb,
        "max_files": max_files,
    }
    return rows, summary


def merkle_root(rows: list[dict[str, Any]]) -> str | None:
    if not rows:
        return None
    leaves = []
    for r in rows:
        s = f"{r.get('uri')}|{r.get('sha256')}|{r.get('object_type')}"
        leaves.append(sha256_bytes(s.encode("utf-8")))
    payload = "\n".join(sorted(leaves)).encode("utf-8")
    return "sha256:" + sha256_bytes(payload)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def copy_to_latest(history_dir: Path, latest_dir: Path) -> None:
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
    ap = argparse.ArgumentParser(description="Export lightweight object snapshot from local Routinator/cache files")
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--location", required=True)
    ap.add_argument("--snapshot-group-id", required=True)
    ap.add_argument("--export-id", required=True)
    ap.add_argument("--out-root", default="data/probe/e4a_joint")
    ap.add_argument("--source-root", action="append", default=[])
    ap.add_argument("--max-file-mb", type=int, default=20)
    ap.add_argument("--max-files", type=int, default=500000)
    args = ap.parse_args()

    started = utc_now()

    if args.source_root:
        source_roots = [Path(x).expanduser().resolve() for x in args.source_root if Path(x).expanduser().exists()]
    else:
        source_roots = discover_source_roots()

    rows, scan_summary = scan_objects(source_roots, args.max_file_mb, args.max_files)
    manifests = [r for r in rows if r.get("object_type") == "mft"]

    object_set_root = merkle_root(rows)
    effective_object_root = merkle_root(manifests) or object_set_root

    out_root = Path(args.out_root)
    history_dir = out_root / "history" / args.export_id
    latest_dir = out_root / "latest"
    object_dir = history_dir / "object"
    object_dir.mkdir(parents=True, exist_ok=True)

    inventory_path = object_dir / "object_inventory.jsonl"
    manifest_path = object_dir / "active_manifest_records.jsonl"
    record_path = object_dir / "object_snapshot_record.json"
    tar_path = object_dir / "object_snapshot.tar.gz"
    sha_path = object_dir / "sha256.txt"

    write_jsonl(inventory_path, rows)
    write_jsonl(manifest_path, manifests)

    finished = utc_now()

    warnings = []
    blockers = []

    if not rows:
        blockers.append("object_inventory_empty")
    if not object_set_root:
        blockers.append("object_set_root_missing")
    if not effective_object_root:
        blockers.append("effective_object_root_missing")
    if not manifests:
        warnings.append("active_manifest_records_empty_or_no_mft_files_found")

    record = {
        "schema": "s3.stage3.object_snapshot_record.v1",
        "snapshot_group_id": args.snapshot_group_id,
        "joint_snapshot_id": f"{args.probe_id}_{args.export_id}",
        "probe_id": args.probe_id,
        "location": args.location,
        "export_id": args.export_id,
        "object_export_started_at": started,
        "object_export_finished_at": finished,
        "object_source_mode": "cache_file_inventory",
        "object_set_root": object_set_root,
        "effective_object_root": effective_object_root,
        "object_inventory_count": len(rows),
        "active_manifest_count": len(manifests),
        "active_manifest_records_path": "active_manifest_records.jsonl",
        "object_inventory_path": "object_inventory.jsonl",
        "manifest_parse_error_count": None,
        "expired_manifest_count": None,
        "fetch_completeness": {
            "all_target_pp_success": None,
            "failed_pp_count": None,
            "timeout_count": None,
            "non_timeout_error_count": None,
            "source": "cache_file_inventory"
        },
        "scan_summary": scan_summary,
        "warnings": warnings,
        "blockers": blockers,
    }

    record_path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")

    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(record_path, arcname="object_snapshot_record.json")
        tar.add(inventory_path, arcname="object_inventory.jsonl")
        tar.add(manifest_path, arcname="active_manifest_records.jsonl")

    sha_rows = []
    for p in [record_path, inventory_path, manifest_path, tar_path]:
        sha_rows.append(f"{sha256_file(p)}  {p.name}\n")
    sha_path.write_text("".join(sha_rows), encoding="utf-8")

    acceptance_ok = not blockers

    acceptance = f"""P1_OBJECT_SNAPSHOT_EXPORT=DONE

probe_id = {args.probe_id}
location = {args.location}
snapshot_group_id = {args.snapshot_group_id}
joint_snapshot_id = {args.probe_id}_{args.export_id}
export_id = {args.export_id}

object_source_mode = cache_file_inventory
object_snapshot_export_success = {acceptance_ok}
source_root_count = {len(source_roots)}
scanned_files = {scan_summary.get("scanned_files")}
object_inventory_count = {len(rows)}
active_manifest_count = {len(manifests)}

object_set_root_exists = {object_set_root is not None}
effective_object_root_exists = {effective_object_root is not None}
active_manifest_records_exists = {manifest_path.exists()}
object_inventory_exists = {inventory_path.exists()}
object_snapshot_tar_gz_exists = {tar_path.exists()}
sha256_txt_exists = {sha_path.exists()}

object_set_root = {object_set_root}
effective_object_root = {effective_object_root}

warnings = {warnings}
blockers = {blockers}

outputs:
  {record_path}
  {manifest_path}
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
