#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable


SUPPORTED_TYPES = {"mft", "roa", "cer", "crl", "gbr", "aspa", "asa", "sig", "tak"}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                obj["_line_no"] = line_no
                yield obj


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    return n


def object_family(obj_type: str) -> str:
    if obj_type in {"cer", "crl"}:
        return "resource_control"
    if obj_type in {"mft", "roa", "gbr", "aspa", "asa", "sig", "tak"}:
        return "signed_object"
    return "unknown"


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
            size += len(chunk)

    return "sha256:" + h.hexdigest(), size


def cas_rel_path(raw_sha256: str) -> Path:
    hexv = raw_sha256.split("sha256:", 1)[1]
    return Path("raw_objects") / "sha256" / hexv[:2] / f"{hexv}.obj"


def infer_uri_from_cache_path(path: Path) -> tuple[str | None, str]:
    s = str(path)

    marker = ".rpki-cache/repository/rsync/"
    if marker in s:
        tail = s.split(marker, 1)[1]
        return "cache://.rpki-cache/repository/rsync/" + tail, "rpki_cache_rsync_path_reverse"

    marker = "/rpki-cache/rsync/"
    if marker in s:
        tail = s.split(marker, 1)[1]
        return "cache://.rpki-cache/repository/rsync/" + tail, "routinator_rpki_cache_rsync_path_reverse"

    marker = ".rpki-cache/repository/stored/rrdp/"
    if marker in s and "/rsync/" in s:
        tail = s.split("/rsync/", 1)[1]
        return "cache://.rpki-cache/repository/rsync/" + tail, "stored_rrdp_rsync_tail_reverse"

    marker = "/rpki-cache/stored/rrdp/"
    if marker in s and "/rsync/" in s:
        tail = s.split("/rsync/", 1)[1]
        return "cache://.rpki-cache/repository/rsync/" + tail, "routinator_stored_rrdp_rsync_tail_reverse"

    marker = "/repository/rsync/"
    if marker in s:
        tail = s.split(marker, 1)[1]
        return "cache://.rpki-cache/repository/rsync/" + tail, "repository_rsync_path_reverse"

    marker = ".rpki-cache/repository/stored/ta/https/"
    if marker in s:
        tail = s.split(marker, 1)[1]
        return "cache://.rpki-cache/repository/stored/ta/https/" + tail, "stored_ta_https_path_reverse"

    marker = "/rpki-cache/stored/ta/https/"
    if marker in s:
        tail = s.split(marker, 1)[1]
        return "cache://.rpki-cache/repository/stored/ta/https/" + tail, "routinator_stored_ta_https_path_reverse"

    return None, "not_resolved"


def infer_uri_from_raw_wrapper_filename(path: Path) -> tuple[str | None, str]:
    name = path.name

    if "__" not in name:
        return None, "not_raw_wrapper"

    # 0001_rsync__host__repo__file.mft -> rsync/host/repo/file.mft
    name2 = re.sub(r"^\d+_", "", name)
    key = name2.replace("__", "/")

    if key.startswith("rsync/"):
        return "cache://.rpki-cache/repository/" + key, "raw_wrapper_filename_reverse"

    return None, "raw_wrapper_unrecognized"


def resolve_canonical_uri(row: Dict[str, Any], source_path: Path) -> tuple[str | None, str, list[str]]:
    warnings = []

    for k in ("canonical_uri", "object_uri", "uri"):
        v = row.get(k)
        if v:
            s = str(v)
            if s.startswith("rsync://"):
                return "cache://.rpki-cache/repository/rsync/" + s[len("rsync://"):], f"input_{k}_rsync_normalized", warnings
            return s, f"input_{k}", warnings

    uri, method = infer_uri_from_cache_path(source_path)
    if uri:
        return uri, method, warnings

    uri, method = infer_uri_from_raw_wrapper_filename(source_path)
    if uri:
        return uri, method, warnings

    warnings.append("canonical_uri_unresolved")
    return None, "uri_unresolved", warnings


def export_one(
    row: Dict[str, Any],
    run_dir: Path,
    probe_id: str,
    export_run_id: str,
) -> tuple[Dict[str, Any] | None, Dict[str, Any] | None]:
    source_path = Path(row.get("real_path") or row.get("source_path") or "").expanduser()

    obj_type = row.get("object_type_guess") or row.get("object_type") or source_path.suffix.lower().lstrip(".")
    obj_type = obj_type if obj_type in SUPPORTED_TYPES else "unknown"

    missing_base = {
        "schema": "s3.m20.probe_missing_object_index.v1",
        "created_at_utc": utc_now_iso(),
        "probe_id": probe_id,
        "export_run_id": export_run_id,
        "source_path": str(source_path),
        "filename": source_path.name,
        "object_type_guess": obj_type,
        "notes": [],
    }

    if not source_path.exists():
        missing = dict(missing_base)
        missing["missing_reason"] = "source_path_not_found"
        return None, missing

    if not source_path.is_file():
        missing = dict(missing_base)
        missing["missing_reason"] = "source_path_not_file"
        return None, missing

    canonical_uri, resolver_method, warnings = resolve_canonical_uri(row, source_path)

    try:
        raw_sha256, raw_size = sha256_file(source_path)
    except PermissionError:
        missing = dict(missing_base)
        missing["missing_reason"] = "permission_denied"
        return None, missing
    except Exception as exc:
        missing = dict(missing_base)
        missing["missing_reason"] = "read_error"
        missing["notes"] = [str(exc)]
        return None, missing

    rel_cas = cas_rel_path(raw_sha256)
    abs_cas = run_dir / rel_cas
    abs_cas.parent.mkdir(parents=True, exist_ok=True)

    if abs_cas.exists():
        recover_status = "duplicate_reused"
    else:
        shutil.copy2(source_path, abs_cas)
        recover_status = "ok"

    verify_sha, verify_size = sha256_file(abs_cas)
    if verify_sha != raw_sha256 or verify_size != raw_size:
        missing = dict(missing_base)
        missing["missing_reason"] = "cas_integrity_error"
        missing["notes"] = [f"expected={raw_sha256}/{raw_size}", f"actual={verify_sha}/{verify_size}"]
        return None, missing

    record = {
        "schema": "s3.m20.probe_raw_object_index.v1",
        "created_at_utc": utc_now_iso(),
        "probe_id": probe_id,
        "export_run_id": export_run_id,

        "canonical_uri": canonical_uri,
        "object_uri": canonical_uri,
        "object_type": obj_type,
        "object_family": object_family(obj_type),

        "source_path": str(source_path),
        "source_resolver_method": resolver_method,

        "raw_sha256": raw_sha256,
        "raw_size_bytes": raw_size,
        "cas_path": str(rel_cas),

        "mtime": row.get("mtime"),
        "recover_status": recover_status,
        "warnings": warnings,
    }

    missing = None
    if canonical_uri is None:
        missing = dict(missing_base)
        missing["missing_reason"] = "uri_unresolved"
        missing["notes"] = ["raw bytes exported to CAS, but canonical_uri is unresolved"]

    return record, missing


def main() -> int:
    parser = argparse.ArgumentParser(description="M20-B probe-side raw CAS export")
    parser.add_argument("--probe-id", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--candidate-file", required=True)
    parser.add_argument("--max-records", type=int, default=0)
    args = parser.parse_args()

    probe_id = args.probe_id
    run_dir = Path(args.run_dir).expanduser().resolve()
    candidate_file = Path(args.candidate_file).expanduser().resolve()

    indexes_dir = run_dir / "indexes"
    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"
    indexes_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)

    export_run_id = run_dir.name

    raw_records = []
    missing_records = []

    processed = 0

    for row in read_jsonl(candidate_file):
        if args.max_records > 0 and processed >= args.max_records:
            break

        processed += 1

        record, missing = export_one(
            row=row,
            run_dir=run_dir,
            probe_id=probe_id,
            export_run_id=export_run_id,
        )

        if record:
            raw_records.append(record)

        if missing:
            missing_records.append(missing)

    raw_index = indexes_dir / "probe_raw_object_index.jsonl"
    missing_index = indexes_dir / "probe_missing_object_index.jsonl"
    summary_path = outputs_dir / "M20B_probe_raw_cas_export_summary.json"
    check_path = checks_dir / "M20B_probe_raw_cas_export.txt"

    write_jsonl(raw_index, raw_records)
    write_jsonl(missing_index, missing_records)

    by_object_type = Counter(r.get("object_type") or "unknown" for r in raw_records)
    by_recover_status = Counter(r.get("recover_status") or "unknown" for r in raw_records)
    by_uri_resolver = Counter(r.get("source_resolver_method") or "unknown" for r in raw_records)
    by_missing_reason = Counter(r.get("missing_reason") or "unknown" for r in missing_records)

    resolved_uri_count = sum(1 for r in raw_records if r.get("canonical_uri"))
    unresolved_uri_count = sum(1 for r in raw_records if not r.get("canonical_uri"))
    distinct_raw_sha256_count = len({r.get("raw_sha256") for r in raw_records if r.get("raw_sha256")})

    cas_file_count = sum(1 for _ in (run_dir / "raw_objects" / "sha256").rglob("*.obj"))

    status = "PASS" if raw_records and cas_file_count > 0 else "FAIL"

    summary = {
        "schema": "s3.m20b.probe_raw_cas_export_summary.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "probe_id": probe_id,
        "run_dir": str(run_dir),
        "candidate_file": str(candidate_file),
        "input_record_processed_count": processed,
        "raw_object_index_count": len(raw_records),
        "missing_object_index_count": len(missing_records),
        "resolved_uri_count": resolved_uri_count,
        "unresolved_uri_count": unresolved_uri_count,
        "distinct_raw_sha256_count": distinct_raw_sha256_count,
        "cas_file_count": cas_file_count,
        "by_object_type": dict(by_object_type),
        "by_recover_status": dict(by_recover_status),
        "by_uri_resolver": dict(by_uri_resolver),
        "by_missing_reason": dict(by_missing_reason),
        "raw_object_index": str(raw_index),
        "missing_object_index": str(missing_index),
    }

    write_json(summary_path, summary)

    text = "\n".join([
        f"M20B_PROBE_RAW_CAS_EXPORT={status}",
        "",
        f"probe_id = {probe_id}",
        f"run_dir = {run_dir}",
        f"input_record_processed_count = {processed}",
        f"raw_object_index_count = {len(raw_records)}",
        f"missing_object_index_count = {len(missing_records)}",
        f"resolved_uri_count = {resolved_uri_count}",
        f"unresolved_uri_count = {unresolved_uri_count}",
        f"distinct_raw_sha256_count = {distinct_raw_sha256_count}",
        f"cas_file_count = {cas_file_count}",
        f"by_object_type = {dict(by_object_type)}",
        f"by_recover_status = {dict(by_recover_status)}",
        f"by_uri_resolver = {dict(by_uri_resolver)}",
        f"by_missing_reason = {dict(by_missing_reason)}",
        "",
        f"raw_object_index = {raw_index}",
        f"missing_object_index = {missing_index}",
        f"summary_path = {summary_path}",
    ]) + "\n"

    check_path.write_text(text, encoding="utf-8")
    print(text)

    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
