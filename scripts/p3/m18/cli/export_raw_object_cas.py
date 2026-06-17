#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


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


def iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                obj["_m18_input_line_no"] = line_no
                yield obj


def cas_path_for_sha(run_dir: Path, raw_sha256: str) -> Path:
    h = raw_sha256.split("sha256:", 1)[-1]
    return run_dir / "raw_objects" / "sha256" / h[:2] / f"{h}.obj"


def recover_one(rec: Dict[str, Any], run_dir: Path) -> Dict[str, Any]:
    src_value = rec.get("source_path")
    src = Path(str(src_value)).expanduser() if src_value else None

    row = {
        "schema": "s3.m18.raw_object_index.v1",
        "created_at_utc": utc_now_iso(),
        "probe_id": rec.get("probe_id"),
        "canonical_uri": rec.get("canonical_uri"),
        "object_uri": rec.get("object_uri"),
        "object_type": rec.get("object_type"),
        "object_family": rec.get("object_family"),
        "source_path": str(src) if src else None,
        "input_line_no": rec.get("_m18_input_line_no"),
        "inventory_source_file": rec.get("inventory_source_file"),
    }

    if src is None:
        row.update({"recover_status": "missing_source_path", "raw_sha256": None, "raw_size_bytes": None, "cas_path": None, "cas_written": False})
        return row

    if not src.exists() or not src.is_file():
        row.update({"recover_status": "source_path_not_found", "raw_sha256": None, "raw_size_bytes": None, "cas_path": None, "cas_written": False})
        return row

    try:
        data = src.read_bytes()
    except Exception as exc:
        row.update({"recover_status": "read_error", "error": str(exc), "raw_sha256": None, "raw_size_bytes": None, "cas_path": None, "cas_written": False})
        return row

    if not data:
        row.update({"recover_status": "empty_object", "raw_sha256": None, "raw_size_bytes": 0, "cas_path": None, "cas_written": False})
        return row

    raw_sha256 = sha256_bytes(data)
    cas_path = cas_path_for_sha(run_dir, raw_sha256)
    cas_path.parent.mkdir(parents=True, exist_ok=True)

    cas_written = not cas_path.exists()
    if cas_written:
        cas_path.write_bytes(data)

    row.update({"recover_status": "ok" if cas_written else "duplicate_reused", "raw_sha256": raw_sha256, "raw_size_bytes": len(data), "cas_path": str(cas_path.relative_to(run_dir)), "cas_written": cas_written})
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description="M18-B Raw Object CAS Export")
    parser.add_argument("--collector-root", required=False)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--max-records", type=int, default=0)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    input_path = Path(args.input).expanduser().resolve()

    indexes_dir = run_dir / "indexes"
    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"
    for d in [indexes_dir, outputs_dir, checks_dir, run_dir / "raw_objects" / "sha256"]:
        d.mkdir(parents=True, exist_ok=True)

    rows = []
    for i, rec in enumerate(iter_jsonl(input_path), start=1):
        if args.max_records and i > args.max_records:
            break
        rows.append(recover_one(rec, run_dir))

    raw_index = indexes_dir / "raw_object_index.jsonl"
    missing_index = indexes_dir / "missing_object_index.jsonl"
    error_index = indexes_dir / "object_recovery_errors.jsonl"
    summary_path = outputs_dir / "M18B_raw_object_cas_export_summary.json"
    check_path = checks_dir / "M18B_raw_object_cas_export.txt"

    missing = [r for r in rows if not r.get("raw_sha256")]
    errors = [r for r in rows if r.get("recover_status") in {"read_error", "empty_object"}]

    write_jsonl(raw_index, rows)
    write_jsonl(missing_index, missing)
    write_jsonl(error_index, errors)

    recovered = sum(1 for r in rows if r.get("raw_sha256"))
    cas_files = sum(1 for _ in (run_dir / "raw_objects" / "sha256").rglob("*.obj"))
    by_status = Counter(r.get("recover_status") for r in rows)

    status = "PASS" if recovered > 0 else "FAIL"
    summary = {
        "schema": "s3.m18b.raw_object_cas_export_summary.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "input_record_processed_count": len(rows),
        "recovered_count": recovered,
        "missing_count": len(missing),
        "error_count": len(errors),
        "cas_file_count": cas_files,
        "by_recover_status": dict(by_status),
        "raw_object_index": str(raw_index),
        "missing_object_index": str(missing_index),
        "object_recovery_errors": str(error_index),
    }
    write_json(summary_path, summary)

    text = "\n".join([
        f"M18B_RAW_OBJECT_CAS_EXPORT={status}",
        "",
        f"input_record_processed_count = {len(rows)}",
        f"recovered_count = {recovered}",
        f"missing_count = {len(missing)}",
        f"error_count = {len(errors)}",
        f"cas_file_count = {cas_files}",
        f"by_recover_status = {dict(by_status)}",
        "",
        f"raw_object_index = {raw_index}",
        f"missing_object_index = {missing_index}",
        f"object_recovery_errors = {error_index}",
        f"summary_path = {summary_path}",
    ]) + "\n"

    check_path.write_text(text, encoding="utf-8")
    print(text)
    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
