#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable


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
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)

    count = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1

    return count


def classify_identity(probe_values: Dict[str, Dict[str, Any]]) -> str:
    recovered = {
        probe: value
        for probe, value in probe_values.items()
        if value.get("raw_sha256")
    }

    if not recovered:
        return "all_missing"

    if len(recovered) == 1:
        return "single_probe_only"

    hashes = {
        value.get("raw_sha256")
        for value in recovered.values()
        if value.get("raw_sha256")
    }

    if len(recovered) == len(probe_values):
        return "all_recovered_aligned" if len(hashes) == 1 else "all_recovered_divergent"

    return "partial_recovered_aligned" if len(hashes) == 1 else "partial_recovered_divergent"


def identity_key(row: Dict[str, Any]) -> str:
    uri = row.get("canonical_uri") or row.get("object_uri") or ""
    return f"uri:{uri}"


def build_identity_index(raw_index: Path) -> tuple[list[Dict[str, Any]], Dict[str, Any]]:
    rows = list(read_jsonl(raw_index))

    grouped: Dict[str, list[Dict[str, Any]]] = defaultdict(list)

    for row in rows:
        key = identity_key(row)
        grouped[key].append(row)

    identity_rows = []

    for key, items in sorted(grouped.items()):
        first = items[0]
        probe_values: Dict[str, Dict[str, Any]] = {}

        for item in items:
            probe = item.get("probe_id") or "unknown"

            probe_values[probe] = {
                "recover_status": item.get("recover_status"),
                "raw_sha256": item.get("raw_sha256"),
                "raw_size_bytes": item.get("raw_size_bytes"),
                "cas_path": item.get("cas_path"),
                "source_path": item.get("source_path"),
                "object_type": item.get("object_type"),
            }

        recovered_hashes = {
            v.get("raw_sha256")
            for v in probe_values.values()
            if v.get("raw_sha256")
        }

        identity_rows.append({
            "schema": "s3.m18.object_identity_index.v1",
            "created_at_utc": utc_now_iso(),
            "identity_key": key,
            "canonical_uri": first.get("canonical_uri"),
            "object_uri": first.get("object_uri"),
            "object_type": first.get("object_type"),
            "object_family": first.get("object_family"),
            "probe_values": probe_values,
            "probe_count": len(probe_values),
            "recovered_probe_count": sum(
                1 for v in probe_values.values() if v.get("raw_sha256")
            ),
            "distinct_raw_sha256_count": len(recovered_hashes),
            "hash_level_status": classify_identity(probe_values),
        })

    status_counter = Counter(
        row["hash_level_status"]
        for row in identity_rows
    )

    summary = {
        "schema": "s3.m18d.object_identity_index_summary.v1",
        "created_at_utc": utc_now_iso(),
        "scope": "recoverable_subset_identity_index",
        "raw_index": str(raw_index),
        "raw_record_count": len(rows),
        "identity_count": len(identity_rows),
        "by_hash_level_status": dict(status_counter),
    }

    return identity_rows, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="M18-D Object Identity Index")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--raw-index", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    raw_index = Path(args.raw_index).expanduser().resolve()

    indexes_dir = run_dir / "indexes"
    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"

    indexes_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)

    identity_rows, summary = build_identity_index(raw_index)

    identity_path = indexes_dir / "object_identity_index.jsonl"
    summary_path = outputs_dir / "M18D_object_identity_index_summary.json"
    check_path = checks_dir / "M18D_object_identity_index.txt"

    write_jsonl(identity_path, identity_rows)

    summary["object_identity_index"] = str(identity_path)
    summary["summary_path"] = str(summary_path)
    write_json(summary_path, summary)

    status = "PASS" if summary["identity_count"] > 0 else "FAIL"

    text = "\n".join([
        f"M18D_OBJECT_IDENTITY_INDEX={status}",
        "",
        "scope = recoverable_subset_identity_index",
        f"raw_record_count = {summary['raw_record_count']}",
        f"identity_count = {summary['identity_count']}",
        f"by_hash_level_status = {summary['by_hash_level_status']}",
        "",
        f"object_identity_index = {identity_path}",
        f"summary_path = {summary_path}",
    ]) + "\n"

    check_path.write_text(text, encoding="utf-8")
    print(text)

    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
