#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


PATTERNS = [
    "*object*inventory*.jsonl",
    "*object*inventory*.json",
    "*object*summary*.json",
    "*semantic*summary*.json",
    "*manifest*summary*.json",
    "*object*diff*.jsonl",
    "*object*diff*.json",
]

URI_KEYS = [
    "canonical_uri",
    "object_uri",
    "uri",
    "rsync_uri",
    "rrdp_uri",
    "url",
    "file_uri",
    "path_uri",
    "filename",
    "name",
]

SOURCE_PATH_KEYS = [
    "source_path",
    "local_path",
    "cache_path",
    "object_path",
    "file_path",
    "path",
    "full_path",
    "raw_path",
    "resolved_path",
    "validator_cache_path",
]

PROBE_KEYS = [
    "probe_id",
    "probe",
    "site",
    "node",
    "node_id",
    "collector_probe_id",
]

TYPE_KEYS = [
    "object_type",
    "type",
    "file_type",
    "suffix",
    "ext",
]

TYPE_BY_SUFFIX = {
    ".mft": "mft",
    ".roa": "roa",
    ".cer": "cer",
    ".crl": "crl",
    ".gbr": "gbr",
    ".aspa": "aspa",
    ".asa": "asa",
    ".sig": "sig",
    ".tak": "tak",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def safe_relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except Exception:
        return str(path)


def first_non_empty(obj: Dict[str, Any], keys: List[str]) -> Any:
    for key in keys:
        if key in obj and obj[key] not in (None, "", [], {}):
            return obj[key]
    return None


def canonicalize_uri(value: Any) -> Optional[str]:
    if value is None:
        return None

    if isinstance(value, dict):
        value = first_non_empty(value, ["uri", "url", "path", "name", "filename"])

    if value is None:
        return None

    s = str(value).strip()
    if not s:
        return None

    s = s.replace("\\", "/")
    s = re.sub(r"#.*$", "", s)
    return s


def infer_probe_id(text: Optional[str]) -> Optional[str]:
    if not text:
        return None

    s = str(text).lower()

    rules = [
        ("probe-cd", ["probe-cd", "chengdu", "cd2", "/cd/", "_cd_", "-cd-"]),
        ("probe-bj", ["probe-bj", "beijing", "/bj/", "_bj_", "-bj-"]),
        ("probe-sg", ["probe-sg", "singapore", "/sg/", "_sg_", "-sg-"]),
    ]

    for probe_id, tokens in rules:
        if any(token in s for token in tokens):
            return probe_id

    return None


def infer_object_type(value: Optional[str]) -> str:
    if not value:
        return "unknown"

    s = str(value).strip().lower()
    s = s.split("?", 1)[0].split("#", 1)[0]
    suffix = Path(s).suffix.lower()

    return TYPE_BY_SUFFIX.get(suffix, "unknown")


def object_family(object_type: str) -> str:
    if object_type in {"mft", "roa", "gbr", "aspa", "asa"}:
        return "signed_object"

    if object_type in {"cer", "crl"}:
        return "resource_control"

    return "auxiliary"


def infer_id_from_path(path: Path, prefix: str) -> Optional[str]:
    for part in reversed(path.parts):
        if part.startswith(prefix):
            return part
    return None


def try_read_json(path: Path) -> Any:
    max_bytes = int(os.environ.get("M18A_MAX_JSON_BYTES", "50000000"))

    try:
        if path.stat().st_size > max_bytes:
            return None

        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            s = line.strip()
            if not s:
                continue

            try:
                obj = json.loads(s)
            except Exception:
                continue

            if isinstance(obj, dict):
                obj["_m18_line_no"] = line_no
                yield obj


def looks_like_object_record(obj: Dict[str, Any]) -> bool:
    keys = set(obj.keys())

    return bool(
        keys.intersection(URI_KEYS)
        or keys.intersection(SOURCE_PATH_KEYS)
        or keys.intersection({"raw_sha256", "sha256", "hash", "object_hash"})
    )


def walk_json_records(obj: Any, limit: int) -> Iterable[Dict[str, Any]]:
    seen = 0

    def walk(x: Any) -> Iterable[Dict[str, Any]]:
        nonlocal seen

        if seen >= limit:
            return

        if isinstance(x, dict):
            if looks_like_object_record(x):
                seen += 1
                yield x
                return

            for key in [
                "records",
                "rows",
                "items",
                "objects",
                "inventory",
                "cases",
                "diff_cases",
                "object_records",
                "manifest_records",
                "entries",
            ]:
                value = x.get(key)
                if isinstance(value, list):
                    for item in value:
                        if seen >= limit:
                            return
                        yield from walk(item)

            for value in x.values():
                if seen >= limit:
                    return
                if isinstance(value, (dict, list)):
                    yield from walk(value)

        elif isinstance(x, list):
            for item in x:
                if seen >= limit:
                    return
                yield from walk(item)

    yield from walk(obj)


def discover_files(root: Path) -> List[Path]:
    found = set()

    for pattern in PATTERNS:
        for path in root.rglob(pattern):
            if not path.is_file():
                continue
            if "e4a_joint_m18" in path.parts:
                continue
            if path.name.endswith(".sha256"):
                continue
            found.add(path)

    return sorted(found)


def normalize_record(raw: Dict[str, Any], source_file: Path, root: Path) -> Optional[Dict[str, Any]]:
    uri = canonicalize_uri(first_non_empty(raw, URI_KEYS))

    source_path_value = first_non_empty(raw, SOURCE_PATH_KEYS)
    source_path = str(source_path_value).strip() if source_path_value not in (None, "") else None

    if not uri and source_path:
        uri = canonicalize_uri(source_path)

    if not uri and not source_path:
        return None

    probe_id = first_non_empty(raw, PROBE_KEYS)

    if not probe_id:
        probe_id = infer_probe_id(str(source_file))

    if not probe_id and source_path:
        probe_id = infer_probe_id(source_path)

    probe_id = str(probe_id) if probe_id else None

    explicit_type = first_non_empty(raw, TYPE_KEYS)

    if explicit_type:
        object_type = str(explicit_type).lower().strip().lstrip(".")
        if object_type == "route_origin_authorization":
            object_type = "roa"
    else:
        object_type = infer_object_type(uri or source_path)

    source_path_abs = None
    source_path_exists = None

    if source_path:
        p = Path(source_path).expanduser()

        if not p.is_absolute():
            p_from_root = (root / p).resolve()
            p_from_file = (source_file.parent / p).resolve()

            if p_from_root.exists():
                p = p_from_root
            elif p_from_file.exists():
                p = p_from_file

        source_path_abs = str(p)
        source_path_exists = p.exists()

    snapshot_group_id = infer_id_from_path(source_file, "group_")

    object_export_id = None
    for part in reversed(source_file.parts):
        lower = part.lower()
        if "object" in lower and ("m16" in lower or "m12" in lower or "export" in lower):
            object_export_id = part
            break

    return {
        "schema": "s3.m18.inventory_record.v1",
        "created_at_utc": utc_now_iso(),
        "probe_id": probe_id,
        "object_uri": uri,
        "canonical_uri": uri,
        "object_type": object_type,
        "object_family": object_family(object_type),
        "source_path": source_path_abs or source_path,
        "source_path_exists": source_path_exists,
        "inventory_source_file": str(source_file),
        "inventory_source_relpath": safe_relpath(source_file, root),
        "snapshot_group_id": snapshot_group_id,
        "object_export_id": object_export_id,
        "raw_keys": sorted(k for k in raw.keys() if not k.startswith("_"))[:80],
        "line_no": raw.get("_m18_line_no"),
    }


def load_records(path: Path, root: Path, max_records: int) -> List[Dict[str, Any]]:
    rows = []

    if path.suffix == ".jsonl":
        iterator = iter_jsonl(path)
    else:
        obj = try_read_json(path)
        if obj is None:
            return []
        iterator = walk_json_records(obj, max_records)

    for raw in iterator:
        if len(rows) >= max_records:
            break

        row = normalize_record(raw, path, root)
        if row:
            rows.append(row)

    return rows


def run(root: Path, run_dir: Path, max_records_per_file: int) -> Dict[str, Any]:
    inputs_dir = run_dir / "inputs"
    checks_dir = run_dir / "checks"

    inputs_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)

    candidate_files = discover_files(root)

    all_records = []
    file_summaries = []

    for path in candidate_files:
        records = load_records(path, root, max_records_per_file)

        file_summaries.append({
            "path": str(path),
            "relpath": safe_relpath(path, root),
            "size_bytes": path.stat().st_size,
            "record_count": len(records),
            "by_probe": dict(Counter(r.get("probe_id") or "unknown" for r in records)),
            "by_object_type": dict(Counter(r.get("object_type") or "unknown" for r in records)),
        })

        all_records.extend(records)

    by_probe = Counter(r.get("probe_id") or "unknown" for r in all_records)
    by_type = Counter(r.get("object_type") or "unknown" for r in all_records)
    by_family = Counter(r.get("object_family") or "unknown" for r in all_records)

    source_path_known = sum(1 for r in all_records if r.get("source_path"))
    source_path_exists_true = sum(1 for r in all_records if r.get("source_path_exists") is True)
    source_path_exists_false = sum(1 for r in all_records if r.get("source_path_exists") is False)

    normalized_records_path = inputs_dir / "normalized_inventory_records.jsonl"
    candidate_files_path = inputs_dir / "inventory_candidate_files.json"
    summary_path = inputs_dir / "inventory_input_summary.json"

    write_jsonl(normalized_records_path, all_records)
    write_json(candidate_files_path, file_summaries)

    status = "PASS" if candidate_files and all_records else "FAIL"

    warnings = []

    if source_path_exists_true == 0:
        warnings.append("no_existing_source_path_found_yet_m18b_may_need_path_resolver")

    summary = {
        "schema": "s3.m18a.inventory_input_summary.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "collector_root": str(root),
        "run_dir": str(run_dir),
        "candidate_file_count": len(candidate_files),
        "candidate_file_with_records_count": sum(1 for x in file_summaries if x["record_count"] > 0),
        "normalized_record_count": len(all_records),
        "by_probe": dict(by_probe),
        "by_object_type": dict(by_type),
        "by_object_family": dict(by_family),
        "source_path_known_count": source_path_known,
        "source_path_exists_true_count": source_path_exists_true,
        "source_path_exists_false_count": source_path_exists_false,
        "normalized_records_path": str(normalized_records_path),
        "candidate_files_path": str(candidate_files_path),
        "file_summaries": file_summaries[:300],
        "warnings": warnings,
    }

    write_json(summary_path, summary)

    check_lines = [
        f"M18A_INVENTORY_INPUT_DISCOVERY={status}",
        "",
        f"created_at_utc = {summary['created_at_utc']}",
        f"collector_root = {root}",
        f"run_dir = {run_dir}",
        "",
        f"candidate_file_count = {summary['candidate_file_count']}",
        f"candidate_file_with_records_count = {summary['candidate_file_with_records_count']}",
        f"normalized_record_count = {summary['normalized_record_count']}",
        f"by_probe = {summary['by_probe']}",
        f"by_object_type = {summary['by_object_type']}",
        f"by_object_family = {summary['by_object_family']}",
        f"source_path_known_count = {source_path_known}",
        f"source_path_exists_true_count = {source_path_exists_true}",
        f"source_path_exists_false_count = {source_path_exists_false}",
        f"warnings = {warnings}",
        "",
        f"summary_path = {summary_path}",
        f"normalized_records_path = {normalized_records_path}",
        f"candidate_files_path = {candidate_files_path}",
    ]

    check_path = checks_dir / "M18A_inventory_input_discovery.txt"
    check_path.write_text("\n".join(check_lines) + "\n", encoding="utf-8")

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="M18-A Inventory Input Discovery")
    parser.add_argument("--collector-root", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--max-records-per-file", type=int, default=200000)

    args = parser.parse_args()

    root = Path(args.collector_root).expanduser().resolve()
    run_dir = Path(args.run_dir).expanduser().resolve()

    summary = run(root, run_dir, args.max_records_per_file)

    check_path = run_dir / "checks" / "M18A_inventory_input_discovery.txt"
    print(check_path.read_text(encoding="utf-8"))

    return 0 if summary.get("status") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
