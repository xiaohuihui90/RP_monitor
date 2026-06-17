#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build S3 semantic object inventory.

Batch 4 scope:
  - MFT-only semantic inventory
  - Input: active_manifest_records.jsonl
  - Output: semantic_object_inventory.jsonl + semantic_inventory_summary.json

This module is intentionally non-invasive and does not modify the legacy
object_inventory pipeline.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from scripts.p3.rpki_objects.canonical_uri import (
    canonicalize_object_uri,
    object_type_from_uri,
    repo_host_from_canonical_uri,
)
from scripts.p3.rpki_objects.cms_extract import extract_rpki_signed_object
from scripts.p3.rpki_objects.semantic_hash import (
    canonical_json_hash,
    sha256_file,
)
from scripts.p3.rpki_objects.parsers.mft import build_mft_semantic_record


def _first(obj: Dict[str, Any], keys: Iterable[str], default: Any = "") -> Any:
    for key in keys:
        value = obj.get(key)
        if value not in (None, ""):
            return value
    return default


def _read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with Path(path).open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                obj["_line_no"] = line_no
                yield obj
            except Exception as exc:
                yield {
                    "_line_no": line_no,
                    "_parse_error": repr(exc),
                    "_raw": line[:500],
                }


def _resolve_source_file(
    record: Dict[str, Any],
    *,
    source_root: Optional[str] = None,
) -> Optional[Path]:
    """
    Resolve a local raw/wrapper file path.

    Preferred order:
      1. source_file if it exists
      2. source_root + relative_path if both exist
      3. direct local URI/path if it exists
    """
    source_file = str(_first(record, ["source_file", "file_path", "path"], "") or "")
    if source_file:
        p = Path(source_file)
        if p.exists() and p.is_file():
            return p

    relative_path = str(_first(record, ["relative_path"], "") or "")
    if source_root and relative_path:
        p = Path(source_root).expanduser() / relative_path
        if p.exists() and p.is_file():
            return p

    raw_uri = str(_first(record, ["uri", "cache_uri", "object_uri"], "") or "")
    if raw_uri and not raw_uri.startswith("cache://"):
        p = Path(raw_uri)
        if p.exists() and p.is_file():
            return p

    return None


def _build_parse_failed_record(
    *,
    record: Dict[str, Any],
    canonical_uri: str,
    object_type: str,
    probe_id: str,
    snapshot_group_id: str,
    object_export_id: str,
    source_adapter: str,
    source_file: Optional[Path],
    source_file_sha256: str,
    parse_status: str,
    warning: str,
) -> Dict[str, Any]:
    return {
        "schema": "s3.object.semantic_inventory.v1",
        "probe_id": probe_id,
        "snapshot_group_id": snapshot_group_id,
        "object_export_id": object_export_id,
        "canonical_uri": canonical_uri,
        "repo_host": repo_host_from_canonical_uri(canonical_uri),
        "object_type": object_type,
        "source_adapter": source_adapter,
        "source_file": str(source_file) if source_file else None,
        "source_file_sha256": source_file_sha256,
        "wrapper_detected": None,
        "wrapper_type": None,
        "wrapper_sha256": None,
        "wrapper_size": None,
        "cms_payload_offset": None,
        "cms_payload_len": None,
        "cms_payload_sha256": None,
        "econtent_type_oid": None,
        "econtent_sha256": None,
        "semantic_fields": {},
        "semantic_object_hash": None,
        "parse_status": parse_status,
        "warnings": [warning],
        "legacy_record": {
            "line_no": record.get("_line_no"),
            "uri": record.get("uri"),
            "relative_path": record.get("relative_path"),
            "source_file": record.get("source_file"),
            "sha256": record.get("sha256"),
            "object_type": record.get("object_type"),
        },
    }


def compute_semantic_object_root(records: Iterable[Dict[str, Any]]) -> str:
    """
    Compute semantic_object_root_v1 from successfully parsed records.

    Only parse_status=ok records with semantic_object_hash are included.
    Duplicate identical triples are collapsed.
    """
    triples = set()
    for r in records:
        if r.get("parse_status") != "ok":
            continue
        h = r.get("semantic_object_hash")
        if not h:
            continue
        triples.add(
            f"{r.get('canonical_uri')}|{r.get('object_type')}|{h}"
        )

    return canonical_json_hash(sorted(triples))


def build_semantic_inventory(
    *,
    active_manifest_records_path: Path,
    out_dir: Path,
    probe_id: str,
    snapshot_group_id: str,
    object_export_id: str,
    source_adapter: str = "generic_file_v1",
    source_root: Optional[str] = None,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build MFT-only semantic inventory from active_manifest_records.jsonl.
    """
    active_manifest_records_path = Path(active_manifest_records_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    inventory_path = out_dir / "semantic_object_inventory.jsonl"
    summary_path = out_dir / "semantic_inventory_summary.json"
    acceptance_path = out_dir / "semantic_inventory_acceptance.txt"

    records_out = []

    counters = Counter()
    warnings = Counter()

    with inventory_path.open("w", encoding="utf-8") as out:
        for idx, rec in enumerate(_read_jsonl(active_manifest_records_path), 1):
            if limit is not None and idx > limit:
                break

            counters["input_records"] += 1

            if "_parse_error" in rec:
                counters["input_json_parse_failed"] += 1
                continue

            raw_uri = str(_first(
                rec,
                ["uri", "relative_path", "path", "cache_uri", "object_uri", "file_path"],
                "",
            ))
            canonical_uri = canonicalize_object_uri(raw_uri, source_root=source_root)
            object_type = str(_first(rec, ["object_type", "type"], "") or object_type_from_uri(canonical_uri)).lower()

            if object_type == "asa":
                object_type = "aspa"

            if object_type != "mft":
                counters["skipped_non_mft"] += 1
                continue

            counters["mft_records"] += 1

            source_file = _resolve_source_file(rec, source_root=source_root)
            source_file_hash = ""

            if source_file is None:
                counters["raw_file_missing"] += 1
                warnings["raw_file_missing"] += 1
                sem = _build_parse_failed_record(
                    record=rec,
                    canonical_uri=canonical_uri,
                    object_type=object_type,
                    probe_id=probe_id,
                    snapshot_group_id=snapshot_group_id,
                    object_export_id=object_export_id,
                    source_adapter=source_adapter,
                    source_file=None,
                    source_file_sha256="",
                    parse_status="raw_file_missing",
                    warning="raw_file_missing",
                )
            else:
                try:
                    data = source_file.read_bytes()
                    source_file_hash = sha256_file(source_file)
                    cms_info = extract_rpki_signed_object(data, preferred_object_type="mft")

                    if cms_info.get("parse_status") != "ok":
                        counters["cms_extract_failed"] += 1
                        warnings[str(cms_info.get("parse_status"))] += 1
                        sem = _build_parse_failed_record(
                            record=rec,
                            canonical_uri=canonical_uri,
                            object_type=object_type,
                            probe_id=probe_id,
                            snapshot_group_id=snapshot_group_id,
                            object_export_id=object_export_id,
                            source_adapter=source_adapter,
                            source_file=source_file,
                            source_file_sha256=source_file_hash,
                            parse_status=str(cms_info.get("parse_status")),
                            warning=str(cms_info.get("parse_error") or cms_info.get("parse_status")),
                        )
                    else:
                        sem = build_mft_semantic_record(
                            canonical_uri=canonical_uri,
                            cms_info=cms_info,
                            probe_id=probe_id,
                            snapshot_group_id=snapshot_group_id,
                            object_export_id=object_export_id,
                            source_adapter=source_adapter,
                            source_file=str(source_file),
                            source_file_sha256=source_file_hash,
                        )

                        if sem.get("parse_status") == "ok":
                            counters["semantic_ok"] += 1
                            if sem.get("wrapper_detected"):
                                counters["wrapper_detected"] += 1
                        else:
                            counters["semantic_parse_failed"] += 1
                            for w in sem.get("warnings", []):
                                warnings[w] += 1

                except Exception as exc:
                    counters["exception"] += 1
                    warnings["exception"] += 1
                    sem = _build_parse_failed_record(
                        record=rec,
                        canonical_uri=canonical_uri,
                        object_type=object_type,
                        probe_id=probe_id,
                        snapshot_group_id=snapshot_group_id,
                        object_export_id=object_export_id,
                        source_adapter=source_adapter,
                        source_file=source_file,
                        source_file_sha256=source_file_hash,
                        parse_status="exception",
                        warning=repr(exc),
                    )

            sem["repo_host"] = repo_host_from_canonical_uri(sem.get("canonical_uri", ""))
            sem["legacy_record"] = {
                "line_no": rec.get("_line_no"),
                "uri": rec.get("uri"),
                "relative_path": rec.get("relative_path"),
                "source_file": rec.get("source_file"),
                "sha256": rec.get("sha256"),
                "object_type": rec.get("object_type"),
            }

            records_out.append(sem)
            out.write(json.dumps(sem, ensure_ascii=False, sort_keys=True) + "\n")

    semantic_root = compute_semantic_object_root(records_out)

    parse_failed = len([
        r for r in records_out
        if r.get("parse_status") != "ok"
    ])

    total_semantic_records = len(records_out)
    parse_failed_ratio = (parse_failed / total_semantic_records) if total_semantic_records else 0.0

    if parse_failed_ratio == 0:
        confidence = "high"
    elif parse_failed_ratio <= 0.01:
        confidence = "medium-high"
    elif parse_failed_ratio <= 0.05:
        confidence = "medium"
    else:
        confidence = "diagnostic_only"

    summary = {
        "schema": "s3.object.semantic_inventory_summary.v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "probe_id": probe_id,
        "snapshot_group_id": snapshot_group_id,
        "object_export_id": object_export_id,
        "source_adapter": source_adapter,
        "source_root": source_root,
        "input_path": str(active_manifest_records_path),
        "inventory_path": str(inventory_path),
        "semantic_object_root": semantic_root,
        "semantic_inventory_available": True,
        "total_semantic_records": total_semantic_records,
        "semantic_ok": counters.get("semantic_ok", 0),
        "parse_failed": parse_failed,
        "parse_failed_ratio": parse_failed_ratio,
        "semantic_compare_confidence": confidence,
        "counters": dict(counters),
        "warnings": dict(warnings),
    }

    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    lines = [
        "SEMANTIC_OBJECT_INVENTORY_BUILD=DONE",
        "",
        f"created_at_utc = {summary['created_at_utc']}",
        f"probe_id = {probe_id}",
        f"snapshot_group_id = {snapshot_group_id}",
        f"object_export_id = {object_export_id}",
        f"source_adapter = {source_adapter}",
        f"source_root = {source_root}",
        "",
        f"semantic_object_root = {semantic_root}",
        f"total_semantic_records = {total_semantic_records}",
        f"semantic_ok = {summary['semantic_ok']}",
        f"parse_failed = {parse_failed}",
        f"parse_failed_ratio = {parse_failed_ratio:.6f}",
        f"semantic_compare_confidence = {confidence}",
        "",
        f"counters = {dict(counters)}",
        f"warnings = {dict(warnings)}",
        "",
        f"inventory_path = {inventory_path}",
        f"summary_path = {summary_path}",
        "",
    ]

    acceptance_path.write_text("\n".join(lines), encoding="utf-8")
    return summary
