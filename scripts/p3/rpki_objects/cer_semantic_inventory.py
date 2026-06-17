#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build CER semantic inventory from S3 object_inventory.jsonl.

Scope:
  - Parse S3-collected repository .cer files.
  - Extract certificate semantic fields, chain index hash, and resource-set hash.
  - Do NOT validate certificate signatures or build full RFC 6487 paths.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse

from scripts.p3.rpki_objects.canonical_uri import canonicalize_object_uri
from scripts.p3.rpki_objects.semantic_hash import canonical_json_hash
from scripts.p3.rpki_objects.parsers.cer import parse_cer_der


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
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
                yield {"_line_no": line_no, "_json_parse_error": repr(exc)}


def is_cer_row(row: Dict[str, Any]) -> bool:
    object_type = str(row.get("object_type") or "").lower()
    uri = str(row.get("uri") or row.get("canonical_uri") or "").lower()
    source_file = str(row.get("source_file") or "").lower()
    relative_path = str(row.get("relative_path") or "").lower()

    return (
        object_type == "cer"
        or uri.endswith(".cer")
        or source_file.endswith(".cer")
        or relative_path.endswith(".cer")
    )


def repo_host_from_uri(uri: str) -> str:
    if not uri:
        return "unknown"

    s = uri

    if s.startswith("cache://rsync/"):
        rest = s[len("cache://rsync/") :]
        return rest.split("/", 1)[0] if rest else "unknown"

    if s.startswith("cache://.rpki-cache/repository/rsync/"):
        rest = s[len("cache://.rpki-cache/repository/rsync/") :]
        return rest.split("/", 1)[0] if rest else "unknown"

    if s.startswith("cache://repository/rsync/"):
        rest = s[len("cache://repository/rsync/") :]
        return rest.split("/", 1)[0] if rest else "unknown"

    if s.startswith("rsync://"):
        rest = s[len("rsync://") :]
        return rest.split("/", 1)[0] if rest else "unknown"

    try:
        parsed = urlparse(s)
        return parsed.netloc or "unknown"
    except Exception:
        return "unknown"


def resolve_source_file(row: Dict[str, Any], source_root: Optional[Path]) -> Optional[Path]:
    candidates = []

    for key in ["source_file", "path", "file_path"]:
        v = row.get(key)
        if v:
            p = Path(str(v))
            candidates.append(p)
            if source_root is not None and not p.is_absolute():
                candidates.append(source_root / p)

    rel = row.get("relative_path")
    if rel and source_root is not None:
        rel_s = str(rel).lstrip("/")
        candidates.append(source_root / rel_s)

        # 常见 relative_path 形态：repository/rsync/...
        if rel_s.startswith("repository/"):
            candidates.append(source_root / rel_s[len("repository/") :])

    uri = row.get("uri") or row.get("canonical_uri")
    if uri and source_root is not None:
        s = str(uri)
        prefixes = [
            "cache://.rpki-cache/",
            "cache://",
        ]
        for prefix in prefixes:
            if s.startswith(prefix):
                tail = s[len(prefix) :].lstrip("/")
                candidates.append(source_root / tail)
                if tail.startswith("repository/"):
                    candidates.append(source_root / tail[len("repository/") :])

    for p in candidates:
        try:
            if p.exists() and p.is_file():
                return p
        except Exception:
            continue

    return None


def inspect_cer_file(path: Path, canonical_uri: Optional[str] = None) -> Dict[str, Any]:
    p = Path(path)
    raw = p.read_bytes()
    parsed = parse_cer_der(raw)

    return {
        "source_file": str(p),
        "source_file_sha256": sha256_hex(raw),
        "canonical_uri": canonical_uri,
        **parsed,
    }


def build_cer_semantic_inventory(
    *,
    probe_id: str,
    snapshot_group_id: str,
    object_export_id: str,
    object_inventory_path: Path,
    source_root: Optional[Path],
    out_dir: Path,
    source_adapter: str = "routinator_cache_v1",
    certificate_source_type: str = "repository_cer",
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    inventory_out = out_dir / "cer_semantic_inventory.jsonl"
    summary_out = out_dir / "cer_semantic_inventory_summary.json"
    acceptance_out = out_dir / "cer_semantic_inventory_acceptance.txt"

    counters = Counter()
    parse_error_counts = Counter()
    repo_counts = Counter()
    role_counts = Counter()
    parse_error_samples = []

    semantic_lines = []
    chain_lines = []
    resource_lines = []

    semantic_by_repo = defaultdict(list)
    chain_by_repo = defaultdict(list)
    resource_by_repo = defaultdict(list)

    with inventory_out.open("w", encoding="utf-8") as w:
        for row in read_jsonl(Path(object_inventory_path)):
            counters["input_rows"] += 1

            if "_json_parse_error" in row:
                counters["json_parse_failed"] += 1
                continue

            if not is_cer_row(row):
                continue

            counters["total_cer_records"] += 1

            if limit is not None and counters["total_cer_records"] > limit:
                break

            raw_uri = row.get("uri") or row.get("canonical_uri") or row.get("source_uri") or ""

            try:
                canonical_uri = canonicalize_object_uri(str(raw_uri))
            except Exception:
                canonical_uri = str(raw_uri)

            repo_host = repo_host_from_uri(canonical_uri)
            repo_counts[repo_host] += 1

            source_file = resolve_source_file(row, source_root)

            record: Dict[str, Any] = {
                "schema": "s3.stage3.rpki_objects.cer_semantic_record.v1",
                "probe_id": probe_id,
                "snapshot_group_id": snapshot_group_id,
                "object_export_id": object_export_id,
                "object_type": "cer",
                "certificate_source_type": certificate_source_type,
                "canonical_uri": canonical_uri,
                "repo_host": repo_host,
                "source_file": str(source_file) if source_file else None,
                "source_root": str(source_root) if source_root else None,
                "source_adapter": source_adapter,
                "source_inventory_line_no": row.get("_line_no"),
            }

            if source_file is None:
                record.update(
                    {
                        "parse_status": "raw_file_missing",
                        "parse_error_class": "raw_file_missing",
                        "parse_error": "source file cannot be resolved",
                        "source_file_sha256": None,
                        "der_sha256": None,
                        "semantic_fields": {},
                        "semantic_object_hash": None,
                        "chain_index_hash": None,
                        "resource_set_hash": None,
                        "warnings": ["raw_file_missing"],
                    }
                )
                parse_error_counts["raw_file_missing"] += 1
            else:
                try:
                    parsed = inspect_cer_file(source_file, canonical_uri=canonical_uri)
                    record.update(parsed)
                    record["parse_error_class"] = None
                    record["parse_error"] = None

                    counters["semantic_ok"] += 1

                    sf = record.get("semantic_fields") or {}
                    role = sf.get("certificate_role") or "unknown"
                    role_counts[role] += 1

                    semantic_hash = record.get("semantic_object_hash")
                    chain_hash = record.get("chain_index_hash")
                    resource_hash = record.get("resource_set_hash")

                    if semantic_hash:
                        line = f"{canonical_uri}\tcer\t{semantic_hash}"
                        semantic_lines.append(line)
                        semantic_by_repo[repo_host].append(line)

                    if chain_hash:
                        line = f"{canonical_uri}\tcer_chain\t{chain_hash}"
                        chain_lines.append(line)
                        chain_by_repo[repo_host].append(line)

                    if resource_hash:
                        line = f"{canonical_uri}\tcer_resource\t{resource_hash}"
                        resource_lines.append(line)
                        resource_by_repo[repo_host].append(line)

                except Exception as exc:
                    err = repr(exc)
                    err_class = str(exc).split(":", 1)[0] if str(exc) else exc.__class__.__name__
                    record.update(
                        {
                            "parse_status": err_class,
                            "parse_error_class": err_class,
                            "parse_error": err,
                            "semantic_fields": {},
                            "semantic_object_hash": None,
                            "chain_index_hash": None,
                            "resource_set_hash": None,
                            "warnings": [err_class],
                        }
                    )
                    parse_error_counts[err_class] += 1

                    if len(parse_error_samples) < 100:
                        parse_error_samples.append(
                            {
                                "canonical_uri": canonical_uri,
                                "source_file": str(source_file),
                                "parse_error_class": err_class,
                                "parse_error": err[:500],
                            }
                        )

            w.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    total_cer = counters["total_cer_records"]
    semantic_ok = counters["semantic_ok"]
    parse_failed = total_cer - semantic_ok
    semantic_ok_ratio = (semantic_ok / total_cer) if total_cer else 0.0

    summary = {
        "schema": "s3.stage3.cer_semantic_inventory_summary.v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "probe_id": probe_id,
        "snapshot_group_id": snapshot_group_id,
        "object_export_id": object_export_id,
        "object_inventory_path": str(object_inventory_path),
        "inventory_path": str(inventory_out),
        "source_root": str(source_root) if source_root else None,
        "source_adapter": source_adapter,
        "certificate_source_type": certificate_source_type,
        "total_input_rows": counters["input_rows"],
        "total_cer_records": total_cer,
        "semantic_ok": semantic_ok,
        "parse_failed": parse_failed,
        "semantic_ok_ratio": round(semantic_ok_ratio, 6),
        "cer_semantic_root": canonical_json_hash(sorted(semantic_lines)),
        "cer_chain_index_root": canonical_json_hash(sorted(chain_lines)),
        "cer_resource_root": canonical_json_hash(sorted(resource_lines)),
        "cer_semantic_root_by_repo_host": {
            repo: canonical_json_hash(sorted(lines))
            for repo, lines in sorted(semantic_by_repo.items())
        },
        "cer_chain_index_root_by_repo_host": {
            repo: canonical_json_hash(sorted(lines))
            for repo, lines in sorted(chain_by_repo.items())
        },
        "cer_resource_root_by_repo_host": {
            repo: canonical_json_hash(sorted(lines))
            for repo, lines in sorted(resource_by_repo.items())
        },
        "counters": dict(counters),
        "role_counts": dict(role_counts),
        "parse_error_counts": dict(parse_error_counts),
        "repo_counts": dict(repo_counts),
        "parse_error_samples": parse_error_samples,
    }

    summary_out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    acceptance = "PASS" if total_cer > 0 and semantic_ok > 0 and semantic_ok_ratio >= 0.95 else "FAIL"

    lines = [
        f"M16_CER_SEMANTIC_INVENTORY={acceptance}",
        "",
        f"created_at_utc = {summary['created_at_utc']}",
        f"probe_id = {probe_id}",
        f"snapshot_group_id = {snapshot_group_id}",
        f"object_export_id = {object_export_id}",
        "",
        f"total_cer_records = {total_cer}",
        f"semantic_ok = {semantic_ok}",
        f"parse_failed = {parse_failed}",
        f"semantic_ok_ratio = {summary['semantic_ok_ratio']}",
        f"role_counts = {summary['role_counts']}",
        f"cer_semantic_root = {summary['cer_semantic_root']}",
        f"cer_chain_index_root = {summary['cer_chain_index_root']}",
        f"cer_resource_root = {summary['cer_resource_root']}",
        f"parse_error_counts = {summary['parse_error_counts']}",
        "",
        f"inventory_path = {inventory_out}",
        f"summary_path = {summary_out}",
    ]

    acceptance_out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary["acceptance"] = acceptance
    summary["acceptance_path"] = str(acceptance_out)
    return summary
