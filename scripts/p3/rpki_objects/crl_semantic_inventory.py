#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
from scripts.p3.rpki_objects.parsers.crl import parse_crl_der


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def normalize_sha256(v: Any) -> str | None:
    if not v:
        return None
    s = str(v)
    if s.startswith("sha256:"):
        return s.lower()
    if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
        return "sha256:" + s.lower()
    return s


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
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
                    "_json_parse_error": repr(exc),
                }


def is_crl_row(row: Dict[str, Any]) -> bool:
    object_type = str(row.get("object_type") or "").lower()
    uri = str(row.get("uri") or row.get("canonical_uri") or "").lower()
    source_file = str(row.get("source_file") or "").lower()
    relative_path = str(row.get("relative_path") or "").lower()

    return (
        object_type == "crl"
        or uri.endswith(".crl")
        or source_file.endswith(".crl")
        or relative_path.endswith(".crl")
    )


def repo_host_from_uri(uri: str) -> str:
    if not uri:
        return "unknown"

    s = uri
    prefixes = [
        "cache://rsync/",
        "cache://rpki-cache/rsync/",
        "cache://.rpki-cache/repository/rsync/",
        "cache://repository/rsync/",
        "rsync://",
    ]

    for prefix in prefixes:
        if s.startswith(prefix):
            rest = s[len(prefix):]
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

        if rel_s.startswith("repository/"):
            candidates.append(source_root / rel_s[len("repository/"):])

    uri = row.get("uri") or row.get("canonical_uri")
    if uri and source_root is not None:
        s = str(uri)

        if "repository/rsync/" in s:
            tail = s.split("repository/rsync/", 1)[1].lstrip("/")
            candidates.append(source_root / "repository" / "rsync" / tail)
            candidates.append(source_root / "rsync" / tail)

        if "rpki-cache/rsync/" in s:
            tail = s.split("rpki-cache/rsync/", 1)[1].lstrip("/")
            candidates.append(source_root / "rsync" / tail)

        if s.startswith("cache://rsync/"):
            tail = s[len("cache://rsync/"):].lstrip("/")
            candidates.append(source_root / "rsync" / tail)
            candidates.append(source_root / "repository" / "rsync" / tail)

    for p in candidates:
        try:
            if p.exists() and p.is_file():
                return p
        except Exception:
            continue

    return None


def build_crl_semantic_inventory(
    *,
    probe_id: str,
    snapshot_group_id: str,
    object_export_id: str,
    object_inventory_path: Path,
    source_root: Optional[Path],
    out_dir: Path,
    source_adapter: str = "routinator_cache_v1",
    semantic_evidence_level: str = "live_cache_semantic_non_frozen",
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)

    frozen_out = out_dir / "crl_frozen_inventory.jsonl"
    semantic_out = out_dir / "crl_semantic_inventory.jsonl"
    summary_out = out_dir / "crl_semantic_inventory_summary.json"
    acceptance_out = out_dir / "crl_semantic_inventory_acceptance.txt"

    counters = Counter()
    parse_error_counts = Counter()
    repo_counts = Counter()
    warning_counts = Counter()
    parse_error_samples = []

    frozen_lines = []
    live_semantic_lines = []
    revoked_lines = []
    freshness_lines = []
    issuer_aki_lines = []
    frozen_by_repo = defaultdict(list)

    with frozen_out.open("w", encoding="utf-8") as wf, semantic_out.open("w", encoding="utf-8") as ws:
        for row in read_jsonl(object_inventory_path):
            counters["input_rows"] += 1

            if "_json_parse_error" in row:
                counters["json_parse_failed"] += 1
                continue

            if not is_crl_row(row):
                continue

            if limit is not None and counters["total_crl_records"] >= limit:
                break

            counters["total_crl_records"] += 1

            raw_uri = row.get("uri") or row.get("canonical_uri") or row.get("source_uri") or ""
            try:
                canonical_uri = canonicalize_object_uri(str(raw_uri))
            except Exception:
                canonical_uri = str(raw_uri)

            repo_host = repo_host_from_uri(canonical_uri)
            repo_counts[repo_host] += 1

            frozen_hash = normalize_sha256(
                row.get("sha256")
                or row.get("object_sha256")
                or row.get("file_sha256")
                or row.get("hash")
                or row.get("source_file_sha256")
            )

            if frozen_hash:
                counters["frozen_hash_available"] += 1
                frozen_line = f"{canonical_uri}\tcrl\t{frozen_hash}"
                frozen_lines.append(frozen_line)
                frozen_by_repo[repo_host].append(frozen_line)
            else:
                counters["frozen_hash_missing"] += 1

            source_file = resolve_source_file(row, source_root)

            frozen_record = {
                "schema": "s3.stage3.rpki_objects.crl_frozen_inventory_record.v1",
                "probe_id": probe_id,
                "snapshot_group_id": snapshot_group_id,
                "object_export_id": object_export_id,
                "object_type": "crl",
                "canonical_uri": canonical_uri,
                "repo_host": repo_host,
                "relative_path": row.get("relative_path"),
                "source_file": str(source_file) if source_file else row.get("source_file"),
                "source_root": str(source_root) if source_root else None,
                "size_bytes": row.get("size_bytes"),
                "frozen_object_sha256": frozen_hash,
                "frozen_hash_available": bool(frozen_hash),
                "frozen_evidence_level": "object_inventory_hash",
                "source_inventory_line_no": row.get("_line_no"),
            }
            wf.write(json.dumps(frozen_record, ensure_ascii=False, sort_keys=True) + "\n")

            semantic_record = {
                "schema": "s3.stage3.rpki_objects.crl_semantic_record.v1",
                "probe_id": probe_id,
                "snapshot_group_id": snapshot_group_id,
                "object_export_id": object_export_id,
                "object_type": "crl",
                "semantic_evidence_level": semantic_evidence_level,
                "canonical_uri": canonical_uri,
                "repo_host": repo_host,
                "source_file": str(source_file) if source_file else row.get("source_file"),
                "source_root": str(source_root) if source_root else None,
                "source_adapter": source_adapter,
                "frozen_object_sha256": frozen_hash,
            }

            if source_file is None:
                semantic_record.update({
                    "parse_status": "raw_file_missing",
                    "parse_error_class": "raw_file_missing",
                    "parse_error": "source file cannot be resolved",
                    "live_source_file_sha256": None,
                    "live_matches_frozen_hash": None,
                    "semantic_fields": {},
                    "warnings": ["raw_file_missing"],
                })
                parse_error_counts["raw_file_missing"] += 1
            else:
                try:
                    raw = source_file.read_bytes()
                    live_hash = sha256_hex(raw)
                    parsed = parse_crl_der(raw)

                    semantic_record.update(parsed)
                    semantic_record.update({
                        "parse_error_class": None,
                        "parse_error": None,
                        "live_source_file_sha256": live_hash,
                        "live_matches_frozen_hash": (live_hash == frozen_hash) if frozen_hash else None,
                    })

                    counters["live_semantic_ok"] += 1

                    if semantic_record.get("live_matches_frozen_hash") is True:
                        counters["live_matches_frozen_hash_count"] += 1
                    elif semantic_record.get("live_matches_frozen_hash") is False:
                        counters["live_mismatch_frozen_hash_count"] += 1

                    for w in parsed.get("warnings") or []:
                        warning_counts[w] += 1

                    if parsed.get("crl_semantic_hash"):
                        live_semantic_lines.append(f"{canonical_uri}\tcrl_live_semantic\t{parsed.get('crl_semantic_hash')}")
                    if parsed.get("crl_revoked_set_hash"):
                        revoked_lines.append(f"{canonical_uri}\tcrl_revoked\t{parsed.get('crl_revoked_set_hash')}")
                    if parsed.get("crl_freshness_hash"):
                        freshness_lines.append(f"{canonical_uri}\tcrl_freshness\t{parsed.get('crl_freshness_hash')}")
                    if parsed.get("crl_issuer_aki_hash"):
                        issuer_aki_lines.append(f"{canonical_uri}\tcrl_issuer_aki\t{parsed.get('crl_issuer_aki_hash')}")

                except Exception as exc:
                    err = repr(exc)
                    err_class = str(exc).split(":", 1)[0] if str(exc) else exc.__class__.__name__

                    semantic_record.update({
                        "parse_status": err_class,
                        "parse_error_class": err_class,
                        "parse_error": err,
                        "semantic_fields": {},
                        "warnings": [err_class],
                    })

                    parse_error_counts[err_class] += 1

                    if len(parse_error_samples) < 100:
                        parse_error_samples.append({
                            "canonical_uri": canonical_uri,
                            "source_file": str(source_file),
                            "parse_error_class": err_class,
                            "parse_error": err[:500],
                        })

            ws.write(json.dumps(semantic_record, ensure_ascii=False, sort_keys=True) + "\n")

    total_crl = counters["total_crl_records"]
    frozen_available = counters["frozen_hash_available"]
    live_ok = counters["live_semantic_ok"]

    frozen_hash_ok_ratio = (frozen_available / total_crl) if total_crl else 0.0
    live_semantic_ok_ratio = (live_ok / total_crl) if total_crl else 0.0
    live_mismatch_ratio = (counters["live_mismatch_frozen_hash_count"] / total_crl) if total_crl else 0.0

    summary = {
        "schema": "s3.stage3.crl_semantic_inventory_summary.v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "probe_id": probe_id,
        "snapshot_group_id": snapshot_group_id,
        "object_export_id": object_export_id,
        "object_inventory_path": str(object_inventory_path),
        "crl_frozen_inventory_path": str(frozen_out),
        "crl_semantic_inventory_path": str(semantic_out),
        "source_root": str(source_root) if source_root else None,
        "source_adapter": source_adapter,
        "semantic_evidence_level": semantic_evidence_level,
        "total_input_rows": counters["input_rows"],
        "total_crl_records": total_crl,
        "frozen_hash_available": frozen_available,
        "frozen_hash_missing": counters["frozen_hash_missing"],
        "frozen_hash_ok_ratio": round(frozen_hash_ok_ratio, 6),
        "live_semantic_ok": live_ok,
        "live_semantic_failed": total_crl - live_ok,
        "live_semantic_ok_ratio": round(live_semantic_ok_ratio, 6),
        "live_matches_frozen_hash_count": counters["live_matches_frozen_hash_count"],
        "live_mismatch_frozen_hash_count": counters["live_mismatch_frozen_hash_count"],
        "live_mismatch_frozen_hash_ratio": round(live_mismatch_ratio, 6),
        "crl_frozen_hash_root": canonical_json_hash(sorted(frozen_lines)),
        "crl_live_semantic_root": canonical_json_hash(sorted(live_semantic_lines)),
        "crl_revoked_set_root": canonical_json_hash(sorted(revoked_lines)),
        "crl_freshness_root": canonical_json_hash(sorted(freshness_lines)),
        "crl_issuer_aki_root": canonical_json_hash(sorted(issuer_aki_lines)),
        "crl_frozen_hash_root_by_repo_host": {
            repo: canonical_json_hash(sorted(lines))
            for repo, lines in sorted(frozen_by_repo.items())
        },
        "counters": dict(counters),
        "parse_error_counts": dict(parse_error_counts),
        "repo_counts": dict(repo_counts),
        "warning_counts": dict(warning_counts),
        "parse_error_samples": parse_error_samples,
    }

    summary_out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    acceptance = "PASS" if (
        total_crl > 0
        and frozen_hash_ok_ratio >= 0.99
        and summary.get("crl_frozen_hash_root")
        and live_semantic_ok_ratio >= 0.95
    ) else "FAIL"

    lines = [
        f"M16_CRL_SEMANTIC_INVENTORY={acceptance}",
        "",
        f"created_at_utc = {summary['created_at_utc']}",
        f"probe_id = {probe_id}",
        f"snapshot_group_id = {snapshot_group_id}",
        f"object_export_id = {object_export_id}",
        "",
        f"total_crl_records = {total_crl}",
        f"frozen_hash_available = {frozen_available}",
        f"frozen_hash_missing = {summary['frozen_hash_missing']}",
        f"frozen_hash_ok_ratio = {summary['frozen_hash_ok_ratio']}",
        f"live_semantic_ok = {live_ok}",
        f"live_semantic_failed = {summary['live_semantic_failed']}",
        f"live_semantic_ok_ratio = {summary['live_semantic_ok_ratio']}",
        f"live_matches_frozen_hash_count = {summary['live_matches_frozen_hash_count']}",
        f"live_mismatch_frozen_hash_count = {summary['live_mismatch_frozen_hash_count']}",
        f"live_mismatch_frozen_hash_ratio = {summary['live_mismatch_frozen_hash_ratio']}",
        f"crl_frozen_hash_root = {summary['crl_frozen_hash_root']}",
        f"crl_live_semantic_root = {summary['crl_live_semantic_root']}",
        f"crl_revoked_set_root = {summary['crl_revoked_set_root']}",
        f"crl_freshness_root = {summary['crl_freshness_root']}",
        f"crl_issuer_aki_root = {summary['crl_issuer_aki_root']}",
        f"parse_error_counts = {summary['parse_error_counts']}",
        f"warning_counts = {summary['warning_counts']}",
        "",
        f"frozen_inventory_path = {frozen_out}",
        f"semantic_inventory_path = {semantic_out}",
        f"summary_path = {summary_out}",
    ]

    acceptance_out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary["acceptance"] = acceptance
    summary["acceptance_path"] = str(acceptance_out)

    return summary
