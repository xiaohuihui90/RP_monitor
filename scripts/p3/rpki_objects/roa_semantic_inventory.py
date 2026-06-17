#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build ROA semantic inventory from S3 object_inventory.jsonl.

Scope:
  - Parse S3-collected ROA objects.
  - Compare payload-level semantics.
  - Do NOT implement full RP validation.
"""

from __future__ import annotations

import json
import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse

try:
    from asn1crypto import cms
except Exception as exc:  # pragma: no cover
    raise RuntimeError("asn1crypto is required for ROA semantic inventory") from exc

from scripts.p3.rpki_objects.canonical_uri import canonicalize_object_uri
from scripts.p3.rpki_objects.semantic_hash import canonical_json_hash
from scripts.p3.rpki_objects.parsers.roa import ROA_ECONTENT_TYPE_OID, parse_roa_econtent


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


def is_roa_row(row: Dict[str, Any]) -> bool:
    object_type = str(row.get("object_type") or "").lower()
    uri = str(row.get("uri") or row.get("canonical_uri") or "").lower()
    source_file = str(row.get("source_file") or "").lower()
    relative_path = str(row.get("relative_path") or "").lower()
    return (
        object_type == "roa"
        or uri.endswith(".roa")
        or source_file.endswith(".roa")
        or relative_path.endswith(".roa")
    )


def repo_host_from_uri(uri: str) -> str:
    if not uri:
        return "unknown"
    s = uri
    if s.startswith("cache://rsync/"):
        rest = s[len("cache://rsync/") :]
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
        candidates.append(source_root / str(rel).lstrip("/"))

    for p in candidates:
        try:
            if p.exists() and p.is_file():
                return p
        except Exception:
            continue

    return None


def _extract_roa_from_bytes(raw: bytes) -> Dict[str, Any]:
    """
    Locate CMS ContentInfo inside raw bytes and extract ROA eContent.
    Routinator cache wrapper may prepend metadata before DER CMS.
    """
    best_error = None

    for offset, b in enumerate(raw):
        if b != 0x30:
            continue
        try:
            ci = cms.ContentInfo.load(raw[offset:], strict=False)
            if str(ci["content_type"].native) != "signed_data":
                continue

            cms_der = ci.dump()
            sd = ci["content"]
            eci = sd["encap_content_info"]
            oid = eci["content_type"].dotted

            content = eci["content"]
            if content is None:
                raise ValueError("cms_econtent_missing")

            econtent = content.native
            if not isinstance(econtent, (bytes, bytearray)):
                econtent = content.contents

            return {
                "cms_payload_offset": offset,
                "cms_payload_len": len(cms_der),
                "cms_payload_sha256": sha256_hex(cms_der),
                "econtent_type_oid": oid,
                "econtent_sha256": sha256_hex(bytes(econtent)),
                "econtent_der": bytes(econtent),
                "wrapper_detected": offset > 0,
                "wrapper_type": "routinator_cache_wrapper_or_prefixed_der" if offset > 0 else "none",
            }
        except Exception as exc:
            best_error = exc
            continue

    raise ValueError(f"no_cms_signed_data_found:{best_error!r}")


def inspect_roa_file(path: Path, canonical_uri: Optional[str] = None) -> Dict[str, Any]:
    p = Path(path)
    raw = p.read_bytes()

    base = {
        "source_file": str(p),
        "source_file_sha256": sha256_hex(raw),
        "wrapper_sha256": sha256_hex(raw),
        "canonical_uri": canonical_uri,
    }

    extracted = _extract_roa_from_bytes(raw)
    base.update({k: v for k, v in extracted.items() if k != "econtent_der"})

    if base["econtent_type_oid"] != ROA_ECONTENT_TYPE_OID:
        raise ValueError(f"unexpected_econtent_type_oid:{base['econtent_type_oid']}")

    fields = parse_roa_econtent(extracted["econtent_der"])

    return {
        **base,
        "parse_status": "ok",
        "semantic_fields": {
            "profile": fields["profile"],
            "version": fields["version"],
            "as_id": fields["as_id"],
            "roa_prefixes": fields["roa_prefixes"],
            "vrp_keys": fields["vrp_keys"],
            "vrp_key_count": fields["vrp_key_count"],
            "vrp_key_digest": fields["vrp_key_digest"],
        },
        "semantic_object_hash": fields["semantic_object_hash"],
        "warnings": [],
    }


def build_roa_semantic_inventory(
    *,
    probe_id: str,
    snapshot_group_id: str,
    object_export_id: str,
    object_inventory_path: Path,
    source_root: Optional[Path],
    out_dir: Path,
    source_adapter: str = "routinator_cache_v1",
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    inventory_out = out_dir / "roa_semantic_inventory.jsonl"
    summary_out = out_dir / "roa_semantic_inventory_summary.json"
    acceptance_out = out_dir / "roa_semantic_inventory_acceptance.txt"

    counters = Counter()
    parse_error_counts = Counter()
    repo_counts = Counter()
    parse_error_samples = []

    semantic_lines = []
    vrp_keys_all = set()
    root_by_repo = defaultdict(list)
    vrp_by_repo = defaultdict(set)

    with inventory_out.open("w", encoding="utf-8") as w:
        for row in read_jsonl(Path(object_inventory_path)):
            counters["input_rows"] += 1

            if "_json_parse_error" in row:
                counters["json_parse_failed"] += 1
                continue

            if not is_roa_row(row):
                continue

            counters["total_roa_records"] += 1
            if limit is not None and counters["total_roa_records"] > limit:
                break

            raw_uri = row.get("uri") or row.get("canonical_uri") or row.get("source_uri") or ""
            try:
                canonical_uri = canonicalize_object_uri(str(raw_uri))
            except Exception:
                canonical_uri = str(raw_uri)

            repo_host = repo_host_from_uri(canonical_uri)
            repo_counts[repo_host] += 1

            source_file = resolve_source_file(row, source_root)

            record = {
                "schema": "s3.stage3.rpki_objects.roa_semantic_record.v1",
                "probe_id": probe_id,
                "snapshot_group_id": snapshot_group_id,
                "object_export_id": object_export_id,
                "object_type": "roa",
                "canonical_uri": canonical_uri,
                "repo_host": repo_host,
                "source_file": str(source_file) if source_file else None,
                "source_root": str(source_root) if source_root else None,
                "source_adapter": source_adapter,
                "source_inventory_line_no": row.get("_line_no"),
            }

            if source_file is None:
                record.update({
                    "parse_status": "raw_file_missing",
                    "parse_error_class": "raw_file_missing",
                    "parse_error": "source file cannot be resolved",
                    "semantic_fields": {},
                    "semantic_object_hash": None,
                    "warnings": ["raw_file_missing"],
                })
                parse_error_counts["raw_file_missing"] += 1
            else:
                try:
                    parsed = inspect_roa_file(source_file, canonical_uri=canonical_uri)
                    record.update(parsed)
                    record["parse_error_class"] = None
                    record["parse_error"] = None

                    counters["semantic_ok"] += 1

                    semantic_hash = record.get("semantic_object_hash")
                    if semantic_hash:
                        line = f"{canonical_uri}\troa\t{semantic_hash}"
                        semantic_lines.append(line)
                        root_by_repo[repo_host].append(line)

                    sf = record.get("semantic_fields") or {}
                    for key in sf.get("vrp_keys") or []:
                        vrp_keys_all.add(key)
                        vrp_by_repo[repo_host].add(key)

                except Exception as exc:
                    err = repr(exc)
                    err_class = str(exc).split(":", 1)[0] if str(exc) else exc.__class__.__name__
                    record.update({
                        "parse_status": err_class,
                        "parse_error_class": err_class,
                        "parse_error": err,
                        "semantic_fields": {},
                        "semantic_object_hash": None,
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

            w.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    total_roa = counters["total_roa_records"]
    semantic_ok = counters["semantic_ok"]
    parse_failed = total_roa - semantic_ok
    semantic_ok_ratio = (semantic_ok / total_roa) if total_roa else 0.0

    summary = {
        "schema": "s3.stage3.roa_semantic_inventory_summary.v1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "probe_id": probe_id,
        "snapshot_group_id": snapshot_group_id,
        "object_export_id": object_export_id,
        "object_inventory_path": str(object_inventory_path),
        "inventory_path": str(inventory_out),
        "source_root": str(source_root) if source_root else None,
        "source_adapter": source_adapter,

        "total_input_rows": counters["input_rows"],
        "total_roa_records": total_roa,
        "semantic_ok": semantic_ok,
        "parse_failed": parse_failed,
        "semantic_ok_ratio": round(semantic_ok_ratio, 6),

        "roa_semantic_root": canonical_json_hash(sorted(semantic_lines)),
        "roa_vrp_key_root": canonical_json_hash(sorted(vrp_keys_all)),
        "unique_vrp_key_count": len(vrp_keys_all),

        "roa_semantic_root_by_repo_host": {
            repo: canonical_json_hash(sorted(lines))
            for repo, lines in sorted(root_by_repo.items())
        },
        "roa_vrp_key_root_by_repo_host": {
            repo: canonical_json_hash(sorted(keys))
            for repo, keys in sorted(vrp_by_repo.items())
        },

        "counters": dict(counters),
        "parse_error_counts": dict(parse_error_counts),
        "repo_counts": dict(repo_counts),
        "parse_error_samples": parse_error_samples,
    }

    summary_out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    acceptance = "PASS" if total_roa > 0 and semantic_ok > 0 and semantic_ok_ratio >= 0.95 else "FAIL"

    lines = [
        f"M16_ROA_SEMANTIC_INVENTORY={acceptance}",
        "",
        f"created_at_utc = {summary['created_at_utc']}",
        f"probe_id = {probe_id}",
        f"snapshot_group_id = {snapshot_group_id}",
        f"object_export_id = {object_export_id}",
        "",
        f"total_roa_records = {total_roa}",
        f"semantic_ok = {semantic_ok}",
        f"parse_failed = {parse_failed}",
        f"semantic_ok_ratio = {summary['semantic_ok_ratio']}",
        f"unique_vrp_key_count = {summary['unique_vrp_key_count']}",
        f"roa_semantic_root = {summary['roa_semantic_root']}",
        f"roa_vrp_key_root = {summary['roa_vrp_key_root']}",
        f"parse_error_counts = {summary['parse_error_counts']}",
        "",
        f"inventory_path = {inventory_out}",
        f"summary_path = {summary_out}",
    ]
    acceptance_out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary["acceptance"] = acceptance
    summary["acceptance_path"] = str(acceptance_out)
    return summary
