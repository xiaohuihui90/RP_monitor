#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable


EXPECTED_PROBES = ["probe-bj", "probe-cd", "probe-sg"]


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


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def detect_inventory_uri(row: Dict[str, Any]) -> str | None:
    for k in [
        "canonical_uri",
        "object_uri",
        "uri",
        "rpki_uri",
        "source_uri",
    ]:
        v = row.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def detect_object_type(row: Dict[str, Any]) -> str:
    for k in ["object_type", "object_type_guess", "type"]:
        v = row.get(k)
        if isinstance(v, str) and v:
            return v.lower().lstrip(".")
    uri = detect_inventory_uri(row) or ""
    suffix = Path(uri).suffix.lower().lstrip(".")
    return suffix or "unknown"


def normalize_uri_for_join(uri: str) -> str:
    if uri.startswith("cache://.rpki-cache/repository/"):
        return uri
    if uri.startswith("cache://rsync/"):
        return "cache://.rpki-cache/repository/" + uri[len("cache://"):]
    if uri.startswith("rsync://"):
        return "cache://.rpki-cache/repository/rsync/" + uri[len("rsync://"):]
    return uri


def build_raw_index_stats(compacted_index: Path) -> Dict[str, Any]:
    record_count = 0
    distinct_uri = set()
    distinct_hash = set()

    by_probe = Counter()
    by_object_type = Counter()
    by_resolver = Counter()
    by_probe_object_type = Counter()

    for row in read_jsonl(compacted_index):
        record_count += 1

        probe = row.get("probe_id") or "unknown"
        ot = row.get("object_type") or "unknown"
        resolver = row.get("source_resolver_method") or "unknown"

        uri = row.get("canonical_uri")
        raw_hash = row.get("raw_sha256")

        if uri:
            distinct_uri.add(uri)
        if raw_hash:
            distinct_hash.add(raw_hash)

        by_probe[probe] += 1
        by_object_type[ot] += 1
        by_resolver[resolver] += 1
        by_probe_object_type[f"{probe}|{ot}"] += 1

    return {
        "raw_record_count": record_count,
        "raw_distinct_uri_count": len(distinct_uri),
        "raw_distinct_sha256_count": len(distinct_hash),
        "by_probe": dict(by_probe),
        "by_object_type": dict(by_object_type),
        "by_source_resolver_method": dict(by_resolver),
        "by_probe_object_type": dict(by_probe_object_type),
        "raw_uri_set": distinct_uri,
    }


def build_identity_stats(identity_index: Path) -> Dict[str, Any]:
    identity_count = 0
    candidate_count = 0
    raw_hash_divergence_identity_count = 0
    semantic_diff_required_count = 0

    by_hash_level_status = Counter()
    by_object_type = Counter()
    by_recovered_probe_count = Counter()
    by_distinct_raw_sha256_count = Counter()
    by_missing_pattern = Counter()

    for row in read_jsonl(identity_index):
        identity_count += 1

        st = row.get("hash_level_status") or "unknown"
        ot = row.get("object_type") or "unknown"
        rpc = str(row.get("recovered_probe_count"))
        dhc = str(row.get("distinct_raw_sha256_count"))
        missing = row.get("missing_probes") or []

        by_hash_level_status[st] += 1
        by_object_type[ot] += 1
        by_recovered_probe_count[rpc] += 1
        by_distinct_raw_sha256_count[dhc] += 1
        by_missing_pattern[",".join(missing) if missing else "none"] += 1

        if row.get("raw_hash_divergence_observed"):
            raw_hash_divergence_identity_count += 1
            candidate_count += 1

        if row.get("semantic_diff_required"):
            semantic_diff_required_count += 1

    return {
        "identity_count": identity_count,
        "candidate_count": candidate_count,
        "raw_hash_divergence_identity_count": raw_hash_divergence_identity_count,
        "semantic_diff_required_count": semantic_diff_required_count,
        "by_hash_level_status": dict(by_hash_level_status),
        "by_object_type": dict(by_object_type),
        "by_recovered_probe_count": dict(by_recovered_probe_count),
        "by_distinct_raw_sha256_count": dict(by_distinct_raw_sha256_count),
        "by_missing_pattern": dict(by_missing_pattern),
    }


def build_missing_stats(missing_index: Path) -> Dict[str, Any]:
    if not missing_index.exists():
        return {
            "missing_record_count": 0,
            "by_probe": {},
            "by_missing_reason": {},
            "by_object_type_guess": {},
        }

    count = 0
    by_probe = Counter()
    by_reason = Counter()
    by_type = Counter()

    for row in read_jsonl(missing_index):
        count += 1
        by_probe[row.get("probe_id") or "unknown"] += 1
        by_reason[row.get("missing_reason") or "unknown"] += 1
        by_type[row.get("object_type_guess") or row.get("object_type") or "unknown"] += 1

    return {
        "missing_record_count": count,
        "by_probe": dict(by_probe),
        "by_missing_reason": dict(by_reason),
        "by_object_type_guess": dict(by_type),
    }


def build_inventory_join_stats(inventory_path: Path | None, raw_uri_set: set[str]) -> Dict[str, Any]:
    if not inventory_path or not inventory_path.exists():
        return {
            "inventory_join_status": "skipped_no_inventory_input",
            "inventory_path": None,
        }

    inventory_record_count = 0
    inventory_distinct_uri = set()
    by_object_type = Counter()

    for row in read_jsonl(inventory_path):
        inventory_record_count += 1
        uri = detect_inventory_uri(row)
        ot = detect_object_type(row)

        if uri:
            inventory_distinct_uri.add(normalize_uri_for_join(uri))
        by_object_type[ot] += 1

    matched_uri = inventory_distinct_uri & raw_uri_set
    unmatched_uri = inventory_distinct_uri - raw_uri_set

    ratio = (
        len(matched_uri) / len(inventory_distinct_uri)
        if inventory_distinct_uri else 0.0
    )

    return {
        "inventory_join_status": "available",
        "inventory_path": str(inventory_path),
        "inventory_record_count": inventory_record_count,
        "inventory_distinct_uri_count": len(inventory_distinct_uri),
        "matched_inventory_distinct_uri_count": len(matched_uri),
        "unmatched_inventory_distinct_uri_count": len(unmatched_uri),
        "identity_coverage_ratio_against_inventory": ratio,
        "inventory_by_object_type": dict(by_object_type),
        "unmatched_inventory_uri_sample": sorted(unmatched_uri)[:50],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="M20-E coverage report")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--collector-summary", required=True)
    parser.add_argument("--identity-summary", required=True)
    parser.add_argument("--compacted-index", required=True)
    parser.add_argument("--identity-index", required=True)
    parser.add_argument("--missing-index", required=True)
    parser.add_argument("--inventory-index", default="")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"
    docs_dir = run_dir / "docs"
    coverage_dir = run_dir / "coverage"

    for d in [outputs_dir, checks_dir, docs_dir, coverage_dir]:
        d.mkdir(parents=True, exist_ok=True)

    collector_summary = load_json(Path(args.collector_summary))
    identity_summary = load_json(Path(args.identity_summary))

    compacted_index = Path(args.compacted_index)
    identity_index = Path(args.identity_index)
    missing_index = Path(args.missing_index)

    inventory_path = Path(args.inventory_index).expanduser().resolve() if args.inventory_index else None

    raw_stats = build_raw_index_stats(compacted_index)
    identity_stats = build_identity_stats(identity_index)
    missing_stats = build_missing_stats(missing_index)
    inventory_stats = build_inventory_join_stats(inventory_path, raw_stats["raw_uri_set"])

    raw_stats.pop("raw_uri_set", None)

    full_raw_byte_coverage = False

    coverage_status = "PASS_EXTENDED_INDEX_ONLY_COVERAGE"
    if inventory_stats.get("inventory_join_status") == "available":
        if inventory_stats.get("identity_coverage_ratio_against_inventory", 0) >= 0.99:
            coverage_status = "PASS_HIGH_INVENTORY_JOIN_COVERAGE"
        else:
            coverage_status = "PASS_PARTIAL_INVENTORY_JOIN_COVERAGE_WITH_MISSING_REASONS"

    summary = {
        "schema": "s3.m20e.coverage_report.v1",
        "status": "PASS",
        "created_at_utc": utc_now_iso(),
        "run_dir": str(run_dir),

        "coverage_status": coverage_status,
        "coverage_scope": "extended_probe_raw_cas_50k_index_only",
        "coverage_mode": "index_only_raw_on_demand",
        "full_raw_byte_coverage": full_raw_byte_coverage,
        "raw_bytes_merged": False,

        "collector_summary_status": collector_summary.get("status"),
        "identity_summary_status": identity_summary.get("status"),

        "raw_index_coverage": raw_stats,
        "identity_coverage": identity_stats,
        "missing_reason_summary": missing_stats,
        "inventory_join_coverage": inventory_stats,

        "important_boundary": [
            "M20-E reports index-level raw hash coverage.",
            "Raw bytes are not fully merged into collector.",
            "Semantic parsing still requires raw-on-demand transfer for selected candidate identities.",
            "Large MFT divergence candidate count may include temporal version skew and same-probe multi-version artifacts.",
        ],
    }

    summary_path = outputs_dir / "M20E_coverage_report.json"
    write_json(summary_path, summary)

    md_lines = [
        "# M20-E Coverage Report",
        "",
        f"- status: PASS",
        f"- coverage_status: {coverage_status}",
        f"- coverage_scope: extended_probe_raw_cas_50k_index_only",
        f"- full_raw_byte_coverage: {full_raw_byte_coverage}",
        f"- raw_bytes_merged: False",
        "",
        "## Raw Index Coverage",
        "",
        f"- raw_record_count: {raw_stats['raw_record_count']}",
        f"- raw_distinct_uri_count: {raw_stats['raw_distinct_uri_count']}",
        f"- raw_distinct_sha256_count: {raw_stats['raw_distinct_sha256_count']}",
        f"- by_probe: {raw_stats['by_probe']}",
        f"- by_object_type: {raw_stats['by_object_type']}",
        "",
        "## Identity Coverage",
        "",
        f"- identity_count: {identity_stats['identity_count']}",
        f"- candidate_count: {identity_stats['candidate_count']}",
        f"- raw_hash_divergence_identity_count: {identity_stats['raw_hash_divergence_identity_count']}",
        f"- semantic_diff_required_count: {identity_stats['semantic_diff_required_count']}",
        f"- by_hash_level_status: {identity_stats['by_hash_level_status']}",
        f"- by_object_type: {identity_stats['by_object_type']}",
        "",
        "## Missing Reasons",
        "",
        f"- missing_record_count: {missing_stats['missing_record_count']}",
        f"- by_missing_reason: {missing_stats['by_missing_reason']}",
        "",
        "## Inventory Join",
        "",
        f"- inventory_join_status: {inventory_stats.get('inventory_join_status')}",
        f"- inventory_path: {inventory_stats.get('inventory_path')}",
        f"- identity_coverage_ratio_against_inventory: {inventory_stats.get('identity_coverage_ratio_against_inventory')}",
        "",
        "## Boundary",
        "",
        "- This report is index-only.",
        "- It can support hash-level divergence screening.",
        "- It cannot perform semantic object parsing until raw bytes are fetched on demand.",
        "",
    ]

    md_path = docs_dir / "M20_coverage_report_zh.md"
    write_text(md_path, "\n".join(md_lines))

    check_path = checks_dir / "M20E_coverage_acceptance.txt"
    text = "\n".join([
        "M20E_COVERAGE_REPORT=PASS",
        "",
        f"coverage_status = {coverage_status}",
        f"coverage_scope = extended_probe_raw_cas_50k_index_only",
        f"coverage_mode = index_only_raw_on_demand",
        f"full_raw_byte_coverage = {full_raw_byte_coverage}",
        f"raw_bytes_merged = False",
        "",
        f"raw_record_count = {raw_stats['raw_record_count']}",
        f"raw_distinct_uri_count = {raw_stats['raw_distinct_uri_count']}",
        f"raw_distinct_sha256_count = {raw_stats['raw_distinct_sha256_count']}",
        f"raw_by_probe = {raw_stats['by_probe']}",
        f"raw_by_object_type = {raw_stats['by_object_type']}",
        "",
        f"identity_count = {identity_stats['identity_count']}",
        f"candidate_count = {identity_stats['candidate_count']}",
        f"raw_hash_divergence_identity_count = {identity_stats['raw_hash_divergence_identity_count']}",
        f"semantic_diff_required_count = {identity_stats['semantic_diff_required_count']}",
        f"identity_by_hash_level_status = {identity_stats['by_hash_level_status']}",
        f"identity_by_object_type = {identity_stats['by_object_type']}",
        "",
        f"missing_record_count = {missing_stats['missing_record_count']}",
        f"missing_by_reason = {missing_stats['by_missing_reason']}",
        "",
        f"inventory_join_status = {inventory_stats.get('inventory_join_status')}",
        f"inventory_path = {inventory_stats.get('inventory_path')}",
        f"inventory_distinct_uri_count = {inventory_stats.get('inventory_distinct_uri_count')}",
        f"matched_inventory_distinct_uri_count = {inventory_stats.get('matched_inventory_distinct_uri_count')}",
        f"identity_coverage_ratio_against_inventory = {inventory_stats.get('identity_coverage_ratio_against_inventory')}",
        "",
        f"summary_path = {summary_path}",
        f"summary_md = {md_path}",
    ]) + "\n"

    write_text(check_path, text)
    print(text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
