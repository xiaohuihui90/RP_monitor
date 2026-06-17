#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


EXPECTED_PROBES = ["probe-bj", "probe-cd", "probe-sg"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            obj = json.loads(line)
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


def object_family_from_type(object_type: str) -> str:
    if object_type in {"cer", "crl"}:
        return "resource_control"
    if object_type in {"mft", "roa", "gbr", "aspa", "asa", "sig", "tak"}:
        return "signed_object"
    return "unknown"


def normalize_probe_value(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "raw_sha256": row.get("raw_sha256"),
        "raw_size_bytes": row.get("raw_size_bytes"),
        "collector_raw_bytes_available": bool(row.get("collector_raw_bytes_available")),
        "collector_cas_path": row.get("collector_cas_path"),
        "probe_cas_path": row.get("probe_cas_path"),
        "raw_fetch_mode": row.get("raw_fetch_mode") or "raw_on_demand",
        "source_resolver_method": row.get("source_resolver_method"),
        "probe_export_run_id": row.get("probe_export_run_id"),
        "probe_source_path": row.get("probe_source_path"),
        "recover_status": row.get("recover_status"),
        "cas_integrity_status": row.get("cas_integrity_status"),
        "source_archive": row.get("source_archive"),
    }


def choose_primary_object_type(rows: List[Dict[str, Any]]) -> str:
    c = Counter((r.get("object_type") or "unknown") for r in rows)
    if not c:
        return "unknown"
    return c.most_common(1)[0][0]


def classify_hash_level_status(
    probe_values: Dict[str, List[Dict[str, Any]]],
    distinct_hashes: set[str],
) -> tuple[str, bool, List[str]]:
    warnings = []

    recovered_probes = [
        probe_id for probe_id, values in probe_values.items()
        if values
    ]
    recovered_probe_count = len(recovered_probes)

    multi_version_same_probe = False
    for probe_id, values in probe_values.items():
        hashes = {
            v.get("raw_sha256")
            for v in values
            if v.get("raw_sha256")
        }
        if len(hashes) > 1:
            multi_version_same_probe = True
            warnings.append(f"{probe_id}:same_probe_same_uri_multi_hash")

    if multi_version_same_probe:
        return "multi_version_same_probe", True, warnings

    if recovered_probe_count == 0:
        return "all_missing", False, warnings

    if recovered_probe_count == 1:
        return "single_probe_only", False, warnings

    if recovered_probe_count == len(EXPECTED_PROBES):
        if len(distinct_hashes) == 1:
            return "all_recovered_aligned", False, warnings
        return "all_recovered_divergent", False, warnings

    if len(distinct_hashes) == 1:
        return "partial_recovered_aligned", False, warnings

    return "partial_recovered_divergent", False, warnings


def is_diff_candidate(hash_level_status: str) -> bool:
    return hash_level_status in {
        "all_recovered_divergent",
        "partial_recovered_divergent",
        "multi_version_same_probe",
    }


def build_identity_rows(
    compacted_index: Path,
    collector_run_id: str,
    coverage_scope: str,
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    input_count = 0
    skipped_missing_uri = 0
    skipped_missing_hash = 0

    for row in read_jsonl(compacted_index):
        input_count += 1
        canonical_uri = row.get("canonical_uri")
        raw_sha256 = row.get("raw_sha256")

        if not canonical_uri:
            skipped_missing_uri += 1
            continue

        if not raw_sha256:
            skipped_missing_hash += 1
            continue

        groups[canonical_uri].append(row)

    identity_rows: List[Dict[str, Any]] = []
    candidate_rows: List[Dict[str, Any]] = []

    by_hash_level_status = Counter()
    by_object_type = Counter()
    by_recovered_probe_count = Counter()
    by_distinct_raw_sha256_count = Counter()
    by_probe_presence_pattern = Counter()

    for canonical_uri, rows in sorted(groups.items()):
        object_type = choose_primary_object_type(rows)
        object_family = object_family_from_type(object_type)

        object_type_set = sorted({
            r.get("object_type") or "unknown"
            for r in rows
        })

        probe_values: Dict[str, List[Dict[str, Any]]] = {
            p: [] for p in EXPECTED_PROBES
        }

        extra_probe_values: Dict[str, List[Dict[str, Any]]] = {}

        for row in rows:
            probe_id = row.get("probe_id") or "unknown"
            value = normalize_probe_value(row)

            if probe_id in probe_values:
                probe_values[probe_id].append(value)
            else:
                extra_probe_values.setdefault(probe_id, []).append(value)

        for probe_id in probe_values:
            probe_values[probe_id] = sorted(
                probe_values[probe_id],
                key=lambda x: (
                    str(x.get("raw_sha256") or ""),
                    int(x.get("raw_size_bytes") or 0),
                    str(x.get("probe_export_run_id") or ""),
                )
            )

        distinct_hashes = {
            v.get("raw_sha256")
            for values in probe_values.values()
            for v in values
            if v.get("raw_sha256")
        }

        recovered_probes = [
            probe_id for probe_id, values in probe_values.items()
            if values
        ]

        missing_probes = [
            probe_id for probe_id in EXPECTED_PROBES
            if probe_id not in recovered_probes
        ]

        hash_level_status, multi_version_same_probe, warnings = classify_hash_level_status(
            probe_values=probe_values,
            distinct_hashes=distinct_hashes,
        )

        if len(object_type_set) > 1:
            warnings.append(f"mixed_object_type:{object_type_set}")

        if extra_probe_values:
            warnings.append(f"unexpected_probe_values:{sorted(extra_probe_values)}")

        probe_presence_pattern = ",".join(
            p if probe_values[p] else f"{p}:missing"
            for p in EXPECTED_PROBES
        )

        identity_key = f"uri:{canonical_uri}"

        row_out = {
            "schema": "s3.m20.object_identity_index_extended.v1",
            "created_at_utc": utc_now_iso(),
            "collector_run_id": collector_run_id,

            "identity_key": identity_key,
            "canonical_uri": canonical_uri,
            "object_uri": canonical_uri,
            "object_type": object_type,
            "object_type_set": object_type_set,
            "object_family": object_family,

            "probe_set": EXPECTED_PROBES,
            "probe_values": probe_values,
            "extra_probe_values": extra_probe_values,

            "probe_count": len(EXPECTED_PROBES),
            "recovered_probe_count": len(recovered_probes),
            "missing_probe_count": len(missing_probes),
            "recovered_probes": recovered_probes,
            "missing_probes": missing_probes,

            "distinct_raw_sha256_count": len(distinct_hashes),
            "distinct_raw_sha256_values": sorted(distinct_hashes),

            "hash_level_status": hash_level_status,
            "multi_version_same_probe": multi_version_same_probe,
            "raw_hash_divergence_observed": hash_level_status in {
                "all_recovered_divergent",
                "partial_recovered_divergent",
                "multi_version_same_probe",
            },
            "semantic_diff_required": hash_level_status in {
                "all_recovered_divergent",
                "partial_recovered_divergent",
                "multi_version_same_probe",
            },
            "raw_bytes_required_for_semantic_diff": hash_level_status in {
                "all_recovered_divergent",
                "partial_recovered_divergent",
                "multi_version_same_probe",
            },

            "coverage_scope": coverage_scope,
            "coverage_mode": "index_only_raw_on_demand",
            "raw_bytes_merged": False,

            "warnings": warnings,
            "notes": [
                "M20-D is based on collector index-only merge.",
                "Raw hash divergence can be detected from metadata.",
                "Semantic parsing requires raw-on-demand CAS transfer for selected identities.",
            ],
        }

        identity_rows.append(row_out)

        if is_diff_candidate(hash_level_status):
            candidate_rows.append(row_out)

        by_hash_level_status[hash_level_status] += 1
        by_object_type[object_type] += 1
        by_recovered_probe_count[len(recovered_probes)] += 1
        by_distinct_raw_sha256_count[len(distinct_hashes)] += 1
        by_probe_presence_pattern[probe_presence_pattern] += 1

    summary = {
        "input_compacted_index": str(compacted_index),
        "input_record_count": input_count,
        "skipped_missing_uri": skipped_missing_uri,
        "skipped_missing_hash": skipped_missing_hash,
        "identity_count": len(identity_rows),
        "diff_candidate_count": len(candidate_rows),
        "raw_hash_divergence_identity_count": sum(
            1 for r in identity_rows
            if r.get("raw_hash_divergence_observed")
        ),
        "semantic_diff_required_count": sum(
            1 for r in identity_rows
            if r.get("semantic_diff_required")
        ),
        "raw_bytes_required_for_semantic_diff_count": sum(
            1 for r in identity_rows
            if r.get("raw_bytes_required_for_semantic_diff")
        ),
        "by_hash_level_status": dict(by_hash_level_status),
        "by_object_type": dict(by_object_type),
        "by_recovered_probe_count": dict(by_recovered_probe_count),
        "by_distinct_raw_sha256_count": dict(by_distinct_raw_sha256_count),
        "top_probe_presence_patterns": by_probe_presence_pattern.most_common(20),
    }

    return identity_rows, candidate_rows, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="M20-D build extended object identity index")
    parser.add_argument("--input-index", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--collector-run-id", required=True)
    parser.add_argument("--coverage-scope", default="extended_probe_raw_cas_50k_index_only")
    args = parser.parse_args()

    input_index = Path(args.input_index).expanduser().resolve()
    run_dir = Path(args.run_dir).expanduser().resolve()
    collector_run_id = args.collector_run_id

    indexes_dir = run_dir / "indexes"
    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"

    for d in [indexes_dir, outputs_dir, checks_dir]:
        d.mkdir(parents=True, exist_ok=True)

    identity_rows, candidate_rows, stats = build_identity_rows(
        compacted_index=input_index,
        collector_run_id=collector_run_id,
        coverage_scope=args.coverage_scope,
    )

    identity_index = indexes_dir / "object_identity_index_extended.jsonl"
    candidate_index = indexes_dir / "object_identity_diff_candidate_index.jsonl"
    summary_path = outputs_dir / "M20D_object_identity_index_extended_summary.json"
    check_path = checks_dir / "M20D_object_identity_index_extended.txt"

    write_jsonl(identity_index, identity_rows)
    write_jsonl(candidate_index, candidate_rows)

    status = "PASS" if identity_rows else "FAIL"

    summary = {
        "schema": "s3.m20d.object_identity_index_extended_summary.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "collector_run_id": collector_run_id,
        "run_dir": str(run_dir),
        "coverage_scope": args.coverage_scope,
        "coverage_mode": "index_only_raw_on_demand",
        "raw_bytes_merged": False,
        **stats,
        "object_identity_index_extended": str(identity_index),
        "object_identity_diff_candidate_index": str(candidate_index),
        "important_boundary": [
            "M20-D identifies object identity and hash-level divergence from metadata.",
            "Raw bytes are not available in collector unless fetched on demand.",
            "M20-F/M21 semantic diff requires raw-on-demand transfer for candidate identities.",
        ],
    }

    write_json(summary_path, summary)

    text = "\n".join([
        f"M20D_OBJECT_IDENTITY_INDEX_EXTENDED={status}",
        "",
        f"collector_run_id = {collector_run_id}",
        f"run_dir = {run_dir}",
        f"coverage_scope = {args.coverage_scope}",
        f"coverage_mode = index_only_raw_on_demand",
        f"raw_bytes_merged = False",
        f"input_record_count = {stats['input_record_count']}",
        f"identity_count = {stats['identity_count']}",
        f"diff_candidate_count = {stats['diff_candidate_count']}",
        f"raw_hash_divergence_identity_count = {stats['raw_hash_divergence_identity_count']}",
        f"semantic_diff_required_count = {stats['semantic_diff_required_count']}",
        f"raw_bytes_required_for_semantic_diff_count = {stats['raw_bytes_required_for_semantic_diff_count']}",
        f"by_hash_level_status = {stats['by_hash_level_status']}",
        f"by_object_type = {stats['by_object_type']}",
        f"by_recovered_probe_count = {stats['by_recovered_probe_count']}",
        f"by_distinct_raw_sha256_count = {stats['by_distinct_raw_sha256_count']}",
        f"top_probe_presence_patterns = {stats['top_probe_presence_patterns'][:10]}",
        "",
        f"object_identity_index_extended = {identity_index}",
        f"object_identity_diff_candidate_index = {candidate_index}",
        f"summary_path = {summary_path}",
    ]) + "\n"

    check_path.write_text(text, encoding="utf-8")
    print(text)

    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
