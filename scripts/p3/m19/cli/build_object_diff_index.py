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


def stable_id(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def map_status(hash_level_status: str) -> Dict[str, Any]:
    if hash_level_status == "all_recovered_aligned":
        return {
            "raw_hash_status": "aligned",
            "diff_candidate_type": "no_raw_diff",
            "severity": "info",
            "semantic_diff_required": False,
            "semantic_diff_status": "not_required",
        }

    if hash_level_status == "all_recovered_divergent":
        return {
            "raw_hash_status": "divergent",
            "diff_candidate_type": "raw_hash_divergence",
            "severity": "high",
            "semantic_diff_required": True,
            "semantic_diff_status": "pending",
        }

    if hash_level_status == "partial_recovered_aligned":
        return {
            "raw_hash_status": "partial_missing",
            "diff_candidate_type": "presence_absence_diff",
            "severity": "warning",
            "semantic_diff_required": False,
            "semantic_diff_status": "not_required",
        }

    if hash_level_status == "partial_recovered_divergent":
        return {
            "raw_hash_status": "divergent",
            "diff_candidate_type": "raw_hash_divergence",
            "severity": "high",
            "semantic_diff_required": True,
            "semantic_diff_status": "pending",
        }

    if hash_level_status == "single_probe_only":
        return {
            "raw_hash_status": "single_probe_only",
            "diff_candidate_type": "single_probe_evidence_only",
            "severity": "warning",
            "semantic_diff_required": False,
            "semantic_diff_status": "not_required",
        }

    if hash_level_status == "all_missing":
        return {
            "raw_hash_status": "all_missing",
            "diff_candidate_type": "missing_raw_bytes",
            "severity": "warning",
            "semantic_diff_required": False,
            "semantic_diff_status": "raw_input_missing",
        }

    return {
        "raw_hash_status": "not_assessed",
        "diff_candidate_type": "missing_raw_bytes",
        "severity": "warning",
        "semantic_diff_required": False,
        "semantic_diff_status": "raw_input_missing",
    }


def build_diff_record(identity: Dict[str, Any], m19_run_id: str, m18_run_dir: str) -> Dict[str, Any]:
    probe_values = identity.get("probe_values") or {}
    probe_set = sorted(probe_values.keys())

    mapped = map_status(identity.get("hash_level_status") or "not_assessed")

    warnings = []
    notes = []

    if mapped["raw_hash_status"] == "single_probe_only":
        warnings.append("single_probe_only_cannot_confirm_cross_probe_diff")

    if mapped["raw_hash_status"] == "aligned":
        notes.append("raw_hash_aligned_no_semantic_diff_required")

    if mapped["semantic_diff_required"]:
        notes.append("raw_hash_divergence_requires_m19d_semantic_diff")

    return {
        "schema": "s3.m19.object_diff_index.v1",
        "created_at_utc": utc_now_iso(),
        "m19_run_id": m19_run_id,
        "m18_run_dir": m18_run_dir,

        "object_diff_id": "odiff_" + stable_id(identity.get("identity_key") or ""),
        "identity_key": identity.get("identity_key"),
        "canonical_uri": identity.get("canonical_uri"),
        "object_uri": identity.get("object_uri"),
        "object_type": identity.get("object_type"),
        "object_family": identity.get("object_family"),

        "probe_set": probe_set,
        "observed_probe_count": identity.get("probe_count"),
        "recovered_probe_count": identity.get("recovered_probe_count"),
        "distinct_raw_sha256_count": identity.get("distinct_raw_sha256_count"),
        "probe_values": probe_values,

        "m18_hash_level_status": identity.get("hash_level_status"),
        "raw_hash_status": mapped["raw_hash_status"],
        "diff_candidate_type": mapped["diff_candidate_type"],
        "severity": mapped["severity"],

        "semantic_diff_required": mapped["semantic_diff_required"],
        "semantic_diff_status": mapped["semantic_diff_status"],

        "coverage_scope": "recoverable_subset",
        "coverage_confidence": "medium",
        "linked_m17_workspaces": [],
        "warnings": warnings,
        "notes": notes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="M19-B build object_diff_index")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--identity-index", required=True)
    parser.add_argument("--m18-run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    identity_index = Path(args.identity_index).expanduser().resolve()
    m18_run_dir = str(Path(args.m18_run_dir).expanduser().resolve())

    indexes_dir = run_dir / "indexes"
    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"

    indexes_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)

    m19_run_id = run_dir.name

    identities = list(read_jsonl(identity_index))
    diff_rows = [
        build_diff_record(identity, m19_run_id, m18_run_dir)
        for identity in identities
    ]

    candidate_rows = [
        row for row in diff_rows
        if row["diff_candidate_type"] != "no_raw_diff"
    ]

    object_diff_index = indexes_dir / "object_diff_index.jsonl"
    candidate_index = indexes_dir / "object_diff_candidate_index.jsonl"
    summary_path = outputs_dir / "M19B_diff_candidate_summary.json"
    check_path = checks_dir / "M19B_diff_candidates.txt"

    write_jsonl(object_diff_index, diff_rows)
    write_jsonl(candidate_index, candidate_rows)

    by_raw_hash_status = Counter(row["raw_hash_status"] for row in diff_rows)
    by_candidate_type = Counter(row["diff_candidate_type"] for row in diff_rows)
    by_semantic_status = Counter(row["semantic_diff_status"] for row in diff_rows)
    by_object_type = Counter(row.get("object_type") or "unknown" for row in diff_rows)

    semantic_required_count = sum(1 for row in diff_rows if row["semantic_diff_required"])
    raw_hash_divergence_count = by_raw_hash_status.get("divergent", 0)

    status = "PASS" if len(diff_rows) > 0 else "FAIL"

    summary = {
        "schema": "s3.m19b.diff_candidate_summary.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "run_dir": str(run_dir),
        "m18_run_dir": m18_run_dir,
        "identity_index": str(identity_index),
        "object_diff_index": str(object_diff_index),
        "object_diff_candidate_index": str(candidate_index),

        "identity_count": len(identities),
        "object_diff_index_count": len(diff_rows),
        "candidate_count": len(candidate_rows),
        "raw_hash_divergence_count": raw_hash_divergence_count,
        "semantic_diff_required_count": semantic_required_count,

        "by_raw_hash_status": dict(by_raw_hash_status),
        "by_candidate_type": dict(by_candidate_type),
        "by_semantic_diff_status": dict(by_semantic_status),
        "by_object_type": dict(by_object_type),

        "coverage_scope": "recoverable_subset",
        "important_boundary": [
            "M19-B builds object_diff_index from M18 recoverable-subset identity index.",
            "raw_hash_divergence_count may be zero for current input.",
            "This is not full 172243-record raw-byte coverage."
        ],
    }

    write_json(summary_path, summary)

    text = "\n".join([
        f"M19B_DIFF_CANDIDATES={status}",
        "",
        "scope = recoverable_subset_object_diff_index",
        f"identity_count = {summary['identity_count']}",
        f"object_diff_index_count = {summary['object_diff_index_count']}",
        f"candidate_count = {summary['candidate_count']}",
        f"raw_hash_divergence_count = {summary['raw_hash_divergence_count']}",
        f"semantic_diff_required_count = {summary['semantic_diff_required_count']}",
        f"by_raw_hash_status = {summary['by_raw_hash_status']}",
        f"by_candidate_type = {summary['by_candidate_type']}",
        f"by_semantic_diff_status = {summary['by_semantic_diff_status']}",
        f"by_object_type = {summary['by_object_type']}",
        "",
        f"object_diff_index = {object_diff_index}",
        f"object_diff_candidate_index = {candidate_index}",
        f"summary_path = {summary_path}",
        "",
        "important_boundary = M19-B uses recoverable subset only, not full raw-byte coverage.",
    ]) + "\n"

    check_path.write_text(text, encoding="utf-8")
    print(text)

    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
