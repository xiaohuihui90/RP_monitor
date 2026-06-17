#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


REQUIRED_TAS = ["afrinic", "apnic", "arin", "lacnic", "ripe"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def guess_ta_from_text(text: str) -> str:
    x = text.lower()
    for ta in REQUIRED_TAS:
        if ta in x:
            return ta
    return "unknown"


def count_vrp_ta(canonical_path: Path) -> Dict[str, Any]:
    c = Counter()
    total = 0

    with gzip.open(canonical_path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            ta = str(row.get("ta", "unknown")).strip().lower()
            c[ta] += 1
            total += 1

    ta_unique = sorted(c.keys())
    missing_required = sorted(set(REQUIRED_TAS) - set(ta_unique))

    return {
        "canonical_path": str(canonical_path),
        "total": total,
        "ta_count": dict(sorted(c.items())),
        "ta_unique": ta_unique,
        "missing_required_tas": missing_required,
        "five_rir_covered": len(missing_required) == 0,
    }


def build_vrp_coverage(pairwise_summary: Dict[str, Any], sync_target_utc: str) -> Dict[str, Any]:
    canonical_paths = pairwise_summary.get("canonical_paths", {})
    probe_counts = pairwise_summary.get("probe_counts", {})

    probe_coverage = {}

    for probe, path in sorted(canonical_paths.items()):
        report = count_vrp_ta(Path(path))
        expected_total = probe_counts.get(probe)
        report["expected_total_from_pairwise_summary"] = expected_total
        report["total_matches_pairwise_summary"] = (expected_total == report["total"])
        probe_coverage[probe] = report

    all_covered = all(v["five_rir_covered"] for v in probe_coverage.values())
    all_total_match = all(v["total_matches_pairwise_summary"] for v in probe_coverage.values())

    return {
        "schema": "s3.m21_0.vrp_5rir_coverage_report.v1",
        "created_at_utc": utc_now_iso(),
        "sync_target_utc": sync_target_utc,
        "required_tas": REQUIRED_TAS,
        "probe_coverage": probe_coverage,
        "all_probes_five_rir_covered": all_covered,
        "all_probe_totals_match_pairwise_summary": all_total_match,
    }


def build_diff_ta_coverage(readable_diff_csv: Path, sync_target_utc: str) -> Dict[str, Any]:
    c = Counter()
    rows = 0

    with readable_diff_csv.open("r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ta = str(row.get("ta", "unknown")).strip().lower()
            c[ta] += 1
            rows += 1

    diff_ta_unique = sorted(c.keys())
    missing_required = sorted(set(REQUIRED_TAS) - set(diff_ta_unique))

    return {
        "schema": "s3.m21_0.vrp_diff_ta_coverage_report.v1",
        "created_at_utc": utc_now_iso(),
        "sync_target_utc": sync_target_utc,
        "readable_diff_csv": str(readable_diff_csv),
        "pairwise_expanded_diff_row_count": rows,
        "diff_ta_count": dict(sorted(c.items())),
        "diff_ta_unique": diff_ta_unique,
        "diff_missing_required_tas": missing_required,
        "diff_involves_all_5rir": len(missing_required) == 0,
        "interpretation": (
            "Full VRP snapshot may cover five RIRs, but the observed pairwise diff "
            "only involves the listed diff_ta_unique values."
        ),
    }


def build_object_ta_coverage(object_index: Path, sync_target_utc: str) -> Dict[str, Any]:
    ta_counter = Counter()
    object_type_counter = Counter()
    hash_status_counter = Counter()
    key_counter = Counter()
    sample_unknown = []
    sample_identified = []
    total = 0

    with object_index.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue

            row = json.loads(line)
            total += 1
            key_counter.update(row.keys())

            obj_type = str(row.get("object_type") or row.get("object_family") or "unknown")
            object_type_counter[obj_type] += 1

            hash_status = str(row.get("hash_level_status") or "unknown")
            hash_status_counter[hash_status] += 1

            explicit = (
                row.get("ta")
                or row.get("tal")
                or row.get("trust_anchor")
                or row.get("rir")
            )

            if explicit:
                ta = str(explicit).lower()
                method = "explicit_field"
            else:
                text = " ".join(
                    str(row.get(k, ""))
                    for k in [
                        "canonical_uri",
                        "object_uri",
                        "identity_key",
                        "probe_values",
                        "notes",
                    ]
                )
                ta = guess_ta_from_text(text)
                method = "heuristic_uri_text_guess"

            ta_counter[ta] += 1

            if ta == "unknown" and len(sample_unknown) < 5:
                sample_unknown.append({
                    "object_uri": row.get("object_uri"),
                    "object_type": row.get("object_type"),
                    "hash_level_status": row.get("hash_level_status"),
                })

            if ta != "unknown" and len(sample_identified) < 5:
                sample_identified.append({
                    "ta": ta,
                    "ta_method": method,
                    "object_uri": row.get("object_uri"),
                    "object_type": row.get("object_type"),
                    "hash_level_status": row.get("hash_level_status"),
                })

    unknown_count = ta_counter.get("unknown", 0)
    identified_count = total - unknown_count
    unknown_ratio = (unknown_count / total) if total else None

    five_rir_observed = all(ta_counter.get(ta, 0) > 0 for ta in REQUIRED_TAS)

    return {
        "schema": "s3.m21_0.object_ta_coverage_report.v1",
        "created_at_utc": utc_now_iso(),
        "sync_target_utc": sync_target_utc,
        "object_index": str(object_index),
        "record_count": total,
        "ta_guess_count": dict(sorted(ta_counter.items())),
        "identified_count": identified_count,
        "unknown_count": unknown_count,
        "unknown_ratio": unknown_ratio,
        "five_rir_observed": five_rir_observed,
        "classification_level": "heuristic_uri_text_guess",
        "needs_chain_based_ta_mapping": True,
        "by_object_type": dict(object_type_counter),
        "by_hash_level_status": dict(hash_status_counter),
        "top_keys": key_counter.most_common(80),
        "sample_unknown": sample_unknown,
        "sample_identified": sample_identified,
        "important_boundary": [
            "Object-layer TA classification here is heuristic.",
            "Delegated repository URI often does not contain the RIR/TAL string.",
            "Unknown objects require chain/TAL/manifest-based mapping in M21-B/M21-C."
        ],
    }


def build_markdown(
    path: Path,
    vrp_report: Dict[str, Any],
    diff_report: Dict[str, Any],
    object_report: Dict[str, Any],
    acceptance: Dict[str, Any],
) -> None:
    lines = []
    lines.append("# M21-0 Coverage 固化报告\n")
    lines.append(f"- sync_target_utc: `{vrp_report.get('sync_target_utc')}`")
    lines.append(f"- status: `{acceptance.get('status')}`\n")

    lines.append("## 1. VRP 5-RIR Coverage\n")
    for probe, r in sorted(vrp_report["probe_coverage"].items()):
        lines.append(f"### {probe}")
        lines.append(f"- total: {r['total']}")
        lines.append(f"- five_rir_covered: {r['five_rir_covered']}")
        lines.append(f"- ta_count: `{r['ta_count']}`\n")

    lines.append("## 2. VRP Diff TA Coverage\n")
    lines.append(f"- pairwise_expanded_diff_row_count: {diff_report['pairwise_expanded_diff_row_count']}")
    lines.append(f"- diff_ta_count: `{diff_report['diff_ta_count']}`")
    lines.append(f"- diff_ta_unique: `{diff_report['diff_ta_unique']}`\n")

    lines.append("## 3. Object-layer TA Coverage\n")
    lines.append(f"- record_count: {object_report['record_count']}")
    lines.append(f"- ta_guess_count: `{object_report['ta_guess_count']}`")
    lines.append(f"- identified_count: {object_report['identified_count']}")
    lines.append(f"- unknown_count: {object_report['unknown_count']}")
    lines.append(f"- unknown_ratio: {object_report['unknown_ratio']:.6f}")
    lines.append(f"- five_rir_observed: {object_report['five_rir_observed']}")
    lines.append(f"- classification_level: `{object_report['classification_level']}`")
    lines.append("- boundary: object-layer TA classification is heuristic; unknown objects require chain/TAL/manifest-based mapping.\n")

    lines.append("## 4. Acceptance\n")
    for k, v in acceptance.items():
        if k != "schema":
            lines.append(f"- {k}: `{v}`")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Build M21-0 coverage reports")
    ap.add_argument("--pairwise-summary", required=True)
    ap.add_argument("--readable-diff-csv", required=True)
    ap.add_argument("--object-index", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--sync-target-utc", default="2026-05-18T02:09:00Z")
    args = ap.parse_args()

    pairwise_summary_path = Path(args.pairwise_summary).resolve()
    readable_diff_csv = Path(args.readable_diff_csv).resolve()
    object_index = Path(args.object_index).resolve()
    out_dir = Path(args.out_dir).resolve()

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    docs = out_dir / "docs"

    for d in [outputs, checks, docs]:
        d.mkdir(parents=True, exist_ok=True)

    pairwise_summary = read_json(pairwise_summary_path)

    vrp_report = build_vrp_coverage(pairwise_summary, args.sync_target_utc)
    diff_report = build_diff_ta_coverage(readable_diff_csv, args.sync_target_utc)
    object_report = build_object_ta_coverage(object_index, args.sync_target_utc)

    acceptance = {
        "schema": "s3.m21_0.coverage_acceptance_summary.v1",
        "status": "PASS",
        "created_at_utc": utc_now_iso(),
        "sync_target_utc": args.sync_target_utc,
        "vrp_all_probes_five_rir_covered": vrp_report["all_probes_five_rir_covered"],
        "vrp_totals_match_pairwise_summary": vrp_report["all_probe_totals_match_pairwise_summary"],
        "vrp_diff_ta_unique": diff_report["diff_ta_unique"],
        "object_five_rir_observed": object_report["five_rir_observed"],
        "object_unknown_ratio": object_report["unknown_ratio"],
        "object_ta_classification_level": object_report["classification_level"],
        "m21b_required_for_strong_object_ta_mapping": object_report["needs_chain_based_ta_mapping"],
    }

    if not vrp_report["all_probes_five_rir_covered"]:
        acceptance["status"] = "FAIL"
    if not vrp_report["all_probe_totals_match_pairwise_summary"]:
        acceptance["status"] = "FAIL"
    if not object_report["five_rir_observed"]:
        acceptance["status"] = "WARN"

    write_json(outputs / "M21_0_vrp_5rir_coverage_report.json", vrp_report)
    write_json(outputs / "M21_0_vrp_diff_ta_coverage_report.json", diff_report)
    write_json(outputs / "M21_0_object_ta_coverage_report.json", object_report)
    write_json(outputs / "M21_0_coverage_acceptance_summary.json", acceptance)

    build_markdown(
        docs / "M21_0_coverage_report_zh.md",
        vrp_report,
        diff_report,
        object_report,
        acceptance,
    )

    check_text = "\n".join([
        "M21_0_COVERAGE_ACCEPTANCE=" + acceptance["status"],
        "",
        f"sync_target_utc = {args.sync_target_utc}",
        f"vrp_all_probes_five_rir_covered = {acceptance['vrp_all_probes_five_rir_covered']}",
        f"vrp_totals_match_pairwise_summary = {acceptance['vrp_totals_match_pairwise_summary']}",
        f"vrp_diff_ta_unique = {acceptance['vrp_diff_ta_unique']}",
        f"object_five_rir_observed = {acceptance['object_five_rir_observed']}",
        f"object_unknown_ratio = {acceptance['object_unknown_ratio']}",
        f"object_ta_classification_level = {acceptance['object_ta_classification_level']}",
        f"m21b_required_for_strong_object_ta_mapping = {acceptance['m21b_required_for_strong_object_ta_mapping']}",
        "",
        f"vrp_report = {outputs / 'M21_0_vrp_5rir_coverage_report.json'}",
        f"diff_report = {outputs / 'M21_0_vrp_diff_ta_coverage_report.json'}",
        f"object_report = {outputs / 'M21_0_object_ta_coverage_report.json'}",
        f"markdown_report = {docs / 'M21_0_coverage_report_zh.md'}",
    ]) + "\n"

    (checks / "M21_0_coverage_acceptance.txt").write_text(check_text, encoding="utf-8")

    print(check_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
