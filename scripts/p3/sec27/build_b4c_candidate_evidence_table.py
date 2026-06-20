#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


def read_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                yield obj


def write_jsonl(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def load_by_source_uri(path: Path):
    d = {}
    for r in read_jsonl(path):
        src = r.get("source_uri")
        if src and src not in d:
            d[src] = r
    return d


def final_evidence_level(b4b: dict, b4a: dict | None):
    b4b_level = b4b.get("b4b_evidence_level")
    b4b_status = b4b.get("b4b_join_status")

    if b4b_level == "A4_OBJECT_HASH_VERIFIED":
        return "A4_OBJECT_HASH_VERIFIED", "object_hash_verified", "high"

    if b4b_level == "A3_MANIFEST_FILELIST_DECLARED":
        return "A3_MANIFEST_FILELIST_DECLARED", "manifest_filelist_declared", "medium"

    if b4a and b4a.get("l2_object_hit") is True:
        return "A2_7_L2_OBJECT_EXACT_HIT", "l2_object_inventory_exact_hit", "medium-high"

    if b4b_level == "A2_5_REVERSE_EVIDENCE_WEAK" or b4b_status == "weak_reverse_evidence":
        return "A2_5_REVERSE_EVIDENCE_WEAK", "weak_reverse_evidence", "low-medium"

    if b4b.get("source_uri"):
        return "A2_L2_SOURCE_PP_COVERED", "l2b_source_uri_only", "medium-high"

    return "A0_UNMAPPED", "no_source_uri", "none"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--b4b", required=True)
    ap.add_argument("--b4a", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--paper-table-dir", required=True)
    ap.add_argument("--report", required=True)
    args = ap.parse_args()

    b4b_path = Path(args.b4b)
    b4a_path = Path(args.b4a)
    out_dir = Path(args.out_dir)
    paper_dir = Path(args.paper_table_dir)
    report_path = Path(args.report)

    out_dir.mkdir(parents=True, exist_ok=True)
    paper_dir.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    b4a_by_source_uri = load_by_source_uri(b4a_path)

    rows = []
    final_level_counter = Counter()
    final_status_counter = Counter()
    tal_counter = Counter()
    host_counter = Counter()
    b4a_hit_counter = Counter()
    b4b_level_counter = Counter()

    input_count = 0

    for b4b in read_jsonl(b4b_path):
        input_count += 1

        src = b4b.get("source_uri")
        b4a = b4a_by_source_uri.get(src) if src else None

        level, status, confidence = final_evidence_level(b4b, b4a)

        row = {
            "schema": "sec27.b4c_candidate_evidence_table.v1",

            "vrp_key": b4b.get("vrp_key"),
            "source_uri": src,
            "source_filename": b4b.get("source_filename"),
            "tal": b4b.get("tal"),
            "repo_host": b4b.get("repo_host"),
            "repo_base": b4b.get("repo_base"),

            "final_evidence_level": level,
            "final_evidence_status": status,
            "final_mapping_confidence": confidence,
            "causal_claim_allowed": False,

            "b3_evidence_level": b4b.get("b3_evidence_level"),
            "b4a_l2_object_hit": bool(b4a and b4a.get("l2_object_hit")),
            "b4a_l2_hit_count": b4a.get("l2_hit_count") if b4a else 0,
            "b4a_l2_object_types": b4a.get("l2_object_types") if b4a else "",

            "b4b_evidence_level": b4b.get("b4b_evidence_level"),
            "b4b_join_status": b4b.get("b4b_join_status"),
            "m21_a2_hit": b4b.get("m21_a2_hit"),
            "m21_a3c_match_hit": b4b.get("m21_a3c_match_hit"),
            "m21_a3c_filelist_hit": b4b.get("m21_a3c_filelist_hit"),
            "m22d_hit": b4b.get("m22d_hit"),

            "manifest_uri": b4b.get("manifest_uri"),
            "manifestNumber": b4b.get("manifestNumber"),
            "manifest_thisUpdate": b4b.get("manifest_thisUpdate"),
            "manifest_nextUpdate": b4b.get("manifest_nextUpdate"),
            "manifest_file_hash": b4b.get("manifest_file_hash"),
            "object_hash_status": b4b.get("object_hash_status"),
            "m22d_verdict": b4b.get("m22d_verdict"),
            "m22d_final_evidence_level": b4b.get("m22d_final_evidence_level"),

            "semantic_boundary": "candidate_evidence_table_not_final_root_cause",
        }

        rows.append(row)

        final_level_counter[level] += 1
        final_status_counter[status] += 1
        b4b_level_counter[str(b4b.get("b4b_evidence_level"))] += 1
        b4a_hit_counter["hit" if row["b4a_l2_object_hit"] else "miss_or_na"] += 1

        if row.get("tal"):
            tal_counter[str(row["tal"])] += 1
        if row.get("repo_host"):
            host_counter[str(row["repo_host"])] += 1

    out_jsonl = out_dir / "candidate_evidence_table.jsonl"
    write_jsonl(out_jsonl, rows)

    strong_subset = [
        r for r in rows
        if r["final_evidence_level"] in {
            "A4_OBJECT_HASH_VERIFIED",
            "A3_MANIFEST_FILELIST_DECLARED",
            "A2_7_L2_OBJECT_EXACT_HIT",
        }
    ]
    strong_jsonl = out_dir / "candidate_evidence_table_object_or_manifest_supported.jsonl"
    write_jsonl(strong_jsonl, strong_subset)

    summary_csv = paper_dir / "table_b4c_candidate_evidence_summary.csv"
    with summary_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["section", "value", "count"])

        w.writerow(["overall", "input_b4b_record_count", input_count])
        w.writerow(["overall", "output_record_count", len(rows)])
        w.writerow(["overall", "object_or_manifest_supported_count", len(strong_subset)])

        for k, v in final_level_counter.most_common():
            w.writerow(["final_evidence_level", k, v])
        for k, v in final_status_counter.most_common():
            w.writerow(["final_evidence_status", k, v])
        for k, v in b4a_hit_counter.most_common():
            w.writerow(["b4a_l2_object_hit", k, v])
        for k, v in b4b_level_counter.most_common():
            w.writerow(["b4b_evidence_level", k, v])
        for k, v in tal_counter.most_common():
            w.writerow(["tal", k, v])
        for k, v in host_counter.most_common(30):
            w.writerow(["repo_host", k, v])

    report = {
        "schema": "sec27.b4c_candidate_evidence_table_report.v1",
        "status": "PASS" if rows else "FAIL_NO_ROWS",
        "input_b4b": str(b4b_path),
        "input_b4a": str(b4a_path),
        "input_b4b_record_count": input_count,
        "output_record_count": len(rows),
        "object_or_manifest_supported_count": len(strong_subset),
        "final_evidence_level_distribution": dict(final_level_counter),
        "final_evidence_status_distribution": dict(final_status_counter),
        "b4a_l2_object_hit_distribution": dict(b4a_hit_counter),
        "b4b_evidence_level_distribution": dict(b4b_level_counter),
        "tal_distribution": dict(tal_counter),
        "top_repo_hosts": host_counter.most_common(30),
        "outputs": {
            "candidate_evidence_table": str(out_jsonl),
            "object_or_manifest_supported_subset": str(strong_jsonl),
            "summary_csv": str(summary_csv),
            "report": str(report_path),
        },
        "interpretation": [
            "B4C consolidates B3/B4A/B4B evidence into one candidate evidence table.",
            "A4 is object hash verified evidence.",
            "A3 is manifest fileList declaration evidence.",
            "A2.7 is exact L2 object inventory hit without manifest/hash confirmation.",
            "A2 remains source_uri/repo_base coverage only.",
            "This stage still does not assert final root cause.",
        ],
    }

    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    print("status =", report["status"])
    print("input_b4b_record_count =", report["input_b4b_record_count"])
    print("output_record_count =", report["output_record_count"])
    print("object_or_manifest_supported_count =", report["object_or_manifest_supported_count"])
    print("final_evidence_level_distribution =", report["final_evidence_level_distribution"])
    print("b4a_l2_object_hit_distribution =", report["b4a_l2_object_hit_distribution"])
    print("WROTE", out_jsonl)
    print("WROTE", strong_jsonl)
    print("WROTE", summary_csv)
    print("WROTE", report_path)


if __name__ == "__main__":
    main()
