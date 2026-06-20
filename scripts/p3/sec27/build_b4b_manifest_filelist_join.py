#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse


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


def filename_from_uri(uri: str) -> str:
    if not isinstance(uri, str) or "://" not in uri:
        return ""
    p = urlparse(uri.strip())
    return (p.path or "").rsplit("/", 1)[-1]


def load_index_by_key(path: Path, key: str):
    d = {}
    for r in read_jsonl(path):
        v = r.get(key)
        if v and v not in d:
            d[v] = r
    return d


def load_filelist_index(path: Path):
    by_manifest_file = {}
    by_manifest = {}

    for r in read_jsonl(path):
        m = r.get("manifest_uri")
        fn = r.get("file")
        if not m or not fn:
            continue

        by_manifest_file[(m, fn)] = r
        by_manifest.setdefault(m, []).append(r)

    return by_manifest_file, by_manifest


def evidence_from_join(l2b, a2, a3c, fl, m22d):
    if m22d:
        lvl = str(m22d.get("final_evidence_level") or "")
        if lvl == "strong":
            return "A4_OBJECT_HASH_VERIFIED", "object_hash_verified", "high"
        if lvl == "medium":
            return "A3_MANIFEST_FILELIST_DECLARED", "manifest_filelist_only", "medium"
        return "A2_5_REVERSE_EVIDENCE_WEAK", "weak_reverse_evidence", "low-medium"

    if a3c and a3c.get("roa_filename_filelist_match") is True:
        return "A3_MANIFEST_FILELIST_DECLARED", "manifest_filelist_declared", "medium"

    if fl:
        return "A3_MANIFEST_FILELIST_DECLARED", "manifest_filelist_declared", "medium"

    if a2 and a2.get("manifest_uri"):
        return "A2_5_ROA_TO_MANIFEST_CANDIDATE", "roa_to_manifest_candidate", "medium-low"

    if l2b.get("covered_by_l2b") and l2b.get("source_uri"):
        return "A2_L2_SOURCE_PP_COVERED", "l2b_source_uri_only", "medium-high"

    return "A0_UNMAPPED", "unmapped", "none"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--l2b", required=True)
    ap.add_argument("--m21-a2", required=True)
    ap.add_argument("--m21-a3c-filelist", required=True)
    ap.add_argument("--m21-a3c-match", required=True)
    ap.add_argument("--m22d", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--paper-table-dir", required=True)
    ap.add_argument("--report", required=True)
    args = ap.parse_args()

    l2b_path = Path(args.l2b)
    m21_a2_path = Path(args.m21_a2)
    m21_a3c_filelist_path = Path(args.m21_a3c_filelist)
    m21_a3c_match_path = Path(args.m21_a3c_match)
    m22d_path = Path(args.m22d)

    out_dir = Path(args.out_dir)
    paper_dir = Path(args.paper_table_dir)
    report_path = Path(args.report)

    out_dir.mkdir(parents=True, exist_ok=True)
    paper_dir.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    a2_by_roa = load_index_by_key(m21_a2_path, "roa_uri")
    a3c_match_by_roa = load_index_by_key(m21_a3c_match_path, "roa_uri")
    m22d_by_source = load_index_by_key(m22d_path, "source_uri")
    fl_by_manifest_file, fl_by_manifest = load_filelist_index(m21_a3c_filelist_path)

    rows = []
    status_counter = Counter()
    evidence_counter = Counter()
    tal_counter = Counter()
    host_counter = Counter()

    input_l2b_count = 0
    source_uri_count = 0

    for l2b in read_jsonl(l2b_path):
        input_l2b_count += 1

        src = l2b.get("source_uri")
        if not src:
            rows.append({
                "schema": "sec27.b4b_manifest_filelist_join.v1",
                "source_uri": None,
                "vrp_key": l2b.get("vrp_key"),
                "tal": l2b.get("tal"),
                "repo_host": l2b.get("repo_host"),
                "repo_base": l2b.get("repo_base"),
                "b4b_join_status": "NO_SOURCE_URI",
                "b4b_evidence_level": "A0_UNMAPPED",
                "causal_claim_allowed": False,
            })
            status_counter["NO_SOURCE_URI"] += 1
            evidence_counter["A0_UNMAPPED"] += 1
            continue

        source_uri_count += 1
        fn = filename_from_uri(src)

        a2 = a2_by_roa.get(src)
        a3c = a3c_match_by_roa.get(src)
        m22d = m22d_by_source.get(src)

        manifest_uri = None
        if a3c and a3c.get("manifest_uri"):
            manifest_uri = a3c.get("manifest_uri")
        elif a2 and a2.get("manifest_uri"):
            manifest_uri = a2.get("manifest_uri")
        elif m22d and m22d.get("publication_point_dir"):
            manifest_uri = None

        fl = None
        if manifest_uri and fn:
            fl = fl_by_manifest_file.get((manifest_uri, fn))

        evidence_level, join_status, confidence = evidence_from_join(l2b, a2, a3c, fl, m22d)

        row = {
            "schema": "sec27.b4b_manifest_filelist_join.v1",
            "vrp_key": l2b.get("vrp_key"),
            "source_uri": src,
            "source_filename": fn,
            "tal": l2b.get("tal"),
            "repo_host": l2b.get("repo_host"),
            "repo_base": l2b.get("repo_base"),

            "b3_evidence_level": l2b.get("evidence_level"),
            "b4b_evidence_level": evidence_level,
            "b4b_join_status": join_status,
            "b4b_confidence": confidence,
            "causal_claim_allowed": False,

            "m21_a2_hit": bool(a2),
            "m21_a3c_match_hit": bool(a3c),
            "m21_a3c_filelist_hit": bool(fl),
            "m22d_hit": bool(m22d),

            "manifest_uri": manifest_uri,
            "manifestNumber": (
                a3c.get("manifestNumber") if a3c else
                fl.get("manifestNumber") if fl else
                m22d.get("best_manifest_number") if m22d else None
            ),
            "manifest_thisUpdate": (
                a3c.get("manifest_thisUpdate") if a3c else
                fl.get("thisUpdate") if fl else
                m22d.get("manifest_this_update") if m22d else None
            ),
            "manifest_nextUpdate": (
                a3c.get("manifest_nextUpdate") if a3c else
                fl.get("nextUpdate") if fl else
                m22d.get("manifest_next_update") if m22d else None
            ),
            "manifest_file_hash": (
                a3c.get("manifest_file_hash") if a3c else
                fl.get("file_hash") if fl else
                m22d.get("roa_hash_from_manifest") if m22d else None
            ),
            "roa_filename_filelist_match": (
                a3c.get("roa_filename_filelist_match") if a3c else
                bool(fl)
            ),
            "object_hash_status": (
                a3c.get("object_hash_status") if a3c else
                m22d.get("verification_status") if m22d else None
            ),
            "m22d_verdict": m22d.get("verdict") if m22d else None,
            "m22d_final_evidence_level": m22d.get("final_evidence_level") if m22d else None,
            "semantic_boundary": "manifest_filelist_join_not_final_root_cause",
        }

        rows.append(row)
        status_counter[join_status] += 1
        evidence_counter[evidence_level] += 1
        if l2b.get("tal"):
            tal_counter[str(l2b.get("tal"))] += 1
        if l2b.get("repo_host"):
            host_counter[str(l2b.get("repo_host"))] += 1

    out_jsonl = out_dir / "b4b_manifest_filelist_join.jsonl"
    write_jsonl(out_jsonl, rows)

    miss_jsonl = out_dir / "b4b_manifest_filelist_unjoined.jsonl"
    write_jsonl(miss_jsonl, [
        r for r in rows
        if r.get("b4b_join_status") in {"l2b_source_uri_only", "unmapped", "NO_SOURCE_URI"}
    ])

    summary_csv = paper_dir / "table_b4b_manifest_filelist_join_summary.csv"
    with summary_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["section", "value", "count"])
        w.writerow(["overall", "input_l2b_record_count", input_l2b_count])
        w.writerow(["overall", "source_uri_record_count", source_uri_count])
        w.writerow(["overall", "output_record_count", len(rows)])

        for k, v in status_counter.most_common():
            w.writerow(["b4b_join_status", k, v])
        for k, v in evidence_counter.most_common():
            w.writerow(["b4b_evidence_level", k, v])
        for k, v in tal_counter.most_common():
            w.writerow(["tal", k, v])
        for k, v in host_counter.most_common(30):
            w.writerow(["repo_host", k, v])

    report = {
        "schema": "sec27.b4b_manifest_filelist_join_report.v1",
        "status": "PASS" if rows else "FAIL_NO_ROWS",
        "input_l2b": str(l2b_path),
        "input_l2b_record_count": input_l2b_count,
        "source_uri_record_count": source_uri_count,
        "output_record_count": len(rows),
        "b4b_join_status_distribution": dict(status_counter),
        "b4b_evidence_level_distribution": dict(evidence_counter),
        "tal_distribution": dict(tal_counter),
        "top_repo_hosts": host_counter.most_common(30),
        "inputs": {
            "m21_a2": str(m21_a2_path),
            "m21_a3c_filelist": str(m21_a3c_filelist_path),
            "m21_a3c_match": str(m21_a3c_match_path),
            "m22d": str(m22d_path),
        },
        "outputs": {
            "join_jsonl": str(out_jsonl),
            "unjoined_jsonl": str(miss_jsonl),
            "summary_csv": str(summary_csv),
            "report": str(report_path),
        },
        "interpretation": [
            "B4B joins L2-b source_uri with structured ROA-manifest/fileList evidence.",
            "A4 means M22D object-hash-verified reverse evidence.",
            "A3 means manifest fileList declaration evidence without final object hash verification.",
            "A2.5 means ROA-to-manifest candidate exists, but fileList confirmation is absent.",
            "This stage does not assert final root cause; causal_claim_allowed remains false.",
        ],
    }

    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    print("status =", report["status"])
    print("input_l2b_record_count =", input_l2b_count)
    print("source_uri_record_count =", source_uri_count)
    print("output_record_count =", len(rows))
    print("b4b_join_status_distribution =", dict(status_counter))
    print("b4b_evidence_level_distribution =", dict(evidence_counter))
    print("WROTE", out_jsonl)
    print("WROTE", miss_jsonl)
    print("WROTE", summary_csv)
    print("WROTE", report_path)


if __name__ == "__main__":
    main()
