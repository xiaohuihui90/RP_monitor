#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


LEVEL_ORDER = [
    "A4_OBJECT_HASH_VERIFIED",
    "A3_MANIFEST_FILELIST_DECLARED",
    "A2_7_L2_OBJECT_EXACT_HIT",
    "A2_5_REVERSE_EVIDENCE_WEAK",
    "A2_L2_SOURCE_PP_COVERED",
    "A0_UNMAPPED",
]

SUPPORTED_LEVELS = {
    "A4_OBJECT_HASH_VERIFIED",
    "A3_MANIFEST_FILELIST_DECLARED",
    "A2_7_L2_OBJECT_EXACT_HIT",
}


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


def pct(n: int, d: int) -> float:
    return round((n / d) if d else 0.0, 8)


def write_dict_csv(path: Path, rows: list[dict], fields: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence-table", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--paper-table-dir", required=True)
    ap.add_argument("--report", required=True)
    args = ap.parse_args()

    evidence_path = Path(args.evidence_table)
    out_dir = Path(args.out_dir)
    paper_dir = Path(args.paper_table_dir)
    report_path = Path(args.report)

    out_dir.mkdir(parents=True, exist_ok=True)
    paper_dir.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    rows = list(read_jsonl(evidence_path))
    total = len(rows)

    level_counter = Counter()
    status_counter = Counter()
    tal_counter = Counter()
    host_counter = Counter()

    tal_level = defaultdict(Counter)
    host_level = defaultdict(Counter)

    unique_vrp_keys = set()
    unique_source_uris = set()

    supported_rows = []

    for r in rows:
        level = r.get("final_evidence_level") or "UNKNOWN"
        status = r.get("final_evidence_status") or "UNKNOWN"
        tal = r.get("tal") or "UNKNOWN"
        host = r.get("repo_host") or "UNKNOWN"

        level_counter[level] += 1
        status_counter[status] += 1
        tal_counter[tal] += 1
        host_counter[host] += 1

        tal_level[tal][level] += 1
        host_level[host][level] += 1

        if r.get("vrp_key"):
            unique_vrp_keys.add(str(r.get("vrp_key")))
        if r.get("source_uri"):
            unique_source_uris.add(str(r.get("source_uri")))

        if level in SUPPORTED_LEVELS:
            supported_rows.append(r)

    supported_count = len(supported_rows)

    all_levels = LEVEL_ORDER + sorted(k for k in level_counter if k not in LEVEL_ORDER)

    # Table 1: overall evidence summary
    overall_rows = []
    overall_rows.append({
        "section": "overall",
        "value": "total_candidate_evidence_records",
        "count": total,
        "ratio": 1.0,
    })
    overall_rows.append({
        "section": "overall",
        "value": "unique_vrp_key_count",
        "count": len(unique_vrp_keys),
        "ratio": "",
    })
    overall_rows.append({
        "section": "overall",
        "value": "unique_source_uri_count",
        "count": len(unique_source_uris),
        "ratio": "",
    })
    overall_rows.append({
        "section": "overall",
        "value": "object_or_manifest_supported_count",
        "count": supported_count,
        "ratio": pct(supported_count, total),
    })

    for lvl in all_levels:
        overall_rows.append({
            "section": "final_evidence_level",
            "value": lvl,
            "count": level_counter.get(lvl, 0),
            "ratio": pct(level_counter.get(lvl, 0), total),
        })

    for st, c in status_counter.most_common():
        overall_rows.append({
            "section": "final_evidence_status",
            "value": st,
            "count": c,
            "ratio": pct(c, total),
        })

    table_overall = paper_dir / "table_b5a_overall_evidence_summary.csv"
    write_dict_csv(
        table_overall,
        overall_rows,
        ["section", "value", "count", "ratio"],
    )

    # Table 2: TAL x evidence
    tal_rows = []
    for tal, c in tal_counter.most_common():
        rr = {
            "tal": tal,
            "total": c,
            "ratio": pct(c, total),
            "supported_count": sum(tal_level[tal].get(l, 0) for l in SUPPORTED_LEVELS),
            "supported_ratio_within_tal": pct(sum(tal_level[tal].get(l, 0) for l in SUPPORTED_LEVELS), c),
        }
        for lvl in all_levels:
            rr[lvl] = tal_level[tal].get(lvl, 0)
        tal_rows.append(rr)

    table_tal = paper_dir / "table_b5b_tal_evidence_crosstab.csv"
    write_dict_csv(
        table_tal,
        tal_rows,
        ["tal", "total", "ratio", "supported_count", "supported_ratio_within_tal"] + all_levels,
    )

    # Table 3: repo_host x evidence
    host_rows = []
    for host, c in host_counter.most_common():
        supported = sum(host_level[host].get(l, 0) for l in SUPPORTED_LEVELS)
        rr = {
            "repo_host": host,
            "total": c,
            "ratio": pct(c, total),
            "supported_count": supported,
            "supported_ratio_within_host": pct(supported, c),
        }
        for lvl in all_levels:
            rr[lvl] = host_level[host].get(lvl, 0)
        host_rows.append(rr)

    table_host = paper_dir / "table_b5c_repo_host_evidence_crosstab.csv"
    write_dict_csv(
        table_host,
        host_rows,
        ["repo_host", "total", "ratio", "supported_count", "supported_ratio_within_host"] + all_levels,
    )

    # Table 4: supported subset top hosts
    supported_host_counter = Counter()
    supported_tal_counter = Counter()
    supported_level_counter = Counter()

    for r in supported_rows:
        supported_host_counter[r.get("repo_host") or "UNKNOWN"] += 1
        supported_tal_counter[r.get("tal") or "UNKNOWN"] += 1
        supported_level_counter[r.get("final_evidence_level") or "UNKNOWN"] += 1

    supported_top_rows = []
    for host, c in supported_host_counter.most_common(50):
        supported_top_rows.append({
            "repo_host": host,
            "supported_count": c,
            "supported_ratio_among_supported": pct(c, supported_count),
            "total_count_for_host": host_counter.get(host, 0),
            "supported_ratio_within_host": pct(c, host_counter.get(host, 0)),
        })

    table_supported_hosts = paper_dir / "table_b5d_supported_subset_top_hosts.csv"
    write_dict_csv(
        table_supported_hosts,
        supported_top_rows,
        [
            "repo_host",
            "supported_count",
            "supported_ratio_among_supported",
            "total_count_for_host",
            "supported_ratio_within_host",
        ],
    )

    # write supported subset
    supported_jsonl = out_dir / "object_or_manifest_supported_subset.jsonl"
    with supported_jsonl.open("w", encoding="utf-8", newline="\n") as f:
        for r in supported_rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    report = {
        "schema": "sec27.b5_paper_candidate_stats_report.v1",
        "status": "PASS" if rows else "FAIL_NO_ROWS",
        "input": str(evidence_path),
        "total_candidate_evidence_records": total,
        "unique_vrp_key_count": len(unique_vrp_keys),
        "unique_source_uri_count": len(unique_source_uris),
        "object_or_manifest_supported_count": supported_count,
        "object_or_manifest_supported_ratio": pct(supported_count, total),
        "final_evidence_level_distribution": dict(level_counter),
        "final_evidence_status_distribution": dict(status_counter),
        "tal_distribution": dict(tal_counter),
        "top_repo_hosts": host_counter.most_common(30),
        "supported_subset": {
            "final_evidence_level_distribution": dict(supported_level_counter),
            "tal_distribution": dict(supported_tal_counter),
            "top_repo_hosts": supported_host_counter.most_common(30),
        },
        "outputs": {
            "table_overall": str(table_overall),
            "table_tal": str(table_tal),
            "table_repo_host": str(table_host),
            "table_supported_hosts": str(table_supported_hosts),
            "supported_subset_jsonl": str(supported_jsonl),
            "report": str(report_path),
        },
        "interpretation": [
            "B5A produces paper-facing descriptive statistics over the B4C candidate evidence table.",
            "This is still evidence-level aggregation, not final root-cause attribution.",
            "Persistent-candidate filtering should be defined and applied in B5B after this baseline table is accepted.",
        ],
    }

    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    print("status =", report["status"])
    print("total_candidate_evidence_records =", total)
    print("unique_vrp_key_count =", len(unique_vrp_keys))
    print("unique_source_uri_count =", len(unique_source_uris))
    print("object_or_manifest_supported_count =", supported_count)
    print("object_or_manifest_supported_ratio =", pct(supported_count, total))
    print("final_evidence_level_distribution =", dict(level_counter))
    print("tal_distribution =", dict(tal_counter))
    print("WROTE", table_overall)
    print("WROTE", table_tal)
    print("WROTE", table_host)
    print("WROTE", table_supported_hosts)
    print("WROTE", supported_jsonl)
    print("WROTE", report_path)


if __name__ == "__main__":
    main()
