#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


SUPPORTED_LEVELS = {
    "A4_OBJECT_HASH_VERIFIED",
    "A3_MANIFEST_FILELIST_DECLARED",
    "A2_7_L2_OBJECT_EXACT_HIT",
}

PERSISTENT_CLASS = "L1_LONGITUDINALLY_PERSISTENT"


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
    return round(n / d, 8) if d else 0.0


def write_csv(path: Path, rows: list[dict], fields: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tuple-bridge-table", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--paper-table-dir", required=True)
    ap.add_argument("--report", required=True)
    args = ap.parse_args()

    src = Path(args.tuple_bridge_table)
    out_dir = Path(args.out_dir)
    paper_dir = Path(args.paper_table_dir)
    report_path = Path(args.report)

    out_dir.mkdir(parents=True, exist_ok=True)
    paper_dir.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    rows = list(read_jsonl(src))
    total = len(rows)

    level_counter = Counter()
    long_counter = Counter()
    tal_counter = Counter()
    host_counter = Counter()
    derivation_counter = Counter()

    level_long = defaultdict(Counter)
    tal_long = defaultdict(Counter)
    host_long = defaultdict(Counter)

    unique_vrp = set()
    unique_source = set()
    unique_tuple = set()

    persistent_rows = []
    supported_rows = []
    a4_persistent_rows = []

    for r in rows:
        level = r.get("final_evidence_level") or "UNKNOWN"
        lcls = r.get("longitudinal_class") or "UNKNOWN"
        tal = r.get("tal") or "UNKNOWN"
        host = r.get("repo_host") or "UNKNOWN"
        deriv = r.get("tuple_derivation_status") or "UNKNOWN"

        level_counter[level] += 1
        long_counter[lcls] += 1
        tal_counter[tal] += 1
        host_counter[host] += 1
        derivation_counter[deriv] += 1

        level_long[level][lcls] += 1
        tal_long[tal][lcls] += 1
        host_long[host][lcls] += 1

        if r.get("vrp_key"):
            unique_vrp.add(str(r.get("vrp_key")))
        if r.get("source_uri"):
            unique_source.add(str(r.get("source_uri")))
        if r.get("derived_tuple_key"):
            unique_tuple.add(str(r.get("derived_tuple_key")))

        if level in SUPPORTED_LEVELS:
            supported_rows.append(r)
        if lcls == PERSISTENT_CLASS:
            persistent_rows.append(r)
        if lcls == PERSISTENT_CLASS and level == "A4_OBJECT_HASH_VERIFIED":
            a4_persistent_rows.append(r)

    # Table 1 overall
    table_overall = paper_dir / "table_b6a_final_overall_counts.csv"
    overall_rows = [
        {"section": "overall", "metric": "candidate_records", "count": total, "ratio": 1.0},
        {"section": "overall", "metric": "unique_vrp_key_count", "count": len(unique_vrp), "ratio": ""},
        {"section": "overall", "metric": "unique_source_uri_count", "count": len(unique_source), "ratio": ""},
        {"section": "overall", "metric": "derived_tuple_key_count", "count": len(unique_tuple), "ratio": pct(len(unique_tuple), total)},
        {"section": "overall", "metric": "object_or_manifest_supported_count", "count": len(supported_rows), "ratio": pct(len(supported_rows), total)},
        {"section": "overall", "metric": "longitudinal_persistent_count", "count": len(persistent_rows), "ratio": pct(len(persistent_rows), total)},
        {"section": "overall", "metric": "a4_persistent_count", "count": len(a4_persistent_rows), "ratio": pct(len(a4_persistent_rows), total)},
    ]

    for k, v in level_counter.most_common():
        overall_rows.append({"section": "final_evidence_level", "metric": k, "count": v, "ratio": pct(v, total)})
    for k, v in long_counter.most_common():
        overall_rows.append({"section": "longitudinal_class", "metric": k, "count": v, "ratio": pct(v, total)})
    for k, v in derivation_counter.most_common():
        overall_rows.append({"section": "tuple_derivation_status", "metric": k, "count": v, "ratio": pct(v, total)})

    write_csv(table_overall, overall_rows, ["section", "metric", "count", "ratio"])

    # Table 2 evidence x longitudinal
    long_classes = sorted(long_counter.keys())
    table_evidence_long = paper_dir / "table_b6b_evidence_by_longitudinal_class.csv"
    evidence_long_rows = []
    for level, c in level_counter.most_common():
        rr = {"final_evidence_level": level, "total": c, "ratio": pct(c, total)}
        for lc in long_classes:
            rr[lc] = level_long[level].get(lc, 0)
        evidence_long_rows.append(rr)
    write_csv(table_evidence_long, evidence_long_rows, ["final_evidence_level", "total", "ratio"] + long_classes)

    # Table 3 TAL x longitudinal
    table_tal_long = paper_dir / "table_b6c_tal_by_longitudinal_class.csv"
    tal_rows = []
    for tal, c in tal_counter.most_common():
        persistent = tal_long[tal].get(PERSISTENT_CLASS, 0)
        rr = {
            "tal": tal,
            "total": c,
            "ratio": pct(c, total),
            "persistent_count": persistent,
            "persistent_ratio_within_tal": pct(persistent, c),
        }
        for lc in long_classes:
            rr[lc] = tal_long[tal].get(lc, 0)
        tal_rows.append(rr)
    write_csv(table_tal_long, tal_rows, ["tal", "total", "ratio", "persistent_count", "persistent_ratio_within_tal"] + long_classes)

    # Table 4 persistent top hosts
    table_persistent_hosts = paper_dir / "table_b6d_persistent_top_hosts.csv"
    persistent_host_counter = Counter(r.get("repo_host") or "UNKNOWN" for r in persistent_rows)
    persistent_host_rows = []
    for host, c in persistent_host_counter.most_common(50):
        total_host = host_counter.get(host, 0)
        persistent_host_rows.append({
            "repo_host": host,
            "persistent_count": c,
            "ratio_among_persistent": pct(c, len(persistent_rows)),
            "total_host_count": total_host,
            "persistent_ratio_within_host": pct(c, total_host),
        })
    write_csv(table_persistent_hosts, persistent_host_rows, ["repo_host", "persistent_count", "ratio_among_persistent", "total_host_count", "persistent_ratio_within_host"])

    # Table 5 selected cases
    def case_rank(r):
        level_rank = {
            "A4_OBJECT_HASH_VERIFIED": 0,
            "A3_MANIFEST_FILELIST_DECLARED": 1,
            "A2_7_L2_OBJECT_EXACT_HIT": 2,
            "A2_L2_SOURCE_PP_COVERED": 3,
        }.get(r.get("final_evidence_level"), 9)
        return (
            level_rank,
            -int(r.get("observed_window_count") or 0),
            -(int(r.get("lifetime_record_count") or 0)),
            str(r.get("repo_host") or ""),
            str(r.get("source_uri") or ""),
        )

    selected_cases = sorted(persistent_rows, key=case_rank)
    case_rows = []
    for i, r in enumerate(selected_cases, 1):
        case_rows.append({
            "case_id": f"SEC27-C{i:03d}",
            "final_evidence_level": r.get("final_evidence_level"),
            "tal": r.get("tal"),
            "repo_host": r.get("repo_host"),
            "source_uri": r.get("source_uri"),
            "derived_tuple_key": r.get("derived_tuple_key"),
            "decoded_tuple": r.get("tuple_derivation_decoded_text"),
            "observed_window_count": r.get("observed_window_count"),
            "lifetime_record_count": r.get("lifetime_record_count"),
            "first_seen_window": r.get("first_seen_window"),
            "last_seen_window": r.get("last_seen_window"),
            "event_types": ";".join(r.get("event_types") or []),
            "diff_types": ";".join(r.get("diff_types") or []),
            "probe_pairs": ";".join(r.get("probe_pairs") or []),
            "m22d_verdict": r.get("m22d_verdict"),
            "object_hash_status": r.get("object_hash_status"),
            "causal_claim_allowed": r.get("causal_claim_allowed"),
        })

    table_cases = paper_dir / "table_b6e_selected_persistent_cases.csv"
    write_csv(
        table_cases,
        case_rows,
        [
            "case_id",
            "final_evidence_level",
            "tal",
            "repo_host",
            "source_uri",
            "derived_tuple_key",
            "decoded_tuple",
            "observed_window_count",
            "lifetime_record_count",
            "first_seen_window",
            "last_seen_window",
            "event_types",
            "diff_types",
            "probe_pairs",
            "m22d_verdict",
            "object_hash_status",
            "causal_claim_allowed",
        ],
    )

    cases_jsonl = out_dir / "selected_persistent_cases.jsonl"
    with cases_jsonl.open("w", encoding="utf-8", newline="\n") as f:
        for r in selected_cases:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    paper_numbers = out_dir / "SEC27_B6_paper_numbers.md"
    paper_numbers.write_text(
        f"""# SEC27 B6 Final Paper Numbers

## Candidate evidence table

- Candidate evidence records: {total}
- Unique VRP keys: {len(unique_vrp)}
- Unique source URIs: {len(unique_source)}
- Derived tuple keys: {len(unique_tuple)}
- Object/manifest supported records: {len(supported_rows)} ({pct(len(supported_rows), total)})
- Longitudinal persistent records: {len(persistent_rows)} ({pct(len(persistent_rows), total)})
- A4 longitudinal persistent records: {len(a4_persistent_rows)} ({pct(len(a4_persistent_rows), total)})

## Evidence levels

{dict(level_counter)}

## Longitudinal classes

{dict(long_counter)}

## TAL distribution

{dict(tal_counter)}

## Caveat

These are evidence-level and longitudinal-persistence measurements. They do not assert final root cause. All rows keep `causal_claim_allowed=false` unless a later counterfactual/replay stage explicitly upgrades the claim.
""",
        encoding="utf-8",
    )

    report = {
        "schema": "sec27.b6_final_paper_tables_report.v1",
        "status": "PASS" if rows else "FAIL_NO_ROWS",
        "input": str(src),
        "candidate_records": total,
        "unique_vrp_key_count": len(unique_vrp),
        "unique_source_uri_count": len(unique_source),
        "derived_tuple_key_count": len(unique_tuple),
        "object_or_manifest_supported_count": len(supported_rows),
        "object_or_manifest_supported_ratio": pct(len(supported_rows), total),
        "longitudinal_persistent_count": len(persistent_rows),
        "longitudinal_persistent_ratio": pct(len(persistent_rows), total),
        "a4_persistent_count": len(a4_persistent_rows),
        "a4_persistent_ratio": pct(len(a4_persistent_rows), total),
        "final_evidence_level_distribution": dict(level_counter),
        "longitudinal_class_distribution": dict(long_counter),
        "tal_distribution": dict(tal_counter),
        "persistent_top_hosts": persistent_host_counter.most_common(30),
        "outputs": {
            "table_overall": str(table_overall),
            "table_evidence_longitudinal": str(table_evidence_long),
            "table_tal_longitudinal": str(table_tal_long),
            "table_persistent_hosts": str(table_persistent_hosts),
            "table_selected_cases": str(table_cases),
            "selected_cases_jsonl": str(cases_jsonl),
            "paper_numbers_md": str(paper_numbers),
            "report": str(report_path),
        },
        "interpretation": [
            "B6 consolidates final paper-facing statistics and persistent case selection.",
            "Persistent cases are selected from B5D-R2 tuple-bridge longitudinal persistence.",
            "A4 persistent cases are the strongest current case candidates.",
            "This remains evidence-level attribution, not final root-cause proof.",
        ],
    }

    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    print("status =", report["status"])
    print("candidate_records =", total)
    print("object_or_manifest_supported_count =", len(supported_rows))
    print("longitudinal_persistent_count =", len(persistent_rows))
    print("a4_persistent_count =", len(a4_persistent_rows))
    print("final_evidence_level_distribution =", dict(level_counter))
    print("longitudinal_class_distribution =", dict(long_counter))
    print("persistent_top_hosts =", persistent_host_counter.most_common(30))
    print("WROTE", table_overall)
    print("WROTE", table_evidence_long)
    print("WROTE", table_tal_long)
    print("WROTE", table_persistent_hosts)
    print("WROTE", table_cases)
    print("WROTE", cases_jsonl)
    print("WROTE", paper_numbers)
    print("WROTE", report_path)


if __name__ == "__main__":
    main()
