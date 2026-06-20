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
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def pct(n: int, d: int) -> float:
    return round(n / d, 8) if d else 0.0


def key_of(vrp_key, source_uri):
    return f"{vrp_key or ''}||{source_uri or ''}"


def load_b3r2(path: Path):
    by_pair = {}
    by_source_uri = {}

    for r in read_jsonl(path):
        src = r.get("source_uri")
        vk = r.get("vrp_key")
        k = key_of(vk, src)

        if k not in by_pair:
            by_pair[k] = r

        if src and src not in by_source_uri:
            by_source_uri[src] = r

    return by_pair, by_source_uri


def persistence_class(source_uri, source_probe_count, temporal_alignment_quality):
    if not source_uri:
        return "PX_NO_SOURCE_URI"

    tq = str(temporal_alignment_quality or "")
    try:
        spc = int(source_probe_count or 0)
    except Exception:
        spc = 0

    if spc >= 2 or tq == "candidate_window_multi_probe":
        return "P1_CROSS_PROBE_CONFIRMED"

    if spc == 1 or tq == "candidate_window_single_probe":
        return "P0_SINGLE_PROBE_OBSERVED"

    return "P0_UNKNOWN_PROBE_SCOPE"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--b4c", required=True)
    ap.add_argument("--b3r2", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--paper-table-dir", required=True)
    ap.add_argument("--report", required=True)
    args = ap.parse_args()

    b4c_path = Path(args.b4c)
    b3r2_path = Path(args.b3r2)
    out_dir = Path(args.out_dir)
    paper_dir = Path(args.paper_table_dir)
    report_path = Path(args.report)

    out_dir.mkdir(parents=True, exist_ok=True)
    paper_dir.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    b3_by_pair, b3_by_source = load_b3r2(b3r2_path)

    rows = []
    class_counter = Counter()
    class_level = defaultdict(Counter)
    class_tal = defaultdict(Counter)
    class_host = defaultdict(Counter)
    level_counter = Counter()
    tal_counter = Counter()
    host_counter = Counter()

    unique_vrp = set()
    unique_source = set()

    for r in read_jsonl(b4c_path):
        src = r.get("source_uri")
        vk = r.get("vrp_key")
        k = key_of(vk, src)

        b3 = b3_by_pair.get(k)
        if not b3 and src:
            b3 = b3_by_source.get(src)

        source_probe_count = b3.get("source_probe_count") if b3 else None
        temporal_alignment_quality = b3.get("temporal_alignment_quality") if b3 else None
        probe_id = b3.get("probe_id") if b3 else None
        probe_presence = b3.get("probe_presence") if b3 else None

        pclass = persistence_class(src, source_probe_count, temporal_alignment_quality)

        level = r.get("final_evidence_level") or "UNKNOWN"
        tal = r.get("tal") or "UNKNOWN"
        host = r.get("repo_host") or "UNKNOWN"

        out = dict(r)
        out["persistence_scope"] = "cross_probe_window_scope"
        out["persistence_class"] = pclass
        out["source_probe_count"] = source_probe_count
        out["temporal_alignment_quality"] = temporal_alignment_quality
        out["probe_id"] = probe_id
        out["probe_presence"] = probe_presence
        out["longitudinal_persistence_evaluable"] = False
        out["longitudinal_persistence_note"] = "B4C/B3R2 records do not carry window_id; longitudinal persistence requires window-level candidate series."

        rows.append(out)

        class_counter[pclass] += 1
        class_level[pclass][level] += 1
        class_tal[pclass][tal] += 1
        class_host[pclass][host] += 1
        level_counter[level] += 1
        tal_counter[tal] += 1
        host_counter[host] += 1

        if vk:
            unique_vrp.add(str(vk))
        if src:
            unique_source.add(str(src))

    out_jsonl = out_dir / "candidate_persistence_evidence_table.jsonl"
    write_jsonl(out_jsonl, rows)

    cross_probe_rows = [r for r in rows if r.get("persistence_class") == "P1_CROSS_PROBE_CONFIRMED"]
    cross_probe_jsonl = out_dir / "cross_probe_confirmed_candidates.jsonl"
    write_jsonl(cross_probe_jsonl, cross_probe_rows)

    # table 1 overall
    table_overall = paper_dir / "table_b5b_overall_persistence_summary.csv"
    with table_overall.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["section", "value", "count", "ratio"])
        total = len(rows)
        w.writerow(["overall", "candidate_evidence_records", total, 1.0])
        w.writerow(["overall", "unique_vrp_key_count", len(unique_vrp), ""])
        w.writerow(["overall", "unique_source_uri_count", len(unique_source), ""])
        for k, v in class_counter.most_common():
            w.writerow(["persistence_class", k, v, pct(v, total)])
        for k, v in level_counter.most_common():
            w.writerow(["final_evidence_level", k, v, pct(v, total)])

    # table 2 persistence x evidence
    all_levels = sorted(level_counter.keys())
    table_class_level = paper_dir / "table_b5b_persistence_by_evidence_level.csv"
    with table_class_level.open("w", newline="", encoding="utf-8") as f:
        fields = ["persistence_class", "total", "ratio"] + all_levels
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        total = len(rows)
        for pc, c in class_counter.most_common():
            row = {"persistence_class": pc, "total": c, "ratio": pct(c, total)}
            for lvl in all_levels:
                row[lvl] = class_level[pc].get(lvl, 0)
            w.writerow(row)

    # table 3 persistence x TAL
    all_tals = sorted(tal_counter.keys())
    table_class_tal = paper_dir / "table_b5b_persistence_by_tal.csv"
    with table_class_tal.open("w", newline="", encoding="utf-8") as f:
        fields = ["persistence_class", "total", "ratio"] + all_tals
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        total = len(rows)
        for pc, c in class_counter.most_common():
            row = {"persistence_class": pc, "total": c, "ratio": pct(c, total)}
            for tal in all_tals:
                row[tal] = class_tal[pc].get(tal, 0)
            w.writerow(row)

    # table 4 cross-probe top hosts
    cross_host = Counter(r.get("repo_host") or "UNKNOWN" for r in cross_probe_rows)
    table_cross_hosts = paper_dir / "table_b5b_cross_probe_top_hosts.csv"
    with table_cross_hosts.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["repo_host", "cross_probe_count", "ratio_among_cross_probe", "total_host_count", "cross_probe_ratio_within_host"])
        total_cross = len(cross_probe_rows)
        for host, c in cross_host.most_common(50):
            total_host = host_counter.get(host, 0)
            w.writerow([host, c, pct(c, total_cross), total_host, pct(c, total_host)])

    definition_md = out_dir / "B5B_candidate_persistence_definition.md"
    definition_md.write_text(
        """# SEC27-B5B Candidate Persistence Definition

## Candidate evidence record
A row in `candidate_evidence_table.jsonl`, keyed by `(vrp_key, source_uri)` when both are available.

## Cross-probe confirmed candidate
A candidate whose B3R2 provenance indicates `source_probe_count >= 2` or
`temporal_alignment_quality = candidate_window_multi_probe`.

This is a cross-probe same-window stability property.

## Longitudinal persistent candidate
A candidate that appears across multiple time windows or validation cycles.

This cannot be evaluated from B4C/B3R2 alone because the current candidate evidence records
do not carry `window_id` / `cycle_id` fields. Longitudinal persistence should be implemented
in a later B5C stage using window-level candidate series.
""",
        encoding="utf-8",
    )

    report = {
        "schema": "sec27.b5b_candidate_persistence_stats_report.v1",
        "status": "PASS" if rows else "FAIL_NO_ROWS",
        "input_b4c": str(b4c_path),
        "input_b3r2": str(b3r2_path),
        "candidate_evidence_record_count": len(rows),
        "unique_vrp_key_count": len(unique_vrp),
        "unique_source_uri_count": len(unique_source),
        "persistence_class_distribution": dict(class_counter),
        "final_evidence_level_distribution": dict(level_counter),
        "tal_distribution": dict(tal_counter),
        "top_repo_hosts": host_counter.most_common(30),
        "cross_probe_confirmed": {
            "count": len(cross_probe_rows),
            "ratio": pct(len(cross_probe_rows), len(rows)),
            "top_repo_hosts": cross_host.most_common(30),
        },
        "longitudinal_persistence": {
            "evaluable": False,
            "reason": "No window_id/cycle_id field in B4C/B3R2 candidate evidence table.",
        },
        "outputs": {
            "candidate_persistence_table": str(out_jsonl),
            "cross_probe_confirmed_candidates": str(cross_probe_jsonl),
            "table_overall": str(table_overall),
            "table_persistence_by_evidence": str(table_class_level),
            "table_persistence_by_tal": str(table_class_tal),
            "table_cross_probe_top_hosts": str(table_cross_hosts),
            "definition": str(definition_md),
            "report": str(report_path),
        },
    }

    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    print("status =", report["status"])
    print("candidate_evidence_record_count =", len(rows))
    print("unique_vrp_key_count =", len(unique_vrp))
    print("unique_source_uri_count =", len(unique_source))
    print("persistence_class_distribution =", dict(class_counter))
    print("cross_probe_confirmed_count =", len(cross_probe_rows))
    print("longitudinal_persistence_evaluable = False")
    print("WROTE", out_jsonl)
    print("WROTE", cross_probe_jsonl)
    print("WROTE", table_overall)
    print("WROTE", table_class_level)
    print("WROTE", table_class_tal)
    print("WROTE", table_cross_hosts)
    print("WROTE", definition_md)
    print("WROTE", report_path)


if __name__ == "__main__":
    main()
