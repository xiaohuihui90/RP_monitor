#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import glob
import json
from collections import Counter, defaultdict
from pathlib import Path


PERSISTENT_MIN_WINDOWS = 2


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


def load_lifetime_records(pattern: str):
    paths = sorted(Path(p) for p in glob.glob(pattern))
    by_vrp = defaultdict(list)

    total_records = 0
    for p in paths:
        for r in read_jsonl(p):
            total_records += 1
            vk = r.get("vrp_key")
            if not vk:
                continue

            rr = dict(r)
            rr["_source_file"] = str(p)
            by_vrp[str(vk)].append(rr)

    return paths, by_vrp, total_records


def summarize_lifetime(records):
    windows = sorted({str(r.get("window_id")) for r in records if r.get("window_id")})
    probe_pairs = sorted({str(r.get("probe_pair")) for r in records if r.get("probe_pair")})
    diff_types = sorted({str(r.get("diff_type")) for r in records if r.get("diff_type")})
    event_types = sorted({str(r.get("event_type")) for r in records if r.get("event_type")})
    temporal_classes = sorted({str(r.get("temporal_class")) for r in records if r.get("temporal_class")})

    duration_values = []
    for r in records:
        try:
            duration_values.append(int(r.get("duration_windows") or 0))
        except Exception:
            pass

    duration_max = max(duration_values) if duration_values else 0

    first_seen = sorted({str(r.get("first_seen_window")) for r in records if r.get("first_seen_window")})
    last_seen = sorted({str(r.get("last_seen_window")) for r in records if r.get("last_seen_window")})

    observed_window_count = len(windows)
    persistent = duration_max >= PERSISTENT_MIN_WINDOWS or observed_window_count >= PERSISTENT_MIN_WINDOWS

    if persistent:
        cls = "L1_LONGITUDINALLY_PERSISTENT"
    elif observed_window_count == 1:
        cls = "L0_SINGLE_WINDOW"
    else:
        cls = "L0_MATCHED_NO_WINDOW_COUNT"

    return {
        "longitudinal_class": cls,
        "longitudinal_persistent": persistent,
        "observed_window_count": observed_window_count,
        "duration_windows_max": duration_max,
        "window_ids": windows,
        "first_seen_window": first_seen[0] if first_seen else None,
        "last_seen_window": last_seen[-1] if last_seen else None,
        "probe_pairs": probe_pairs,
        "diff_types": diff_types,
        "event_types": event_types,
        "temporal_classes": temporal_classes,
        "lifetime_record_count": len(records),
        "lifetime_source_file_count": len({r.get("_source_file") for r in records if r.get("_source_file")}),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--b4c", required=True)
    ap.add_argument("--lifetime-pattern", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--paper-table-dir", required=True)
    ap.add_argument("--report", required=True)
    args = ap.parse_args()

    b4c_path = Path(args.b4c)
    out_dir = Path(args.out_dir)
    paper_dir = Path(args.paper_table_dir)
    report_path = Path(args.report)

    out_dir.mkdir(parents=True, exist_ok=True)
    paper_dir.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    lifetime_paths, lifetime_by_vrp, lifetime_total_records = load_lifetime_records(args.lifetime_pattern)

    rows = []
    persistent_rows = []

    class_counter = Counter()
    final_level_counter = Counter()
    tal_counter = Counter()
    host_counter = Counter()
    persistent_tal_counter = Counter()
    persistent_host_counter = Counter()
    persistent_level_counter = Counter()

    matched_count = 0
    unmatched_count = 0

    for r in read_jsonl(b4c_path):
        vk = r.get("vrp_key")
        lifetime_records = lifetime_by_vrp.get(str(vk), []) if vk else []

        if lifetime_records:
            matched_count += 1
            ls = summarize_lifetime(lifetime_records)
        else:
            unmatched_count += 1
            ls = {
                "longitudinal_class": "LX_NO_LONGITUDINAL_MATCH",
                "longitudinal_persistent": False,
                "observed_window_count": 0,
                "duration_windows_max": 0,
                "window_ids": [],
                "first_seen_window": None,
                "last_seen_window": None,
                "probe_pairs": [],
                "diff_types": [],
                "event_types": [],
                "temporal_classes": [],
                "lifetime_record_count": 0,
                "lifetime_source_file_count": 0,
            }

        out = dict(r)
        out.update(ls)
        out["longitudinal_join_key"] = "vrp_key"
        out["longitudinal_source_family"] = "m17_m18_lifetime_seed_records"

        rows.append(out)

        cls = out["longitudinal_class"]
        level = out.get("final_evidence_level") or "UNKNOWN"
        tal = out.get("tal") or "UNKNOWN"
        host = out.get("repo_host") or "UNKNOWN"

        class_counter[cls] += 1
        final_level_counter[level] += 1
        tal_counter[tal] += 1
        host_counter[host] += 1

        if out["longitudinal_persistent"]:
            persistent_rows.append(out)
            persistent_tal_counter[tal] += 1
            persistent_host_counter[host] += 1
            persistent_level_counter[level] += 1

    out_jsonl = out_dir / "longitudinal_persistence_evidence_table.jsonl"
    persistent_jsonl = out_dir / "longitudinal_persistent_candidates.jsonl"
    write_jsonl(out_jsonl, rows)
    write_jsonl(persistent_jsonl, persistent_rows)

    table_overall = paper_dir / "table_b5d_overall_longitudinal_summary.csv"
    with table_overall.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["section", "value", "count", "ratio"])
        total = len(rows)
        w.writerow(["overall", "b4c_candidate_records", total, 1.0])
        w.writerow(["overall", "lifetime_source_file_count", len(lifetime_paths), ""])
        w.writerow(["overall", "lifetime_total_records", lifetime_total_records, ""])
        w.writerow(["overall", "longitudinal_matched_count", matched_count, pct(matched_count, total)])
        w.writerow(["overall", "longitudinal_unmatched_count", unmatched_count, pct(unmatched_count, total)])
        w.writerow(["overall", "longitudinal_persistent_count", len(persistent_rows), pct(len(persistent_rows), total)])

        for k, v in class_counter.most_common():
            w.writerow(["longitudinal_class", k, v, pct(v, total)])
        for k, v in persistent_level_counter.most_common():
            w.writerow(["persistent_final_evidence_level", k, v, pct(v, len(persistent_rows))])

    all_levels = sorted(final_level_counter.keys())
    table_class_level = paper_dir / "table_b5d_longitudinal_by_evidence_level.csv"
    class_level = defaultdict(Counter)
    for r in rows:
        class_level[r["longitudinal_class"]][r.get("final_evidence_level") or "UNKNOWN"] += 1

    with table_class_level.open("w", newline="", encoding="utf-8") as f:
        fields = ["longitudinal_class", "total", "ratio"] + all_levels
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        total = len(rows)
        for cls, c in class_counter.most_common():
            rr = {"longitudinal_class": cls, "total": c, "ratio": pct(c, total)}
            for lvl in all_levels:
                rr[lvl] = class_level[cls].get(lvl, 0)
            w.writerow(rr)

    table_persistent_hosts = paper_dir / "table_b5d_persistent_top_hosts.csv"
    with table_persistent_hosts.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["repo_host", "persistent_count", "ratio_among_persistent", "total_host_count", "persistent_ratio_within_host"])
        for host, c in persistent_host_counter.most_common(50):
            total_host = host_counter.get(host, 0)
            w.writerow([host, c, pct(c, len(persistent_rows)), total_host, pct(c, total_host)])

    table_persistent_tal = paper_dir / "table_b5d_persistent_by_tal.csv"
    with table_persistent_tal.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["tal", "persistent_count", "ratio_among_persistent", "total_tal_count", "persistent_ratio_within_tal"])
        for tal, c in persistent_tal_counter.most_common():
            total_tal = tal_counter.get(tal, 0)
            w.writerow([tal, c, pct(c, len(persistent_rows)), total_tal, pct(c, total_tal)])

    report = {
        "schema": "sec27.b5d_longitudinal_persistence_join_report.v1",
        "status": "PASS" if rows else "FAIL_NO_ROWS",
        "input_b4c": str(b4c_path),
        "lifetime_pattern": args.lifetime_pattern,
        "lifetime_source_file_count": len(lifetime_paths),
        "lifetime_total_records": lifetime_total_records,
        "b4c_candidate_record_count": len(rows),
        "longitudinal_matched_count": matched_count,
        "longitudinal_unmatched_count": unmatched_count,
        "longitudinal_persistent_count": len(persistent_rows),
        "longitudinal_persistent_ratio": pct(len(persistent_rows), len(rows)),
        "longitudinal_class_distribution": dict(class_counter),
        "persistent_final_evidence_level_distribution": dict(persistent_level_counter),
        "persistent_tal_distribution": dict(persistent_tal_counter),
        "persistent_top_repo_hosts": persistent_host_counter.most_common(30),
        "outputs": {
            "longitudinal_evidence_table": str(out_jsonl),
            "longitudinal_persistent_candidates": str(persistent_jsonl),
            "table_overall": str(table_overall),
            "table_by_evidence_level": str(table_class_level),
            "table_persistent_hosts": str(table_persistent_hosts),
            "table_persistent_tal": str(table_persistent_tal),
            "report": str(report_path),
        },
        "interpretation": [
            "B5D joins B4C candidate evidence records with M17/M18 lifetime seed records by vrp_key.",
            "L1_LONGITUDINALLY_PERSISTENT means duration_windows >= 2 or observation in >=2 windows.",
            "This is a longitudinal persistence measurement over available M17/M18 windows, not a final root-cause attribution.",
        ],
    }

    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    print("status =", report["status"])
    print("lifetime_source_file_count =", len(lifetime_paths))
    print("lifetime_total_records =", lifetime_total_records)
    print("b4c_candidate_record_count =", len(rows))
    print("longitudinal_matched_count =", matched_count)
    print("longitudinal_unmatched_count =", unmatched_count)
    print("longitudinal_persistent_count =", len(persistent_rows))
    print("longitudinal_persistent_ratio =", pct(len(persistent_rows), len(rows)))
    print("longitudinal_class_distribution =", dict(class_counter))
    print("persistent_final_evidence_level_distribution =", dict(persistent_level_counter))
    print("persistent_tal_distribution =", dict(persistent_tal_counter))
    print("WROTE", out_jsonl)
    print("WROTE", persistent_jsonl)
    print("WROTE", table_overall)
    print("WROTE", table_class_level)
    print("WROTE", table_persistent_hosts)
    print("WROTE", table_persistent_tal)
    print("WROTE", report_path)


if __name__ == "__main__":
    main()
