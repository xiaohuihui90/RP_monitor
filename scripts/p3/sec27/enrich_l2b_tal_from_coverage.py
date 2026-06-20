#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def read_jsonl(path: Path):
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


def norm(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip()


def valid_tal(v: Any) -> bool:
    s = norm(v).lower()
    return s in {"afrinic", "apnic", "arin", "lacnic", "ripe"}


def choose_tal(counter: Counter) -> tuple[str | None, str, list[str]]:
    if not counter:
        return None, "no_candidate", []

    ranked = counter.most_common()
    candidates = [k for k, _ in ranked]

    if len(ranked) == 1:
        return ranked[0][0], "unique", candidates

    if ranked[0][1] > ranked[1][1]:
        return ranked[0][0], "majority", candidates

    return ranked[0][0], "tie_choose_first", candidates


def build_tal_indexes(coverage_path: Path):
    base_tals = defaultdict(Counter)
    host_tals = defaultdict(Counter)

    total = 0
    with_tal = 0
    for r in read_jsonl(coverage_path):
        total += 1
        tal = norm(r.get("tal")).lower()
        if not valid_tal(tal):
            continue

        with_tal += 1
        repo_base = norm(r.get("repo_base"))
        repo_host = norm(r.get("repo_host")).lower()

        if repo_base:
            base_tals[repo_base][tal] += int(r.get("l3_observation_count") or 1)
        if repo_host:
            host_tals[repo_host][tal] += int(r.get("l3_observation_count") or 1)

    base_index = {}
    for base, counter in base_tals.items():
        tal, method, candidates = choose_tal(counter)
        base_index[base] = {
            "tal": tal,
            "method": f"repo_base_{method}",
            "candidates": candidates,
            "counts": dict(counter),
        }

    host_index = {}
    for host, counter in host_tals.items():
        tal, method, candidates = choose_tal(counter)
        host_index[host] = {
            "tal": tal,
            "method": f"repo_host_{method}",
            "candidates": candidates,
            "counts": dict(counter),
        }

    return {
        "coverage_record_count": total,
        "coverage_record_with_tal_count": with_tal,
        "base_index": base_index,
        "host_index": host_index,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--l2b", required=True)
    ap.add_argument("--coverage", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--summary-csv", required=True)
    args = ap.parse_args()

    l2b_path = Path(args.l2b)
    coverage_path = Path(args.coverage)
    out_path = Path(args.out)
    report_path = Path(args.report)
    summary_csv = Path(args.summary_csv)

    indexes = build_tal_indexes(coverage_path)
    base_index = indexes["base_index"]
    host_index = indexes["host_index"]

    out_rows = []
    tal_dist = Counter()
    method_dist = Counter()
    still_null = 0
    input_rows = 0
    changed = 0

    for r in read_jsonl(l2b_path):
        input_rows += 1
        old_tal = norm(r.get("tal")).lower()
        repo_base = norm(r.get("repo_base"))
        repo_host = norm(r.get("repo_host")).lower()

        tal = old_tal if valid_tal(old_tal) else None
        method = "original_tal"

        candidates = []

        if tal is None and repo_base in base_index:
            info = base_index[repo_base]
            tal = info["tal"]
            method = info["method"]
            candidates = info["candidates"]

        if tal is None and repo_host in host_index:
            info = host_index[repo_host]
            tal = info["tal"]
            method = info["method"]
            candidates = info["candidates"]

        if tal is None:
            still_null += 1
            r["tal"] = None
            r["tal_enrichment_method"] = "unresolved"
            r["tal_candidates"] = []
        else:
            if old_tal != tal:
                changed += 1
            r["tal"] = tal
            r["tal_enrichment_method"] = method
            r["tal_candidates"] = candidates or [tal]
            tal_dist[tal] += 1
            method_dist[method] += 1

        out_rows.append(r)

    write_jsonl(out_path, out_rows)

    summary_csv.parent.mkdir(parents=True, exist_ok=True)
    with summary_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["section", "value", "count"])
        for k, v in sorted(tal_dist.items()):
            w.writerow(["tal_distribution", k, v])
        for k, v in sorted(method_dist.items()):
            w.writerow(["tal_enrichment_method", k, v])
        w.writerow(["null_tal_count", "null", still_null])

    report = {
        "schema": "sec27.b3r2_l2b_tal_enrichment_report.v1",
        "status": "PASS" if input_rows > 0 else "FAIL_NO_INPUT",
        "input_l2b": str(l2b_path),
        "coverage": str(coverage_path),
        "output_l2b": str(out_path),
        "input_l2b_record_count": input_rows,
        "output_l2b_record_count": len(out_rows),
        "tal_enriched_record_count": changed,
        "null_tal_count": still_null,
        "tal_distribution": dict(tal_dist),
        "tal_enrichment_method_distribution": dict(method_dist),
        "coverage_record_count": indexes["coverage_record_count"],
        "coverage_record_with_tal_count": indexes["coverage_record_with_tal_count"],
        "coverage_base_tal_index_count": len(base_index),
        "coverage_host_tal_index_count": len(host_index),
        "summary_csv": str(summary_csv),
        "notes": [
            "TAL enrichment is derived from full B2B source_pp_coverage.jsonl.",
            "Exact repo_base match is preferred over repo_host fallback.",
            "This does not change evidence_level or causal_claim_allowed.",
            "This stage only enriches TAL for downstream TAL/PP/CA aggregation.",
        ],
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    print("status =", report["status"])
    print("input_l2b_record_count =", report["input_l2b_record_count"])
    print("output_l2b_record_count =", report["output_l2b_record_count"])
    print("tal_enriched_record_count =", report["tal_enriched_record_count"])
    print("null_tal_count =", report["null_tal_count"])
    print("tal_distribution =", report["tal_distribution"])
    print("tal_enrichment_method_distribution =", report["tal_enrichment_method_distribution"])
    print("WROTE", out_path)
    print("WROTE", report_path)
    print("WROTE", summary_csv)


if __name__ == "__main__":
    main()
