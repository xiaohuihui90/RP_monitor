#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def write_jsonl(path: Path, rows: list[dict]):
    with path.open("w", encoding="utf-8") as w:
        for r in rows:
            w.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict], fields: list[str]):
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-jsonl", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    seed = Path(args.seed_jsonl)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    rows = []
    tal = Counter()
    afi = Counter()
    asn = Counter()
    prefix = Counter()
    maxlen = Counter()
    probe_seen = Counter()
    duration_windows = Counter()
    duration_seconds_bucket = Counter()

    for o in iter_jsonl(seed):
        r = {
            "schema": "s3.m22d.tal_stratified_roa_mapping_input.v1",
            "vrp_key": o.get("vrp_key"),
            "afi": o.get("afi"),
            "tal": o.get("tal"),
            "prefix": o.get("prefix"),
            "asn": o.get("asn"),
            "maxLength": o.get("maxLength"),
            "global_duration_windows": o.get("global_duration_windows"),
            "global_duration_seconds_approx": o.get("global_duration_seconds_approx"),
            "probe_seen_count": o.get("probe_seen_count"),
            "seen_probe_set": o.get("seen_probe_set"),
            "transient_or_persistent": o.get("transient_or_persistent"),
            "trailing_cache_candidate_v1": o.get("trailing_cache_candidate_v1"),
            "m22c_score": o.get("m22c_score"),
            "source_file": o.get("source_file"),
            "semantic_boundary": "tal_stratified_seed_for_roa_mapping_not_yet_attributed",
        }
        rows.append(r)

        tal[r["tal"]] += 1
        afi[r["afi"]] += 1
        asn[r["asn"]] += 1
        prefix[r["prefix"]] += 1
        maxlen[str(r["maxLength"])] += 1
        probe_seen[str(r["probe_seen_count"])] += 1
        duration_windows[str(r["global_duration_windows"])] += 1

        try:
            sec = float(r["global_duration_seconds_approx"] or 0)
            if sec >= 7 * 24 * 3600:
                b = ">=7d"
            elif sec >= 24 * 3600:
                b = "1d-7d"
            elif sec >= 3600:
                b = "1h-1d"
            else:
                b = "<1h"
        except Exception:
            b = "unknown"
        duration_seconds_bucket[b] += 1

    input_jsonl = out / "m22d_tal_stratified_roa_mapping_input.jsonl"
    input_csv = out / "m22d_tal_stratified_roa_mapping_input.csv"
    summary_json = out / "m22d_tal_stratified_roa_mapping_precheck_summary.json"
    summary_md = out / "m22d_tal_stratified_roa_mapping_precheck_summary.md"
    check_txt = out / "M22D_TAL_STRATIFIED_ROA_MAPPING_PRECHECK.txt"

    write_jsonl(input_jsonl, rows)
    write_csv(input_csv, rows, [
        "vrp_key", "afi", "tal", "prefix", "asn", "maxLength",
        "global_duration_windows", "global_duration_seconds_approx",
        "probe_seen_count", "seen_probe_set",
        "transient_or_persistent", "trailing_cache_candidate_v1",
        "m22c_score", "source_file", "semantic_boundary",
    ])

    summary = {
        "schema": "s3.m22d.tal_stratified_roa_mapping_precheck_summary.v1",
        "generated_at_utc": utc_now(),
        "seed_jsonl": str(seed),
        "record_count": len(rows),
        "tal_distribution": tal.most_common(),
        "afi_distribution": afi.most_common(),
        "asn_top20": asn.most_common(20),
        "prefix_top20": prefix.most_common(20),
        "maxLength_top20": maxlen.most_common(20),
        "probe_seen_count": probe_seen.most_common(),
        "duration_windows": duration_windows.most_common(),
        "duration_seconds_bucket": duration_seconds_bucket.most_common(),
        "outputs": {
            "input_jsonl": str(input_jsonl),
            "input_csv": str(input_csv),
            "summary_json": str(summary_json),
            "summary_md": str(summary_md),
        },
        "interpretation": {
            "purpose": "Prepare TAL-stratified persistent candidates for subsequent JSONEXT/ROA source mapping.",
            "next": "Run M19-like JSONEXT source bridge on this input, then M21 manifest mapping for successfully mapped candidates.",
        },
        "semantic_boundary": "precheck_only_no_roa_mapping_executed",
    }

    summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    md = []
    md.append("# M22D TAL-stratified ROA Mapping Precheck")
    md.append("")
    md.append(f"- record_count: `{len(rows)}`")
    md.append(f"- TAL distribution: `{tal.most_common()}`")
    md.append(f"- AFI distribution: `{afi.most_common()}`")
    md.append(f"- maxLength top20: `{maxlen.most_common(20)}`")
    md.append(f"- probe_seen_count: `{probe_seen.most_common()}`")
    md.append(f"- duration_windows: `{duration_windows.most_common()}`")
    md.append(f"- duration_seconds_bucket: `{duration_seconds_bucket.most_common()}`")
    md.append("")
    md.append("## Interpretation")
    md.append("- This precheck only prepares input for ROA-level mapping.")
    md.append("- No ROA URI / manifest URI has been mapped at this stage.")
    md.append("- Next stage should reuse or generalize the M19 JSONEXT source bridge for this TAL-stratified input.")
    summary_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    check_txt.write_text(
        "\n".join([
            "M22D_TAL_STRATIFIED_ROA_MAPPING_PRECHECK=PASS",
            f"generated_at_utc = {summary['generated_at_utc']}",
            f"record_count = {len(rows)}",
            f"tal_distribution = {tal.most_common()}",
            f"input_jsonl = {input_jsonl}",
            f"input_csv = {input_csv}",
            f"summary_json = {summary_json}",
            f"summary_md = {summary_md}",
            "semantic_boundary = precheck_only_no_roa_mapping_executed",
            "next_stage = M22E_JSONEXT_SOURCE_BRIDGE_FOR_TAL_STRATIFIED_SAMPLE",
            "",
        ]),
        encoding="utf-8",
    )

    print(check_txt.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
