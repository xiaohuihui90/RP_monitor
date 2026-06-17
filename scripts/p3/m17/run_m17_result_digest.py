#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in fields})


def top_counter(counter: Counter, top_n: int) -> list[dict[str, Any]]:
    rows = []
    for key, count in counter.most_common(top_n):
        rows.append({
            "key": key,
            "diff_count": count,
        })
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--m17-window-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--top-n", type=int, default=30)
    args = ap.parse_args()

    window_dir = Path(args.m17_window_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_path = window_dir / "outputs" / "vrp_entry_diff_summary.json"
    diff_path = window_dir / "outputs" / "vrp_entry_diff_records.jsonl"
    pair_path = window_dir / "outputs" / "pairwise_diff_summary.json"
    vote_path = window_dir / "outputs" / "vrp_vote_profile_summary.json"

    summary = read_json(summary_path)
    pair_summary = read_json(pair_path) if pair_path.exists() else {}
    vote_summary = read_json(vote_path) if vote_path.exists() else {}

    prefix_counter: Counter[str] = Counter()
    asn_counter: Counter[str] = Counter()
    tal_counter: Counter[str] = Counter()
    pair_counter: Counter[str] = Counter()
    event_counter: Counter[str] = Counter()

    prefix_pair_counter: dict[str, Counter[str]] = defaultdict(Counter)
    asn_pair_counter: dict[str, Counter[str]] = defaultdict(Counter)
    tal_pair_counter: dict[str, Counter[str]] = defaultdict(Counter)

    changed_records: list[dict[str, Any]] = []
    sample_records: list[dict[str, Any]] = []

    single_probe_candidate_counter: Counter[str] = Counter()

    total_records = 0

    for r in iter_jsonl(diff_path):
        total_records += 1

        pair = str(r.get("probe_pair"))
        event = str(r.get("event_type"))
        vrp = r.get("vrp", {}) if isinstance(r.get("vrp"), dict) else {}

        prefix = str(vrp.get("prefix"))
        asn = str(vrp.get("asn"))
        tal = str(vrp.get("tal"))

        prefix_counter[prefix] += 1
        asn_counter[asn] += 1
        tal_counter[tal] += 1
        pair_counter[pair] += 1
        event_counter[event] += 1

        prefix_pair_counter[prefix][pair] += 1
        asn_pair_counter[asn][pair] += 1
        tal_pair_counter[tal][pair] += 1

        # A lightweight heuristic:
        # if event appears in a pair involving probe-sg frequently, it may be a probe-sg outlier candidate.
        if "probe-sg" in pair:
            single_probe_candidate_counter["probe-sg_related"] += 1
        if "probe-bj" in pair:
            single_probe_candidate_counter["probe-bj_related"] += 1
        if "probe-cd" in pair:
            single_probe_candidate_counter["probe-cd_related"] += 1

        if r.get("diff_type") == "changed" or event == "modified":
            changed_records.append(r)

        if len(sample_records) < 20:
            sample_records.append(r)

    top_prefix = []
    for prefix, count in prefix_counter.most_common(args.top_n):
        top_prefix.append({
            "prefix": prefix,
            "diff_count": count,
            "pair_breakdown": dict(prefix_pair_counter[prefix]),
        })

    top_asn = []
    for asn, count in asn_counter.most_common(args.top_n):
        top_asn.append({
            "asn": asn,
            "diff_count": count,
            "pair_breakdown": dict(asn_pair_counter[asn]),
        })

    top_tal = []
    for tal, count in tal_counter.most_common(args.top_n):
        top_tal.append({
            "tal": tal,
            "diff_count": count,
            "pair_breakdown": dict(tal_pair_counter[tal]),
        })

    digest = {
        "schema": "s3.m17.result_digest.v1",
        "window_id": summary.get("window_id"),
        "m17_window_dir": str(window_dir),
        "total_diff_records": total_records,
        "summary_core": {
            "total_added_vrps": summary.get("total_added_vrps"),
            "total_removed_vrps": summary.get("total_removed_vrps"),
            "total_changed_vrps": summary.get("total_changed_vrps"),
            "affected_prefix_count": summary.get("affected_prefix_count"),
            "affected_asn_count": summary.get("affected_asn_count"),
            "affected_tal_count": summary.get("affected_tal_count"),
            "mapping_strength": summary.get("mapping_strength"),
            "strong_causal_claim_allowed": summary.get("strong_causal_claim_allowed"),
        },
        "event_counter": dict(event_counter),
        "pair_counter": dict(pair_counter),
        "tal_counter": dict(tal_counter),
        "top_prefix": top_prefix,
        "top_asn": top_asn,
        "top_tal": top_tal,
        "changed_record_count": len(changed_records),
        "changed_records_sample": changed_records[:50],
        "sample_records": sample_records,
        "pair_summary": pair_summary.get("pair_summaries", {}),
        "vote_summary": vote_summary,
        "interpretation_notes": [
            "This digest describes VRP entry-level differences only.",
            "source_uri / roa_uri are unavailable in current Routinator JSON output, so ROA/Manifest/PP mapping is deferred to M19/M20.",
            "Mapping strength remains weak.",
            "No high-confidence causal attribution is made.",
        ],
    }

    write_json(out_dir / "M17_result_digest.json", digest)

    write_csv(
        out_dir / "top_affected_prefix.csv",
        top_prefix,
        ["prefix", "diff_count", "pair_breakdown"],
    )

    write_csv(
        out_dir / "top_affected_asn.csv",
        top_asn,
        ["asn", "diff_count", "pair_breakdown"],
    )

    write_csv(
        out_dir / "top_diff_by_tal.csv",
        top_tal,
        ["tal", "diff_count", "pair_breakdown"],
    )

    write_json(out_dir / "changed_vrp_records_sample.json", changed_records[:100])

    md = []
    md.append(f"# M17 Result Digest: {summary.get('window_id')}")
    md.append("")
    md.append("## Core metrics")
    md.append("")
    md.append(f"- total_diff_records: `{total_records}`")
    md.append(f"- total_added_vrps: `{summary.get('total_added_vrps')}`")
    md.append(f"- total_removed_vrps: `{summary.get('total_removed_vrps')}`")
    md.append(f"- total_changed_vrps: `{summary.get('total_changed_vrps')}`")
    md.append(f"- affected_prefix_count: `{summary.get('affected_prefix_count')}`")
    md.append(f"- affected_asn_count: `{summary.get('affected_asn_count')}`")
    md.append(f"- affected_tal_count: `{summary.get('affected_tal_count')}`")
    md.append(f"- mapping_strength: `{summary.get('mapping_strength')}`")
    md.append("")
    md.append("## Pairwise scale")
    md.append("")
    for pair, info in pair_summary.get("pair_summaries", {}).items():
        md.append(
            f"- `{pair}`: added={info.get('added_vrps')}, "
            f"removed={info.get('removed_vrps')}, "
            f"changed={info.get('changed_vrps')}, "
            f"affected_prefix={info.get('affected_prefix_count')}, "
            f"affected_asn={info.get('affected_asn_count')}"
        )
    md.append("")
    md.append("## Diff by TAL")
    md.append("")
    for tal, info in summary.get("diff_by_tal", {}).items():
        md.append(
            f"- `{tal}`: added={info.get('added_count')}, "
            f"removed={info.get('removed_count')}, "
            f"changed={info.get('changed_count')}, "
            f"affected_prefix={info.get('affected_prefix_count')}, "
            f"affected_asn={info.get('affected_asn_count')}"
        )
    md.append("")
    md.append("## Top affected prefixes")
    md.append("")
    for row in top_prefix[:10]:
        md.append(f"- `{row['prefix']}`: {row['diff_count']} diffs, pairs={row['pair_breakdown']}")
    md.append("")
    md.append("## Top affected ASNs")
    md.append("")
    for row in top_asn[:10]:
        md.append(f"- `AS{row['asn']}`: {row['diff_count']} diffs, pairs={row['pair_breakdown']}")
    md.append("")
    md.append("## Changed VRP records")
    md.append("")
    md.append(f"- changed_record_count: `{len(changed_records)}`")
    md.append("")
    md.append("## Semantic boundary")
    md.append("")
    md.append("This digest does not claim object-layer causality, specific ROA causality, validator implementation divergence, or BGP control-plane impact. It only reports VRP entry-level differences.")
    md.append("")

    (out_dir / "M17_result_digest.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print("M17_RESULT_DIGEST=PASS")
    print(f"window_id = {summary.get('window_id')}")
    print(f"total_diff_records = {total_records}")
    print(f"changed_record_count = {len(changed_records)}")
    print(f"out_dir = {out_dir}")


if __name__ == "__main__":
    main()
