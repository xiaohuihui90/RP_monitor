#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def iter_jsonl(path: Path):
    if not path.exists():
        return
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


def top_counter_rows(counter: Counter, key_name: str, n: int = 30) -> list[dict[str, Any]]:
    rows = []
    for k, c in counter.most_common(n):
        rows.append({
            key_name: k,
            "count": c,
        })
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", required=True)
    ap.add_argument("--check-dir", required=True)
    ap.add_argument("--report-dir", required=True)
    args = ap.parse_args()

    input_dir = Path(args.input_dir)
    check_dir = Path(args.check_dir)
    report_dir = Path(args.report_dir)

    check_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    lifetime_path = input_dir / "vrp_diff_lifetime_records.jsonl"
    persistent_path = input_dir / "persistent_divergence_candidates.jsonl"
    trailing_path = input_dir / "trailing_cache_candidates.jsonl"
    m19_path = input_dir / "m19_mapping_candidates.jsonl"
    lifetime_summary_path = input_dir / "m18_lifetime_tracker_summary.json"

    lifetime_records = list(iter_jsonl(lifetime_path))
    persistent_records = list(iter_jsonl(persistent_path))
    trailing_records = list(iter_jsonl(trailing_path))
    m19_records = list(iter_jsonl(m19_path))

    lifetime_summary = read_json(lifetime_summary_path) if lifetime_summary_path.exists() else {}

    temporal_counter = Counter()
    event_counter = Counter()
    tal_counter = Counter()
    asn_counter = Counter()
    prefix_counter = Counter()
    probe_pair_counter = Counter()

    event_temporal_counter = defaultdict(Counter)
    tal_temporal_counter = defaultdict(Counter)

    duration_by_class = defaultdict(list)
    duration_by_event = defaultdict(list)

    for r in lifetime_records:
        temporal_class = r.get("temporal_class") or "unknown"
        event_type = r.get("event_type") or "unknown"
        tal = r.get("tal") or "unknown"
        asn = str(r.get("asn") or "unknown")
        prefix = r.get("prefix") or "unknown"
        probe_pair = r.get("probe_pair") or "unknown|unknown"
        dur_upper = int(r.get("duration_upper_bound_minutes") or 0)

        temporal_counter[temporal_class] += 1
        event_counter[event_type] += 1
        tal_counter[tal] += 1
        asn_counter[asn] += 1
        prefix_counter[prefix] += 1
        probe_pair_counter[probe_pair] += 1

        event_temporal_counter[event_type][temporal_class] += 1
        tal_temporal_counter[tal][temporal_class] += 1

        duration_by_class[temporal_class].append(dur_upper)
        duration_by_event[event_type].append(dur_upper)

    def duration_stats(vals: list[int]) -> dict[str, Any]:
        if not vals:
            return {"count": 0}
        vals = sorted(vals)
        n = len(vals)
        return {
            "count": n,
            "min": vals[0],
            "p50": vals[n // 2],
            "p90": vals[int(n * 0.9) if int(n * 0.9) < n else n - 1],
            "max": vals[-1],
        }

    event_type_summary = {}
    for event_type, c in event_counter.items():
        event_type_summary[event_type] = {
            "record_count": c,
            "temporal_class_counts": dict(event_temporal_counter[event_type]),
            "duration_upper_bound_minutes": duration_stats(duration_by_event[event_type]),
        }

    temporal_class_summary = {}
    for cls, c in temporal_counter.items():
        temporal_class_summary[cls] = {
            "record_count": c,
            "duration_upper_bound_minutes": duration_stats(duration_by_class[cls]),
        }

    top_repeated_asn = top_counter_rows(asn_counter, "asn", 30)
    top_repeated_prefix = top_counter_rows(prefix_counter, "prefix", 30)
    top_repeated_tal = top_counter_rows(tal_counter, "tal", 30)
    top_probe_pair = top_counter_rows(probe_pair_counter, "probe_pair", 20)

    large_scale_timeline = lifetime_summary.get("large_scale_event_timeline", [])

    report = {
        "schema": "s3.m18.convergence_baseline_report.v1",
        "generated_at_utc": utc_now(),
        "input_dir": str(input_dir),

        "window_count": lifetime_summary.get("window_count"),
        "merged_seed_record_count": lifetime_summary.get("merged_seed_record_count"),
        "diff_lifetime_record_count": len(lifetime_records),

        "persistent_candidate_count": len(persistent_records),
        "trailing_cache_candidate_count": len(trailing_records),
        "m19_candidate_count": len(m19_records),

        "temporal_class_counts": dict(temporal_counter),
        "event_type_counts": dict(event_counter),

        "temporal_class_summary": temporal_class_summary,
        "event_type_summary": event_type_summary,

        "top_repeated_tal": top_repeated_tal,
        "top_repeated_asn": top_repeated_asn,
        "top_repeated_prefix": top_repeated_prefix,
        "top_probe_pair": top_probe_pair,

        "large_scale_event_timeline": large_scale_timeline,

        "m19_candidate_selector_version": lifetime_summary.get("m19_candidate_selector_version"),
        "m19_candidate_priority_counts": lifetime_summary.get("m19_candidate_priority_counts"),

        "interpretation": {
            "note": (
                "This is a coarse M18-lite convergence baseline based on available scheduled-lite windows. "
                "Duration estimates are bounded by the sampling interval and should not be interpreted as precise minute-level convergence times."
            ),
            "m18_role": (
                "M18 filters M17 VRP entry-level differences into temporal classes and selects high-value M19 mapping candidates."
            ),
        },

        "semantic_boundary": {
            "mapping_strength": "weak",
            "strong_causal_claim_allowed": False,
            "accepted_object_set_available": False,
        },
    }

    write_json(input_dir / "convergence_baseline_report.json", report)
    write_json(report_dir / "latest_convergence_baseline_report.json", report)

    write_csv(report_dir / "top_repeated_asn.csv", top_repeated_asn, ["asn", "count"])
    write_csv(report_dir / "top_repeated_prefix.csv", top_repeated_prefix, ["prefix", "count"])
    write_csv(report_dir / "top_repeated_tal.csv", top_repeated_tal, ["tal", "count"])
    write_csv(report_dir / "top_probe_pair.csv", top_probe_pair, ["probe_pair", "count"])

    md = []
    md.append("# M18 Convergence Baseline Report")
    md.append("")
    md.append(f"generated_at_utc: `{report['generated_at_utc']}`")
    md.append("")
    md.append("## Summary")
    md.append("")
    for k in [
        "window_count",
        "merged_seed_record_count",
        "diff_lifetime_record_count",
        "persistent_candidate_count",
        "trailing_cache_candidate_count",
        "m19_candidate_count",
    ]:
        md.append(f"- {k}: `{report.get(k)}`")

    md.append("")
    md.append("## Temporal classes")
    md.append("")
    for k, v in sorted(report["temporal_class_counts"].items(), key=lambda x: x[0]):
        md.append(f"- {k}: `{v}`")

    md.append("")
    md.append("## Event types")
    md.append("")
    for k, v in sorted(report["event_type_counts"].items(), key=lambda x: x[0]):
        md.append(f"- {k}: `{v}`")

    md.append("")
    md.append("## Top TAL")
    md.append("")
    for r in top_repeated_tal[:10]:
        md.append(f"- {r['tal']}: `{r['count']}`")

    md.append("")
    md.append("## Top ASN")
    md.append("")
    for r in top_repeated_asn[:10]:
        md.append(f"- AS{r['asn']}: `{r['count']}`")

    md.append("")
    md.append("## Top Prefix")
    md.append("")
    for r in top_repeated_prefix[:10]:
        md.append(f"- {r['prefix']}: `{r['count']}`")

    md.append("")
    md.append("## Large-scale event timeline")
    md.append("")
    for item in large_scale_timeline:
        md.append(f"- `{item.get('window_id')}`: {item.get('m17_window_quality')}")

    md.append("")
    md.append("## Semantic boundary")
    md.append("")
    md.append(
        "This report describes temporal behavior of VRP entry-level differences. "
        "It does not claim object-layer causality, validator implementation divergence, "
        "or equality between Routinator cache and accepted object set."
    )
    md.append("")
    md.append("## Next stage")
    md.append("")
    md.append(
        "Use `m19_mapping_candidates.jsonl` as the scoped input for M19 ROA-to-VRP mapping. "
        "Do not map all single-window large-scale diff records by default."
    )
    md.append("")

    (input_dir / "convergence_baseline_report.md").write_text("\n".join(md), encoding="utf-8")
    (report_dir / "latest_convergence_baseline_report.md").write_text("\n".join(md), encoding="utf-8")

    txt = [
        "M18_CONVERGENCE_REPORT=PASS",
        f"generated_at_utc = {report['generated_at_utc']}",
        f"window_count = {report.get('window_count')}",
        f"diff_lifetime_record_count = {len(lifetime_records)}",
        f"persistent_candidate_count = {len(persistent_records)}",
        f"trailing_cache_candidate_count = {len(trailing_records)}",
        f"m19_candidate_count = {len(m19_records)}",
        f"mapping_strength = weak",
        f"strong_causal_claim_allowed = False",
        f"report_json = {input_dir / 'convergence_baseline_report.json'}",
        f"report_md = {input_dir / 'convergence_baseline_report.md'}",
    ]

    check_path = check_dir / "M18_CONVERGENCE_REPORT_CHECK.txt"
    check_path.write_text("\n".join(txt) + "\n", encoding="utf-8")

    print("\n".join(txt))


if __name__ == "__main__":
    main()

from scripts.p3.m18.m18_d2_probewise_lifetime import attach_control_plane_impact

def m18_with_impact(records):

    records = attach_control_plane_impact(records)

    impact = sum(1 for r in records if r.get("control_plane_impact"))

    print("[M18 IMPACT]", impact)

    return records

