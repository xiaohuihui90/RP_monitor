#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--m17-root", default="data/p3_collector/m17_vrp_entry_diff/history")
    ap.add_argument("--m245-root", default="data/p3_collector/m245_three_layer_baseline/history")
    args = ap.parse_args()

    window_id = args.window_id
    m17_dir = Path(args.m17_root) / f"m17_window_{window_id}"
    m245_dir = Path(args.m245_root) / f"m245_window_{window_id}"

    summary = read_json(m17_dir / "outputs" / "vrp_entry_diff_summary.json")
    pairwise = read_json(m17_dir / "outputs" / "pairwise_diff_summary.json")
    validator_meta = read_json(m245_dir / "outputs" / "validator_runtime_metadata.json")

    pair_summaries = pairwise.get("pair_summaries", {})
    canonical_counts = summary.get("canonical_counts_by_probe", {})

    counts = {
        p: int(v)
        for p, v in canonical_counts.items()
        if isinstance(v, int)
    }

    max_count = max(counts.values()) if counts else 0
    min_count = min(counts.values()) if counts else 0
    count_gap = max_count - min_count

    low_probe = None
    if counts:
        low_probe = min(counts, key=lambda p: counts[p])

    probe_pair_large_drop = []
    for pair, info in pair_summaries.items():
        removed = int(info.get("removed_vrps") or 0)
        added = int(info.get("added_vrps") or 0)
        changed = int(info.get("changed_vrps") or 0)
        affected_prefix = int(info.get("affected_prefix_count") or 0)
        affected_asn = int(info.get("affected_asn_count") or 0)

        if removed >= 10000 or affected_prefix >= 10000 or affected_asn >= 1000:
            probe_pair_large_drop.append({
                "probe_pair": pair,
                "added_vrps": added,
                "removed_vrps": removed,
                "changed_vrps": changed,
                "affected_prefix_count": affected_prefix,
                "affected_asn_count": affected_asn,
            })

    tal_large = []
    for tal, info in summary.get("diff_by_tal", {}).items():
        removed = int(info.get("removed_count") or 0)
        added = int(info.get("added_count") or 0)
        changed = int(info.get("changed_count") or 0)
        affected_prefix = int(info.get("affected_prefix_count") or 0)
        affected_asn = int(info.get("affected_asn_count") or 0)

        if removed >= 1000 or affected_prefix >= 1000 or affected_asn >= 500:
            tal_large.append({
                "tal": tal,
                "added_count": added,
                "removed_count": removed,
                "changed_count": changed,
                "affected_prefix_count": affected_prefix,
                "affected_asn_count": affected_asn,
            })

    probe_meta_brief = {}
    for probe, meta in sorted((validator_meta.get("probe_metadata") or {}).items()):
        probe_meta_brief[probe] = {
            "vrp_count": meta.get("vrp_count"),
            "raw_vrp_vrp_count_guess": meta.get("raw_vrp_vrp_count_guess"),
            "suspicious_low_count": meta.get("suspicious_low_count"),
            "validation_output_quality": meta.get("validation_output_quality"),
            "validator_update_mode": meta.get("validator_update_mode"),
            "metadata_quality": meta.get("metadata_quality"),
        }

    quality_flags = []

    if count_gap >= 10000:
        quality_flags.append("large_cross_probe_vrp_count_gap")

    if low_probe:
        quality_flags.append(f"lowest_vrp_count_probe:{low_probe}")

    if any("probe-sg" in x["probe_pair"] for x in probe_pair_large_drop):
        quality_flags.append("probe_sg_related_large_entry_diff")

    if tal_large:
        quality_flags.append("large_tal_level_diff")

    if summary.get("total_diff_records", 0) >= 10000:
        quality_flags.append("large_scale_vrp_entry_diff")

    if not quality_flags:
        quality = "normal_entry_diff_window"
    elif "probe_sg_related_large_entry_diff" in quality_flags:
        quality = "diagnostic_large_scale_probe_sg_drop_candidate"
    else:
        quality = "diagnostic_large_scale_vrp_diff_candidate"

    annotation = {
        "schema": "s3.m17.quality_annotation.v1",
        "generated_at_utc": utc_now(),
        "window_id": window_id,
        "m17_window_dir": str(m17_dir),
        "m245_window_dir": str(m245_dir),

        "m17_window_quality": quality,
        "quality_flags": quality_flags,

        "canonical_counts_by_probe": counts,
        "max_canonical_count": max_count,
        "min_canonical_count": min_count,
        "canonical_count_gap": count_gap,
        "lowest_vrp_count_probe": low_probe,

        "total_diff_records": summary.get("total_diff_records"),
        "total_added_vrps": summary.get("total_added_vrps"),
        "total_removed_vrps": summary.get("total_removed_vrps"),
        "total_changed_vrps": summary.get("total_changed_vrps"),
        "affected_prefix_count": summary.get("affected_prefix_count"),
        "affected_asn_count": summary.get("affected_asn_count"),

        "large_probe_pair_diffs": probe_pair_large_drop,
        "large_tal_diffs": tal_large,

        "validator_metadata_by_probe": probe_meta_brief,

        "mapping_strength": "weak",
        "strong_causal_claim_allowed": False,
        "allowed_claims": [
            "large_scale_vrp_entry_difference_observed",
            "probe_pair_entry_diff_scale_reported",
            "affected_prefix_and_asn_identified",
            "diagnostic_window_quality_annotation",
        ],
        "disallowed_claims": [
            "probe_sg_failure_confirmed",
            "object_layer_caused_vrp_drop",
            "specific_roa_caused_vrp_diff",
            "publication_point_caused_vrp_diff",
            "validator_implementation_divergence",
            "high_confidence_attribution",
        ],
        "recommended_next_actions": [
            "include_in_daily_report_as_diagnostic_large_scale_window",
            "run_m18_lifetime_tracking",
            "prioritize_changed_vrp_and_top_tal_clusters_for_m19_mapping",
            "avoid_strong_causal_claim_until_mapping_and_replay",
        ],
        "semantic_note": (
            "This annotation marks large-scale VRP entry divergence observed in this window. "
            "It does not prove probe failure, object-layer causality, specific ROA causality, "
            "or validator implementation divergence."
        ),
    }

    out_path = m17_dir / "outputs" / "M17_quality_annotation.json"
    write_json(out_path, annotation)

    txt = [
        f"M17_QUALITY_ANNOTATION=PASS",
        f"generated_at_utc = {annotation['generated_at_utc']}",
        f"window_id = {window_id}",
        f"m17_window_quality = {quality}",
        f"quality_flags = {quality_flags}",
        f"canonical_count_gap = {count_gap}",
        f"lowest_vrp_count_probe = {low_probe}",
        f"total_diff_records = {summary.get('total_diff_records')}",
        f"affected_prefix_count = {summary.get('affected_prefix_count')}",
        f"affected_asn_count = {summary.get('affected_asn_count')}",
        f"strong_causal_claim_allowed = False",
        f"annotation_path = {out_path}",
    ]

    txt_path = m17_dir / "outputs" / "M17_quality_annotation.txt"
    txt_path.write_text("\n".join(txt) + "\n", encoding="utf-8")

    print("\n".join(txt))


if __name__ == "__main__":
    main()
