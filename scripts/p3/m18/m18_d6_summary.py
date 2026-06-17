#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path, default=None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return default


def iter_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                yield {
                    "_parse_error": True,
                    "_line_no": line_no,
                    "_raw": line[:300],
                }


def count_jsonl(path: Path) -> int:
    n = 0
    for rec in iter_jsonl(path):
        if isinstance(rec, dict) and not rec.get("_parse_error"):
            n += 1
    return n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trailing-cache-json", required=True)
    ap.add_argument("--transient-persistent-json", required=True)
    ap.add_argument("--lifetime-json", required=True)
    ap.add_argument("--pair-lag-json", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    trailing_cache_path = Path(args.trailing_cache_json)
    transient_persistent_path = Path(args.transient_persistent_json)
    lifetime_path = Path(args.lifetime_json)
    pair_lag_path = Path(args.pair_lag_json)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_path = out_dir / "m18_d6_summary.json"
    check_path = out_dir / "M18_D6_SUMMARY_CHECK.txt"
    high_priority_path = out_dir / "M18_to_M19_high_priority_candidates.jsonl"
    v3_records_sample_path = out_dir / "M18_v3_records_sample.jsonl"

    trailing_cache = read_json(trailing_cache_path, {})
    transient_summary = read_json(transient_persistent_path, {})

    d2_summary = read_json(lifetime_path.parent / "m18_probewise_lifetime_summary.json", {})
    d3_summary = read_json(pair_lag_path.parent / "m18_probe_pair_lag_summary.json", {})

    counters = Counter()
    high_priority_count = 0
    normal_priority_count = 0
    low_priority_count = 0
    sample_written = 0

    # D5 summary counters are authoritative for classification counts.
    transient_counters = transient_summary.get("counters", {}) if isinstance(transient_summary, dict) else {}

    with high_priority_path.open("w", encoding="utf-8") as hp, \
         v3_records_sample_path.open("w", encoding="utf-8") as sample:
        for rec in iter_jsonl(out_dir.parent / "d5_transient_persistent" / "m18_transient_persistent_records.jsonl"):
            if not isinstance(rec, dict) or rec.get("_parse_error"):
                continue

            counters["d5_records_scanned"] += 1

            priority = rec.get("m19_mapping_priority")
            classification = rec.get("transient_or_persistent")
            if priority:
                counters[f"priority_{priority}"] += 1
            if classification:
                counters[f"classification_{classification}"] += 1

            if priority == "high":
                high_priority_count += 1
                hp.write(json.dumps({
                    "schema": "s3.m18.to_m19.high_priority_candidate.v1",
                    "vrp_key": rec.get("vrp_key"),
                    "tal": rec.get("tal"),
                    "prefix": rec.get("prefix"),
                    "asn": rec.get("asn"),
                    "maxLength": rec.get("maxLength"),
                    "transient_or_persistent": classification,
                    "m19_mapping_priority": priority,
                    "m19_mapping_reason": rec.get("m19_mapping_reason"),
                    "probe_seen_count": rec.get("probe_seen_count"),
                    "seen_probe_set": rec.get("seen_probe_set"),
                    "global_duration_windows": rec.get("global_duration_windows"),
                    "global_duration_seconds_approx": rec.get("global_duration_seconds_approx"),
                    "trailing_cache_candidate_v1": rec.get("trailing_cache_candidate_v1"),
                    "semantic_boundary": "candidate_for_mapping_not_causal_attribution",
                }, ensure_ascii=False, sort_keys=True) + "\n")
            elif priority == "normal":
                normal_priority_count += 1
            elif priority == "low":
                low_priority_count += 1

            if sample_written < 100:
                sample.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
                sample_written += 1

    lifetime_record_count = count_jsonl(lifetime_path)
    pair_lag_record_count = count_jsonl(pair_lag_path)

    trailing_counters = trailing_cache.get("counters", {}) if isinstance(trailing_cache, dict) else {}
    trailing_v1_summary = trailing_cache.get("trailing_v1_summary", {}) if isinstance(trailing_cache, dict) else {}

    summary = {
        "schema": "s3.m18.v3.deep_analysis_summary.v1",
        "generated_at_utc": utc_now(),

        "inputs": {
            "trailing_cache_json": str(trailing_cache_path),
            "transient_persistent_json": str(transient_persistent_path),
            "lifetime_json": str(lifetime_path),
            "pair_lag_json": str(pair_lag_path),
            "d2_summary_json": str(lifetime_path.parent / "m18_probewise_lifetime_summary.json"),
            "d3_summary_json": str(pair_lag_path.parent / "m18_probe_pair_lag_summary.json"),
        },

        "d2_probewise_lifetime": {
            "lifetime_record_count": lifetime_record_count,
            "summary": d2_summary,
        },

        "d3_probe_pair_lag": {
            "pair_lag_record_count": pair_lag_record_count,
            "summary": d3_summary,
        },

        "d4_trailing_cache": {
            "summary_records_written": trailing_cache.get("records_written") if isinstance(trailing_cache, dict) else None,
            "trailing_cache_v1_summary_count": len(trailing_v1_summary) if isinstance(trailing_v1_summary, dict) else 0,
            "counters": trailing_counters,
            "supported_or_confirmed_available": False,
            "missing_evidence_for_supported_or_confirmed": [
                "jsonext_source_uri",
                "repository_metrics",
                "cache_index",
                "same_input_replay",
            ],
        },

        "d5_dynamic_classification": {
            "summary_records_written": transient_summary.get("records_written") if isinstance(transient_summary, dict) else None,
            "pair_lag_record_count": transient_summary.get("pair_lag_record_count") if isinstance(transient_summary, dict) else None,
            "summary_counters": transient_counters,
            "streamed_counters": dict(counters),
        },

        "m19_candidate_export": {
            "high_priority_count": high_priority_count,
            "normal_priority_count": normal_priority_count,
            "low_priority_count": low_priority_count,
            "high_priority_candidates_jsonl": str(high_priority_path),
        },

        "outputs": {
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
            "high_priority_candidates_jsonl": str(high_priority_path),
            "v3_records_sample_jsonl": str(v3_records_sample_path),
        },

        "semantic_boundary": "candidate_level_analysis_not_causal_attribution",
        "strong_causal_claim_allowed": False,
        "next_stage": "M19_ROA_TO_VRP_MAPPING_PRECHECK",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M18_D6_SUMMARY=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"lifetime_record_count = {lifetime_record_count}",
        f"pair_lag_record_count = {pair_lag_record_count}",
        f"d5_records_scanned = {counters['d5_records_scanned']}",
        f"high_priority_count = {high_priority_count}",
        f"normal_priority_count = {normal_priority_count}",
        f"low_priority_count = {low_priority_count}",
        f"trailing_cache_v1_summary_count = {len(trailing_v1_summary) if isinstance(trailing_v1_summary, dict) else 0}",
        f"classification_not_observed_in_canonical = {transient_counters.get('classification_not_observed_in_canonical')}",
        f"classification_transient_temporal_skew_candidate = {transient_counters.get('classification_transient_temporal_skew_candidate')}",
        f"classification_persistent_divergence_candidate_v1 = {transient_counters.get('classification_persistent_divergence_candidate_v1')}",
        f"classification_persistent_or_large_lag_candidate_v1 = {transient_counters.get('classification_persistent_or_large_lag_candidate_v1')}",
        f"summary_json = {summary_path}",
        f"high_priority_candidates_jsonl = {high_priority_path}",
        f"v3_records_sample_jsonl = {v3_records_sample_path}",
        "semantic_boundary = candidate_level_analysis_not_causal_attribution",
        "strong_causal_claim_allowed = False",
        "next_stage = M19_ROA_TO_VRP_MAPPING_PRECHECK",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state = Path("data/p3_collector/m18_deep_analysis/state/current_m18_d6_run.env")
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(
        "\n".join([
            f'export M18_D6_OUT_DIR="{out_dir}"',
            f'export M18_D6_SUMMARY="{summary_path}"',
            f'export M18_D6_CHECK="{check_path}"',
            f'export M18_D6_HIGH_PRIORITY_CANDIDATES="{high_priority_path}"',
            "",
        ]),
        encoding="utf-8",
    )

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
