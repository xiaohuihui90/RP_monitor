#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_probe_summary(
    window_id: str,
    probe_id: str,
    cycle: dict[str, Any],
    validator_meta: dict[str, Any],
    mapping_context: dict[str, Any],
    quality_annotation: dict[str, Any],
) -> dict[str, Any]:
    probe_meta = {}
    all_probe_meta = validator_meta.get("probe_metadata")
    if isinstance(all_probe_meta, dict) and isinstance(all_probe_meta.get(probe_id), dict):
        probe_meta = all_probe_meta[probe_id]

    blockers = [
        "accepted_object_set_not_available",
        "validator_cache_view_observed_but_unstable",
        "validator_effective_input_not_reconstructed",
        "s3_observer_object_view_not_equal_validator_input",
    ]

    if quality_annotation.get("m17_window_quality", "").startswith("diagnostic_large_scale"):
        blockers.append("large_scale_diagnostic_window_requires_lifetime_analysis")

    return {
        "schema": "s3.m17.validator_effective_input_probe_summary.v1",
        "window_id": window_id,
        "probe_id": probe_id,

        "validator": cycle.get("validator") or probe_meta.get("validator") or "routinator",
        "validator_version": cycle.get("validator_version") or probe_meta.get("validator_version"),

        "validator_update_mode": cycle.get("validator_update_mode") or "noupdate",
        "validator_update_policy": cycle.get("validator_update_policy") or "observation_window_noupdate",

        "vrp_count": cycle.get("vrp_count"),
        "raw_vrp_size_bytes": cycle.get("raw_vrp_size_bytes"),
        "canonical_vrp_count": cycle.get("canonical_vrp_count"),
        "suspicious_low_count": cycle.get("suspicious_low_count"),
        "validation_output_quality": cycle.get("validation_output_quality"),

        "validator_cache_view_status": "observed_but_unstable",
        "accepted_object_set_available": False,
        "validator_cache_view_medium_eligible": False,

        "repository_status_available": False,
        "repository_count": None,
        "failed_repository_count": None,
        "stale_repository_count": None,
        "rsync_fallback_count": None,

        "cache_health": probe_meta.get("cache_health") or "unknown",
        "last_refresh_at_utc": probe_meta.get("last_successful_refresh_at_utc") or probe_meta.get("last_refresh_at_utc"),
        "refresh_age_sec": probe_meta.get("cache_age_sec"),

        "mapping_strength_candidate": "weak",
        "strong_causal_claim_allowed": False,
        "evidence_blockers": blockers,

        "semantic_note": (
            "This probe summary records validator-side context only. "
            "It does not represent Routinator's accepted object set."
        ),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--m245-history-root", default="data/p3_collector/m245_three_layer_baseline/history")
    ap.add_argument("--m17-root", default="data/p3_collector/m17_vrp_entry_diff/history")
    args = ap.parse_args()

    window_id = args.window_id
    m245_dir = Path(args.m245_history_root) / f"m245_window_{window_id}"
    m17_dir = Path(args.m17_root) / f"m17_window_{window_id}"
    out_dir = m17_dir / "outputs"

    cycle_records_path = out_dir / "validator_cycle_records.jsonl"
    cycle_summary_path = out_dir / "validator_cycle_summary.json"
    validator_meta_path = m245_dir / "outputs" / "validator_runtime_metadata.json"
    mapping_context_path = m245_dir / "outputs" / "M245_layer_mapping_context_h7_overlay.json"
    quality_path = out_dir / "M17_quality_annotation.json"

    cycle_records = read_jsonl(cycle_records_path)
    cycle_summary = read_json(cycle_summary_path)
    validator_meta = read_json(validator_meta_path)
    mapping_context = read_json(mapping_context_path)
    quality_annotation = read_json(quality_path)

    if not isinstance(cycle_summary, dict):
        cycle_summary = {}
    if not isinstance(validator_meta, dict):
        validator_meta = {}
    if not isinstance(mapping_context, dict):
        mapping_context = {}
    if not isinstance(quality_annotation, dict):
        quality_annotation = {}

    probe_summaries = {}
    for cycle in cycle_records:
        probe_id = cycle.get("probe_id")
        if not isinstance(probe_id, str):
            continue
        probe_summaries[probe_id] = build_probe_summary(
            window_id=window_id,
            probe_id=probe_id,
            cycle=cycle,
            validator_meta=validator_meta,
            mapping_context=mapping_context,
            quality_annotation=quality_annotation,
        )

    status = "PASS" if len(probe_summaries) >= 3 else "FAIL"

    summary = {
        "schema": "s3.m17.validator_effective_input_summary.v1",
        "generated_at_utc": utc_now(),
        "window_id": window_id,
        "status": status,

        "probe_count": len(probe_summaries),
        "probe_summaries": probe_summaries,

        "validator_cache_view_status": "observed_but_unstable",
        "accepted_object_set_available": False,
        "validator_cache_view_medium_eligible": False,
        "repository_status_available": False,

        "mapping_strength": "weak",
        "strong_causal_claim_allowed": False,

        "evidence_blockers": [
            "accepted_object_set_not_available",
            "validator_cache_view_observed_but_unstable",
            "validator_effective_input_not_reconstructed",
            "s3_l2a_observer_view_not_equal_l2b_validator_input",
        ],

        "source_files": {
            "validator_cycle_records": str(cycle_records_path),
            "validator_cycle_summary": str(cycle_summary_path),
            "validator_runtime_metadata": str(validator_meta_path),
            "mapping_context_h7_overlay": str(mapping_context_path),
            "quality_annotation": str(quality_path),
        },

        "semantic_note": (
            "This summary is the minimal L2-b validator-side context. "
            "It does not claim that Routinator cache equals accepted object set."
        ),
    }

    write_json(out_dir / "validator_effective_input_summary.json", summary)

    txt = [
        f"M17_VALIDATOR_EFFECTIVE_INPUT_SUMMARY={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"window_id = {window_id}",
        f"probe_count = {summary['probe_count']}",
        f"validator_cache_view_status = observed_but_unstable",
        f"accepted_object_set_available = False",
        f"validator_cache_view_medium_eligible = False",
        f"mapping_strength = weak",
        f"strong_causal_claim_allowed = False",
        f"summary_path = {out_dir / 'validator_effective_input_summary.json'}",
    ]

    (out_dir / "M17_validator_effective_input_summary_check.txt").write_text(
        "\n".join(txt) + "\n",
        encoding="utf-8",
    )

    print("\n".join(txt))


if __name__ == "__main__":
    main()
