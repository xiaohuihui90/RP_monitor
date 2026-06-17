#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.p3.m245.common.m245_jsonl import read_jsonl, write_jsonl, write_json


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def severity_for(layer: str, diff_type: str, matrix: dict[str, Any]) -> str:
    if layer == "validation_output":
        if diff_type in {"vrp_root", "vrp_count"}:
            return "high"
        return "medium"

    if layer == "object_view":
        if diff_type in {"object_set_root", "manifest_summary_root"}:
            return "high"
        return "medium"

    if layer == "advertised_view":
        if diff_type in {"notif_digest", "serial"}:
            return "medium"
        return "low"

    return "low"


def trigger_event_type(layer: str, diff_type: str) -> str:
    mapping = {
        ("advertised_view", "serial"): "advertised_view_serial_skew",
        ("advertised_view", "notif_digest"): "advertised_view_digest_divergence",
        ("object_view", "object_set_root"): "object_root_diff",
        ("object_view", "object_count"): "object_count_skew",
        ("object_view", "manifest_count"): "manifest_count_skew",
        ("object_view", "manifest_summary_root"): "manifest_summary_diff",
        ("validation_output", "vrp_count"): "vrp_count_skew",
        ("validation_output", "vrp_root"): "vrp_root_diff",
        ("validation_output", "validator_version"): "validator_context_diff",
        ("validation_output", "export_status"): "validation_output_export_status_diff",
    }
    return mapping.get((layer, diff_type), f"{layer}_{diff_type}_diff")


def trigger_strength(matrix: dict[str, Any]) -> str:
    run_mode = matrix.get("run_mode")
    tq = matrix.get("time_alignment_quality")
    comp = matrix.get("comparison_strength")

    if run_mode == "scheduled" and tq == "on_time" and comp == "strict_same_window":
        return "strict_same_window"

    if run_mode == "scheduled" and tq in {"on_time", "slightly_late"}:
        return "weak_same_window"

    return "diagnostic_only"


def strict_allowed(matrix: dict[str, Any]) -> bool:
    return trigger_strength(matrix) == "strict_same_window"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--collector-run-dir", required=True)
    ap.add_argument("--d2-records", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    collector_run_dir = Path(args.collector_run_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    matrix_path = collector_run_dir / "outputs" / "M245_three_layer_status_matrix.json"
    summary_path = collector_run_dir / "outputs" / "M245_window_summary.json"

    matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    window_summary = json.loads(summary_path.read_text(encoding="utf-8"))

    d2_records = list(read_jsonl(args.d2_records))

    strength = trigger_strength(matrix)
    allow_strict = strict_allowed(matrix)

    baseline_records = []
    trigger_records = []

    for i, r in enumerate(d2_records, 1):
        layer = r.get("layer")
        diff_type = r.get("diff_type")
        pp_id = r.get("pp_id")
        event_type = trigger_event_type(layer, diff_type)
        severity = severity_for(layer, diff_type, matrix)

        event_id = f"m245-{matrix.get('window_id')}-{i:04d}"

        baseline = {
            "schema": "s3.m245.baseline_diff_record.v1",
            "event_id": event_id,
            "window_id": matrix.get("window_id"),
            "created_at_utc": utc_now(),
            "run_mode": matrix.get("run_mode"),
            "time_alignment_quality": matrix.get("time_alignment_quality"),
            "comparison_strength": matrix.get("comparison_strength"),
            "strict_compare_allowed": allow_strict,

            "layer": layer,
            "pp_id": pp_id,
            "diff_type": event_type,
            "raw_diff_type": diff_type,
            "relation": r.get("relation"),
            "probe_values": r.get("probe_values"),

            "severity": severity,
            "m25_trigger_required": True,
            "trigger_strength": strength,
            "reason": r.get("reason"),
            "boundary": (
                "diagnostic_only trigger: useful for pipeline validation, "
                "not strict same-window anomaly evidence"
                if strength == "diagnostic_only"
                else "scheduled same-window trigger"
            ),
        }
        baseline_records.append(baseline)

        trigger = {
            "schema": "s3.m245.m25_trigger_candidate_record.v1",
            "trigger_id": f"m25_from_{event_id}",
            "window_id": matrix.get("window_id"),
            "created_at_utc": utc_now(),

            "trigger_source": "m245_three_layer_baseline",
            "trigger_layer": layer,
            "trigger_event_type": event_type,
            "event_id": event_id,
            "pp_id": pp_id,

            "probe_scope": matrix.get("probe_ids", []),
            "priority": "high" if severity == "high" else "medium",
            "severity": severity,
            "trigger_strength": strength,
            "strict_compare_allowed": allow_strict,

            "requires_source_uri_expansion": layer in {"object_view", "validation_output"},
            "requires_m25_attribution": True,
            "requires_m26_interface": layer == "validation_output",

            "input_window_summary": str(summary_path),
            "input_status_matrix": str(matrix_path),
            "input_diff_record": baseline,
            "boundary": baseline["boundary"],
        }
        trigger_records.append(trigger)

    baseline_path = collector_run_dir / "indexes" / "m245_baseline_diff_records.jsonl"
    trigger_path = collector_run_dir / "indexes" / "m25_trigger_candidate_records.jsonl"

    write_jsonl(baseline_path, baseline_records)
    write_jsonl(trigger_path, trigger_records)

    by_layer = {}
    by_strength = {}
    by_event_type = {}

    for r in baseline_records:
        by_layer[r["layer"]] = by_layer.get(r["layer"], 0) + 1
        by_strength[r["trigger_strength"]] = by_strength.get(r["trigger_strength"], 0) + 1
        by_event_type[r["diff_type"]] = by_event_type.get(r["diff_type"], 0) + 1

    status = "PASS" if baseline_records and trigger_records else "FAIL"

    summary = {
        "schema": "s3.m245.e.baseline_diff_trigger_summary.v1",
        "status": status,
        "created_at_utc": utc_now(),
        "window_id": matrix.get("window_id"),
        "run_mode": matrix.get("run_mode"),
        "time_alignment_quality": matrix.get("time_alignment_quality"),
        "comparison_strength": matrix.get("comparison_strength"),
        "strict_compare_allowed": allow_strict,
        "trigger_strength": strength,
        "baseline_diff_count": len(baseline_records),
        "m25_trigger_candidate_count": len(trigger_records),
        "by_layer": by_layer,
        "by_trigger_strength": by_strength,
        "by_event_type": by_event_type,
        "outputs": {
            "baseline_diff_records": str(baseline_path),
            "m25_trigger_candidate_records": str(trigger_path),
        },
    }

    write_json(out_dir / "M245_E_baseline_diff_trigger_summary.json", summary)

    with (out_dir / "M245_E_baseline_diff_trigger_check.txt").open("w", encoding="utf-8") as f:
        f.write(f"M245_E_BASELINE_DIFF_TRIGGER={status}\n\n")
        f.write(f"created_at_utc = {summary['created_at_utc']}\n")
        f.write(f"window_id = {summary['window_id']}\n")
        f.write(f"run_mode = {summary['run_mode']}\n")
        f.write(f"time_alignment_quality = {summary['time_alignment_quality']}\n")
        f.write(f"comparison_strength = {summary['comparison_strength']}\n")
        f.write(f"strict_compare_allowed = {summary['strict_compare_allowed']}\n")
        f.write(f"trigger_strength = {summary['trigger_strength']}\n")
        f.write(f"baseline_diff_count = {summary['baseline_diff_count']}\n")
        f.write(f"m25_trigger_candidate_count = {summary['m25_trigger_candidate_count']}\n")
        f.write(f"by_layer = {summary['by_layer']}\n")
        f.write(f"by_trigger_strength = {summary['by_trigger_strength']}\n")
        f.write(f"by_event_type = {summary['by_event_type']}\n")
        f.write(f"baseline_diff_records = {baseline_path}\n")
        f.write(f"m25_trigger_candidate_records = {trigger_path}\n")

    print(f"M245_E_STATUS={status}")
    print(f"M245_E_BASELINE_DIFF_RECORDS={baseline_path}")
    print(f"M245_E_M25_TRIGGER_CANDIDATES={trigger_path}")
    print(f"M245_E_CHECK={out_dir / 'M245_E_baseline_diff_trigger_check.txt'}")

    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
