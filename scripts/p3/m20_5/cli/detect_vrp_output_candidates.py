#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return len(rows)


def make_candidate_id(window_id: str, anomaly_type: str) -> str:
    h = hashlib.sha256(f"{window_id}|{anomaly_type}".encode("utf-8")).hexdigest()[:16]
    return f"voutcand_{h}"


def severity_for_window(window_mapping_level: str, anomaly_type: str) -> str:
    if anomaly_type == "V5_VALIDATOR_EXPORT_FAILURE":
        return "warning"

    if anomaly_type == "V6_VALIDATOR_VERSION_MISMATCH":
        return "warning"

    if window_mapping_level == "strong":
        return "warning"

    if window_mapping_level in {"weak", "partial"}:
        return "info"

    return "info"


def confidence_for_window(window_mapping_level: str) -> str:
    if window_mapping_level == "strong":
        return "medium"
    if window_mapping_level == "weak":
        return "weak_window"
    if window_mapping_level == "partial":
        return "partial_window"
    return "invalid_window"


def build_probe_values(window: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for probe_id, r in (window.get("probe_records") or {}).items():
        out[probe_id] = {
            "run_id": r.get("run_id"),
            "export_status": r.get("export_status"),
            "vrp_count": r.get("vrp_count"),
            "vrp_digest": r.get("vrp_digest"),
            "validator_version": r.get("validator_version"),
            "collection_finished_at_utc": r.get("collection_finished_at_utc"),
            "last_update_done": r.get("last_update_done"),
            "latency_ms": r.get("latency_ms"),
            "refresh_before_export": r.get("refresh_before_export"),
            "cli_export_policy": r.get("cli_export_policy"),
        }
    return out


def candidate_from_window(window: Dict[str, Any], anomaly_type: str, reason: str) -> Dict[str, Any]:
    window_id = window.get("window_id") or "unknown"
    level = window.get("window_mapping_level") or "unknown"
    severity = severity_for_window(level, anomaly_type)
    confidence = confidence_for_window(level)

    strong_attribution_allowed = level == "strong"

    full_snapshot_required = bool(window.get("full_snapshot_required"))
    if level != "strong":
        full_snapshot_action = "defer_until_strong_window_or_policy_trigger"
    elif full_snapshot_required:
        full_snapshot_action = "required"
    else:
        full_snapshot_action = "not_required"

    return {
        "schema": "s3.m20_5.validation_output_candidate.v1",
        "created_at_utc": utc_now_iso(),

        "candidate_id": make_candidate_id(window_id, anomaly_type),
        "window_id": window_id,
        "layer": "validation_output_view",
        "anomaly_type": anomaly_type,
        "severity": severity,
        "confidence": confidence,

        "window_mapping_level": level,
        "window_skew_seconds": window.get("window_skew_seconds"),
        "window_started_at_utc": window.get("window_started_at_utc"),
        "window_finished_at_utc": window.get("window_finished_at_utc"),

        "reason": reason,
        "probe_values": build_probe_values(window),

        "vrp_count_values": window.get("vrp_count_values") or [],
        "vrp_digest_values": window.get("vrp_digest_values") or [],
        "validator_version_values": window.get("validator_version_values") or [],

        "entry_level_diff_required": anomaly_type in {
            "V2_VALIDATOR_OUTPUT_DIGEST_DIVERGENCE",
            "V3_VALIDATOR_OUTPUT_ENTRY_DIFF_REQUIRED",
        },
        "full_snapshot_required": full_snapshot_required,
        "full_snapshot_action": full_snapshot_action,
        "cross_layer_join_required": True,

        "strong_attribution_allowed": strong_attribution_allowed,
        "preliminary_interpretation": (
            "validation_output_divergence_candidate_weak_window"
            if level != "strong"
            else "validation_output_divergence_candidate_strong_window"
        ),

        "warnings": (
            ["weak_window_not_for_strong_attribution"]
            if level == "weak"
            else []
        ),
        "notes": [
            "M20.5-C classifies validation output layer candidates from M20.5-B timeline.",
            "Weak/partial windows are monitoring evidence, not strong attribution evidence.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="M20.5-C VRP output divergence candidate detector")
    parser.add_argument("--timeline-index", required=True)
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    timeline_path = Path(args.timeline_index).expanduser().resolve()

    indexes_dir = run_dir / "indexes"
    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"

    for d in [indexes_dir, outputs_dir, checks_dir]:
        d.mkdir(parents=True, exist_ok=True)

    candidates: List[Dict[str, Any]] = []
    windows = list(read_jsonl(timeline_path))

    for window in windows:
        level = window.get("window_mapping_level")
        output_diff_status = window.get("output_diff_status")

        probe_records = window.get("probe_records") or {}

        failed_probes = [
            p for p, r in probe_records.items()
            if r.get("export_status") != "success"
        ]
        if failed_probes:
            candidates.append(candidate_from_window(
                window,
                "V5_VALIDATOR_EXPORT_FAILURE",
                f"export failure observed on probes: {failed_probes}",
            ))

        if window.get("validator_version_unique_count", 0) > 1:
            candidates.append(candidate_from_window(
                window,
                "V6_VALIDATOR_VERSION_MISMATCH",
                "validator version differs across probes",
            ))

        if window.get("vrp_count_unique_count", 0) > 1:
            candidates.append(candidate_from_window(
                window,
                "V1_VALIDATOR_OUTPUT_COUNT_DIVERGENCE",
                "vrp_count differs across probes",
            ))

        if window.get("vrp_digest_unique_count", 0) > 1:
            candidates.append(candidate_from_window(
                window,
                "V2_VALIDATOR_OUTPUT_DIGEST_DIVERGENCE",
                "vrp_digest differs across probes",
            ))

        if output_diff_status in {
            "vrp_digest_divergent",
            "vrp_count_and_digest_divergent",
        }:
            candidates.append(candidate_from_window(
                window,
                "V3_VALIDATOR_OUTPUT_ENTRY_DIFF_REQUIRED",
                "entry-level VRP diff is required if a strong window or snapshot trigger is available",
            ))

        if level == "weak":
            candidates.append(candidate_from_window(
                window,
                "V4_VALIDATOR_CYCLE_SKEW",
                "collection window skew exceeds strong-window threshold",
            ))

    candidate_index = indexes_dir / "validation_output_candidate_index.jsonl"
    write_jsonl(candidate_index, candidates)

    by_anomaly_type = Counter(c.get("anomaly_type") for c in candidates)
    by_severity = Counter(c.get("severity") for c in candidates)
    by_confidence = Counter(c.get("confidence") for c in candidates)
    by_window_level = Counter(c.get("window_mapping_level") for c in candidates)

    summary = {
        "schema": "s3.m20_5c.vrp_output_candidate_summary.v1",
        "status": "PASS",
        "created_at_utc": utc_now_iso(),
        "run_dir": str(run_dir),
        "timeline_index": str(timeline_path),

        "timeline_window_count": len(windows),
        "candidate_count": len(candidates),

        "by_anomaly_type": dict(by_anomaly_type),
        "by_severity": dict(by_severity),
        "by_confidence": dict(by_confidence),
        "by_window_mapping_level": dict(by_window_level),

        "vrp_count_divergent_candidate_count": by_anomaly_type.get("V1_VALIDATOR_OUTPUT_COUNT_DIVERGENCE", 0),
        "vrp_digest_divergent_candidate_count": by_anomaly_type.get("V2_VALIDATOR_OUTPUT_DIGEST_DIVERGENCE", 0),
        "entry_level_diff_required_candidate_count": by_anomaly_type.get("V3_VALIDATOR_OUTPUT_ENTRY_DIFF_REQUIRED", 0),
        "validator_cycle_skew_candidate_count": by_anomaly_type.get("V4_VALIDATOR_CYCLE_SKEW", 0),
        "validator_export_failure_candidate_count": by_anomaly_type.get("V5_VALIDATOR_EXPORT_FAILURE", 0),
        "validator_version_mismatch_candidate_count": by_anomaly_type.get("V6_VALIDATOR_VERSION_MISMATCH", 0),

        "strong_attribution_candidate_count": sum(
            1 for c in candidates if c.get("strong_attribution_allowed")
        ),
        "weak_or_partial_candidate_count": sum(
            1 for c in candidates if not c.get("strong_attribution_allowed")
        ),

        "candidate_index": str(candidate_index),
        "important_boundary": [
            "M20.5-C detects validation output candidates only.",
            "Weak window candidates should not be used as strong attribution evidence.",
            "Entry-level VRP diff requires full snapshot or trigger policy.",
        ],
    }

    summary_path = outputs_dir / "M20_5C_vrp_output_candidate_summary.json"
    write_json(summary_path, summary)

    check_text = "\n".join([
        "M20_5C_VRP_DIVERGENCE_CANDIDATE=PASS",
        "",
        f"run_dir = {run_dir}",
        f"timeline_window_count = {len(windows)}",
        f"candidate_count = {len(candidates)}",
        f"by_anomaly_type = {dict(by_anomaly_type)}",
        f"by_severity = {dict(by_severity)}",
        f"by_confidence = {dict(by_confidence)}",
        f"by_window_mapping_level = {dict(by_window_level)}",
        "",
        f"vrp_count_divergent_candidate_count = {summary['vrp_count_divergent_candidate_count']}",
        f"vrp_digest_divergent_candidate_count = {summary['vrp_digest_divergent_candidate_count']}",
        f"entry_level_diff_required_candidate_count = {summary['entry_level_diff_required_candidate_count']}",
        f"validator_cycle_skew_candidate_count = {summary['validator_cycle_skew_candidate_count']}",
        f"validator_export_failure_candidate_count = {summary['validator_export_failure_candidate_count']}",
        f"validator_version_mismatch_candidate_count = {summary['validator_version_mismatch_candidate_count']}",
        "",
        f"strong_attribution_candidate_count = {summary['strong_attribution_candidate_count']}",
        f"weak_or_partial_candidate_count = {summary['weak_or_partial_candidate_count']}",
        "",
        f"candidate_index = {candidate_index}",
        f"summary_path = {summary_path}",
    ]) + "\n"

    check_path = checks_dir / "M20_5C_vrp_output_candidate.txt"
    check_path.write_text(check_text, encoding="utf-8")

    print(check_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
