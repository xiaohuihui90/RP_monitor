#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import shutil
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


def disk_free_gb(path: Path) -> float:
    usage = shutil.disk_usage(path)
    return usage.free / (1024 ** 3)


def default_policy(min_free_gb: float) -> Dict[str, Any]:
    return {
        "schema": "s3.m20_5.full_snapshot_trigger_policy.v1",
        "created_at_utc": utc_now_iso(),

        "default_snapshot_mode": "summary_only",

        "trigger_rules": {
            "same_probe_vrp_digest_changed": True,
            "same_probe_vrp_count_changed": True,
            "same_window_vrp_digest_divergence": True,
            "same_window_vrp_count_divergence": True,
            "validator_export_failure": True,
            "validator_version_mismatch": True,
            "validator_cycle_skew": True,
            "hourly_sampling": False,
            "object_layer_raw_hash_divergence": True,
            "announced_view_e2_e3": True
        },

        "snapshot_modes": {
            "default": "summary_only",
            "on_digest_divergence": "canonical_only",
            "on_count_divergence": "canonical_only",
            "on_entry_diff_required": "canonical_only",
            "on_cycle_skew": "summary_only",
            "on_export_failure": "summary_only",
            "on_version_mismatch": "summary_only",
            "hourly_sampling": "canonical_only"
        },

        "retention_policy": {
            "keep_summary_days": 90,
            "keep_full_snapshot_days": 7,
            "max_full_snapshots_per_probe": 24
        },

        "disk_guard": {
            "min_free_gb": min_free_gb,
            "disable_full_snapshot_when_low_disk": True
        },

        "important_boundary": [
            "Default mode is summary_only.",
            "Full VRP snapshot should not be taken for weak-window evidence unless explicitly enabled by policy.",
            "Weak-window candidates are monitoring evidence, not strong attribution evidence."
        ]
    }


def trigger_reason_for_candidate(c: Dict[str, Any]) -> str:
    t = c.get("anomaly_type")

    if t == "V1_VALIDATOR_OUTPUT_COUNT_DIVERGENCE":
        return "same_window_vrp_count_divergence"
    if t == "V2_VALIDATOR_OUTPUT_DIGEST_DIVERGENCE":
        return "same_window_vrp_digest_divergence"
    if t == "V3_VALIDATOR_OUTPUT_ENTRY_DIFF_REQUIRED":
        return "entry_level_vrp_diff_required"
    if t == "V4_VALIDATOR_CYCLE_SKEW":
        return "validator_cycle_skew"
    if t == "V5_VALIDATOR_EXPORT_FAILURE":
        return "validator_export_failure"
    if t == "V6_VALIDATOR_VERSION_MISMATCH":
        return "validator_version_mismatch"

    return "unknown_candidate_type"


def snapshot_mode_for_candidate(c: Dict[str, Any]) -> str:
    t = c.get("anomaly_type")

    if t == "V1_VALIDATOR_OUTPUT_COUNT_DIVERGENCE":
        return "canonical_only"
    if t == "V2_VALIDATOR_OUTPUT_DIGEST_DIVERGENCE":
        return "canonical_only"
    if t == "V3_VALIDATOR_OUTPUT_ENTRY_DIFF_REQUIRED":
        return "canonical_only"
    if t == "V4_VALIDATOR_CYCLE_SKEW":
        return "summary_only"
    if t == "V5_VALIDATOR_EXPORT_FAILURE":
        return "summary_only"
    if t == "V6_VALIDATOR_VERSION_MISMATCH":
        return "summary_only"

    return "summary_only"


def build_decision(candidate: Dict[str, Any], free_gb: float, min_free_gb: float) -> Dict[str, Any]:
    level = candidate.get("window_mapping_level")
    strong = bool(candidate.get("strong_attribution_allowed"))
    anomaly_type = candidate.get("anomaly_type")

    disk_guard_status = "pass" if free_gb >= min_free_gb else "low_disk"

    requested_snapshot_mode = snapshot_mode_for_candidate(candidate)
    trigger_reason = trigger_reason_for_candidate(candidate)

    full_snapshot_required_by_candidate = bool(candidate.get("full_snapshot_required"))

    immediate_allowed_by_window = strong
    immediate_allowed_by_disk = disk_guard_status == "pass"

    immediate_full_snapshot_required = (
        full_snapshot_required_by_candidate
        and immediate_allowed_by_window
        and immediate_allowed_by_disk
        and requested_snapshot_mode != "summary_only"
    )

    if immediate_full_snapshot_required:
        decision_status = "trigger_now"
        full_snapshot_action = "take_snapshot_now"
        effective_snapshot_mode = requested_snapshot_mode
    elif full_snapshot_required_by_candidate and not immediate_allowed_by_window:
        decision_status = "deferred_weak_window"
        full_snapshot_action = "defer_until_strong_window_or_manual_trigger"
        effective_snapshot_mode = "summary_only"
    elif full_snapshot_required_by_candidate and not immediate_allowed_by_disk:
        decision_status = "blocked_by_disk_guard"
        full_snapshot_action = "disable_full_snapshot_due_to_low_disk"
        effective_snapshot_mode = "summary_only"
    else:
        decision_status = "summary_only"
        full_snapshot_action = "no_full_snapshot_required"
        effective_snapshot_mode = "summary_only"

    warnings = []
    if level == "weak":
        warnings.append("weak_window_defer_full_snapshot")
    if disk_guard_status != "pass":
        warnings.append("low_disk_disable_full_snapshot")

    return {
        "schema": "s3.m20_5.full_snapshot_trigger_decision.v1",
        "created_at_utc": utc_now_iso(),

        "candidate_id": candidate.get("candidate_id"),
        "window_id": candidate.get("window_id"),
        "anomaly_type": anomaly_type,
        "window_mapping_level": level,
        "confidence": candidate.get("confidence"),
        "severity": candidate.get("severity"),

        "trigger_reasons": [trigger_reason],
        "full_snapshot_required_by_candidate": full_snapshot_required_by_candidate,
        "immediate_full_snapshot_required": immediate_full_snapshot_required,

        "requested_snapshot_mode": requested_snapshot_mode,
        "effective_snapshot_mode": effective_snapshot_mode,
        "decision_status": decision_status,
        "full_snapshot_action": full_snapshot_action,

        "strong_attribution_allowed": strong,
        "disk_guard_status": disk_guard_status,
        "free_gb": round(free_gb, 3),
        "min_free_gb": min_free_gb,

        "retention_policy_applied": True,
        "warnings": warnings,
        "notes": [
            "M20.5-D only decides whether full snapshot should be triggered.",
            "This step does not export full VRP snapshot by itself.",
            "Weak-window candidates are deferred by default."
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="M20.5-D full snapshot trigger policy builder")
    parser.add_argument("--candidate-index", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--min-free-gb", type=float, default=10.0)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    candidate_index = Path(args.candidate_index).expanduser().resolve()

    configs_dir = run_dir / "configs"
    indexes_dir = run_dir / "indexes"
    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"

    for d in [configs_dir, indexes_dir, outputs_dir, checks_dir]:
        d.mkdir(parents=True, exist_ok=True)

    candidates = list(read_jsonl(candidate_index))

    free_gb = disk_free_gb(run_dir)
    policy = default_policy(args.min_free_gb)

    decisions = [
        build_decision(c, free_gb=free_gb, min_free_gb=args.min_free_gb)
        for c in candidates
    ]

    policy_path = configs_dir / "m20_5_full_snapshot_trigger_policy.json"
    decision_index = indexes_dir / "full_snapshot_trigger_decision_index.jsonl"

    write_json(policy_path, policy)
    write_jsonl(decision_index, decisions)

    by_decision_status = Counter(d.get("decision_status") for d in decisions)
    by_snapshot_mode = Counter(d.get("effective_snapshot_mode") for d in decisions)
    by_anomaly_type = Counter(d.get("anomaly_type") for d in decisions)
    by_window_level = Counter(d.get("window_mapping_level") for d in decisions)

    immediate_trigger_count = sum(1 for d in decisions if d.get("immediate_full_snapshot_required"))
    deferred_count = by_decision_status.get("deferred_weak_window", 0)
    disk_blocked_count = by_decision_status.get("blocked_by_disk_guard", 0)

    status = "PASS"

    summary = {
        "schema": "s3.m20_5d.full_snapshot_trigger_summary.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "run_dir": str(run_dir),
        "candidate_index": str(candidate_index),

        "candidate_count": len(candidates),
        "trigger_decision_count": len(decisions),

        "immediate_trigger_count": immediate_trigger_count,
        "deferred_trigger_count": deferred_count,
        "disk_blocked_count": disk_blocked_count,

        "by_decision_status": dict(by_decision_status),
        "by_effective_snapshot_mode": dict(by_snapshot_mode),
        "by_anomaly_type": dict(by_anomaly_type),
        "by_window_mapping_level": dict(by_window_level),

        "free_gb": round(free_gb, 3),
        "min_free_gb": args.min_free_gb,

        "policy_path": str(policy_path),
        "trigger_decision_index": str(decision_index),

        "important_boundary": [
            "M20.5-D does not execute full snapshot export.",
            "Weak-window candidates are deferred by default.",
            "Full snapshot export should be done only for strong windows or explicit manual/policy triggers."
        ],
    }

    summary_path = outputs_dir / "M20_5D_full_snapshot_trigger_summary.json"
    write_json(summary_path, summary)

    check_text = "\n".join([
        "M20_5D_FULL_SNAPSHOT_TRIGGER_POLICY=PASS",
        "",
        f"run_dir = {run_dir}",
        f"candidate_count = {len(candidates)}",
        f"trigger_decision_count = {len(decisions)}",
        f"immediate_trigger_count = {immediate_trigger_count}",
        f"deferred_trigger_count = {deferred_count}",
        f"disk_blocked_count = {disk_blocked_count}",
        f"by_decision_status = {dict(by_decision_status)}",
        f"by_effective_snapshot_mode = {dict(by_snapshot_mode)}",
        f"by_anomaly_type = {dict(by_anomaly_type)}",
        f"by_window_mapping_level = {dict(by_window_level)}",
        f"free_gb = {round(free_gb, 3)}",
        f"min_free_gb = {args.min_free_gb}",
        "",
        f"policy_path = {policy_path}",
        f"trigger_decision_index = {decision_index}",
        f"summary_path = {summary_path}",
    ]) + "\n"

    check_path = checks_dir / "M20_5D_full_snapshot_trigger_policy.txt"
    check_path.write_text(check_text, encoding="utf-8")

    print(check_text)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
