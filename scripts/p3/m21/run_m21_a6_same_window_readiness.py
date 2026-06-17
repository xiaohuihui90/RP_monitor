#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m21-run-dir", required=True)
    ap.add_argument("--m245-history", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    m21 = Path(args.m21_run_dir)
    m245 = Path(args.m245_history)
    out_dir = Path(args.out_dir)

    out_dir.mkdir(parents=True, exist_ok=True)
    checks = m21 / "checks"
    outputs = m21 / "outputs"
    checks.mkdir(parents=True, exist_ok=True)
    outputs.mkdir(parents=True, exist_ok=True)

    a5_check = m21 / "checks/M21_A5_ALIGNMENT_CONFIDENCE_SUMMARY_CHECK.txt"
    a5_summary = m21 / "outputs/m21_a5_alignment_confidence_summary.json"
    a4_records = m21 / "outputs/m21_a4_pp_notification_temporal_binding_records.jsonl"

    latest_windows = sorted(m245.glob("m245_window_*"))[-10:] if m245.exists() else []

    existing_current_like = []
    for w in latest_windows:
        outputs_dir = w / "outputs"
        candidates = [
            outputs_dir / "M245_three_layer_status_matrix.json",
            outputs_dir / "M245_mapping_context.json",
            outputs_dir / "M245_merged_validator_context.json",
        ]
        existing_current_like.append({
            "window_dir": str(w),
            "files": {str(p): p.exists() for p in candidates},
        })

    a5_obj = read_json(a5_summary)
    strong_l1_binding = False
    blockers = []

    if not a5_check.exists():
        blockers.append("M21_A5_check_missing")
    if not a5_summary.exists():
        blockers.append("M21_A5_summary_missing")
    if not a4_records.exists():
        blockers.append("M21_A4_binding_records_missing")

    # 当前历史结果是 late binding，不是 same-window strong binding。
    blockers.append("same_window_jsonext_sidecar_not_confirmed")
    blockers.append("same_window_manifest_filelist_capture_not_confirmed")
    blockers.append("same_window_pp_notification_serial_session_not_confirmed")

    status = "BLOCKED_NEEDS_FUTURE_SAME_WINDOW_CAPTURE"

    summary = {
        "schema": "s3.m21.a6.same_window_readiness.v1",
        "generated_at_utc": utc_now(),
        "status": status,
        "m21_run_dir": str(m21),
        "m245_history": str(m245),
        "a5_summary": str(a5_summary),
        "a4_records": str(a4_records),
        "a5_key": a5_obj.get("nearest_delta_sec") if isinstance(a5_obj, dict) else None,
        "latest_m245_windows_checked": existing_current_like,
        "blockers": blockers,
        "current_evidence_level": "medium_late_temporal_window",
        "strong_l1_binding": strong_l1_binding,
        "required_for_strong_binding": [
            "same-window routinator jsonext sidecar for each probe",
            "same-window manifest fileList index for matched repositories",
            "same-window PP notification session_id/serial/notif_digest",
            "validator cycle timing metadata",
            "window_id shared across L1/L2/L3 artifacts",
        ],
        "recommended_next_stage": "M21_A6_FUTURE_WINDOW_CAPTURE_HOOK",
        "semantic_boundary": "readiness_check_not_strong_binding",
        "strong_causal_claim_allowed": False,
    }

    summary_path = out_dir / "m21_a6_same_window_readiness_summary.json"
    check_path = checks / "M21_A6_SAME_WINDOW_READINESS_CHECK.txt"

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        f"M21_A6_SAME_WINDOW_READINESS={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"m21_run_dir = {m21}",
        f"current_evidence_level = {summary['current_evidence_level']}",
        f"strong_l1_binding = {strong_l1_binding}",
        f"blockers = {blockers}",
        f"summary_json = {summary_path}",
        "semantic_boundary = readiness_check_not_strong_binding",
        "strong_causal_claim_allowed = False",
        "next_stage = M21_A6_FUTURE_WINDOW_CAPTURE_HOOK",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
