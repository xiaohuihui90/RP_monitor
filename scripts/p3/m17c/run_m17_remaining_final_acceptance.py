#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def main():
    report_dir = Path("data/p3_collector/m17_continuous_lite/reports")
    daily = read_json(report_dir / "M17C_daily_report.json")
    m18_manifest = read_json(report_dir / "M17C_m18_input_manifest.json")

    if not isinstance(daily, dict):
        daily = {}
    if not isinstance(m18_manifest, dict):
        m18_manifest = {}

    conditions = {
        "window_count_ge_3": int(daily.get("window_count") or 0) >= 3,
        "m17_done_windows_ge_3": int(daily.get("m17_done_windows") or 0) >= 3,
        "validator_cycle_record_windows_ge_3": int(daily.get("validator_cycle_record_windows") or 0) >= 3,
        "effective_input_summary_windows_ge_3": int(daily.get("effective_input_summary_windows") or 0) >= 3,
        "result_digest_windows_ge_3": int(daily.get("result_digest_windows") or 0) >= 3,
        "m18_input_window_count_ge_3": int(daily.get("m18_input_window_count") or 0) >= 3,
    }

    status = "PASS" if all(conditions.values()) else "FAIL"

    result = {
        "schema": "s3.m17.remaining_final_acceptance.v1",
        "generated_at_utc": utc_now(),
        "status": status,
        "conditions": conditions,
        "summary": {
            "window_count": daily.get("window_count"),
            "m17_done_windows": daily.get("m17_done_windows"),
            "large_scale_candidate_windows": daily.get("large_scale_candidate_windows"),
            "validator_cycle_record_windows": daily.get("validator_cycle_record_windows"),
            "effective_input_summary_windows": daily.get("effective_input_summary_windows"),
            "result_digest_windows": daily.get("result_digest_windows"),
            "m18_input_window_count": daily.get("m18_input_window_count"),
            "total_diff_records": daily.get("total_diff_records"),
            "max_diff_records_per_window": daily.get("max_diff_records_per_window"),
        },
        "semantic_boundary": {
            "mapping_strength": "weak",
            "accepted_object_set_available": False,
            "strong_causal_claim_allowed": False,
            "note": "M17 remaining stage completes VRP diff evidence entry and validator-side context, but does not claim object-layer causality or validator implementation divergence."
        },
        "next_stage": "M18_DIFF_LIFETIME_PRECHECK" if status == "PASS" else "M17_REPAIR_REQUIRED",
        "m18_input_manifest": "data/p3_collector/m17_continuous_lite/reports/M17C_m18_input_manifest.json",
    }

    out_json = report_dir / "M17_REMAINING_FINAL_ACCEPTANCE.json"
    out_txt = report_dir / "M17_REMAINING_FINAL_ACCEPTANCE.txt"

    out_json.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        f"M17_REMAINING_FINAL_ACCEPTANCE={status}",
        f"generated_at_utc = {result['generated_at_utc']}",
        f"window_count = {result['summary']['window_count']}",
        f"m17_done_windows = {result['summary']['m17_done_windows']}",
        f"validator_cycle_record_windows = {result['summary']['validator_cycle_record_windows']}",
        f"effective_input_summary_windows = {result['summary']['effective_input_summary_windows']}",
        f"result_digest_windows = {result['summary']['result_digest_windows']}",
        f"m18_input_window_count = {result['summary']['m18_input_window_count']}",
        f"total_diff_records = {result['summary']['total_diff_records']}",
        f"next_stage = {result['next_stage']}",
        "",
        "conditions:",
    ]

    for k, v in conditions.items():
        lines.append(f"  {k} = {v}")

    out_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n".join(lines))


if __name__ == "__main__":
    main()
