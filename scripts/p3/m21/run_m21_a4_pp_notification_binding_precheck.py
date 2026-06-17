#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--a3-summary", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    a3_summary_path = Path(args.a3_summary)
    out_dir = Path(args.out_dir)

    checks = out_dir / "checks"
    outputs = out_dir / "outputs"
    checks.mkdir(parents=True, exist_ok=True)
    outputs.mkdir(parents=True, exist_ok=True)

    check_path = checks / "M21_A4_PP_NOTIFICATION_BINDING_PRECHECK.txt"
    summary_path = outputs / "m21_a4_pp_notification_binding_precheck_summary.json"

    if not a3_summary_path.exists():
        status = "BLOCKED_A3_SUMMARY_MISSING"
        counters = {}
        blockers = ["a3_summary_missing"]
    else:
        obj = json.loads(a3_summary_path.read_text(encoding="utf-8"))
        counters = obj.get("counters", {})

        manifest_parse_success = counters.get("manifest_parse_success", 0)
        filelist_match = counters.get("roa_filename_filelist_match", 0)

        blockers = []
        if manifest_parse_success <= 0:
            blockers.append("manifest_filelist_not_parsed")
        if filelist_match <= 0:
            blockers.append("roa_not_confirmed_in_manifest_filelist")

        status = "PASS_READY_FOR_A4" if not blockers else "BLOCKED_MANIFEST_FILELIST_NOT_READY"

    summary = {
        "schema": "s3.m21.a4.pp_notification_binding_precheck.v1",
        "generated_at_utc": utc_now(),
        "a3_summary": str(a3_summary_path),
        "status": status,
        "a3_counters": counters,
        "blockers": blockers,
        "required_before_a4": [
            "manifest_parse_success > 0",
            "roa_filename_filelist_match > 0",
            "manifestNumber / thisUpdate / nextUpdate available",
            "manifest_uri available",
        ],
        "semantic_boundary": "a4_precheck_only_no_l1_binding_attempted",
        "strong_causal_claim_allowed": False,
        "next_stage": "M21_A3B_MANIFEST_PARSE_DEBUG_AND_FIX" if blockers else "M21_A4_PP_NOTIFICATION_BINDING",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        f"M21_A4_PP_NOTIFICATION_BINDING_PRECHECK={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"a3_summary = {a3_summary_path}",
        f"manifest_parse_success = {counters.get('manifest_parse_success', 0)}",
        f"manifest_parse_failed = {counters.get('manifest_parse_failed', 0)}",
        f"candidate_count = {counters.get('candidate_count', 0)}",
        f"roa_filename_filelist_match = {counters.get('roa_filename_filelist_match', 0)}",
        f"roa_filename_filelist_not_match = {counters.get('roa_filename_filelist_not_match', 0)}",
        f"manifest_filehash_unavailable = {counters.get('manifest_filehash_unavailable', 0)}",
        f"blockers = {blockers}",
        f"summary_json = {summary_path}",
        "semantic_boundary = a4_precheck_only_no_l1_binding_attempted",
        "strong_causal_claim_allowed = False",
        f"next_stage = {summary['next_stage']}",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
