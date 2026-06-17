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


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    n = 0
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()

    run_dir = Path(args.run_dir)
    check_dir = run_dir / "checks"
    out_dir = run_dir / "outputs"

    precheck = read_json(out_dir / "m18_input_precheck_summary.json") or {}
    lifetime_summary = read_json(out_dir / "m18_lifetime_tracker_summary.json") or {}
    convergence_report = read_json(out_dir / "convergence_baseline_report.json") or {}

    lifetime_records = out_dir / "vrp_diff_lifetime_records.jsonl"
    persistent_candidates = out_dir / "persistent_divergence_candidates.jsonl"
    trailing_candidates = out_dir / "trailing_cache_candidates.jsonl"
    m19_candidates = out_dir / "m19_mapping_candidates.jsonl"
    convergence_md = out_dir / "convergence_baseline_report.md"

    counts = {
        "lifetime_record_count_file": count_jsonl(lifetime_records),
        "persistent_candidate_count_file": count_jsonl(persistent_candidates),
        "trailing_cache_candidate_count_file": count_jsonl(trailing_candidates),
        "m19_candidate_count_file": count_jsonl(m19_candidates),
    }

    conditions = {
        "input_precheck_pass": precheck.get("status") == "PASS",
        "ready_window_count_ge_5": int(precheck.get("ready_window_count") or 0) >= 5,
        "lifetime_tracker_pass": lifetime_summary.get("status") == "PASS",
        "lifetime_records_non_empty": counts["lifetime_record_count_file"] > 0,
        "convergence_report_exists": (out_dir / "convergence_baseline_report.json").exists(),
        "convergence_report_md_exists": convergence_md.exists() and convergence_md.stat().st_size > 0,
        "persistent_candidates_exists": persistent_candidates.exists(),
        "m19_candidates_exists": m19_candidates.exists(),
        "m19_candidate_count_reasonable": 0 < counts["m19_candidate_count_file"] < counts["lifetime_record_count_file"],
        "mapping_strength_weak": convergence_report.get("semantic_boundary", {}).get("mapping_strength") == "weak",
        "strong_causal_claim_disallowed": convergence_report.get("semantic_boundary", {}).get("strong_causal_claim_allowed") is False,
    }

    status = "PASS" if all(conditions.values()) else "FAIL"

    result = {
        "schema": "s3.m18.acceptance.v1",
        "generated_at_utc": utc_now(),
        "status": status,
        "run_dir": str(run_dir),
        "conditions": conditions,
        "summary": {
            "ready_window_count": precheck.get("ready_window_count"),
            "window_count": convergence_report.get("window_count"),
            "merged_seed_record_count": convergence_report.get("merged_seed_record_count"),
            "diff_lifetime_record_count": convergence_report.get("diff_lifetime_record_count"),
            "persistent_candidate_count": convergence_report.get("persistent_candidate_count"),
            "trailing_cache_candidate_count": convergence_report.get("trailing_cache_candidate_count"),
            "m19_candidate_count": convergence_report.get("m19_candidate_count"),
            **counts,
        },
        "semantic_boundary": {
            "mapping_strength": "weak",
            "strong_causal_claim_allowed": False,
            "accepted_object_set_available": False,
            "note": (
                "M18 describes temporal behavior and convergence baseline only. "
                "It does not claim object-layer causality, validator implementation divergence, "
                "or BGP/ROV impact."
            ),
        },
        "outputs": {
            "vrp_diff_lifetime_records": str(lifetime_records),
            "persistent_divergence_candidates": str(persistent_candidates),
            "trailing_cache_candidates": str(trailing_candidates),
            "m19_mapping_candidates": str(m19_candidates),
            "convergence_baseline_report_json": str(out_dir / "convergence_baseline_report.json"),
            "convergence_baseline_report_md": str(convergence_md),
        },
        "next_stage": "M19_ROA_TO_VRP_MAPPING_PRECHECK" if status == "PASS" else "M18_REPAIR_REQUIRED",
    }

    write_json(out_dir / "M18_ACCEPTANCE.json", result)

    lines = [
        f"M18_ACCEPTANCE={status}",
        f"generated_at_utc = {result['generated_at_utc']}",
        f"ready_window_count = {result['summary']['ready_window_count']}",
        f"window_count = {result['summary']['window_count']}",
        f"merged_seed_record_count = {result['summary']['merged_seed_record_count']}",
        f"diff_lifetime_record_count = {result['summary']['diff_lifetime_record_count']}",
        f"persistent_candidate_count = {result['summary']['persistent_candidate_count']}",
        f"trailing_cache_candidate_count = {result['summary']['trailing_cache_candidate_count']}",
        f"m19_candidate_count = {result['summary']['m19_candidate_count']}",
        f"mapping_strength = weak",
        f"strong_causal_claim_allowed = False",
        f"next_stage = {result['next_stage']}",
        "",
        "conditions:",
    ]

    for k, v in conditions.items():
        lines.append(f"  {k} = {v}")

    (check_dir / "M18_ACCEPTANCE.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("\n".join(lines))

    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
