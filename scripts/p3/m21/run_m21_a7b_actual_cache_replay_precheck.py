#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_cmd(cmd):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        return {
            "returncode": p.returncode,
            "stdout": p.stdout.decode("utf-8", errors="ignore"),
            "stderr": p.stderr.decode("utf-8", errors="ignore"),
        }
    except Exception as e:
        return {"error": str(e), "stdout": "", "stderr": ""}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m21-run-dir", required=True)
    ap.add_argument("--a7-plan-jsonl", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    m21 = Path(args.m21_run_dir)
    plan = Path(args.a7_plan_jsonl)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    checks = m21 / "checks"
    checks.mkdir(parents=True, exist_ok=True)

    version = run_cmd(["routinator", "--version"])
    help_main = run_cmd(["routinator", "--help"])
    help_vrps = run_cmd(["routinator", "vrps", "--help"])

    help_text = help_main.get("stdout", "") + "\n" + help_main.get("stderr", "") + "\n" + help_vrps.get("stdout", "") + "\n" + help_vrps.get("stderr", "")

    cache_option_candidates = []
    for token in ["--repository-dir", "--cache-dir", "--rrdp-root", "--rsync-root", "--config"]:
        if token in help_text:
            cache_option_candidates.append(token)

    plan_count = 0
    if plan.exists():
        plan_count = sum(1 for _ in plan.open("r", encoding="utf-8", errors="ignore"))

    cache_paths = []
    for p in [
        Path.home() / ".rpki-cache",
        Path.home() / ".cache/routinator",
        Path.home() / ".local/share/routinator",
    ]:
        if p.exists():
            cache_paths.append(str(p))

    blockers = []
    if version.get("returncode") != 0:
        blockers.append("routinator_not_available")
    if plan_count <= 0:
        blockers.append("a7_plan_empty_or_missing")
    if not cache_option_candidates:
        blockers.append("cache_dir_option_not_identified_from_help")
    if not cache_paths:
        blockers.append("no_existing_cache_path_detected")

    status = "PASS_READY_FOR_A7B_SCRIPTING" if not blockers else "BLOCKED_NEEDS_MANUAL_CACHE_OPTION_CHECK"

    summary = {
        "schema": "s3.m21.a7b.actual_cache_replay_precheck.v1",
        "generated_at_utc": utc_now(),
        "status": status,
        "m21_run_dir": str(m21),
        "a7_plan_jsonl": str(plan),
        "a7_plan_record_count": plan_count,
        "routinator_version": version,
        "cache_option_candidates": cache_option_candidates,
        "existing_cache_paths": cache_paths,
        "blockers": blockers,
        "required_for_actual_replay": [
            "isolated fresh cache directory",
            "isolated warm cache copied from current cache",
            "stale cache snapshot from earlier failed/older state",
            "same input repository snapshot or controlled live fetch boundary",
            "VRP jsonext export for each replay mode",
        ],
        "semantic_boundary": "actual_cache_replay_precheck_no_validator_replay",
        "strong_causal_claim_allowed": False,
        "next_stage": "M21_A7B_ACTUAL_CACHE_REPLAY_SMALL_BATCH_SCRIPT" if not blockers else "MANUAL_CONFIRM_ROUTINATOR_CACHE_OPTIONS",
    }

    summary_path = out_dir / "m21_a7b_actual_cache_replay_precheck_summary.json"
    check_path = checks / "M21_A7B_ACTUAL_CACHE_REPLAY_PRECHECK.txt"

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        f"M21_A7B_ACTUAL_CACHE_REPLAY_PRECHECK={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"a7_plan_record_count = {plan_count}",
        f"cache_option_candidates = {cache_option_candidates}",
        f"existing_cache_paths = {cache_paths}",
        f"blockers = {blockers}",
        f"summary_json = {summary_path}",
        "semantic_boundary = actual_cache_replay_precheck_no_validator_replay",
        "strong_causal_claim_allowed = False",
        f"next_stage = {summary['next_stage']}",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
