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
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        return {
            "returncode": p.returncode,
            "stdout": p.stdout.decode("utf-8", errors="ignore")[:2000],
            "stderr": p.stderr.decode("utf-8", errors="ignore")[:2000],
        }
    except Exception as e:
        return {"error": str(e)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m21-run-dir", required=True)
    ap.add_argument("--m20-joined-records", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    m21 = Path(args.m21_run_dir)
    joined = Path(args.m20_joined_records)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    checks = m21 / "checks"
    checks.mkdir(parents=True, exist_ok=True)

    routinator_version = run_cmd(["routinator", "--version"])
    routinator_help = run_cmd(["routinator", "vrps", "--help"])

    cache_candidates = [
        Path.home() / ".rpki-cache",
        Path.home() / ".cache/routinator",
        Path.home() / ".local/share/routinator",
        Path("data/probe"),
        Path("data/p3_collector"),
    ]

    existing_cache_paths = []
    for p in cache_candidates:
        if p.exists():
            existing_cache_paths.append(str(p))

    joined_count = 0
    if joined.exists():
        joined_count = sum(1 for _ in joined.open("r", encoding="utf-8", errors="ignore"))

    summary = {
        "schema": "s3.m21.a7.cache_replay_precheck.v1",
        "generated_at_utc": utc_now(),
        "routinator_version": routinator_version,
        "routinator_vrps_help": routinator_help,
        "m20_joined_records": str(joined),
        "m20_joined_record_count": joined_count,
        "existing_cache_paths": existing_cache_paths,
        "planned_modes": ["fresh_cache", "warm_cache", "stale_cache"],
        "blockers": [],
        "semantic_boundary": "precheck_only_no_cache_replay_executed",
        "strong_causal_claim_allowed": False,
        "next_stage": "M21_A7_CACHE_REPLAY_DESIGN_OR_SMALL_BATCH",
    }

    if joined_count <= 0:
        summary["blockers"].append("m20_joined_records_empty")
    if routinator_version.get("returncode") != 0:
        summary["blockers"].append("routinator_not_available")

    summary_path = out_dir / "m21_a7_cache_replay_precheck_summary.json"
    check_path = checks / "M21_A7_CACHE_REPLAY_PRECHECK.txt"

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    status = "PASS" if not summary["blockers"] else "BLOCKED"
    lines = [
        f"M21_A7_CACHE_REPLAY_PRECHECK={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"m20_joined_record_count = {joined_count}",
        f"existing_cache_paths = {existing_cache_paths}",
        f"blockers = {summary['blockers']}",
        f"summary_json = {summary_path}",
        "semantic_boundary = precheck_only_no_cache_replay_executed",
        "strong_causal_claim_allowed = False",
        "next_stage = M21_A7_CACHE_REPLAY_DESIGN_OR_SMALL_BATCH",
    ]
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
