#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    summary_path = run_dir / "summaries" / "m14_vrp_summary.json"
    diff_path = run_dir / "diffs" / "m14_vrp_pairwise_diff.json"
    check_path = run_dir / "checks" / "M14A_acceptance_check.txt"

    summary = read_json(summary_path) if summary_path.exists() else {}
    diff = read_json(diff_path) if diff_path.exists() else {}

    out = {
        "run_id": run_dir.name,
        "run_dir": str(run_dir),
        "summary_exists": summary_path.exists(),
        "pairwise_diff_exists": diff_path.exists(),
        "acceptance_check_exists": check_path.exists(),
        "all_vrp_roots_aligned": summary.get("all_vrp_roots_aligned"),
        "all_pairwise_entry_level_diff_count": diff.get("all_pairwise_entry_level_diff_count"),
        "min_pairwise_jaccard_similarity": diff.get("min_pairwise_jaccard_similarity"),
        "probe_unique_counts": {
            probe: obj.get("unique_vrp_count")
            for probe, obj in summary.get("probe_summaries", {}).items()
        },
        "probe_parse_errors": {
            probe: obj.get("parse_error_count")
            for probe, obj in summary.get("probe_summaries", {}).items()
        },
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))

    if check_path.exists():
        print()
        print("========== M14A_acceptance_check.txt ==========")
        print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
