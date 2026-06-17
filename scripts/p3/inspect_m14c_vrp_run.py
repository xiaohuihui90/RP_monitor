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
    verdict_path = run_dir / "verdicts" / "final_verdict_m14.json"
    check_path = run_dir / "checks" / "M14C_acceptance_check.txt"
    text_path = run_dir / "verdicts" / "99_m14_validator_context_verdict.txt"

    verdict = read_json(verdict_path) if verdict_path.exists() else {}
    vc = verdict.get("context", {}).get("validator_config", {})

    out = {
        "run_id": run_dir.name,
        "final_verdict_exists": verdict_path.exists(),
        "m14c_acceptance_check_exists": check_path.exists(),
        "final_status": verdict.get("final_status"),
        "e4_status": verdict.get("e4_status"),
        "confirmed_allowed": verdict.get("confirmed_allowed"),
        "validator_context_available": vc.get("available"),
        "validator_environment_aligned_for_confirmed": vc.get("validator_environment_aligned_for_confirmed"),
        "hard_blockers": vc.get("hard_blockers"),
        "warnings": verdict.get("warnings"),
    }

    print(json.dumps(out, ensure_ascii=False, indent=2))

    if check_path.exists():
        print()
        print("========== M14C_acceptance_check.txt ==========")
        print(check_path.read_text(encoding="utf-8"))

    if text_path.exists():
        print()
        print("========== 99_m14_validator_context_verdict.txt ==========")
        print(text_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
