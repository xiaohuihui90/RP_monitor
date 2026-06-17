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
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def count_jsonl(path: Path) -> int:
    if not path.exists() or not path.is_file():
        return 0
    n = 0
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def file_status(path_str: str) -> dict[str, Any]:
    p = Path(path_str) if path_str else Path("__missing_path__")
    exists = p.exists()
    is_file = p.is_file() if exists else False
    size = p.stat().st_size if exists and is_file else 0
    return {
        "path": str(p),
        "exists": exists,
        "is_file": is_file,
        "size_bytes": size,
        "non_empty": size > 0,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--check-dir", required=True)
    args = ap.parse_args()

    manifest_path = Path(args.manifest)
    out_dir = Path(args.out_dir)
    check_dir = Path(args.check_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    check_dir.mkdir(parents=True, exist_ok=True)

    manifest = read_json(manifest_path)
    windows = manifest.get("windows", [])

    required_keys = [
        "vrp_entry_diff_records",
        "m18_lifetime_seed_records",
        "validator_cycle_records",
        "validator_effective_input_summary",
        "quality_annotation",
        "result_digest",
    ]

    records = []
    ready_count = 0
    failed_count = 0
    total_missing_or_empty = 0

    for w in windows:
        wid = w.get("window_id")
        hard_fail = []
        file_checks = {}

        for key in required_keys:
            st = file_status(w.get(key, ""))
            file_checks[key] = st
            if not st["exists"]:
                hard_fail.append(f"{key}:missing")
            elif not st["non_empty"]:
                hard_fail.append(f"{key}:empty")

        seed_count = count_jsonl(Path(w.get("m18_lifetime_seed_records", "")))
        diff_count = count_jsonl(Path(w.get("vrp_entry_diff_records", "")))
        cycle_count = count_jsonl(Path(w.get("validator_cycle_records", "")))

        if seed_count <= 0:
            hard_fail.append("m18_lifetime_seed_records:zero_records")
        if diff_count <= 0:
            hard_fail.append("vrp_entry_diff_records:zero_records")
        if cycle_count < 3:
            hard_fail.append("validator_cycle_records:less_than_3_records")

        status = "PASS" if not hard_fail else "FAIL"
        if status == "PASS":
            ready_count += 1
        else:
            failed_count += 1
            total_missing_or_empty += len(hard_fail)

        records.append({
            "schema": "s3.m18.input_precheck_window_record.v1",
            "window_id": wid,
            "status": status,
            "hard_fail": hard_fail,
            "file_checks": file_checks,
            "record_counts": {
                "m18_lifetime_seed_records": seed_count,
                "vrp_entry_diff_records": diff_count,
                "validator_cycle_records": cycle_count,
            },
            "m17_window_dir": w.get("m17_window_dir"),
        })

    status = "PASS" if failed_count == 0 and ready_count > 0 else "FAIL"

    summary = {
        "schema": "s3.m18.input_precheck_summary.v1",
        "generated_at_utc": utc_now(),
        "status": status,
        "manifest_path": str(manifest_path),
        "manifest_window_count": manifest.get("window_count"),
        "window_count": len(windows),
        "ready_window_count": ready_count,
        "failed_window_count": failed_count,
        "total_missing_or_empty_count": total_missing_or_empty,
        "required_keys": required_keys,
        "records": records,
        "semantic_boundary": {
            "mapping_strength": "weak",
            "strong_causal_claim_allowed": False,
            "accepted_object_set_available": False,
        },
    }

    summary_path = out_dir / "m18_input_precheck_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    txt_lines = [
        f"M18_INPUT_PRECHECK={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"manifest_path = {manifest_path}",
        f"window_count = {summary['window_count']}",
        f"ready_window_count = {ready_count}",
        f"failed_window_count = {failed_count}",
        f"total_missing_or_empty_count = {total_missing_or_empty}",
        f"mapping_strength = weak",
        f"strong_causal_claim_allowed = False",
        f"summary_path = {summary_path}",
        "",
        "windows:",
    ]

    for r in records:
        txt_lines.append(
            f"  {r['window_id']} status={r['status']} "
            f"seed_count={r['record_counts']['m18_lifetime_seed_records']} "
            f"diff_count={r['record_counts']['vrp_entry_diff_records']} "
            f"cycle_count={r['record_counts']['validator_cycle_records']} "
            f"hard_fail={r['hard_fail']}"
        )

    check_path = check_dir / "M18_INPUT_PRECHECK.txt"
    check_path.write_text("\n".join(txt_lines) + "\n", encoding="utf-8")

    print("\n".join(txt_lines))

    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
