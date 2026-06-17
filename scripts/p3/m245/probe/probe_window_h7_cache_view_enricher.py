from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def append_jsonl(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--cache-dir", default=str(Path.home() / ".rpki-cache"))
    ap.add_argument("--timeout-sec", type=int, default=2400)
    ap.add_argument("--lock-timeout-sec", type=int, default=600)
    ap.add_argument("--vrp-count-low-threshold", type=int, default=500000)
    ap.add_argument("--include-suffixes", default=".mft,.roa,.cer,.crl,.asa")
    ap.add_argument("--max-read-bytes", type=int, default=4096)
    args = ap.parse_args()

    created = utc_now()
    project_dir = Path(args.project_dir).resolve()
    run_dir = Path(args.run_dir).resolve()

    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"
    indexes_dir = run_dir / "indexes"

    outputs_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)
    indexes_dir.mkdir(parents=True, exist_ok=True)

    h7_run_dir = run_dir / "h7_validator_cache_view" / f"h7_logical_cache_index_lite_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    h7_run_dir.mkdir(parents=True, exist_ok=True)

    hard_fail: list[str] = []

    cmd = [
        sys.executable,
        "-m",
        "scripts.p3.m245.probe.validator_logical_cache_index_lite_diagnoser",
        "--project-dir",
        str(project_dir),
        "--probe-id",
        args.probe_id,
        "--window-id",
        args.window_id,
        "--cache-dir",
        args.cache_dir,
        "--out-dir",
        str(h7_run_dir),
        "--timeout-sec",
        str(args.timeout_sec),
        "--lock-timeout-sec",
        str(args.lock_timeout_sec),
        "--vrp-count-low-threshold",
        str(args.vrp_count_low_threshold),
        "--include-suffixes",
        args.include_suffixes,
        "--max-read-bytes",
        str(args.max_read_bytes),
    ]

    proc = subprocess.run(
        cmd,
        cwd=str(project_dir),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    (h7_run_dir / "h7_enricher_child.stdout").write_text(proc.stdout or "", encoding="utf-8")
    (h7_run_dir / "h7_enricher_child.stderr").write_text(proc.stderr or "", encoding="utf-8")

    if proc.returncode != 0:
        hard_fail.append(f"h7_child_return_code_{proc.returncode}")

    h7_summary_path = h7_run_dir / "outputs" / "validator_logical_cache_index_lite_summary.json"
    h7_check_path = h7_run_dir / "checks" / "H7_LOGICAL_CACHE_INDEX_LITE_CHECK.txt"

    if not h7_summary_path.exists():
        hard_fail.append("h7_summary_missing")
        h7_summary = {}
    else:
        h7_summary = json.loads(h7_summary_path.read_text(encoding="utf-8"))

    if not h7_check_path.exists():
        hard_fail.append("h7_check_missing")

    stable = h7_summary.get("logical_cache_index_stable") is True
    mapping_candidate = h7_summary.get("mapping_strength_candidate")
    root = h7_summary.get("validator_logical_cache_index_root")

    if not stable:
        hard_fail.append("logical_cache_index_not_stable")
    if mapping_candidate != "medium_candidate_index_only":
        hard_fail.append("mapping_candidate_not_medium_index_only")
    if not root:
        hard_fail.append("validator_logical_cache_index_root_missing")

    probe_summary_path = outputs_dir / "m245_probe_window_summary.json"

    existing_summary = {}
    if probe_summary_path.exists():
        existing_summary = json.loads(probe_summary_path.read_text(encoding="utf-8"))
        backup_path = outputs_dir / f"m245_probe_window_summary.before_h7_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
        shutil.copy2(probe_summary_path, backup_path)

    before = h7_summary.get("before", {})
    after = h7_summary.get("after", {})

    h7_record = {
        "schema": "s3.m245.h7.probe_window_cache_view.v1",
        "created_at_utc": created,
        "probe_id": args.probe_id,
        "window_id": args.window_id,
        "run_dir": str(run_dir),
        "validator": "routinator",
        "validator_update_policy": "scheduled_refresh_plus_noupdate_observation",
        "validator_update_mode": "noupdate",
        "validator_cache_view_type": "logical_cache_index_lite",
        "validator_logical_cache_index_root": root,
        "validator_logical_cache_index_root_method": "logical_cache_index_lite_path_size_embedded_uri_v1",
        "logical_cache_index_stable": stable,
        "before_record_count": before.get("record_count"),
        "after_record_count": after.get("record_count"),
        "before_class_count": before.get("class_count"),
        "after_class_count": after.get("class_count"),
        "before_suffix_count": before.get("suffix_count"),
        "after_suffix_count": after.get("suffix_count"),
        "before_duration_sec": before.get("duration_sec"),
        "after_duration_sec": after.get("duration_sec"),
        "vrp_count_from_h7_export": h7_summary.get("vrp_count"),
        "vrp_export_duration_sec_from_h7": h7_summary.get("vrp_export_duration_sec"),
        "mapping_strength_candidate": mapping_candidate,
        "content_hash_computed": False,
        "accepted_object_set_available": False,
        "accepted_object_set_root": None,
        "h7_child_run_dir": str(h7_run_dir),
        "h7_summary_path": str(h7_summary_path),
        "h7_check_path": str(h7_check_path),
        "notes": [
            "validator_logical_cache_index_root_is_not_accepted_object_set",
            "medium_candidate_index_only_not_high_causality",
            "content_hash_not_computed",
            "manifest_effective_object_set_not_available",
        ],
        "hard_fail": hard_fail,
    }

    write_json(outputs_dir / "validator_cache_view_summary.json", h7_record)
    append_jsonl(indexes_dir / "validator_cache_view_records.jsonl", h7_record)

    if existing_summary:
        existing_summary["validator_cache_view_available"] = not hard_fail
        existing_summary["validator_cache_view_type"] = "logical_cache_index_lite"
        existing_summary["validator_logical_cache_index_root"] = root
        existing_summary["validator_logical_cache_index_root_method"] = "logical_cache_index_lite_path_size_embedded_uri_v1"
        existing_summary["validator_logical_cache_index_stable"] = stable
        existing_summary["validator_cache_view_mapping_strength_candidate"] = mapping_candidate
        existing_summary["validator_cache_view_content_hash_computed"] = False
        existing_summary["validator_cache_view_accepted_object_set_available"] = False
        existing_summary["validator_cache_view_h7_summary_path"] = str(h7_summary_path)
        write_json(probe_summary_path, existing_summary)

    status = "PASS" if not hard_fail else "FAIL"

    check_path = checks_dir / "H7_PROBE_WINDOW_CACHE_VIEW_ENRICH_CHECK.txt"
    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"H7_PROBE_WINDOW_CACHE_VIEW_ENRICH={status}\n\n")
        f.write(f"created_at_utc = {created}\n")
        f.write(f"probe_id = {args.probe_id}\n")
        f.write(f"window_id = {args.window_id}\n")
        f.write(f"run_dir = {run_dir}\n")
        f.write(f"validator_cache_view_available = {not hard_fail}\n")
        f.write(f"validator_cache_view_type = logical_cache_index_lite\n")
        f.write(f"validator_logical_cache_index_root = {root}\n")
        f.write(f"root_method = logical_cache_index_lite_path_size_embedded_uri_v1\n")
        f.write(f"logical_cache_index_stable = {stable}\n")
        f.write(f"before_record_count = {before.get('record_count')}\n")
        f.write(f"after_record_count = {after.get('record_count')}\n")
        f.write(f"mapping_strength_candidate = {mapping_candidate}\n")
        f.write(f"content_hash_computed = False\n")
        f.write(f"accepted_object_set_available = False\n")
        f.write(f"h7_child_run_dir = {h7_run_dir}\n")
        f.write(f"h7_summary_path = {h7_summary_path}\n")
        f.write(f"hard_fail = {hard_fail}\n")

    print(f"H7_PROBE_WINDOW_CACHE_VIEW_ENRICH_CHECK={check_path}")
    print(f"H7_PROBE_WINDOW_CACHE_VIEW_ENRICH_STATUS={status}")
    print(f"H7_PROBE_WINDOW_RUN_DIR={run_dir}")

    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
