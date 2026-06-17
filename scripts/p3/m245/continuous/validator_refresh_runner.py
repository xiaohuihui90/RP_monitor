from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_jsonl(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")


def read_vrp_count(path: Path) -> tuple[int | None, str | None]:
    if not path.exists() or path.stat().st_size == 0:
        return None, None

    obj = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(obj, list):
        return len(obj), "list"

    if isinstance(obj, dict):
        for k in ["roas", "vrps", "validated_roa_payloads", "validated_roas", "payloads"]:
            if isinstance(obj.get(k), list):
                return len(obj[k]), k

    return 0, "unknown"


def classify_warnings(stderr_text: str) -> list[str]:
    txt = stderr_text.lower()
    warnings = []

    if "timed out" in txt or "operation timed out" in txt:
        warnings.append("timeout_warning_observed")
    if "lacnic" in txt:
        warnings.append("lacnic_warning_observed")
    if "failed to process snapshot" in txt:
        warnings.append("rrdp_snapshot_process_warning_observed")
    if "failed" in txt:
        warnings.append("generic_failed_warning_observed")

    return sorted(set(warnings))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--refresh-mode", default="manual_bootstrap_refresh")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--timeout-sec", type=int, default=2400)
    ap.add_argument("--vrp-count-low-threshold", type=int, default=500000)
    ap.add_argument("--keep-json", action="store_true")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    data_dir = project_dir / "data/probe/m245_three_layer_baseline/validator_refresh"
    records_path = data_dir / "validator_refresh_records.jsonl"
    health_path = data_dir / "validator_cache_health_records.jsonl"

    created_at = utc_now()
    vrp_json = out_dir / f"{args.probe_id}_validator_refresh_vrps.json"
    stdout_path = out_dir / "validator_refresh_stdout.txt"
    stderr_path = out_dir / "validator_refresh_stderr.txt"

    cmd = [
        "routinator",
        "vrps",
        "--format",
        "json",
        "--output",
        str(vrp_json),
    ]

    start = time.time()
    timed_out = False

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(project_dir),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.timeout_sec,
        )
        return_code = proc.returncode
        stdout_text = proc.stdout or ""
        stderr_text = proc.stderr or ""
    except subprocess.TimeoutExpired as e:
        timed_out = True
        return_code = 124
        stdout_text = e.stdout if isinstance(e.stdout, str) else ""
        stderr_text = e.stderr if isinstance(e.stderr, str) else ""
        stderr_text += f"\nTIMEOUT_AFTER_{args.timeout_sec}_SEC\n"

    duration_sec = round(time.time() - start, 3)

    stdout_path.write_text(stdout_text, encoding="utf-8")
    stderr_path.write_text(stderr_text, encoding="utf-8")

    vrp_count, record_key = read_vrp_count(vrp_json)
    json_size_bytes = vrp_json.stat().st_size if vrp_json.exists() else None
    warnings = classify_warnings(stderr_text)

    if return_code != 0:
        refresh_status = "failed"
        cache_health = "refresh_failed"
    elif vrp_count is None:
        refresh_status = "failed_no_json"
        cache_health = "refresh_failed"
    elif vrp_count < args.vrp_count_low_threshold:
        refresh_status = "low_count"
        cache_health = "suspicious_low_count"
    elif warnings:
        refresh_status = "ok_with_warning"
        cache_health = "ok"
    else:
        refresh_status = "ok"
        cache_health = "ok"

    record = {
        "schema": "s3.m245.validator_refresh_record.v1",
        "created_at_utc": created_at,
        "probe_id": args.probe_id,
        "validator": "routinator",
        "validator_update_policy": "scheduled_refresh_plus_noupdate_observation",
        "refresh_mode": args.refresh_mode,
        "command": " ".join(cmd),
        "return_code": return_code,
        "timed_out": timed_out,
        "duration_sec": duration_sec,
        "vrp_count": vrp_count,
        "record_key": record_key,
        "json_size_bytes": json_size_bytes,
        "stderr_warning_count": len(warnings),
        "warnings": warnings,
        "refresh_status": refresh_status,
        "cache_health": cache_health,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "vrp_json_path": str(vrp_json) if vrp_json.exists() else None,
    }

    health_record = {
        "schema": "s3.m245.validator_cache_health_record.v1",
        "created_at_utc": created_at,
        "probe_id": args.probe_id,
        "validator": "routinator",
        "validator_update_policy": "scheduled_refresh_plus_noupdate_observation",
        "cache_health": cache_health,
        "refresh_required": cache_health in ["suspicious_low_count", "refresh_failed"],
        "last_refresh_at_utc": created_at if cache_health == "ok" else None,
        "vrp_count": vrp_count,
        "refresh_status": refresh_status,
        "warnings": warnings,
    }

    append_jsonl(records_path, record)
    append_jsonl(health_path, health_record)

    status = "PASS" if cache_health == "ok" else "FAIL"

    summary = {
        "schema": "s3.m245.validator_refresh_summary.v1",
        "status": status,
        "created_at_utc": created_at,
        "probe_id": args.probe_id,
        "refresh_mode": args.refresh_mode,
        "refresh_status": refresh_status,
        "cache_health": cache_health,
        "vrp_count": vrp_count,
        "record_key": record_key,
        "duration_sec": duration_sec,
        "warnings": warnings,
        "records_path": str(records_path),
        "health_path": str(health_path),
        "kept_json": args.keep_json,
    }

    (out_dir / "validator_refresh_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    if vrp_json.exists() and not args.keep_json:
        vrp_json.unlink()

    check_path = out_dir / "VALIDATOR_REFRESH_CHECK.txt"
    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"VALIDATOR_REFRESH={status}\n\n")
        f.write(f"created_at_utc = {created_at}\n")
        f.write(f"probe_id = {args.probe_id}\n")
        f.write(f"refresh_mode = {args.refresh_mode}\n")
        f.write(f"refresh_status = {refresh_status}\n")
        f.write(f"cache_health = {cache_health}\n")
        f.write(f"vrp_count = {vrp_count}\n")
        f.write(f"duration_sec = {duration_sec}\n")
        f.write(f"warnings = {warnings}\n")
        f.write(f"records_path = {records_path}\n")
        f.write(f"health_path = {health_path}\n")
        f.write(f"kept_json = {args.keep_json}\n")

    print(f"VALIDATOR_REFRESH_CHECK={check_path}")
    print(f"VALIDATOR_REFRESH_STATUS={status}")
    print(f"VALIDATOR_REFRESH_CACHE_HEALTH={cache_health}")
    print(f"VALIDATOR_REFRESH_VRP_COUNT={vrp_count}")

    if status != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    main()
