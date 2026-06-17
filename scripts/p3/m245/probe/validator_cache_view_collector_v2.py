from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import time
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


def acquire_lock(lock_file: Path, timeout_sec: int):
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_file.open("a+")
    start = time.time()

    while True:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fh, round(time.time() - start, 3)
        except BlockingIOError:
            if time.time() - start > timeout_sec:
                fh.close()
                raise TimeoutError(f"failed_to_acquire_lock:{lock_file}")
            time.sleep(1)


def release_lock(fh) -> None:
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    finally:
        fh.close()


def snapshot_cache(cache_dir: Path) -> dict[str, Any]:
    created_at = utc_now()
    start = time.time()

    entries: dict[str, dict[str, Any]] = {}
    suffix_count: dict[str, int] = {}
    total_bytes = 0
    error_count = 0

    for root, _dirs, files in os.walk(cache_dir):
        for name in files:
            p = Path(root) / name
            try:
                if not p.is_file():
                    continue
                st = p.stat()
                rel = str(p.relative_to(cache_dir))
                suffix = p.suffix.lower() or "<none>"

                entries[rel] = {
                    "size": st.st_size,
                    "mtime_ns": st.st_mtime_ns,
                    "suffix": suffix,
                }

                total_bytes += st.st_size
                suffix_count[suffix] = suffix_count.get(suffix, 0) + 1
            except Exception:
                error_count += 1

    h_size = hashlib.sha256()
    h_size_mtime = hashlib.sha256()

    for rel in sorted(entries):
        e = entries[rel]
        h_size.update(f"{rel}\0{e['size']}\n".encode("utf-8"))
        h_size_mtime.update(f"{rel}\0{e['size']}\0{e['mtime_ns']}\n".encode("utf-8"))

    return {
        "created_at_utc": created_at,
        "cache_dir": str(cache_dir),
        "cache_dir_exists": cache_dir.exists(),
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "total_mb": round(total_bytes / 1024 / 1024, 2),
        "suffix_count_top": dict(sorted(suffix_count.items(), key=lambda x: x[1], reverse=True)[:30]),
        "error_count": error_count,
        "duration_sec": round(time.time() - start, 3),
        "root_size_only_method": "sorted_relative_path_size_v1",
        "root_size_only": "sha256:" + h_size.hexdigest(),
        "root_size_mtime_method": "sorted_relative_path_size_mtime_ns_v1",
        "root_size_mtime": "sha256:" + h_size_mtime.hexdigest(),
        "entries": entries,
    }


def diff_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    b = before.get("entries", {})
    a = after.get("entries", {})

    b_keys = set(b)
    a_keys = set(a)

    added = sorted(a_keys - b_keys)
    removed = sorted(b_keys - a_keys)

    size_changed = 0
    mtime_only_changed = 0
    size_and_mtime_changed = 0

    suffix_delta: dict[str, dict[str, int]] = {}

    def bump(suffix: str, key: str) -> None:
        suffix_delta.setdefault(suffix, {})
        suffix_delta[suffix][key] = suffix_delta[suffix].get(key, 0) + 1

    for rel in sorted(b_keys & a_keys):
        bi = b[rel]
        ai = a[rel]

        size_changed_flag = bi.get("size") != ai.get("size")
        mtime_changed_flag = bi.get("mtime_ns") != ai.get("mtime_ns")
        suffix = ai.get("suffix") or bi.get("suffix") or "<none>"

        if size_changed_flag and mtime_changed_flag:
            size_and_mtime_changed += 1
            bump(suffix, "size_and_mtime_changed")
        elif size_changed_flag:
            size_changed += 1
            bump(suffix, "size_changed")
        elif mtime_changed_flag:
            mtime_only_changed += 1
            bump(suffix, "mtime_only_changed")

    for rel in added:
        bump(a[rel].get("suffix", "<none>"), "added")
    for rel in removed:
        bump(b[rel].get("suffix", "<none>"), "removed")

    return {
        "root_size_only_stable": before.get("root_size_only") == after.get("root_size_only"),
        "root_size_mtime_stable": before.get("root_size_mtime") == after.get("root_size_mtime"),
        "added_count": len(added),
        "removed_count": len(removed),
        "size_changed_count": size_changed,
        "mtime_only_changed_count": mtime_only_changed,
        "size_and_mtime_changed_count": size_and_mtime_changed,
        "suffix_delta": suffix_delta,
    }


def read_vrp_payload(path: Path) -> tuple[list[Any], str | None]:
    obj = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(obj, list):
        return obj, "list"

    if isinstance(obj, dict):
        for k in ["roas", "vrps", "validated_roa_payloads", "validated_roas", "payloads"]:
            v = obj.get(k)
            if isinstance(v, list):
                return v, k

    return [], "unknown"


def compute_vrp_root(path: Path) -> dict[str, Any]:
    if not path.exists() or path.stat().st_size == 0:
        return {
            "vrp_count": None,
            "vrp_root": None,
            "record_key": None,
            "json_size_bytes": path.stat().st_size if path.exists() else None,
            "error": "vrp_json_missing_or_empty",
        }

    records, key = read_vrp_payload(path)

    encoded = [
        json.dumps(x, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for x in records
    ]
    encoded.sort()

    h = hashlib.sha256()
    for line in encoded:
        h.update(line.encode("utf-8"))
        h.update(b"\n")

    return {
        "vrp_count": len(records),
        "vrp_root": "sha256:" + h.hexdigest(),
        "record_key": key,
        "json_size_bytes": path.stat().st_size,
        "error": None,
    }


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
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--cache-dir", default=str(Path.home() / ".rpki-cache"))
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--timeout-sec", type=int, default=2400)
    ap.add_argument("--lock-timeout-sec", type=int, default=600)
    ap.add_argument("--vrp-count-low-threshold", type=int, default=500000)
    ap.add_argument(
        "--cache-root-method",
        default="sorted_relative_path_size_v1",
        choices=[
            "sorted_relative_path_size_v1",
            "sorted_relative_path_size_mtime_ns_v1",
        ],
    )
    ap.add_argument("--keep-json", action="store_true")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    cache_dir = Path(args.cache_dir).expanduser().resolve()
    out_dir = Path(args.out_dir).resolve()

    outputs_dir = out_dir / "outputs"
    checks_dir = out_dir / "checks"
    indexes_dir = out_dir / "indexes"
    extras_dir = out_dir / "extras"

    for d in [outputs_dir, checks_dir, indexes_dir, extras_dir]:
        d.mkdir(parents=True, exist_ok=True)

    created_at = utc_now()
    lock_file = Path(f"/tmp/m245_validator_refresh_{args.probe_id}.lock")
    global_record_path = project_dir / "data/probe/m245_three_layer_baseline/validator_cache_view/validator_cache_view_records.jsonl"

    vrp_json = extras_dir / f"{args.probe_id}_{args.window_id}_vrps_noupdate.json"
    stdout_path = extras_dir / "routinator_noupdate_stdout.txt"
    stderr_path = extras_dir / "routinator_noupdate_stderr.txt"

    hard_fail: list[str] = []
    lock_fh = None
    lock_wait_sec = None
    lock_acquired_at = None
    lock_released_at = None

    try:
        lock_fh, lock_wait_sec = acquire_lock(lock_file, args.lock_timeout_sec)
        lock_acquired_at = utc_now()

        before = snapshot_cache(cache_dir)

        cmd = [
            "routinator",
            "vrps",
            "--format",
            "json",
            "--noupdate",
            "--output",
            str(vrp_json),
        ]

        start = time.time()
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
            return_code = 124
            stdout_text = e.stdout if isinstance(e.stdout, str) else ""
            stderr_text = e.stderr if isinstance(e.stderr, str) else ""
            stderr_text += f"\nTIMEOUT_AFTER_{args.timeout_sec}_SEC\n"

        export_duration_sec = round(time.time() - start, 3)
        stdout_path.write_text(stdout_text, encoding="utf-8")
        stderr_path.write_text(stderr_text, encoding="utf-8")

        vrp = compute_vrp_root(vrp_json)
        warnings = classify_warnings(stderr_text)

        after = snapshot_cache(cache_dir)
        delta = diff_snapshots(before, after)

    except Exception as e:
        hard_fail.append(str(e))
        before = {}
        after = {}
        delta = {}
        return_code = None
        export_duration_sec = None
        warnings = []
        vrp = {
            "vrp_count": None,
            "vrp_root": None,
            "record_key": None,
            "json_size_bytes": None,
            "error": str(e),
        }

    finally:
        if lock_fh is not None:
            lock_released_at = utc_now()
            release_lock(lock_fh)

    if args.cache_root_method == "sorted_relative_path_size_v1":
        selected_before_root = before.get("root_size_only")
        selected_after_root = after.get("root_size_only")
        selected_stable = delta.get("root_size_only_stable")
        volatile_mtime = not bool(delta.get("root_size_mtime_stable"))
    else:
        selected_before_root = before.get("root_size_mtime")
        selected_after_root = after.get("root_size_mtime")
        selected_stable = delta.get("root_size_mtime_stable")
        volatile_mtime = False

    vrp_count = vrp.get("vrp_count")

    if return_code not in [0, None]:
        hard_fail.append(f"routinator_return_code_{return_code}")
    if vrp_count is None:
        hard_fail.append("vrp_count_missing")
    elif vrp_count < args.vrp_count_low_threshold:
        hard_fail.append("vrp_count_below_threshold")
    if not before.get("cache_dir_exists", False):
        hard_fail.append("cache_dir_missing")
    if before.get("file_count", 0) <= 0:
        hard_fail.append("cache_file_count_zero")

    if hard_fail:
        status = "FAIL"
        mapping_strength_candidate = "none"
        validation_output_quality = "failed"
    elif selected_stable and volatile_mtime:
        status = "PASS_WITH_VOLATILE_MTIME"
        mapping_strength_candidate = "medium_candidate"
        validation_output_quality = "ok"
    elif selected_stable:
        status = "PASS"
        mapping_strength_candidate = "medium_candidate"
        validation_output_quality = "ok"
    else:
        status = "PASS_WITH_UNSTABLE_CACHE"
        mapping_strength_candidate = "weak"
        validation_output_quality = "ok"

    record = {
        "schema": "s3.m245.validator_cache_view_record.v2",
        "created_at_utc": created_at,
        "probe_id": args.probe_id,
        "window_id": args.window_id,

        "validator": "routinator",
        "validator_update_policy": "scheduled_refresh_plus_noupdate_observation",
        "validator_update_mode": "noupdate",

        "lock_used": True,
        "lock_file": str(lock_file),
        "lock_wait_sec": lock_wait_sec,
        "lock_acquired_at_utc": lock_acquired_at,
        "lock_released_at_utc": lock_released_at,

        "cache_dir": str(cache_dir),
        "cache_root_method": args.cache_root_method,
        "cache_snapshot_before_root": selected_before_root,
        "cache_snapshot_after_root": selected_after_root,
        "validator_cache_root": selected_after_root,
        "cache_stable_during_export": bool(selected_stable),
        "cache_stability_basis": (
            "path_size_stable_mtime_volatile"
            if selected_stable and volatile_mtime
            else "selected_root_stable"
            if selected_stable
            else "selected_root_unstable"
        ),

        "root_size_only_before": before.get("root_size_only"),
        "root_size_only_after": after.get("root_size_only"),
        "root_size_only_stable": delta.get("root_size_only_stable"),
        "root_size_mtime_before": before.get("root_size_mtime"),
        "root_size_mtime_after": after.get("root_size_mtime"),
        "root_size_mtime_stable": delta.get("root_size_mtime_stable"),

        "cache_file_count_before": before.get("file_count"),
        "cache_file_count_after": after.get("file_count"),
        "cache_total_bytes_before": before.get("total_bytes"),
        "cache_total_bytes_after": after.get("total_bytes"),
        "cache_total_mb_after": after.get("total_mb"),
        "cache_snapshot_before_duration_sec": before.get("duration_sec"),
        "cache_snapshot_after_duration_sec": after.get("duration_sec"),

        "delta": delta,

        "vrp_export_return_code": return_code,
        "vrp_export_duration_sec": export_duration_sec,
        "vrp_count": vrp.get("vrp_count"),
        "vrp_root": vrp.get("vrp_root"),
        "vrp_record_key": vrp.get("record_key"),
        "vrp_json_size_bytes": vrp.get("json_size_bytes"),
        "vrp_error": vrp.get("error"),

        "warnings": warnings,
        "validation_output_quality": validation_output_quality,
        "mapping_strength_candidate": mapping_strength_candidate,

        "content_hash_computed": False,
        "notes": [
            "validator_cache_root_is_not_accepted_object_set",
            "size_only_cache_root_ignores_mtime_noise",
            "content_hash_not_computed",
            "accepted_object_set_not_available",
        ],

        "hard_fail": hard_fail,
    }

    write_json(outputs_dir / "validator_cache_view_summary.json", record)
    append_jsonl(indexes_dir / "validator_cache_view_records.jsonl", record)
    append_jsonl(global_record_path, record)

    if vrp_json.exists() and not args.keep_json:
        vrp_json.unlink()

    check_path = checks_dir / "VALIDATOR_CACHE_VIEW_V2_CHECK.txt"
    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"VALIDATOR_CACHE_VIEW_V2={status}\n\n")
        f.write(f"created_at_utc = {created_at}\n")
        f.write(f"probe_id = {args.probe_id}\n")
        f.write(f"window_id = {args.window_id}\n")
        f.write(f"cache_root_method = {args.cache_root_method}\n")
        f.write(f"lock_used = True\n")
        f.write(f"lock_wait_sec = {lock_wait_sec}\n")
        f.write(f"cache_snapshot_before_root = {selected_before_root}\n")
        f.write(f"cache_snapshot_after_root = {selected_after_root}\n")
        f.write(f"cache_stable_during_export = {bool(selected_stable)}\n")
        f.write(f"cache_stability_basis = {record['cache_stability_basis']}\n")
        f.write(f"root_size_only_stable = {delta.get('root_size_only_stable')}\n")
        f.write(f"root_size_mtime_stable = {delta.get('root_size_mtime_stable')}\n")
        f.write(f"added_count = {delta.get('added_count')}\n")
        f.write(f"removed_count = {delta.get('removed_count')}\n")
        f.write(f"size_changed_count = {delta.get('size_changed_count')}\n")
        f.write(f"mtime_only_changed_count = {delta.get('mtime_only_changed_count')}\n")
        f.write(f"size_and_mtime_changed_count = {delta.get('size_and_mtime_changed_count')}\n")
        f.write(f"cache_file_count_after = {after.get('file_count')}\n")
        f.write(f"cache_total_mb_after = {after.get('total_mb')}\n")
        f.write(f"vrp_count = {vrp.get('vrp_count')}\n")
        f.write(f"vrp_root = {vrp.get('vrp_root')}\n")
        f.write(f"vrp_export_duration_sec = {export_duration_sec}\n")
        f.write(f"validation_output_quality = {validation_output_quality}\n")
        f.write(f"mapping_strength_candidate = {mapping_strength_candidate}\n")
        f.write(f"content_hash_computed = False\n")
        f.write(f"warnings = {warnings}\n")
        f.write(f"hard_fail = {hard_fail}\n")
        f.write(f"summary_path = {outputs_dir / 'validator_cache_view_summary.json'}\n")
        f.write(f"records_path = {indexes_dir / 'validator_cache_view_records.jsonl'}\n")
        f.write(f"global_records_path = {global_record_path}\n")
        f.write(f"kept_json = {args.keep_json}\n")

    print(f"VALIDATOR_CACHE_VIEW_V2_CHECK={check_path}")
    print(f"VALIDATOR_CACHE_VIEW_V2_STATUS={status}")
    print(f"VALIDATOR_CACHE_ROOT_METHOD={args.cache_root_method}")
    print(f"VALIDATOR_CACHE_STABLE={bool(selected_stable)}")
    print(f"VALIDATOR_CACHE_MAPPING_CANDIDATE={mapping_strength_candidate}")
    print(f"VALIDATOR_CACHE_VRP_COUNT={vrp.get('vrp_count')}")

    if status == "FAIL":
        sys.exit(1)


if __name__ == "__main__":
    main()
