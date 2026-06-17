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
    error_count = 0
    total_bytes = 0

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

    duration_sec = round(time.time() - start, 3)

    root_size_mtime = hashlib.sha256()
    root_size_only = hashlib.sha256()

    for rel in sorted(entries):
        item = entries[rel]
        root_size_mtime.update(
            f"{rel}\0{item['size']}\0{item['mtime_ns']}\n".encode("utf-8")
        )
        root_size_only.update(
            f"{rel}\0{item['size']}\n".encode("utf-8")
        )

    return {
        "created_at_utc": created_at,
        "cache_dir": str(cache_dir),
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "total_mb": round(total_bytes / 1024 / 1024, 2),
        "error_count": error_count,
        "duration_sec": duration_sec,
        "suffix_count_top": dict(sorted(suffix_count.items(), key=lambda x: x[1], reverse=True)[:30]),
        "root_size_mtime_method": "sorted_relative_path_size_mtime_ns_v1",
        "root_size_mtime": "sha256:" + root_size_mtime.hexdigest(),
        "root_size_only_method": "sorted_relative_path_size_v1",
        "root_size_only": "sha256:" + root_size_only.hexdigest(),
        "entries": entries,
    }


def diff_snapshots(before: dict[str, Any], after: dict[str, Any], sample_limit: int) -> dict[str, Any]:
    b = before.get("entries", {})
    a = after.get("entries", {})

    b_keys = set(b)
    a_keys = set(a)

    added = sorted(a_keys - b_keys)
    removed = sorted(b_keys - a_keys)

    size_changed = []
    mtime_only_changed = []
    size_and_mtime_changed = []
    unchanged = 0

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
            size_and_mtime_changed.append(rel)
            bump(suffix, "size_and_mtime_changed")
        elif size_changed_flag:
            size_changed.append(rel)
            bump(suffix, "size_changed")
        elif mtime_changed_flag:
            mtime_only_changed.append(rel)
            bump(suffix, "mtime_only_changed")
        else:
            unchanged += 1

    for rel in added:
        bump(a[rel].get("suffix", "<none>"), "added")
    for rel in removed:
        bump(b[rel].get("suffix", "<none>"), "removed")

    root_size_mtime_stable = before.get("root_size_mtime") == after.get("root_size_mtime")
    root_size_only_stable = before.get("root_size_only") == after.get("root_size_only")

    if root_size_only_stable and not root_size_mtime_stable:
        suggested = "sorted_relative_path_size_v1"
        interpretation = "metadata_mtime_only_instability"
    elif root_size_only_stable and root_size_mtime_stable:
        suggested = "sorted_relative_path_size_mtime_ns_v1"
        interpretation = "cache_metadata_stable"
    else:
        suggested = "no_stable_metadata_root_keep_weak_or_try_content_hash"
        interpretation = "path_or_size_changed"

    return {
        "root_size_mtime_stable": root_size_mtime_stable,
        "root_size_only_stable": root_size_only_stable,
        "added_count": len(added),
        "removed_count": len(removed),
        "size_changed_count": len(size_changed),
        "mtime_only_changed_count": len(mtime_only_changed),
        "size_and_mtime_changed_count": len(size_and_mtime_changed),
        "unchanged_count": unchanged,
        "sample_added": added[:sample_limit],
        "sample_removed": removed[:sample_limit],
        "sample_size_changed": size_changed[:sample_limit],
        "sample_mtime_only_changed": mtime_only_changed[:sample_limit],
        "sample_size_and_mtime_changed": size_and_mtime_changed[:sample_limit],
        "suffix_delta": suffix_delta,
        "suggested_cache_root_method": suggested,
        "interpretation": interpretation,
    }


def read_vrp_count(path: Path) -> tuple[int | None, str | None]:
    if not path.exists() or path.stat().st_size == 0:
        return None, None

    obj = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(obj, list):
        return len(obj), "list"

    if isinstance(obj, dict):
        for k in ["roas", "vrps", "validated_roa_payloads", "validated_roas", "payloads"]:
            v = obj.get(k)
            if isinstance(v, list):
                return len(v), k

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
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--cache-dir", default=str(Path.home() / ".rpki-cache"))
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--timeout-sec", type=int, default=2400)
    ap.add_argument("--lock-timeout-sec", type=int, default=600)
    ap.add_argument("--vrp-count-low-threshold", type=int, default=500000)
    ap.add_argument("--sample-limit", type=int, default=30)
    ap.add_argument("--keep-json", action="store_true")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    cache_dir = Path(args.cache_dir).expanduser().resolve()
    out_dir = Path(args.out_dir).resolve()

    outputs_dir = out_dir / "outputs"
    checks_dir = out_dir / "checks"
    extras_dir = out_dir / "extras"

    outputs_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)
    extras_dir.mkdir(parents=True, exist_ok=True)

    created_at = utc_now()
    lock_file = Path(f"/tmp/m245_validator_refresh_{args.probe_id}.lock")
    vrp_json = extras_dir / f"{args.probe_id}_{args.window_id}_vrps_noupdate.json"
    stdout_path = extras_dir / "routinator_noupdate_stdout.txt"
    stderr_path = extras_dir / "routinator_noupdate_stderr.txt"

    hard_fail = []
    lock_fh = None
    lock_wait_sec = None

    before = {}
    after = {}
    delta = {}
    return_code = None
    export_duration_sec = None
    warnings = []
    vrp_count = None
    vrp_record_key = None

    try:
        lock_fh, lock_wait_sec = acquire_lock(lock_file, args.lock_timeout_sec)

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

        warnings = classify_warnings(stderr_text)
        vrp_count, vrp_record_key = read_vrp_count(vrp_json)

        after = snapshot_cache(cache_dir)
        delta = diff_snapshots(before, after, args.sample_limit)

    except Exception as e:
        hard_fail.append(str(e))

    finally:
        if lock_fh is not None:
            release_lock(lock_fh)

    if return_code not in [0, None]:
        hard_fail.append(f"routinator_return_code_{return_code}")
    if vrp_count is None:
        hard_fail.append("vrp_count_missing")
    elif vrp_count < args.vrp_count_low_threshold:
        hard_fail.append("vrp_count_below_threshold")

    if not before or not after:
        hard_fail.append("snapshot_missing")

    status = "PASS" if not hard_fail else "FAIL"

    summary = {
        "schema": "s3.m245.h7.cache_delta_diagnosis.v1",
        "status": status,
        "created_at_utc": created_at,
        "probe_id": args.probe_id,
        "window_id": args.window_id,
        "cache_dir": str(cache_dir),
        "lock_used": True,
        "lock_file": str(lock_file),
        "lock_wait_sec": lock_wait_sec,
        "before": {k: v for k, v in before.items() if k != "entries"},
        "after": {k: v for k, v in after.items() if k != "entries"},
        "delta": delta,
        "routinator_return_code": return_code,
        "vrp_export_duration_sec": export_duration_sec,
        "vrp_count": vrp_count,
        "vrp_record_key": vrp_record_key,
        "warnings": warnings,
        "hard_fail": hard_fail,
    }

    write_json(outputs_dir / "validator_cache_delta_diagnosis_summary.json", summary)

    if vrp_json.exists() and not args.keep_json:
        vrp_json.unlink()

    check_path = checks_dir / "H7_CACHE_DELTA_DIAGNOSIS_CHECK.txt"

    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"H7_CACHE_DELTA_DIAGNOSIS={status}\n\n")
        f.write(f"created_at_utc = {created_at}\n")
        f.write(f"probe_id = {args.probe_id}\n")
        f.write(f"window_id = {args.window_id}\n")
        f.write(f"lock_used = True\n")
        f.write(f"lock_file = {lock_file}\n")
        f.write(f"lock_wait_sec = {lock_wait_sec}\n")
        f.write(f"before_root_size_mtime = {before.get('root_size_mtime')}\n")
        f.write(f"after_root_size_mtime = {after.get('root_size_mtime')}\n")
        f.write(f"before_root_size_only = {before.get('root_size_only')}\n")
        f.write(f"after_root_size_only = {after.get('root_size_only')}\n")
        f.write(f"root_size_mtime_stable = {delta.get('root_size_mtime_stable')}\n")
        f.write(f"root_size_only_stable = {delta.get('root_size_only_stable')}\n")
        f.write(f"added_count = {delta.get('added_count')}\n")
        f.write(f"removed_count = {delta.get('removed_count')}\n")
        f.write(f"size_changed_count = {delta.get('size_changed_count')}\n")
        f.write(f"mtime_only_changed_count = {delta.get('mtime_only_changed_count')}\n")
        f.write(f"size_and_mtime_changed_count = {delta.get('size_and_mtime_changed_count')}\n")
        f.write(f"suggested_cache_root_method = {delta.get('suggested_cache_root_method')}\n")
        f.write(f"interpretation = {delta.get('interpretation')}\n")
        f.write(f"vrp_count = {vrp_count}\n")
        f.write(f"vrp_export_duration_sec = {export_duration_sec}\n")
        f.write(f"warnings = {warnings}\n")
        f.write(f"hard_fail = {hard_fail}\n")
        f.write(f"summary_path = {outputs_dir / 'validator_cache_delta_diagnosis_summary.json'}\n")

    print(f"H7_CACHE_DELTA_DIAGNOSIS_CHECK={check_path}")
    print(f"H7_CACHE_DELTA_DIAGNOSIS_STATUS={status}")
    print(f"H7_ROOT_SIZE_MTIME_STABLE={delta.get('root_size_mtime_stable')}")
    print(f"H7_ROOT_SIZE_ONLY_STABLE={delta.get('root_size_only_stable')}")
    print(f"H7_SUGGESTED_CACHE_ROOT_METHOD={delta.get('suggested_cache_root_method')}")

    if status != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    main()
