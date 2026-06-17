from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


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


def snapshot(cache_dir: Path) -> dict[str, Any]:
    entries = {}
    total_bytes = 0
    start = time.time()

    for root, _dirs, files in os.walk(cache_dir):
        for name in files:
            p = Path(root) / name
            try:
                if not p.is_file():
                    continue
                st = p.stat()
                rel = str(p.relative_to(cache_dir))
                entries[rel] = {
                    "size": st.st_size,
                    "mtime_ns": st.st_mtime_ns,
                    "suffix": p.suffix.lower() or "<none>",
                }
                total_bytes += st.st_size
            except Exception:
                pass

    h_size = hashlib.sha256()
    h_size_mtime = hashlib.sha256()

    for rel in sorted(entries):
        e = entries[rel]
        h_size.update(f"{rel}\0{e['size']}\n".encode())
        h_size_mtime.update(f"{rel}\0{e['size']}\0{e['mtime_ns']}\n".encode())

    return {
        "created_at_utc": utc_now(),
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "total_mb": round(total_bytes / 1024 / 1024, 2),
        "duration_sec": round(time.time() - start, 3),
        "root_size_only": "sha256:" + h_size.hexdigest(),
        "root_size_mtime": "sha256:" + h_size_mtime.hexdigest(),
        "entries": entries,
    }


def diff(before: dict[str, Any], after: dict[str, Any], limit: int) -> dict[str, Any]:
    b = before["entries"]
    a = after["entries"]

    added = sorted(set(a) - set(b))
    removed = sorted(set(b) - set(a))

    size_changed = []
    mtime_only_changed = []
    size_and_mtime_changed = []

    for rel in sorted(set(a) & set(b)):
        bi = b[rel]
        ai = a[rel]
        size_changed_flag = bi["size"] != ai["size"]
        mtime_changed_flag = bi["mtime_ns"] != ai["mtime_ns"]

        item = {
            "path": rel,
            "suffix": ai.get("suffix") or bi.get("suffix"),
            "before_size": bi["size"],
            "after_size": ai["size"],
            "before_mtime_ns": bi["mtime_ns"],
            "after_mtime_ns": ai["mtime_ns"],
            "size_delta": ai["size"] - bi["size"],
        }

        if size_changed_flag and mtime_changed_flag:
            size_and_mtime_changed.append(item)
        elif size_changed_flag:
            size_changed.append(item)
        elif mtime_changed_flag:
            mtime_only_changed.append(item)

    return {
        "root_size_only_stable": before["root_size_only"] == after["root_size_only"],
        "root_size_mtime_stable": before["root_size_mtime"] == after["root_size_mtime"],
        "added_count": len(added),
        "removed_count": len(removed),
        "size_changed_count": len(size_changed),
        "mtime_only_changed_count": len(mtime_only_changed),
        "size_and_mtime_changed_count": len(size_and_mtime_changed),
        "added_sample": added[:limit],
        "removed_sample": removed[:limit],
        "size_changed_detail_sample": size_changed[:limit],
        "mtime_only_changed_detail_sample": mtime_only_changed[:limit],
        "size_and_mtime_changed_detail_sample": size_and_mtime_changed[:limit],
    }


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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--cache-dir", default=str(Path.home() / ".rpki-cache"))
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--timeout-sec", type=int, default=2400)
    ap.add_argument("--lock-timeout-sec", type=int, default=600)
    ap.add_argument("--sample-limit", type=int, default=100)
    ap.add_argument("--keep-json", action="store_true")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    cache_dir = Path(args.cache_dir).expanduser().resolve()
    out_dir = Path(args.out_dir).resolve()
    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    extras = out_dir / "extras"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)
    extras.mkdir(parents=True, exist_ok=True)

    lock_file = Path(f"/tmp/m245_validator_refresh_{args.probe_id}.lock")
    vrp_json = extras / f"{args.probe_id}_{args.window_id}_vrps_noupdate.json"

    hard_fail = []
    fh = None
    lock_wait_sec = None

    try:
        fh, lock_wait_sec = acquire_lock(lock_file, args.lock_timeout_sec)

        before = snapshot(cache_dir)

        cmd = [
            "routinator", "vrps",
            "--format", "json",
            "--noupdate",
            "--output", str(vrp_json),
        ]

        start = time.time()
        proc = subprocess.run(
            cmd,
            cwd=str(project_dir),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.timeout_sec,
        )
        export_duration_sec = round(time.time() - start, 3)

        (extras / "routinator_stdout.txt").write_text(proc.stdout or "", encoding="utf-8")
        (extras / "routinator_stderr.txt").write_text(proc.stderr or "", encoding="utf-8")

        after = snapshot(cache_dir)
        delta = diff(before, after, args.sample_limit)
        vrp_count, vrp_record_key = read_vrp_count(vrp_json)

        if proc.returncode != 0:
            hard_fail.append(f"routinator_return_code_{proc.returncode}")
        if vrp_count is None:
            hard_fail.append("vrp_count_missing")

    except Exception as e:
        before = {}
        after = {}
        delta = {}
        export_duration_sec = None
        vrp_count = None
        vrp_record_key = None
        hard_fail.append(str(e))
    finally:
        if fh:
            release_lock(fh)

    status = "PASS" if not hard_fail else "FAIL"

    if vrp_json.exists() and not args.keep_json:
        vrp_json.unlink()

    summary = {
        "schema": "s3.m245.h7.cache_delta_detail_diagnosis.v1",
        "status": status,
        "created_at_utc": utc_now(),
        "probe_id": args.probe_id,
        "window_id": args.window_id,
        "cache_dir": str(cache_dir),
        "lock_used": True,
        "lock_file": str(lock_file),
        "lock_wait_sec": lock_wait_sec,
        "before": {k: v for k, v in before.items() if k != "entries"},
        "after": {k: v for k, v in after.items() if k != "entries"},
        "delta": delta,
        "vrp_count": vrp_count,
        "vrp_record_key": vrp_record_key,
        "vrp_export_duration_sec": export_duration_sec,
        "hard_fail": hard_fail,
    }

    write_json(outputs / "validator_cache_delta_detail_summary.json", summary)

    check_path = checks / "H7_CACHE_DELTA_DETAIL_CHECK.txt"
    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"H7_CACHE_DELTA_DETAIL={status}\n\n")
        f.write(f"created_at_utc = {summary['created_at_utc']}\n")
        f.write(f"probe_id = {args.probe_id}\n")
        f.write(f"window_id = {args.window_id}\n")
        f.write(f"lock_used = True\n")
        f.write(f"lock_wait_sec = {lock_wait_sec}\n")
        f.write(f"root_size_only_stable = {delta.get('root_size_only_stable')}\n")
        f.write(f"root_size_mtime_stable = {delta.get('root_size_mtime_stable')}\n")
        f.write(f"added_count = {delta.get('added_count')}\n")
        f.write(f"removed_count = {delta.get('removed_count')}\n")
        f.write(f"size_changed_count = {delta.get('size_changed_count')}\n")
        f.write(f"mtime_only_changed_count = {delta.get('mtime_only_changed_count')}\n")
        f.write(f"size_and_mtime_changed_count = {delta.get('size_and_mtime_changed_count')}\n")
        f.write(f"vrp_count = {vrp_count}\n")
        f.write(f"vrp_export_duration_sec = {export_duration_sec}\n")
        f.write(f"hard_fail = {hard_fail}\n")
        f.write(f"summary_path = {outputs / 'validator_cache_delta_detail_summary.json'}\n")

    print(f"H7_CACHE_DELTA_DETAIL_CHECK={check_path}")
    print(f"H7_CACHE_DELTA_DETAIL_STATUS={status}")


if __name__ == "__main__":
    main()
