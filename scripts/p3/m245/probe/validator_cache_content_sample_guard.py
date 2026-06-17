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


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


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


def load_candidate_paths(cache_dir: Path, max_paths: int) -> list[str]:
    candidates: list[str] = []

    latest_detail = sorted(
        Path("/tmp").glob("debug_m245_h7_cache_delta_detail_probe_cd_*/outputs/validator_cache_delta_detail_summary.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if latest_detail:
        s = json.loads(latest_detail[0].read_text(encoding="utf-8"))
        d = s.get("delta", {})
        for key in [
            "size_and_mtime_changed_detail_sample",
            "size_changed_detail_sample",
            "mtime_only_changed_detail_sample",
        ]:
            for item in d.get(key, []) or []:
                p = item.get("path")
                if p:
                    candidates.append(p)

    for p in sorted(cache_dir.rglob("*.bin")):
        try:
            candidates.append(str(p.relative_to(cache_dir)))
        except Exception:
            pass

    seen = set()
    out = []
    for p in candidates:
        if p in seen:
            continue
        seen.add(p)
        out.append(p)
        if len(out) >= max_paths:
            break

    return out


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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--cache-dir", default=str(Path.home() / ".rpki-cache"))
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--timeout-sec", type=int, default=2400)
    ap.add_argument("--lock-timeout-sec", type=int, default=600)
    ap.add_argument("--max-sample-paths", type=int, default=300)
    ap.add_argument("--vrp-count-low-threshold", type=int, default=500000)
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

    created_at = utc_now()
    lock_file = Path(f"/tmp/m245_validator_refresh_{args.probe_id}.lock")
    vrp_json = extras / f"{args.probe_id}_{args.window_id}_vrps_noupdate.json"

    hard_fail: list[str] = []
    lock_wait_sec = None
    fh = None

    candidates = load_candidate_paths(cache_dir, args.max_sample_paths)

    try:
        fh, lock_wait_sec = acquire_lock(lock_file, args.lock_timeout_sec)

        before = {}
        for rel in candidates:
            before[rel] = sha256_file(cache_dir / rel)

        start = time.time()
        proc = subprocess.run(
            [
                "routinator",
                "vrps",
                "--format",
                "json",
                "--noupdate",
                "--output",
                str(vrp_json),
            ],
            cwd=str(project_dir),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.timeout_sec,
        )
        export_duration_sec = round(time.time() - start, 3)

        (extras / "routinator_stdout.txt").write_text(proc.stdout or "", encoding="utf-8")
        (extras / "routinator_stderr.txt").write_text(proc.stderr or "", encoding="utf-8")

        after = {}
        for rel in candidates:
            after[rel] = sha256_file(cache_dir / rel)

        vrp_count, vrp_key = read_vrp_count(vrp_json)

        if proc.returncode != 0:
            hard_fail.append(f"routinator_return_code_{proc.returncode}")
        if vrp_count is None or vrp_count < args.vrp_count_low_threshold:
            hard_fail.append("vrp_count_missing_or_low")

    except Exception as e:
        before = {}
        after = {}
        export_duration_sec = None
        vrp_count = None
        vrp_key = None
        hard_fail.append(str(e))
    finally:
        if fh:
            release_lock(fh)

    changed = []
    missing_before = []
    missing_after = []

    for rel in candidates:
        b = before.get(rel)
        a = after.get(rel)
        if b is None:
            missing_before.append(rel)
        elif a is None:
            missing_after.append(rel)
        elif b != a:
            changed.append({
                "path": rel,
                "before_sha256": b,
                "after_sha256": a,
            })

    content_sample_stable = not changed and not missing_before and not missing_after

    if hard_fail:
        status = "FAIL"
    elif content_sample_stable:
        status = "PASS"
    else:
        status = "PASS_WITH_CONTENT_SAMPLE_CHANGE"

    summary = {
        "schema": "s3.m245.h7.cache_content_sample_guard.v1",
        "status": status,
        "created_at_utc": created_at,
        "probe_id": args.probe_id,
        "window_id": args.window_id,
        "cache_dir": str(cache_dir),
        "lock_used": True,
        "lock_file": str(lock_file),
        "lock_wait_sec": lock_wait_sec,
        "sample_count": len(candidates),
        "content_sample_stable": content_sample_stable,
        "changed_count": len(changed),
        "missing_before_count": len(missing_before),
        "missing_after_count": len(missing_after),
        "changed_sample": changed[:30],
        "missing_before_sample": missing_before[:30],
        "missing_after_sample": missing_after[:30],
        "vrp_count": vrp_count,
        "vrp_record_key": vrp_key,
        "vrp_export_duration_sec": export_duration_sec,
        "hard_fail": hard_fail,
        "notes": [
            "sampled_content_hash_guard_only",
            "full_content_hash_not_computed",
            "validator_cache_root_is_not_accepted_object_set",
        ],
    }

    (outputs / "validator_cache_content_sample_guard_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    if vrp_json.exists() and not args.keep_json:
        vrp_json.unlink()

    check_path = checks / "H7_CACHE_CONTENT_SAMPLE_GUARD_CHECK.txt"
    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"H7_CACHE_CONTENT_SAMPLE_GUARD={status}\n\n")
        f.write(f"created_at_utc = {created_at}\n")
        f.write(f"probe_id = {args.probe_id}\n")
        f.write(f"window_id = {args.window_id}\n")
        f.write(f"lock_used = True\n")
        f.write(f"lock_wait_sec = {lock_wait_sec}\n")
        f.write(f"sample_count = {len(candidates)}\n")
        f.write(f"content_sample_stable = {content_sample_stable}\n")
        f.write(f"changed_count = {len(changed)}\n")
        f.write(f"missing_before_count = {len(missing_before)}\n")
        f.write(f"missing_after_count = {len(missing_after)}\n")
        f.write(f"vrp_count = {vrp_count}\n")
        f.write(f"vrp_export_duration_sec = {export_duration_sec}\n")
        f.write(f"hard_fail = {hard_fail}\n")
        f.write(f"summary_path = {outputs / 'validator_cache_content_sample_guard_summary.json'}\n")

    print(f"H7_CACHE_CONTENT_SAMPLE_GUARD_CHECK={check_path}")
    print(f"H7_CACHE_CONTENT_SAMPLE_GUARD_STATUS={status}")

    if status == "FAIL":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
