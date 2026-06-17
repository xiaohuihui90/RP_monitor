from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def extract_ascii_strings(data: bytes) -> list[str]:
    text = "".join(chr(x) if 32 <= x <= 126 else "\n" for x in data)
    return [x.strip() for x in text.splitlines() if len(x.strip()) >= 6]


def extract_uris(data: bytes) -> dict[str, Any]:
    text = "".join(chr(x) if 32 <= x <= 126 else " " for x in data)

    rsyncs = re.findall(r"rsync://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", text)
    https = re.findall(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", text)

    return {
        "rsync_uri": rsyncs[0] if rsyncs else None,
        "rrdp_notification_uri": next((u for u in https if "notification.xml" in u), https[0] if https else None),
        "rsync_uri_count": len(rsyncs),
        "http_uri_count": len(https),
    }


def classify_path(rel: str) -> str:
    if rel.startswith("repository/stored/rrdp/"):
        return "stored_rrdp_wrapper"
    if rel.startswith("repository/stored/rsync/"):
        return "stored_rsync_wrapper"
    if rel.startswith("repository/rrdp/"):
        return "rrdp_container_or_state"
    if rel.startswith("repository/rsync/"):
        return "rsync_cache"
    return "other"


def snapshot_logical_index(cache_dir: Path, include_suffixes: set[str]) -> dict[str, Any]:
    start = time.time()
    created = utc_now()

    records = []
    suffix_count = {}
    class_count = {}
    parse_error_count = 0
    sample_records = []

    for root, _dirs, files in os.walk(cache_dir):
        for name in files:
            p = Path(root) / name
            try:
                if not p.is_file():
                    continue

                suffix = p.suffix.lower() or "<none>"
                if suffix not in include_suffixes:
                    continue

                rel = str(p.relative_to(cache_dir))
                st = p.stat()
                data = p.read_bytes()

                uris = extract_uris(data)
                cls = classify_path(rel)

                item = {
                    "path": rel,
                    "size": st.st_size,
                    "suffix": suffix,
                    "class": cls,
                    "rsync_uri": uris["rsync_uri"],
                    "rrdp_notification_uri": uris["rrdp_notification_uri"],
                }

                line = json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                records.append(line)

                suffix_count[suffix] = suffix_count.get(suffix, 0) + 1
                class_count[cls] = class_count.get(cls, 0) + 1

                if len(sample_records) < 30:
                    sample_records.append(item)

            except Exception:
                parse_error_count += 1

    records.sort()
    h = hashlib.sha256()
    for line in records:
        h.update(line.encode("utf-8"))
        h.update(b"\n")

    return {
        "created_at_utc": created,
        "cache_dir": str(cache_dir),
        "root_method": "logical_cache_index_path_size_embedded_uri_v1",
        "logical_cache_index_root": "sha256:" + h.hexdigest(),
        "record_count": len(records),
        "suffix_count": dict(sorted(suffix_count.items())),
        "class_count": dict(sorted(class_count.items())),
        "parse_error_count": parse_error_count,
        "duration_sec": round(time.time() - start, 3),
        "sample_records": sample_records,
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
    ap.add_argument("--include-suffixes", default=".mft,.roa,.cer,.crl,.asa,.bin")
    ap.add_argument("--keep-json", action="store_true")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    cache_dir = Path(args.cache_dir).expanduser().resolve()
    out_dir = Path(args.out_dir).resolve()

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    extras = out_dir / "extras"
    for d in [outputs, checks, extras]:
        d.mkdir(parents=True, exist_ok=True)

    created = utc_now()
    include_suffixes = {x.strip().lower() for x in args.include_suffixes.split(",") if x.strip()}

    lock_file = Path(f"/tmp/m245_validator_refresh_{args.probe_id}.lock")
    vrp_json = extras / f"{args.probe_id}_{args.window_id}_vrps_noupdate.json"

    hard_fail = []
    fh = None
    lock_wait_sec = None

    try:
        fh, lock_wait_sec = acquire_lock(lock_file, args.lock_timeout_sec)

        before = snapshot_logical_index(cache_dir, include_suffixes)

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

        after = snapshot_logical_index(cache_dir, include_suffixes)

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

    stable = (
        before.get("logical_cache_index_root")
        and before.get("logical_cache_index_root") == after.get("logical_cache_index_root")
        and before.get("record_count") == after.get("record_count")
    )

    if hard_fail:
        status = "FAIL"
        mapping_strength_candidate = "none"
    elif stable:
        status = "PASS"
        mapping_strength_candidate = "medium_candidate_index_only"
    else:
        status = "PASS_WITH_UNSTABLE_LOGICAL_INDEX"
        mapping_strength_candidate = "weak"

    summary = {
        "schema": "s3.m245.h7.logical_cache_index_diagnosis.v1",
        "status": status,
        "created_at_utc": created,
        "probe_id": args.probe_id,
        "window_id": args.window_id,
        "lock_used": True,
        "lock_file": str(lock_file),
        "lock_wait_sec": lock_wait_sec,
        "include_suffixes": sorted(include_suffixes),
        "before": before,
        "after": after,
        "logical_cache_index_stable": bool(stable),
        "validator_logical_cache_index_root": after.get("logical_cache_index_root"),
        "vrp_count": vrp_count,
        "vrp_record_key": vrp_key,
        "vrp_export_duration_sec": export_duration_sec,
        "mapping_strength_candidate": mapping_strength_candidate,
        "content_hash_computed": False,
        "accepted_object_set_available": False,
        "hard_fail": hard_fail,
        "notes": [
            "logical_cache_index_root_uses_embedded_uri_not_wrapper_content_hash",
            "validator_logical_cache_index_root_is_not_accepted_object_set",
            "medium_candidate_index_only_not_high_causality",
        ],
    }

    (outputs / "validator_logical_cache_index_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    if vrp_json.exists() and not args.keep_json:
        vrp_json.unlink()

    check_path = checks / "H7_LOGICAL_CACHE_INDEX_CHECK.txt"
    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"H7_LOGICAL_CACHE_INDEX={status}\n\n")
        f.write(f"created_at_utc = {created}\n")
        f.write(f"probe_id = {args.probe_id}\n")
        f.write(f"window_id = {args.window_id}\n")
        f.write(f"lock_used = True\n")
        f.write(f"lock_wait_sec = {lock_wait_sec}\n")
        f.write(f"root_method = logical_cache_index_path_size_embedded_uri_v1\n")
        f.write(f"before_root = {before.get('logical_cache_index_root')}\n")
        f.write(f"after_root = {after.get('logical_cache_index_root')}\n")
        f.write(f"logical_cache_index_stable = {bool(stable)}\n")
        f.write(f"before_record_count = {before.get('record_count')}\n")
        f.write(f"after_record_count = {after.get('record_count')}\n")
        f.write(f"before_class_count = {before.get('class_count')}\n")
        f.write(f"after_class_count = {after.get('class_count')}\n")
        f.write(f"before_suffix_count = {before.get('suffix_count')}\n")
        f.write(f"after_suffix_count = {after.get('suffix_count')}\n")
        f.write(f"vrp_count = {vrp_count}\n")
        f.write(f"vrp_export_duration_sec = {export_duration_sec}\n")
        f.write(f"mapping_strength_candidate = {mapping_strength_candidate}\n")
        f.write(f"content_hash_computed = False\n")
        f.write(f"accepted_object_set_available = False\n")
        f.write(f"hard_fail = {hard_fail}\n")
        f.write(f"summary_path = {outputs / 'validator_logical_cache_index_summary.json'}\n")

    print(f"H7_LOGICAL_CACHE_INDEX_CHECK={check_path}")
    print(f"H7_LOGICAL_CACHE_INDEX_STATUS={status}")

    if status == "FAIL":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
