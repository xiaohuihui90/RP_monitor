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


def sha256_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


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


def read_bytes(path: Path) -> bytes | None:
    if not path.exists() or not path.is_file():
        return None
    return path.read_bytes()


def byte_summary(b: bytes | None) -> dict[str, Any]:
    if b is None:
        return {
            "exists": False,
            "size": None,
            "sha256": None,
            "first16_hex": None,
            "last16_hex": None,
            "looks_der_sequence": False,
            "ascii_ratio": None,
            "ascii_preview": None,
        }

    printable = sum(1 for x in b if x in b"\r\n\t" or 32 <= x <= 126)
    ascii_ratio = round(printable / len(b), 4) if b else 0.0

    preview = "".join(chr(x) if x in b"\r\n\t" or 32 <= x <= 126 else "." for x in b[:200])

    return {
        "exists": True,
        "size": len(b),
        "sha256": sha256_bytes(b),
        "first16_hex": b[:16].hex(),
        "last16_hex": b[-16:].hex() if b else "",
        "looks_der_sequence": bool(len(b) >= 2 and b[0] == 0x30),
        "ascii_ratio": ascii_ratio,
        "ascii_preview": preview,
    }


def diff_bytes(before: bytes | None, after: bytes | None, max_positions: int = 50) -> dict[str, Any]:
    if before is None or after is None:
        return {
            "comparable": False,
            "same_size": None,
            "same_sha256": None,
            "diff_byte_count_prefix_aligned": None,
            "first_diff_positions": [],
        }

    n = min(len(before), len(after))
    positions = []
    diff_count = 0

    for i in range(n):
        if before[i] != after[i]:
            diff_count += 1
            if len(positions) < max_positions:
                positions.append({
                    "offset": i,
                    "before_hex": f"{before[i]:02x}",
                    "after_hex": f"{after[i]:02x}",
                    "before_chr": chr(before[i]) if 32 <= before[i] <= 126 else ".",
                    "after_chr": chr(after[i]) if 32 <= after[i] <= 126 else ".",
                })

    diff_count += abs(len(before) - len(after))

    return {
        "comparable": True,
        "same_size": len(before) == len(after),
        "same_sha256": sha256_bytes(before) == sha256_bytes(after),
        "diff_byte_count_prefix_aligned": diff_count,
        "first_diff_positions": positions,
    }


def load_candidate_paths(cache_dir: Path, max_paths: int) -> list[str]:
    candidates = []

    latest = sorted(
        Path("/tmp").glob("debug_m245_h7_cache_content_guard_probe_cd_*/outputs/validator_cache_content_sample_guard_summary.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if latest:
        s = json.loads(latest[0].read_text(encoding="utf-8"))
        for item in s.get("changed_sample", []) or []:
            p = item.get("path")
            if p:
                candidates.append(p)

    if not candidates:
        for p in sorted(cache_dir.glob("repository/stored/rrdp/**/*.mft")):
            try:
                candidates.append(str(p.relative_to(cache_dir)))
            except Exception:
                pass

    out = []
    seen = set()
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
    ap.add_argument("--max-sample-paths", type=int, default=30)
    ap.add_argument("--keep-json", action="store_true")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    cache_dir = Path(args.cache_dir).expanduser().resolve()
    out_dir = Path(args.out_dir).resolve()

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    extras = out_dir / "extras"
    copies = out_dir / "copies"

    for d in [outputs, checks, extras, copies]:
        d.mkdir(parents=True, exist_ok=True)

    created_at = utc_now()
    lock_file = Path(f"/tmp/m245_validator_refresh_{args.probe_id}.lock")
    vrp_json = extras / f"{args.probe_id}_{args.window_id}_vrps_noupdate.json"

    hard_fail = []
    fh = None
    lock_wait_sec = None
    sample_paths = load_candidate_paths(cache_dir, args.max_sample_paths)

    before_bytes = {}
    after_bytes = {}

    try:
        fh, lock_wait_sec = acquire_lock(lock_file, args.lock_timeout_sec)

        for rel in sample_paths:
            before_bytes[rel] = read_bytes(cache_dir / rel)
            if before_bytes[rel] is not None:
                safe = rel.replace("/", "__").replace(":", "_")
                (copies / f"before__{safe}").write_bytes(before_bytes[rel])

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

        for rel in sample_paths:
            after_bytes[rel] = read_bytes(cache_dir / rel)
            if after_bytes[rel] is not None:
                safe = rel.replace("/", "__").replace(":", "_")
                (copies / f"after__{safe}").write_bytes(after_bytes[rel])

        vrp_count, vrp_key = read_vrp_count(vrp_json)

        if proc.returncode != 0:
            hard_fail.append(f"routinator_return_code_{proc.returncode}")
        if vrp_count is None:
            hard_fail.append("vrp_count_missing")

    except Exception as e:
        export_duration_sec = None
        vrp_count = None
        vrp_key = None
        hard_fail.append(str(e))

    finally:
        if fh is not None:
            release_lock(fh)

    records = []

    for rel in sample_paths:
        b = before_bytes.get(rel)
        a = after_bytes.get(rel)

        rec = {
            "path": rel,
            "suffix": Path(rel).suffix.lower() or "<none>",
            "class": (
                "stored_rrdp_object_wrapper"
                if rel.startswith("repository/stored/rrdp/")
                else "rrdp_container_or_state"
                if rel.startswith("repository/rrdp/")
                else "other"
            ),
            "before": byte_summary(b),
            "after": byte_summary(a),
            "diff": diff_bytes(b, a),
        }
        records.append(rec)

    changed_records = [
        r for r in records
        if r["before"]["sha256"] != r["after"]["sha256"]
    ]

    same_size_changed = [
        r for r in changed_records
        if r["before"]["size"] == r["after"]["size"]
    ]

    looks_der_before_count = sum(1 for r in records if r["before"]["looks_der_sequence"])
    looks_der_after_count = sum(1 for r in records if r["after"]["looks_der_sequence"])

    avg_ascii_ratio_before = None
    vals = [r["before"]["ascii_ratio"] for r in records if r["before"]["ascii_ratio"] is not None]
    if vals:
        avg_ascii_ratio_before = round(sum(vals) / len(vals), 4)

    status = "PASS" if not hard_fail else "FAIL"

    summary = {
        "schema": "s3.m245.h7.cache_wrapper_diagnosis.v1",
        "status": status,
        "created_at_utc": created_at,
        "probe_id": args.probe_id,
        "window_id": args.window_id,
        "cache_dir": str(cache_dir),
        "lock_used": True,
        "lock_file": str(lock_file),
        "lock_wait_sec": lock_wait_sec,
        "sample_count": len(sample_paths),
        "changed_count": len(changed_records),
        "same_size_changed_count": len(same_size_changed),
        "looks_der_before_count": looks_der_before_count,
        "looks_der_after_count": looks_der_after_count,
        "avg_ascii_ratio_before": avg_ascii_ratio_before,
        "vrp_count": vrp_count,
        "vrp_record_key": vrp_key,
        "vrp_export_duration_sec": export_duration_sec,
        "records": records,
        "changed_records_sample": changed_records[:20],
        "hard_fail": hard_fail,
        "notes": [
            "diagnoses_routinator_cache_wrapper_not_validated_object_set",
            "do_not_use_wrapper_content_hash_as_medium_mapping_until_classified",
        ],
    }

    (outputs / "validator_cache_wrapper_diagnosis_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    if vrp_json.exists() and not args.keep_json:
        vrp_json.unlink()

    check_path = checks / "H7_CACHE_WRAPPER_DIAGNOSIS_CHECK.txt"
    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"H7_CACHE_WRAPPER_DIAGNOSIS={status}\n\n")
        f.write(f"created_at_utc = {created_at}\n")
        f.write(f"probe_id = {args.probe_id}\n")
        f.write(f"window_id = {args.window_id}\n")
        f.write(f"lock_used = True\n")
        f.write(f"lock_wait_sec = {lock_wait_sec}\n")
        f.write(f"sample_count = {len(sample_paths)}\n")
        f.write(f"changed_count = {len(changed_records)}\n")
        f.write(f"same_size_changed_count = {len(same_size_changed)}\n")
        f.write(f"looks_der_before_count = {looks_der_before_count}\n")
        f.write(f"looks_der_after_count = {looks_der_after_count}\n")
        f.write(f"avg_ascii_ratio_before = {avg_ascii_ratio_before}\n")
        f.write(f"vrp_count = {vrp_count}\n")
        f.write(f"vrp_export_duration_sec = {export_duration_sec}\n")
        f.write(f"hard_fail = {hard_fail}\n")
        f.write(f"summary_path = {outputs / 'validator_cache_wrapper_diagnosis_summary.json'}\n")

    print(f"H7_CACHE_WRAPPER_DIAGNOSIS_CHECK={check_path}")
    print(f"H7_CACHE_WRAPPER_DIAGNOSIS_STATUS={status}")

    if status == "FAIL":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
