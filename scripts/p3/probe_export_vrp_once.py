#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def read_roas_count(raw_json: Path) -> tuple[int, str | None, dict[str, Any]]:
    obj = json.loads(raw_json.read_text(encoding="utf-8"))
    roas = obj.get("roas", [])
    if not isinstance(roas, list):
        raise ValueError("invalid_routinator_json_no_roas_list")
    metadata = obj.get("metadata", {}) if isinstance(obj.get("metadata"), dict) else {}
    generated_time = metadata.get("generatedTime")
    return len(roas), generated_time, metadata


def gzip_file(src: Path, dst: Path) -> None:
    with src.open("rb") as fin, gzip.open(dst, "wb", compresslevel=6) as fout:
        shutil.copyfileobj(fin, fout)


def run_cmd(cmd: list[str], stdout_path: Path, stderr_path: Path, timeout_seconds: int | None) -> int:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        proc = subprocess.run(cmd, stdout=out, stderr=err, timeout=timeout_seconds)
    return int(proc.returncode)


def get_version(routinator_bin: str) -> str | None:
    try:
        proc = subprocess.run(
            [routinator_bin, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
        text = (proc.stdout or proc.stderr or "").strip()
        return text or None
    except Exception:
        return None


def build_cmd(routinator_bin: str, raw_out: Path, noupdate: bool) -> list[str]:
    cmd = [
        routinator_bin,
        "vrps",
        "--format",
        "json",
    ]
    if noupdate:
        cmd.append("--noupdate")
    cmd.extend(["--output", str(raw_out)])
    return cmd


def validate_raw(raw_path: Path, min_roa_count: int, min_raw_json_size_bytes: int) -> tuple[bool, dict[str, Any]]:
    if not raw_path.exists():
        return False, {"reason": "raw_file_missing"}

    size = raw_path.stat().st_size
    try:
        roa_count, generated_time, metadata = read_roas_count(raw_path)
    except Exception as exc:
        return False, {
            "reason": "raw_json_parse_failed",
            "error": str(exc),
            "size_bytes": size,
        }

    ok = size >= min_raw_json_size_bytes and roa_count >= min_roa_count
    reason = "ok" if ok else "raw_too_small_or_roa_count_too_low"
    return ok, {
        "reason": reason,
        "size_bytes": size,
        "roa_count": roa_count,
        "generatedTime": generated_time,
        "metadata": metadata,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Probe-side one-shot Routinator VRP export package builder")
    ap.add_argument("--probe-id", required=True, help="probe-cd / probe-bj / probe-sg")
    ap.add_argument("--location", required=True, help="chengdu / beijing / singapore")
    ap.add_argument("--validator", default="routinator")
    ap.add_argument("--routinator-bin", default="routinator")
    ap.add_argument("--out-root", default="data/probe/m14_vrp_export")
    ap.add_argument("--prefer-noupdate", action="store_true")
    ap.add_argument("--allow-refresh-fallback", action="store_true")
    ap.add_argument("--min-roa-count", type=int, default=100000)
    ap.add_argument("--min-raw-json-size-bytes", type=int, default=10000000)
    ap.add_argument("--timeout-seconds", type=int, default=1800)
    ap.add_argument("--keep-raw-json", action="store_true", default=True)
    args = ap.parse_args()

    out_root = Path(args.out_root).resolve()
    export_id = utc_id()
    history_dir = out_root / "history" / export_id
    latest_dir = out_root / "latest"
    logs_dir = out_root / "logs"

    for d in [history_dir, latest_dir, logs_dir]:
        d.mkdir(parents=True, exist_ok=True)

    raw_path = history_dir / f"{args.probe_id}_vrps.raw.json"
    gzip_path = history_dir / f"{args.probe_id}_vrps.raw.json.gz"
    manifest_path = history_dir / "manifest.json"
    sha256_path = history_dir / "sha256.txt"
    acceptance_path = history_dir / "P3_probe_export_acceptance_check.txt"

    started_at = utc_now()
    validator_version = get_version(args.routinator_bin)

    attempts = []

    # Primary export.
    primary_noupdate = bool(args.prefer_noupdate)
    cmd = build_cmd(args.routinator_bin, raw_path, noupdate=primary_noupdate)
    ret = run_cmd(
        cmd,
        logs_dir / f"{export_id}_primary.out",
        logs_dir / f"{export_id}_primary.err",
        args.timeout_seconds,
    )
    ok, validation = validate_raw(raw_path, args.min_roa_count, args.min_raw_json_size_bytes)
    attempts.append({
        "name": "primary",
        "noupdate": primary_noupdate,
        "command": cmd,
        "returncode": ret,
        "validation": validation,
    })

    used_refresh = False

    # Fallback refresh if needed.
    if not ok and args.allow_refresh_fallback:
        fallback_raw = history_dir / f"{args.probe_id}_vrps.raw.refresh.json"
        cmd2 = build_cmd(args.routinator_bin, fallback_raw, noupdate=False)
        ret2 = run_cmd(
            cmd2,
            logs_dir / f"{export_id}_fallback_refresh.out",
            logs_dir / f"{export_id}_fallback_refresh.err",
            args.timeout_seconds,
        )
        ok2, validation2 = validate_raw(fallback_raw, args.min_roa_count, args.min_raw_json_size_bytes)
        attempts.append({
            "name": "fallback_refresh",
            "noupdate": False,
            "command": cmd2,
            "returncode": ret2,
            "validation": validation2,
        })
        if ok2:
            shutil.copy2(fallback_raw, raw_path)
            ok = True
            validation = validation2
            used_refresh = True

    if not ok:
        manifest = {
            "schema": "s3.stage3.m14.vrp_snapshot_manifest.v1",
            "probe_id": args.probe_id,
            "location": args.location,
            "validator": args.validator,
            "validator_version": validator_version,
            "export_started_at": started_at,
            "export_finished_at": utc_now(),
            "export_status": "failed",
            "used_refresh": used_refresh,
            "attempts": attempts,
            "error": "valid_raw_vrp_not_generated",
        }
        write_json(manifest_path, manifest)
        write_json(out_root / "state.json", {
            "last_success_at": None,
            "last_upload_status": None,
            "last_error": "valid_raw_vrp_not_generated",
            "last_export_id": export_id,
        })
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
        sys.exit(2)

    # Build gzip and hashes.
    gzip_file(raw_path, gzip_path)
    raw_sha256 = sha256_file(raw_path)
    gzip_sha256 = sha256_file(gzip_path)

    roa_count, generated_time, metadata = read_roas_count(raw_path)
    finished_at = utc_now()

    sha256_text = (
        f"{raw_sha256}  {raw_path.name}\n"
        f"{gzip_sha256}  {gzip_path.name}\n"
    )
    sha256_path.write_text(sha256_text, encoding="utf-8")

    manifest = {
        "schema": "s3.stage3.m14.vrp_snapshot_manifest.v1",
        "probe_id": args.probe_id,
        "location": args.location,
        "validator": args.validator,
        "validator_version": validator_version,
        "export_started_at": started_at,
        "export_finished_at": finished_at,
        "generatedTime": generated_time,
        "routinator_metadata": metadata,
        "raw_json_size_bytes": raw_path.stat().st_size,
        "gzip_size_bytes": gzip_path.stat().st_size,
        "roa_count": roa_count,
        "sha256_raw": raw_sha256,
        "sha256_gzip": gzip_sha256,
        "raw_json_file": str(raw_path),
        "gzip_file": str(gzip_path),
        "sha256_file": str(sha256_path),
        "used_refresh": used_refresh,
        "export_status": "success",
        "attempts": attempts,
        "upload_ready": True,
        "upload_status": "not_uploaded_p3_export_only"
    }
    write_json(manifest_path, manifest)

    # Copy to latest.
    shutil.copy2(raw_path, latest_dir / raw_path.name)
    shutil.copy2(gzip_path, latest_dir / gzip_path.name)
    shutil.copy2(manifest_path, latest_dir / "manifest.json")
    shutil.copy2(sha256_path, latest_dir / "sha256.txt")

    state = {
        "last_success_at": finished_at,
        "last_upload_status": "not_uploaded_p3_export_only",
        "last_roa_count": roa_count,
        "last_generatedTime": generated_time,
        "last_error": None,
        "last_export_id": export_id,
        "latest_dir": str(latest_dir),
    }
    write_json(out_root / "state.json", state)

    acceptance = f"""P3_PROBE_EXPORT_ONCE=DONE

probe_id = {args.probe_id}
location = {args.location}
export_id = {export_id}
out_root = {out_root}

export_status = success
upload_ready = True
upload_status = not_uploaded_p3_export_only
used_refresh = {used_refresh}

validator = {args.validator}
validator_version = {validator_version}
generatedTime = {generated_time}
roa_count = {roa_count}
raw_json_size_bytes = {raw_path.stat().st_size}
gzip_size_bytes = {gzip_path.stat().st_size}
sha256_raw = {raw_sha256}
sha256_gzip = {gzip_sha256}

outputs:
  {raw_path}
  {gzip_path}
  {manifest_path}
  {sha256_path}
  {latest_dir / 'manifest.json'}
  {latest_dir / 'sha256.txt'}

P3_export_acceptance = True
"""
    acceptance_path.write_text(acceptance, encoding="utf-8")
    shutil.copy2(acceptance_path, latest_dir / "P3_probe_export_acceptance_check.txt")

    print(json.dumps({
        "status": "done",
        "probe_id": args.probe_id,
        "location": args.location,
        "export_id": export_id,
        "roa_count": roa_count,
        "generatedTime": generated_time,
        "raw_json_size_bytes": raw_path.stat().st_size,
        "gzip_size_bytes": gzip_path.stat().st_size,
        "used_refresh": used_refresh,
        "latest_dir": str(latest_dir),
        "acceptance_check": str(latest_dir / "P3_probe_export_acceptance_check.txt"),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
