#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def gzip_test(path: Path) -> bool:
    try:
        with gzip.open(path, "rb") as f:
            while f.read(1024 * 1024):
                pass
        return True
    except Exception:
        return False


def find_gzip(snapshot_dir: Path, probe_id: str) -> Path:
    preferred = snapshot_dir / f"{probe_id}_vrps.raw.json.gz"
    if preferred.exists():
        return preferred

    candidates = sorted(snapshot_dir.glob("*_vrps.raw.json.gz"))
    if len(candidates) == 1:
        return candidates[0]

    raise FileNotFoundError(f"cannot locate gzip VRP file in {snapshot_dir}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Probe-side VRP upload client; dry-run first")
    ap.add_argument("--snapshot-dir", default="data/probe/m14_vrp_export/latest")
    ap.add_argument("--collector-url", default="http://47.108.137.128:28081")
    ap.add_argument("--upload-api", default="/api/v1/m14/vrp/upload")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    snapshot_dir = Path(args.snapshot_dir).resolve()
    manifest_path = snapshot_dir / "manifest.json"
    sha256_path = snapshot_dir / "sha256.txt"

    if not snapshot_dir.exists():
        raise FileNotFoundError(snapshot_dir)
    if not manifest_path.exists():
        raise FileNotFoundError(manifest_path)
    if not sha256_path.exists():
        raise FileNotFoundError(sha256_path)

    manifest = read_json(manifest_path)
    probe_id = manifest.get("probe_id")
    validator = manifest.get("validator")
    validator_version = manifest.get("validator_version")
    generated_time = manifest.get("generatedTime")
    roa_count = manifest.get("roa_count")
    expected_gzip_sha256 = manifest.get("sha256_gzip")

    if not probe_id:
        raise ValueError("manifest missing probe_id")

    gzip_path = find_gzip(snapshot_dir, probe_id)

    actual_gzip_sha256 = sha256_file(gzip_path)
    gzip_valid = gzip_test(gzip_path)
    sha256_ok = actual_gzip_sha256 == expected_gzip_sha256

    upload_ready = bool(manifest.get("upload_ready")) and gzip_valid and sha256_ok

    upload_url = args.collector_url.rstrip("/") + args.upload_api

    preview = {
        "schema": "s3.stage3.m14.vrp_upload_request_preview.v1",
        "created_at_utc": utc_now(),
        "dry_run": bool(args.dry_run),
        "upload_url": upload_url,
        "method": "POST",
        "content_type": "multipart/form-data",
        "fields": {
            "probe_id": probe_id,
            "validator": validator,
            "validator_version": validator_version,
            "generatedTime": generated_time,
            "roa_count": roa_count,
        },
        "files": {
            "manifest": str(manifest_path),
            "file": str(gzip_path),
            "sha256": str(sha256_path),
        },
        "checks": {
            "snapshot_dir_exists": snapshot_dir.exists(),
            "manifest_exists": manifest_path.exists(),
            "sha256_txt_exists": sha256_path.exists(),
            "gzip_exists": gzip_path.exists(),
            "gzip_valid": gzip_valid,
            "sha256_expected": expected_gzip_sha256,
            "sha256_actual": actual_gzip_sha256,
            "sha256_ok": sha256_ok,
            "manifest_upload_ready": manifest.get("upload_ready"),
            "computed_upload_ready": upload_ready,
        },
        "note": "Dry-run only. P4 will implement collector upload API and real HTTP POST."
    }

    out_preview = snapshot_dir / "upload_request_preview.json"
    write_json(out_preview, preview)

    acceptance = f"""P3_PROBE_UPLOAD_DRY_RUN=DONE

snapshot_dir = {snapshot_dir}
collector_url = {args.collector_url}
upload_api = {args.upload_api}
upload_url = {upload_url}

probe_id = {probe_id}
validator = {validator}
validator_version = {validator_version}
generatedTime = {generated_time}
roa_count = {roa_count}

manifest_exists = {manifest_path.exists()}
sha256_txt_exists = {sha256_path.exists()}
gzip_file = {gzip_path}
gzip_exists = {gzip_path.exists()}
gzip_valid = {gzip_valid}
sha256_ok = {sha256_ok}
manifest_upload_ready = {manifest.get("upload_ready")}
computed_upload_ready = {upload_ready}

dry_run = {bool(args.dry_run)}
real_http_post_executed = False
collector_upload_api_required_in_P4 = True

outputs:
  {out_preview}

P3_upload_dry_run_acceptance = {upload_ready}
"""
    out_acceptance = snapshot_dir / "P3_probe_upload_dry_run_acceptance_check.txt"
    out_acceptance.write_text(acceptance, encoding="utf-8")

    print(json.dumps({
        "status": "done",
        "dry_run": bool(args.dry_run),
        "probe_id": probe_id,
        "gzip_valid": gzip_valid,
        "sha256_ok": sha256_ok,
        "computed_upload_ready": upload_ready,
        "preview": str(out_preview),
        "acceptance": str(out_acceptance),
    }, ensure_ascii=False, indent=2))

    if not upload_ready:
        sys.exit(2)


if __name__ == "__main__":
    main()
