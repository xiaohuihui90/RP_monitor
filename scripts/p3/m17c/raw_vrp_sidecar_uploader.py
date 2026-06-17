#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in str(s))


def make_package(project_dir: Path, probe_id: str, window_id: str, out_dir: Path) -> Path:
    sidecar_root = project_dir / "data/probe/m245_three_layer_baseline/raw_vrp_sidecar"
    source_dir = sidecar_root / window_id / probe_id

    if not source_dir.exists():
        raise SystemExit(f"sidecar source dir missing: {source_dir}")

    out_dir.mkdir(parents=True, exist_ok=True)
    package_name = f"{safe_name(probe_id)}_{safe_name(window_id)}_raw_vrp_sidecar.tar.gz"
    package_path = out_dir / package_name

    with tarfile.open(package_path, "w:gz") as tar:
        tar.add(source_dir, arcname=f"{window_id}/{probe_id}", recursive=True)

    return package_path


def upload(package_path: Path, collector_url: str, token: str, probe_id: str, window_id: str) -> dict:
    data = package_path.read_bytes()

    req = urllib.request.Request(
        collector_url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/gzip",
            "Content-Length": str(len(data)),
            "X-M245-Token": token,
            "X-Probe-Id": probe_id,
            "X-Window-Id": window_id,
            "X-Package-Name": package_path.name,
        },
    )

    with urllib.request.urlopen(req, timeout=300) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--collector-url", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--out-dir", default="/tmp")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    out_dir = Path(args.out_dir)

    package_path = make_package(
        project_dir=project_dir,
        probe_id=args.probe_id,
        window_id=args.window_id,
        out_dir=out_dir,
    )

    receipt = upload(
        package_path=package_path,
        collector_url=args.collector_url,
        token=args.token,
        probe_id=args.probe_id,
        window_id=args.window_id,
    )

    result = {
        "schema": "s3.m17c.raw_vrp_sidecar_upload_result.v1",
        "status": "PASS" if receipt.get("status") == "received" else "FAIL",
        "created_at_utc": utc_now(),
        "probe_id": args.probe_id,
        "window_id": args.window_id,
        "collector_url": args.collector_url,
        "package_path": str(package_path),
        "package_size_bytes": package_path.stat().st_size,
        "receipt": receipt,
    }

    result_path = out_dir / f"raw_vrp_sidecar_upload_result_{safe_name(args.probe_id)}_{safe_name(args.window_id)}.json"
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))

    if result["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
