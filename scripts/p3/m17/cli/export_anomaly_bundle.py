#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List


def utc_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def file_manifest(workspace: Path) -> List[dict]:
    rows = []
    for p in sorted(workspace.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(workspace)
        rows.append({
            "path": str(rel),
            "size_bytes": p.stat().st_size,
            "sha256": sha256_file(p),
        })
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="Export an M17 anomaly workspace bundle.")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--include-manual-results", action="store_true")
    args = ap.parse_args()

    workspace = Path(args.workspace).resolve()
    out_root = Path(args.out).resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    event_path = workspace / "anomaly_event.json"
    if not event_path.exists():
        raise RuntimeError(f"anomaly_event.json missing: {event_path}")

    event = json.loads(event_path.read_text(encoding="utf-8"))
    event_id = event.get("event_id") or workspace.name

    manifest = {
        "schema": "s3.m17.anomaly_bundle_manifest.v1",
        "created_at_utc": utc_compact(),
        "event_id": event_id,
        "workspace": str(workspace),
        "include_manual_results": args.include_manual_results,
        "files": file_manifest(workspace),
    }

    manifest_path = workspace / "bundle_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    bundle = out_root / f"{event_id}_bundle_{utc_compact()}.tar.gz"

    with tarfile.open(bundle, "w:gz") as tar:
        for p in sorted(workspace.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(workspace)

            if not args.include_manual_results and str(rel).startswith("manual_results/"):
                continue

            tar.add(p, arcname=f"{workspace.name}/{rel}")

    digest = sha256_file(bundle)
    sha_path = Path(str(bundle) + ".sha256")
    sha_path.write_text(f"{digest}  {bundle}\n", encoding="utf-8")

    result = {
        "schema": "s3.m17.export_anomaly_bundle.v1",
        "event_id": event_id,
        "workspace": str(workspace),
        "bundle": str(bundle),
        "sha256": digest,
        "sha256_file": str(sha_path),
        "manifest": str(manifest_path),
    }

    print("M17_EXPORT_ANOMALY_BUNDLE=DONE")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
