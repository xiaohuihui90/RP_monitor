#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.p3.rpki_objects.semantic_inventory import build_semantic_inventory


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build S3 MFT-only semantic object inventory."
    )
    parser.add_argument("--probe-id", required=True)
    parser.add_argument("--snapshot-group-id", required=True)
    parser.add_argument("--object-export-id", required=True)
    parser.add_argument("--active-manifest-records", required=True)
    parser.add_argument("--source-adapter", default="generic_file_v1")
    parser.add_argument("--source-root", default=None)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--limit", type=int, default=None)

    args = parser.parse_args()

    summary = build_semantic_inventory(
        active_manifest_records_path=Path(args.active_manifest_records),
        out_dir=Path(args.out_dir),
        probe_id=args.probe_id,
        snapshot_group_id=args.snapshot_group_id,
        object_export_id=args.object_export_id,
        source_adapter=args.source_adapter,
        source_root=args.source_root,
        limit=args.limit,
    )

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
