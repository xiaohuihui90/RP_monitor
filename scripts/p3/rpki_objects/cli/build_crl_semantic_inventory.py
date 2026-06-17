#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.p3.rpki_objects.crl_semantic_inventory import build_crl_semantic_inventory


def main() -> int:
    parser = argparse.ArgumentParser(description="Build CRL frozen and semantic inventories.")

    parser.add_argument("--probe-id", required=True)
    parser.add_argument("--snapshot-group-id", required=True)
    parser.add_argument("--object-export-id", required=True)
    parser.add_argument("--object-inventory", required=True)
    parser.add_argument("--source-root", default=None)
    parser.add_argument("--source-adapter", default="routinator_cache_v1")
    parser.add_argument("--semantic-evidence-level", default="live_cache_semantic_non_frozen")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--limit", type=int, default=None)

    args = parser.parse_args()

    summary = build_crl_semantic_inventory(
        probe_id=args.probe_id,
        snapshot_group_id=args.snapshot_group_id,
        object_export_id=args.object_export_id,
        object_inventory_path=Path(args.object_inventory),
        source_root=Path(args.source_root) if args.source_root else None,
        out_dir=Path(args.out_dir),
        source_adapter=args.source_adapter,
        semantic_evidence_level=args.semantic_evidence_level,
        limit=args.limit,
    )

    print(json.dumps({
        "status": "done",
        "acceptance": summary.get("acceptance"),
        "probe_id": summary.get("probe_id"),
        "total_crl_records": summary.get("total_crl_records"),
        "frozen_hash_ok_ratio": summary.get("frozen_hash_ok_ratio"),
        "live_semantic_ok_ratio": summary.get("live_semantic_ok_ratio"),
        "live_mismatch_frozen_hash_count": summary.get("live_mismatch_frozen_hash_count"),
        "crl_frozen_hash_root": summary.get("crl_frozen_hash_root"),
        "crl_live_semantic_root": summary.get("crl_live_semantic_root"),
        "acceptance_path": summary.get("acceptance_path"),
    }, ensure_ascii=False, indent=2))

    return 0 if summary.get("acceptance") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
