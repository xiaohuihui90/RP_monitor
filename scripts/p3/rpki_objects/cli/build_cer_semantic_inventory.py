#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.p3.rpki_objects.cer_semantic_inventory import build_cer_semantic_inventory


def main() -> int:
    parser = argparse.ArgumentParser(description="Build CER semantic inventory from object_inventory.jsonl.")
    parser.add_argument("--probe-id", required=True)
    parser.add_argument("--snapshot-group-id", required=True)
    parser.add_argument("--object-export-id", required=True)
    parser.add_argument("--object-inventory", required=True)
    parser.add_argument("--source-root", default=None)
    parser.add_argument("--source-adapter", default="routinator_cache_v1")
    parser.add_argument("--certificate-source-type", default="repository_cer")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    summary = build_cer_semantic_inventory(
        probe_id=args.probe_id,
        snapshot_group_id=args.snapshot_group_id,
        object_export_id=args.object_export_id,
        object_inventory_path=Path(args.object_inventory),
        source_root=Path(args.source_root) if args.source_root else None,
        out_dir=Path(args.out_dir),
        source_adapter=args.source_adapter,
        certificate_source_type=args.certificate_source_type,
        limit=args.limit,
    )

    print(
        json.dumps(
            {
                "status": "done",
                "acceptance": summary.get("acceptance"),
                "probe_id": summary.get("probe_id"),
                "total_cer_records": summary.get("total_cer_records"),
                "semantic_ok": summary.get("semantic_ok"),
                "parse_failed": summary.get("parse_failed"),
                "semantic_ok_ratio": summary.get("semantic_ok_ratio"),
                "role_counts": summary.get("role_counts"),
                "cer_semantic_root": summary.get("cer_semantic_root"),
                "cer_chain_index_root": summary.get("cer_chain_index_root"),
                "cer_resource_root": summary.get("cer_resource_root"),
                "inventory_path": summary.get("inventory_path"),
                "acceptance_path": summary.get("acceptance_path"),
            },
            ensure_ascii=False,
            indent=2,
        )
    )

    return 0 if summary.get("acceptance") == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
