#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.p3.rpki_objects.semantic_compare import compare_semantic_inventories


def parse_probe_inventory(values):
    result = {}
    for item in values:
        if "=" not in item:
            raise ValueError(f"--probe-inventory must be probe=path, got: {item}")
        probe, path = item.split("=", 1)
        result[probe] = Path(path)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare MFT semantic inventories across probes."
    )
    parser.add_argument(
        "--probe-inventory",
        action="append",
        required=True,
        help="Probe inventory mapping, e.g. probe-cd=/path/semantic_object_inventory.jsonl",
    )
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--sample-limit-per-class", type=int, default=50)

    args = parser.parse_args()

    probe_inventory_paths = parse_probe_inventory(args.probe_inventory)

    summary = compare_semantic_inventories(
        probe_inventory_paths=probe_inventory_paths,
        out_dir=Path(args.out_dir),
        sample_limit_per_class=args.sample_limit_per_class,
    )

    print(json.dumps({
        "status": "done",
        "out_dir": args.out_dir,
        "overall": summary.get("overall"),
        "semantic_object_roots_aligned_recomputed": summary.get("semantic_object_roots_aligned_recomputed"),
    }, ensure_ascii=False, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
