#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.p3.m17.registry_state import compact_registry


def main() -> int:
    ap = argparse.ArgumentParser(description="Compact M17 anomaly registry and generate registry_index.json.")
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--summary-out", default=None)
    args = ap.parse_args()

    result = compact_registry(Path(args.out_root))

    if args.summary_out:
        p = Path(args.summary_out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("M17_COMPACT_REGISTRY=DONE")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
