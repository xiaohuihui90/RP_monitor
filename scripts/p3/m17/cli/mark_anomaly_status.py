#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.p3.m17.registry_state import update_status


def main() -> int:
    ap = argparse.ArgumentParser(description="Mark an M17 anomaly workspace status.")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--status", required=True)
    ap.add_argument("--note", default="")
    ap.add_argument("--actor", default="manual")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    result = update_status(
        workspace=Path(args.workspace),
        status=args.status,
        note=args.note,
        actor=args.actor,
    )

    if args.json_out:
        p = Path(args.json_out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("M17_MARK_ANOMALY_STATUS=DONE")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
