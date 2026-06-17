#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_rows(path: Path):
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="List recent M17 anomalies.")
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--limit", type=int, default=30)
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    out_root = Path(args.out_root)
    compacted = out_root / "anomaly_event_registry_compacted.jsonl"
    raw = out_root / "anomaly_event_registry.jsonl"

    path = compacted if compacted.exists() else raw
    rows = read_rows(path)

    rows = sorted(
        rows,
        key=lambda x: x.get("last_seen_utc") or x.get("first_seen_utc") or "",
        reverse=True,
    )[: args.limit]

    result = {
        "schema": "s3.m17.list_recent_anomalies.v1",
        "source": str(path),
        "count": len(rows),
        "rows": rows,
    }

    if args.json_out:
        p = Path(args.json_out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("M17_LIST_RECENT_ANOMALIES=DONE")
    print(f"source = {path}")
    print(f"count = {len(rows)}")
    print()
    print("idx | last_seen_utc | status | layer | anomaly_type | occurrence_count | event_id")
    print("--- | --- | --- | --- | --- | --- | ---")
    for i, r in enumerate(rows, start=1):
        print(
            f"{i} | {r.get('last_seen_utc')} | {r.get('status')} | "
            f"{r.get('layer')} | {r.get('anomaly_type')} | "
            f"{r.get('occurrence_count')} | {r.get('event_id')}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
