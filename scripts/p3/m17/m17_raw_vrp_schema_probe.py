#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def detect_array(data: Any):
    if isinstance(data, list):
        return "__top_level_list__", data

    if isinstance(data, dict):
        for key in ["roas", "vrps", "validated_roa_payloads", "validated_roas", "records", "data", "items"]:
            value = data.get(key)
            if isinstance(value, list):
                return key, value

    return None, None


def main() -> None:
    window_id = "win_20260528T054000Z_10m"
    root = Path(
        f"data/p3_collector/m245_three_layer_baseline/history/"
        f"m245_window_{window_id}/outputs/raw_vrp"
    )

    summary = {
        "schema": "s3.m17.raw_vrp_schema_probe.v1",
        "window_id": window_id,
        "raw_vrp_root": str(root),
        "files": [],
    }

    for path in sorted(root.glob("probe-*/*_raw_vrp.json")):
        probe_id = path.parent.name

        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        array_key, records = detect_array(data)

        record_count = len(records) if isinstance(records, list) else None
        first_record = records[0] if isinstance(records, list) and records else None

        first_keys = sorted(first_record.keys()) if isinstance(first_record, dict) else []

        sample = None
        if isinstance(first_record, dict):
            sample = first_record

        summary["files"].append({
            "probe_id": probe_id,
            "path": str(path),
            "file_size_bytes": path.stat().st_size,
            "top_type": type(data).__name__,
            "array_key": array_key,
            "record_count": record_count,
            "first_record_keys": first_keys,
            "first_record_sample": sample,
        })

    out = Path("data/p3_collector/m17_vrp_entry_diff/debug/raw_vrp_schema_probe.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True)[:12000])
    print()
    print("WROTE", out)


if __name__ == "__main__":
    main()
