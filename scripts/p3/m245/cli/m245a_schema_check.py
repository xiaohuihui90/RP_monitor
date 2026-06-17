#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone

from scripts.p3.m245.common.m245_window import make_window, parse_window_id
from scripts.p3.m245.common.m245_errors import FETCH_STATUS, FAILURE_STAGE, ERROR_CLASS


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    schema_dir = Path("scripts/p3/m245/schemas")
    catalog = schema_dir / "m245_schema_catalog.md"
    config = schema_dir / "m245_default_config.yaml"

    w = make_window()
    parsed = parse_window_id(w.window_id)

    checks = {
        "schema": "s3.m245.schema_check.v1",
        "status": "PASS",
        "created_at_utc": utc_now(),
        "schema_catalog_exists": catalog.exists(),
        "default_config_exists": config.exists(),
        "window_id_sample": w.window_id,
        "window_parse_ok": parsed["window_id"] == w.window_id,
        "fetch_status_count": len(FETCH_STATUS),
        "failure_stage_count": len(FAILURE_STAGE),
        "error_class_count": len(ERROR_CLASS),
    }

    hard_fail = []
    for key in ["schema_catalog_exists", "default_config_exists", "window_parse_ok"]:
        if not checks[key]:
            hard_fail.append(key)

    if len(FETCH_STATUS) < 5:
        hard_fail.append("fetch_status_enum_too_short")
    if len(FAILURE_STAGE) < 10:
        hard_fail.append("failure_stage_enum_too_short")
    if len(ERROR_CLASS) < 10:
        hard_fail.append("error_class_enum_too_short")

    if hard_fail:
        checks["status"] = "FAIL"
    checks["hard_fail"] = hard_fail

    out_dir = Path(__import__("os").environ.get("M245_BATCH1_DIR", "."))
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "M245A_schema_summary.json").write_text(
        json.dumps(checks, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    with (out_dir / "M245A_schema_check.txt").open("w", encoding="utf-8") as f:
        f.write(f"M245A_SCHEMA={checks['status']}\n\n")
        f.write(f"created_at_utc = {checks['created_at_utc']}\n")
        f.write(f"schema_catalog_exists = {checks['schema_catalog_exists']}\n")
        f.write(f"default_config_exists = {checks['default_config_exists']}\n")
        f.write(f"window_id_sample = {checks['window_id_sample']}\n")
        f.write(f"window_parse_ok = {checks['window_parse_ok']}\n")
        f.write(f"fetch_status_count = {checks['fetch_status_count']}\n")
        f.write(f"failure_stage_count = {checks['failure_stage_count']}\n")
        f.write(f"error_class_count = {checks['error_class_count']}\n")
        f.write(f"hard_fail = {hard_fail}\n")

    return 0 if checks["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
