#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                yield obj


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256_lines(lines: list[str]) -> str:
    h = hashlib.sha256()
    for line in sorted(lines):
        h.update(line.encode("utf-8"))
        h.update(b"\n")
    return "sha256:" + h.hexdigest()


def build_rollup(raw_index: Path, run_dir: Path) -> Dict[str, Any]:
    rows = list(read_jsonl(raw_index))
    recovered = [r for r in rows if r.get("raw_sha256")]

    by_probe = Counter(r.get("probe_id") or "unknown" for r in rows)
    by_type = Counter(r.get("object_type") or "unknown" for r in rows)
    by_status = Counter(r.get("recover_status") or "unknown" for r in rows)

    root_lines_by_probe = defaultdict(list)
    root_lines_by_type = defaultdict(lambda: defaultdict(list))

    for r in recovered:
        probe = r.get("probe_id") or "unknown"
        obj_type = r.get("object_type") or "unknown"
        uri = r.get("canonical_uri") or r.get("object_uri") or ""
        raw_sha = r.get("raw_sha256")

        line = f"{uri}\t{raw_sha}"
        root_lines_by_probe[probe].append(line)
        root_lines_by_type[obj_type][probe].append(line)

    all_object_root_by_probe = {
        probe: sha256_lines(lines)
        for probe, lines in sorted(root_lines_by_probe.items())
    }

    all_object_root_by_type = {}
    for obj_type, probe_map in sorted(root_lines_by_type.items()):
        all_object_root_by_type[obj_type] = {
            probe: sha256_lines(lines)
            for probe, lines in sorted(probe_map.items())
        }

    coverage_by_probe = {}
    for probe in sorted(by_probe):
        total = sum(1 for r in rows if (r.get("probe_id") or "unknown") == probe)
        ok = sum(1 for r in recovered if (r.get("probe_id") or "unknown") == probe)
        coverage_by_probe[probe] = {
            "records": total,
            "recovered": ok,
            "missing": total - ok,
            "coverage_ratio": ok / total if total else 0.0,
        }

    coverage_by_type = {}
    for obj_type in sorted(by_type):
        total = sum(1 for r in rows if (r.get("object_type") or "unknown") == obj_type)
        ok = sum(1 for r in recovered if (r.get("object_type") or "unknown") == obj_type)
        coverage_by_type[obj_type] = {
            "records": total,
            "recovered": ok,
            "missing": total - ok,
            "coverage_ratio": ok / total if total else 0.0,
        }

    return {
        "schema": "s3.m18c.all_object_rollup_summary.v1",
        "created_at_utc": utc_now_iso(),
        "scope": "recoverable_subset_rollup",
        "raw_index": str(raw_index),
        "run_dir": str(run_dir),
        "input_record_count": len(rows),
        "recovered_record_count": len(recovered),
        "distinct_raw_sha256_count": len({r.get("raw_sha256") for r in recovered}),
        "by_probe": dict(by_probe),
        "by_object_type": dict(by_type),
        "by_recover_status": dict(by_status),
        "all_object_root_by_probe": all_object_root_by_probe,
        "all_object_root_by_type": all_object_root_by_type,
        "coverage_by_probe": coverage_by_probe,
        "coverage_by_type": coverage_by_type,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="M18-C All-object Hash-level Rollup")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--raw-index", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()
    raw_index = Path(args.raw_index).expanduser().resolve()

    rollups_dir = run_dir / "rollups"
    checks_dir = run_dir / "checks"
    rollups_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)

    summary = build_rollup(raw_index, run_dir)

    summary_path = rollups_dir / "all_object_rollup_summary.json"
    root_by_probe_path = rollups_dir / "all_object_root_by_probe.json"
    root_by_type_path = rollups_dir / "all_object_root_by_type.json"
    type_summary_path = rollups_dir / "all_object_type_summary.json"
    check_path = checks_dir / "M18C_all_object_hash_rollup.txt"

    write_json(summary_path, summary)
    write_json(root_by_probe_path, summary["all_object_root_by_probe"])
    write_json(root_by_type_path, summary["all_object_root_by_type"])
    write_json(type_summary_path, summary["coverage_by_type"])

    status = "PASS" if summary["recovered_record_count"] > 0 else "FAIL"

    text = "\n".join([
        f"M18C_ALL_OBJECT_HASH_ROLLUP={status}",
        "",
        "scope = recoverable_subset_rollup",
        f"input_record_count = {summary['input_record_count']}",
        f"recovered_record_count = {summary['recovered_record_count']}",
        f"distinct_raw_sha256_count = {summary['distinct_raw_sha256_count']}",
        f"by_probe = {summary['by_probe']}",
        f"by_object_type = {summary['by_object_type']}",
        f"by_recover_status = {summary['by_recover_status']}",
        "",
        f"summary_path = {summary_path}",
        f"root_by_probe_path = {root_by_probe_path}",
        f"root_by_type_path = {root_by_type_path}",
        f"type_summary_path = {type_summary_path}",
    ]) + "\n"

    check_path.write_text(text, encoding="utf-8")
    print(text)

    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
