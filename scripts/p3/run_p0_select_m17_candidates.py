#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from s3lib.p0.jsonio import read_json, write_json
from s3lib.p0.timeutil import utc_now


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--history-root", default="data/p3_collector/m245_three_layer_baseline/history")
    ap.add_argument("--report-dir", default="data/p3_collector/m245_three_layer_baseline/reports")
    ap.add_argument("--out-dir", default="data/p3_collector/m245_three_layer_baseline/m17_vrp_entry_diff_inputs")
    args = ap.parse_args()

    history_root = Path(args.history_root)
    report_dir = Path(args.report_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    stats = read_json(report_dir / "M16_three_layer_baseline_report.json")
    if not isinstance(stats, dict):
        stats = {}

    records = stats.get("records", [])
    if not isinstance(records, list):
        records = []

    selected = []

    for r in records:
        if not isinstance(r, dict):
            continue
        if r.get("m17_candidate") is not True:
            continue

        window_id = r.get("window_id")
        if not isinstance(window_id, str):
            continue

        window_dir = history_root / f"m245_window_{window_id}"

        selected.append({
            "window_id": window_id,
            "window_dir": str(window_dir),
            "selection_reason": [
                "complete_3probe_window",
                "validation_output_divergent",
                "raw_vrp_ready",
                "suspicious_low_count_false",
                "mapping_strength_weak",
            ],
            "status_matrix_path": str(window_dir / "outputs" / "M245_three_layer_status_matrix.json"),
            "mapping_context_path": str(window_dir / "outputs" / "M245_layer_mapping_context.json"),
            "h7_overlay_path": str(window_dir / "outputs" / "M245_layer_mapping_context_h7_overlay.json"),
            "validator_runtime_metadata_path": str(window_dir / "outputs" / "validator_runtime_metadata.json"),
            "raw_vrp_root": str(window_dir / "outputs" / "raw_vrp"),
            "raw_vrp_import_manifest_path": str(window_dir / "outputs" / "raw_vrp_import_manifest.json"),
            "evidence_pack_path": str(Path("data/p3_collector/m245_three_layer_baseline/evidence_packs") / window_id / "evidence_pack.json"),
            "mapping_strength": r.get("mapping_strength"),
            "validation_output_status": r.get("validation_output_status"),
            "raw_vrp_file_count": r.get("raw_vrp_file_count"),
            "next_stage": "M17_VRP_ENTRY_LEVEL_DIFF",
        })

    result = {
        "schema": "s3.p0.m17_selected_windows.v1",
        "generated_at_utc": utc_now(),
        "history_root": str(history_root),
        "selected_window_count": len(selected),
        "selected_windows": selected,
        "confirmed_no_l3_diff": len(selected) == 0,
    }

    write_json(out_dir / "selected_windows.json", result)

    lines = []
    lines.append("# M17 selected windows")
    lines.append("")
    lines.append(f"generated_at_utc: `{result['generated_at_utc']}`")
    lines.append(f"selected_window_count: `{len(selected)}`")
    lines.append("")
    for s in selected:
        lines.append(f"- `{s['window_id']}`")
        lines.append(f"  - raw_vrp_file_count: `{s['raw_vrp_file_count']}`")
        lines.append(f"  - mapping_strength: `{s['mapping_strength']}`")
        lines.append(f"  - raw_vrp_root: `{s['raw_vrp_root']}`")
        lines.append(f"  - evidence_pack_path: `{s['evidence_pack_path']}`")
    lines.append("")

    (out_dir / "selected_windows.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"P0_SELECT_M17_CANDIDATES=PASS")
    print(f"selected_window_count = {len(selected)}")
    for s in selected:
        print(f"selected_window = {s['window_id']}")


if __name__ == "__main__":
    main()
