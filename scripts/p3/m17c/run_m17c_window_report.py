#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    n = 0
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path: Path, records: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in records:
            w.writerow({k: r.get(k) for k in fields})


def window_id_from_m17_dir(path: Path) -> str:
    return path.name.replace("m17_window_", "", 1)


def build_window_record(m17_dir: Path) -> dict[str, Any]:
    window_id = window_id_from_m17_dir(m17_dir)
    out_dir = m17_dir / "outputs"

    acceptance = read_json(out_dir / "M17_ACCEPTANCE.json")
    summary = read_json(out_dir / "vrp_entry_diff_summary.json")
    quality = read_json(out_dir / "M17_quality_annotation.json")
    cycle_summary = read_json(out_dir / "validator_cycle_summary.json")
    effective_input = read_json(out_dir / "validator_effective_input_summary.json")
    digest = read_json(Path("data/p3_collector/m17_vrp_entry_diff/reports") / window_id / "M17_result_digest.json")

    if not isinstance(acceptance, dict):
        acceptance = {}
    if not isinstance(summary, dict):
        summary = {}
    if not isinstance(quality, dict):
        quality = {}
    if not isinstance(cycle_summary, dict):
        cycle_summary = {}
    if not isinstance(effective_input, dict):
        effective_input = {}
    if not isinstance(digest, dict):
        digest = {}

    record = {
        "schema": "s3.m17c.window_index_record.v1",
        "window_id": window_id,
        "m17_window_dir": str(m17_dir),

        "m17_acceptance_status": acceptance.get("status"),
        "m17_status": summary.get("m17_status"),
        "m17_done": acceptance.get("status") == "PASS",

        "total_diff_records": summary.get("total_diff_records"),
        "total_added_vrps": summary.get("total_added_vrps"),
        "total_removed_vrps": summary.get("total_removed_vrps"),
        "total_changed_vrps": summary.get("total_changed_vrps"),
        "affected_prefix_count": summary.get("affected_prefix_count"),
        "affected_asn_count": summary.get("affected_asn_count"),
        "affected_tal_count": summary.get("affected_tal_count"),

        "mapping_strength": summary.get("mapping_strength"),
        "strong_causal_claim_allowed": summary.get("strong_causal_claim_allowed"),

        "quality_annotation_available": bool(quality),
        "m17_window_quality": quality.get("m17_window_quality"),
        "quality_flags": quality.get("quality_flags"),

        "validator_cycle_available": bool(cycle_summary),
        "validator_cycle_status": cycle_summary.get("status"),
        "validator_cycle_record_count": cycle_summary.get("cycle_record_count"),

        "effective_input_available": bool(effective_input),
        "effective_input_status": effective_input.get("status"),
        "accepted_object_set_available": effective_input.get("accepted_object_set_available"),
        "validator_cache_view_status": effective_input.get("validator_cache_view_status"),

        "result_digest_available": bool(digest),

        "vrp_entry_diff_records": str(out_dir / "vrp_entry_diff_records.jsonl"),
        "m18_lifetime_seed_records": str(out_dir / "m18_lifetime_seed_records.jsonl"),
        "validator_cycle_records": str(out_dir / "validator_cycle_records.jsonl"),
        "validator_effective_input_summary": str(out_dir / "validator_effective_input_summary.json"),
        "quality_annotation": str(out_dir / "M17_quality_annotation.json"),
        "result_digest": str(Path("data/p3_collector/m17_vrp_entry_diff/reports") / window_id / "M17_result_digest.json"),

        "m18_seed_count": count_jsonl(out_dir / "m18_lifetime_seed_records.jsonl"),
    }

    return record


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--m17-root", default="data/p3_collector/m17_vrp_entry_diff/history")
    ap.add_argument("--report-dir", default="data/p3_collector/m17_continuous_lite/reports")
    args = ap.parse_args()

    m17_root = Path(args.m17_root)
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    m17_dirs = sorted(p for p in m17_root.glob("m17_window_*") if p.is_dir())
    records = [build_window_record(p) for p in m17_dirs]

    m17_done = [r for r in records if r.get("m17_done")]
    large_windows = [
        r for r in records
        if isinstance(r.get("m17_window_quality"), str)
        and r["m17_window_quality"].startswith("diagnostic_large_scale")
    ]

    m18_windows = [
        r for r in records
        if r.get("m17_done")
        and Path(r["m18_lifetime_seed_records"]).exists()
    ]

    summary = {
        "schema": "s3.m17c.window_report.v1",
        "generated_at_utc": utc_now(),
        "m17_root": str(m17_root),
        "window_count": len(records),
        "m17_done_windows": len(m17_done),
        "large_scale_candidate_windows": len(large_windows),
        "validator_cycle_record_windows": sum(1 for r in records if r.get("validator_cycle_available")),
        "effective_input_summary_windows": sum(1 for r in records if r.get("effective_input_available")),
        "result_digest_windows": sum(1 for r in records if r.get("result_digest_available")),
        "m18_input_window_count": len(m18_windows),
        "total_diff_records": sum(int(r.get("total_diff_records") or 0) for r in m17_done),
        "max_diff_records_per_window": max([int(r.get("total_diff_records") or 0) for r in m17_done] or [0]),
        "records": records,
    }

    m18_manifest = {
        "schema": "s3.m17c.m18_input_manifest.v1",
        "generated_at_utc": summary["generated_at_utc"],
        "window_count": len(m18_windows),
        "windows": [
            {
                "window_id": r["window_id"],
                "m17_window_dir": r["m17_window_dir"],
                "vrp_entry_diff_records": r["vrp_entry_diff_records"],
                "m18_lifetime_seed_records": r["m18_lifetime_seed_records"],
                "validator_cycle_records": r["validator_cycle_records"],
                "validator_effective_input_summary": r["validator_effective_input_summary"],
                "quality_annotation": r["quality_annotation"],
                "result_digest": r["result_digest"],
            }
            for r in m18_windows
        ],
    }

    write_jsonl(report_dir / "M17C_window_index.jsonl", records)
    write_json(report_dir / "M17C_daily_report.json", summary)
    write_json(report_dir / "M17C_m18_input_manifest.json", m18_manifest)

    fields = [
        "window_id",
        "m17_done",
        "total_diff_records",
        "total_added_vrps",
        "total_removed_vrps",
        "total_changed_vrps",
        "affected_prefix_count",
        "affected_asn_count",
        "affected_tal_count",
        "m17_window_quality",
        "validator_cycle_available",
        "effective_input_available",
        "result_digest_available",
        "m18_seed_count",
    ]
    write_csv(report_dir / "M17C_window_statistics.csv", records, fields)

    md = []
    md.append("# M17C Window Report")
    md.append("")
    md.append(f"generated_at_utc: `{summary['generated_at_utc']}`")
    md.append("")
    md.append("## Summary")
    md.append("")
    for k in [
        "window_count",
        "m17_done_windows",
        "large_scale_candidate_windows",
        "validator_cycle_record_windows",
        "effective_input_summary_windows",
        "result_digest_windows",
        "m18_input_window_count",
        "total_diff_records",
        "max_diff_records_per_window",
    ]:
        md.append(f"- {k}: `{summary[k]}`")
    md.append("")
    md.append("## Windows")
    md.append("")
    for r in records:
        md.append(
            f"- `{r['window_id']}`: "
            f"done={r.get('m17_done')}, "
            f"diff={r.get('total_diff_records')}, "
            f"quality={r.get('m17_window_quality')}, "
            f"cycle={r.get('validator_cycle_available')}, "
            f"effective_input={r.get('effective_input_available')}"
        )
    md.append("")
    md.append("## Semantic boundary")
    md.append("")
    md.append(
        "This report aggregates M17 VRP entry-level differences and validator-side context. "
        "It does not claim object-layer causality, validator implementation divergence, "
        "or equality between Routinator cache and accepted object set."
    )
    md.append("")

    (report_dir / "M17C_daily_report.md").write_text("\n".join(md), encoding="utf-8")

    txt = [
        "M17C_WINDOW_REPORT=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"window_count = {summary['window_count']}",
        f"m17_done_windows = {summary['m17_done_windows']}",
        f"large_scale_candidate_windows = {summary['large_scale_candidate_windows']}",
        f"validator_cycle_record_windows = {summary['validator_cycle_record_windows']}",
        f"effective_input_summary_windows = {summary['effective_input_summary_windows']}",
        f"result_digest_windows = {summary['result_digest_windows']}",
        f"m18_input_window_count = {summary['m18_input_window_count']}",
        f"total_diff_records = {summary['total_diff_records']}",
        f"report_dir = {report_dir}",
    ]

    (report_dir / "M17C_window_report_check.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")
    print("\n".join(txt))


if __name__ == "__main__":
    main()
