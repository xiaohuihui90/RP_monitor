#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from s3lib.p0.jsonio import read_json, write_json, write_jsonl
from s3lib.p0.scanner import scan_window_dirs, window_id_from_dir
from s3lib.p0.timeutil import utc_now


LAYER_KEYS = [
    "advertised_view",
    "object_view",
    "validation_output",
    "validator_cache_view",
]


def as_json_text(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True).lower()
    except Exception:
        return str(obj).lower()


def get_layer_status(status_matrix: dict[str, Any], layer: str) -> str:
    section = status_matrix.get(layer)

    if isinstance(section, dict):
        for key in ["layer_status", "status", "view_status"]:
            value = section.get(key)
            if isinstance(value, str) and value:
                return value

        if section.get("divergent") is True:
            return "divergent"

        if section.get("consistent") is True:
            return "consistent"

    text = as_json_text(section)
    if "divergent" in text:
        return "divergent"
    if "consistent" in text:
        return "consistent"

    return "unknown"


def is_layer_divergent(status_matrix: dict[str, Any], layer: str) -> bool:
    return get_layer_status(status_matrix, layer) == "divergent"


def suspicious_low_count(status_matrix: dict[str, Any]) -> bool:
    validation_output = status_matrix.get("validation_output")
    if isinstance(validation_output, dict):
        by_probe = validation_output.get("suspicious_low_count_by_probe")
        if isinstance(by_probe, dict):
            return any(v is True for v in by_probe.values())

        value = validation_output.get("suspicious_low_count")
        if isinstance(value, bool):
            return value

    value = status_matrix.get("suspicious_low_count")
    if isinstance(value, bool):
        return value

    return False


def extract_probe_ids(status_matrix: dict[str, Any]) -> list[str]:
    probes: set[str] = set()

    for key in ["probe_status", "probe_health", "probes"]:
        value = status_matrix.get(key)
        if isinstance(value, dict):
            for k in value:
                if isinstance(k, str) and k.startswith("probe-"):
                    probes.add(k)
        elif isinstance(value, list):
            for x in value:
                if isinstance(x, str) and x.startswith("probe-"):
                    probes.add(x)

    for section in status_matrix.values():
        if isinstance(section, dict):
            for k in section:
                if isinstance(k, str) and k.startswith("probe-"):
                    probes.add(k)

    return sorted(probes)


def has_hard_fail(status_matrix: dict[str, Any], loop_summary: dict[str, Any]) -> bool:
    for obj in [status_matrix, loop_summary]:
        hard_fail = obj.get("hard_fail") if isinstance(obj, dict) else None
        if isinstance(hard_fail, list) and hard_fail:
            return True

    text = as_json_text(loop_summary)
    return "hard_fail" in text and "[]" not in text


def complete_3probe_window(status_matrix: dict[str, Any], loop_summary: dict[str, Any]) -> bool:
    probes = extract_probe_ids(status_matrix)
    if len(probes) >= 3 and not has_hard_fail(status_matrix, loop_summary):
        return True

    value = loop_summary.get("complete_3probe_window") if isinstance(loop_summary, dict) else None
    if isinstance(value, bool):
        return value

    return False


def load_context(window_dir: Path) -> tuple[dict[str, Any], str | None]:
    h7 = window_dir / "outputs" / "M245_layer_mapping_context_h7_overlay.json"
    base = window_dir / "outputs" / "M245_layer_mapping_context.json"

    for p in [h7, base]:
        obj = read_json(p)
        if isinstance(obj, dict):
            return obj, str(p)

    return {}, None


def raw_vrp_ready(window_dir: Path) -> bool:
    obj = read_json(window_dir / "outputs" / "validator_runtime_metadata.json")
    if isinstance(obj, dict) and obj.get("raw_vrp_ready") is True:
        return True

    raw_root = window_dir / "outputs" / "raw_vrp"
    if not raw_root.exists():
        return False

    manifests = sorted(raw_root.glob("probe-*/raw_vrp_export_manifest.json"))
    return len(manifests) >= 3


def count_raw_vrp_files(window_dir: Path) -> int:
    raw_root = window_dir / "outputs" / "raw_vrp"
    if not raw_root.exists():
        return 0

    count = 0
    for p in raw_root.glob("probe-*/*_raw_vrp.json"):
        if p.is_file():
            count += 1
    for p in raw_root.glob("probe-*/*_raw_vrp.jsonext"):
        if p.is_file():
            count += 1
    return count


def m25_trigger_required(window_dir: Path, status_matrix: dict[str, Any]) -> bool:
    summary = read_json(window_dir / "outputs" / "M245_F2E_diff_trigger_summary.json")
    if isinstance(summary, dict):
        value = summary.get("m25_trigger_required")
        if isinstance(value, bool):
            return value

    return any(
        is_layer_divergent(status_matrix, layer)
        for layer in ["advertised_view", "object_view", "validation_output"]
    )


def infer_m25_reasons(status_matrix: dict[str, Any]) -> list[str]:
    reasons = []
    for layer in ["advertised_view", "object_view", "validation_output"]:
        if is_layer_divergent(status_matrix, layer):
            reasons.append(layer)
    return reasons


def build_window_record(window_dir: Path) -> dict[str, Any]:
    window_id = window_id_from_dir(window_dir)

    status_matrix = read_json(window_dir / "outputs" / "M245_three_layer_status_matrix.json")
    if not isinstance(status_matrix, dict):
        status_matrix = {}

    loop_summary = read_json(window_dir / "outputs" / "THREE_LAYER_BASELINE_LOOP_SUMMARY.json")
    if not isinstance(loop_summary, dict):
        loop_summary = {}

    context, context_path = load_context(window_dir)

    layer_status = {
        layer: get_layer_status(status_matrix, layer)
        for layer in LAYER_KEYS
    }

    probes = extract_probe_ids(status_matrix)

    h7_overlay_path = window_dir / "outputs" / "M245_layer_mapping_context_h7_overlay.json"

    m25_required = m25_trigger_required(window_dir, status_matrix)
    m25_reasons = infer_m25_reasons(status_matrix)

    rec = {
        "schema": "s3.p0.window_stats_record.v1",
        "window_id": window_id,
        "window_dir": str(window_dir),
        "probe_count": len(probes),
        "probes": probes,
        "complete_3probe_window": complete_3probe_window(status_matrix, loop_summary),

        "advertised_view_status": layer_status["advertised_view"],
        "object_view_status": layer_status["object_view"],
        "validation_output_status": layer_status["validation_output"],
        "validator_cache_view_status": layer_status["validator_cache_view"],

        "advertised_view_divergent": is_layer_divergent(status_matrix, "advertised_view"),
        "object_view_divergent": is_layer_divergent(status_matrix, "object_view"),
        "validation_output_divergent": is_layer_divergent(status_matrix, "validation_output"),

        "suspicious_low_count": suspicious_low_count(status_matrix),
        "m25_trigger_required": m25_required,
        "m25_trigger_reasons": m25_reasons,

        "mapping_context_path": context_path,
        "mapping_strength": context.get("mapping_strength"),
        "mapping_type": context.get("mapping_type"),
        "scope_alignment": context.get("scope_alignment"),
        "h7_overlay_applied": h7_overlay_path.exists(),
        "validator_cache_view_medium_eligible": context.get("validator_cache_view_medium_eligible"),
        "strong_causal_claim_allowed": context.get("strong_causal_claim_allowed"),

        "raw_vrp_ready": raw_vrp_ready(window_dir),
        "raw_vrp_file_count": count_raw_vrp_files(window_dir),
    }

    anomaly_reasons = []
    for key in [
        "advertised_view_divergent",
        "object_view_divergent",
        "validation_output_divergent",
        "suspicious_low_count",
        "m25_trigger_required",
    ]:
        if rec.get(key):
            anomaly_reasons.append(key)

    if rec.get("validator_cache_view_status") == "observed_but_unstable":
        anomaly_reasons.append("validator_cache_view_observed_but_unstable")

    if rec.get("mapping_strength") == "weak":
        anomaly_reasons.append("weak_mapping")

    rec["is_anomaly_window"] = bool(anomaly_reasons)
    rec["anomaly_reasons"] = sorted(set(anomaly_reasons))

    rec["m17_candidate"] = bool(
        rec["complete_3probe_window"]
        and rec["validation_output_divergent"]
        and rec["raw_vrp_ready"]
        and not rec["suspicious_low_count"]
    )

    return rec


def write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "window_id",
        "complete_3probe_window",
        "probe_count",
        "advertised_view_status",
        "object_view_status",
        "validation_output_status",
        "validator_cache_view_status",
        "advertised_view_divergent",
        "object_view_divergent",
        "validation_output_divergent",
        "suspicious_low_count",
        "m25_trigger_required",
        "mapping_strength",
        "mapping_type",
        "h7_overlay_applied",
        "raw_vrp_ready",
        "raw_vrp_file_count",
        "m17_candidate",
    ]

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in records:
            writer.writerow({k: r.get(k) for k in fields})


def build_markdown(summary: dict[str, Any], records: list[dict[str, Any]]) -> str:
    lines = []
    lines.append("# M16 / P0 Three-Layer Baseline Report")
    lines.append("")
    lines.append(f"generated_at_utc: `{summary['generated_at_utc']}`")
    lines.append("")
    lines.append("## Window statistics")
    lines.append("")
    for key in [
        "total_windows",
        "complete_3probe_windows",
        "advertised_view_divergent_windows",
        "object_view_divergent_windows",
        "validation_output_divergent_windows",
        "validator_cache_view_observed_but_unstable_windows",
        "suspicious_low_count_windows",
        "m25_trigger_windows",
        "weak_mapping_windows",
        "h7_overlay_applied_windows",
        "raw_vrp_ready_windows",
        "m17_candidate_windows",
    ]:
        lines.append(f"- {key}: `{summary[key]}`")

    lines.append("")
    lines.append("## M17 candidate windows")
    lines.append("")

    candidates = [r for r in records if r.get("m17_candidate")]
    if not candidates:
        lines.append("- None")
    else:
        for r in candidates:
            lines.append(
                f"- `{r['window_id']}`: "
                f"validation_output={r['validation_output_status']}, "
                f"raw_vrp_ready={r['raw_vrp_ready']}, "
                f"mapping_strength={r.get('mapping_strength')}"
            )

    lines.append("")
    lines.append("## Semantic note")
    lines.append("")
    lines.append(
        "P0 report is diagnostic-only. It records same-window multilayer divergence and readiness for M17 VRP entry-level diff. "
        "It does not claim object root caused VRP root, validator cache equals accepted object set, or validator implementation divergence."
    )
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--history-root", default="data/p3_collector/m245_three_layer_baseline/history")
    ap.add_argument("--report-dir", default="data/p3_collector/m245_three_layer_baseline/reports")
    args = ap.parse_args()

    history_root = Path(args.history_root)
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    windows = scan_window_dirs(history_root)
    records = [build_window_record(w) for w in windows]

    summary = {
        "schema": "s3.p0.m16_window_statistics.v1",
        "generated_at_utc": utc_now(),
        "history_root": str(history_root),

        "total_windows": len(records),
        "complete_3probe_windows": sum(1 for r in records if r["complete_3probe_window"]),

        "advertised_view_divergent_windows": sum(1 for r in records if r["advertised_view_divergent"]),
        "object_view_divergent_windows": sum(1 for r in records if r["object_view_divergent"]),
        "validation_output_divergent_windows": sum(1 for r in records if r["validation_output_divergent"]),

        "validator_cache_view_observed_but_unstable_windows": sum(
            1 for r in records if r["validator_cache_view_status"] == "observed_but_unstable"
        ),
        "suspicious_low_count_windows": sum(1 for r in records if r["suspicious_low_count"]),
        "m25_trigger_windows": sum(1 for r in records if r["m25_trigger_required"]),

        "weak_mapping_windows": sum(1 for r in records if r.get("mapping_strength") == "weak"),
        "h7_overlay_applied_windows": sum(1 for r in records if r["h7_overlay_applied"]),
        "raw_vrp_ready_windows": sum(1 for r in records if r["raw_vrp_ready"]),
        "m17_candidate_windows": sum(1 for r in records if r["m17_candidate"]),

        "records": records,
    }

    anomaly_records = []
    for r in records:
        if r["is_anomaly_window"]:
            anomaly_records.append({
                "schema": "s3.p0.anomaly_window_index.v1",
                "generated_at_utc": summary["generated_at_utc"],
                "window_id": r["window_id"],
                "window_dir": r["window_dir"],
                "anomaly_reasons": r["anomaly_reasons"],
                "mapping_strength": r.get("mapping_strength"),
                "raw_vrp_ready": r["raw_vrp_ready"],
                "m17_candidate": r["m17_candidate"],
                "recommended_next_actions": [
                    "build_basic_evidence_pack",
                    "run_m17_vrp_entry_level_diff" if r["m17_candidate"] else "keep_for_diagnostic_baseline",
                ],
            })

    write_json(report_dir / "M16_three_layer_baseline_report.json", summary)
    write_csv(report_dir / "M16_window_statistics.csv", records)
    write_jsonl(report_dir / "M16_anomaly_window_index.jsonl", anomaly_records)

    md = build_markdown(summary, records)
    (report_dir / "M16_three_layer_baseline_report.md").write_text(md + "\n", encoding="utf-8")

    status = "PASS" if summary["total_windows"] > 0 and summary["complete_3probe_windows"] > 0 else "FAIL"

    txt = [
        f"P0_WINDOW_STATS={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"history_root = {summary['history_root']}",
        f"total_windows = {summary['total_windows']}",
        f"complete_3probe_windows = {summary['complete_3probe_windows']}",
        f"advertised_view_divergent_windows = {summary['advertised_view_divergent_windows']}",
        f"object_view_divergent_windows = {summary['object_view_divergent_windows']}",
        f"validation_output_divergent_windows = {summary['validation_output_divergent_windows']}",
        f"validator_cache_view_observed_but_unstable_windows = {summary['validator_cache_view_observed_but_unstable_windows']}",
        f"suspicious_low_count_windows = {summary['suspicious_low_count_windows']}",
        f"m25_trigger_windows = {summary['m25_trigger_windows']}",
        f"weak_mapping_windows = {summary['weak_mapping_windows']}",
        f"h7_overlay_applied_windows = {summary['h7_overlay_applied_windows']}",
        f"raw_vrp_ready_windows = {summary['raw_vrp_ready_windows']}",
        f"m17_candidate_windows = {summary['m17_candidate_windows']}",
    ]

    (report_dir / "M16_window_statistics_check.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")
    print("\n".join(txt))


if __name__ == "__main__":
    main()
