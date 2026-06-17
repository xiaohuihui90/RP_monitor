#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def iter_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def infer_cycle_summary_path(window_record: dict[str, Any]) -> Path | None:
    # manifest 里通常有 validator_cycle_records 路径，summary 在同一 outputs 目录下
    p = window_record.get("validator_cycle_records")
    if not p:
        return None
    return Path(p).parent / "validator_cycle_summary.json"


def normalize_alignment(x: Any) -> str:
    v = str(x or "unknown").lower()
    if v in {"good", "medium", "weak", "unknown"}:
        return v
    return "unknown"


def combine_alignment(qualities: list[str]) -> str:
    """
    lifetime record 可能跨多个窗口：
    - 任一窗口 weak/unknown，则整体先保守标记 weak；
    - 含 medium 且无 weak/unknown，则 medium；
    - 全 good，则 good。
    """
    if not qualities:
        return "unknown"
    qs = [normalize_alignment(q) for q in qualities]
    if "weak" in qs or "unknown" in qs:
        return "weak"
    if "medium" in qs:
        return "medium"
    if all(q == "good" for q in qs):
        return "good"
    return "unknown"


def make_timing_note(quality: str, timing_available: bool, refresh_available: bool) -> str:
    if not timing_available:
        return (
            "Validator export timing metadata is unavailable for at least one seen window; "
            "treat temporal interpretation as candidate-only."
        )
    if quality == "good":
        if refresh_available:
            return (
                "Validator export timing is well aligned across probes, and partial refresh context is available. "
                "M18 temporal classification can use timing evidence, but still does not imply object-layer causality."
            )
        return (
            "Validator export timing is well aligned across probes, but validator update/refresh cycle is not fully observed. "
            "Do not interpret export time as validation start time."
        )
    if quality == "medium":
        return (
            "Validator export timing is moderately aligned. M18 temporal interpretation is usable but should remain conservative."
        )
    if quality == "weak":
        return (
            "Validator export timing is weak, missing, or spans too long. Do not make strong temporal explanations; keep as candidate."
        )
    return (
        "Validator export timing quality is unknown. Keep this diff as candidate evidence only."
    )


def enrich_record(record: dict[str, Any], timing_by_window: dict[str, dict[str, Any]]) -> dict[str, Any]:
    seen_windows = record.get("seen_windows") or []
    if not isinstance(seen_windows, list):
        seen_windows = []

    seen_timing = []
    qualities = []
    timing_available_flags = []
    refresh_available_flags = []
    export_spans = []

    for wid in seen_windows:
        t = timing_by_window.get(wid, {})
        timing_available = bool(t.get("timing_metadata_complete"))
        quality = normalize_alignment(t.get("temporal_alignment_quality"))
        refresh_available = bool(t.get("validator_refresh_context_available_all"))
        span = t.get("export_time_span_sec")

        if span is not None:
            try:
                export_spans.append(float(span))
            except Exception:
                pass

        qualities.append(quality)
        timing_available_flags.append(timing_available)
        refresh_available_flags.append(refresh_available)

        seen_timing.append({
            "window_id": wid,
            "validator_cycle_timing_available": timing_available,
            "export_time_span_sec": span,
            "temporal_alignment_quality": quality,
            "refresh_context_available": refresh_available,
            "earliest_export_started_at_utc": t.get("earliest_export_started_at_utc"),
            "latest_export_started_at_utc": t.get("latest_export_started_at_utc"),
            "ntp_sync_status_by_probe": t.get("ntp_sync_status_by_probe"),
        })

    record_quality = combine_alignment(qualities)
    record_timing_available = bool(timing_available_flags) and all(timing_available_flags)
    record_refresh_available = bool(refresh_available_flags) and all(refresh_available_flags)

    enriched = dict(record)
    enriched["validator_cycle_timing_available"] = record_timing_available
    enriched["validator_cycle_timing_by_window"] = seen_timing
    enriched["export_time_span_sec"] = max(export_spans) if export_spans else None
    enriched["temporal_alignment_quality"] = record_quality
    enriched["refresh_context_available"] = record_refresh_available
    enriched["timing_evidence_note"] = make_timing_note(
        record_quality,
        record_timing_available,
        record_refresh_available,
    )

    # 语义护栏：weak/unknown alignment 不允许强解释
    if record_quality in {"weak", "unknown"}:
        enriched["timing_interpretation_boundary"] = "candidate_only_due_to_weak_or_missing_alignment"
    else:
        enriched["timing_interpretation_boundary"] = "timing_usable_for_m18_temporal_context"

    enriched["strong_causal_claim_allowed"] = False
    enriched["mapping_strength"] = "weak"

    return enriched


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--run-dir", required=True)
    args = ap.parse_args()

    manifest_path = Path(args.manifest)
    run_dir = Path(args.run_dir)
    out_dir = run_dir / "outputs"
    check_dir = run_dir / "checks"
    report_dir = Path("data/p3_collector/m18_diff_lifetime/reports")

    out_dir.mkdir(parents=True, exist_ok=True)
    check_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict):
        raise SystemExit(f"bad manifest: {manifest_path}")

    timing_by_window: dict[str, dict[str, Any]] = {}
    missing_summary_windows = []

    for w in manifest.get("windows", []):
        wid = w.get("window_id")
        summary_path = infer_cycle_summary_path(w)
        summary = read_json(summary_path) if summary_path else None

        if isinstance(summary, dict):
            timing_by_window[wid] = {
                "window_id": wid,
                "summary_path": str(summary_path),
                "timing_metadata_complete": summary.get("timing_metadata_complete"),
                "export_time_span_sec": summary.get("export_time_span_sec"),
                "temporal_alignment_quality": summary.get("temporal_alignment_quality"),
                "validator_refresh_context_available_all": summary.get("validator_refresh_context_available_all"),
                "earliest_export_started_at_utc": summary.get("earliest_export_started_at_utc"),
                "latest_export_started_at_utc": summary.get("latest_export_started_at_utc"),
                "ntp_sync_status_by_probe": summary.get("ntp_sync_status_by_probe"),
            }
        else:
            missing_summary_windows.append(wid)
            timing_by_window[wid] = {
                "window_id": wid,
                "summary_path": str(summary_path) if summary_path else None,
                "timing_metadata_complete": False,
                "export_time_span_sec": None,
                "temporal_alignment_quality": "unknown",
                "validator_refresh_context_available_all": False,
            }

    lifetime_path = out_dir / "vrp_diff_lifetime_records.jsonl"
    m19_path = out_dir / "m19_mapping_candidates.jsonl"
    report_json_path = out_dir / "convergence_baseline_report.json"
    report_md_path = out_dir / "convergence_baseline_report.md"

    lifetime_records = list(iter_jsonl(lifetime_path))
    m19_records = list(iter_jsonl(m19_path))

    enriched_lifetime = [enrich_record(r, timing_by_window) for r in lifetime_records]
    enriched_m19 = [enrich_record(r, timing_by_window) for r in m19_records]

    out_lifetime = out_dir / "vrp_diff_lifetime_records_with_timing.jsonl"
    out_m19 = out_dir / "m19_mapping_candidates_with_timing.jsonl"

    write_jsonl(out_lifetime, enriched_lifetime)
    write_jsonl(out_m19, enriched_m19)

    timing_quality_counter = Counter(r.get("temporal_alignment_quality", "unknown") for r in enriched_lifetime)
    m19_timing_quality_counter = Counter(r.get("temporal_alignment_quality", "unknown") for r in enriched_m19)
    timing_available_count = sum(1 for r in enriched_lifetime if r.get("validator_cycle_timing_available"))
    refresh_available_count = sum(1 for r in enriched_lifetime if r.get("refresh_context_available"))

    window_timing_counter = Counter(
        normalize_alignment(t.get("temporal_alignment_quality"))
        for t in timing_by_window.values()
    )

    timing_summary = {
        "schema": "s3.m18.timing_evidence_summary.v1",
        "generated_at_utc": utc_now(),
        "manifest_path": str(manifest_path),
        "run_dir": str(run_dir),
        "window_count": len(timing_by_window),
        "missing_cycle_summary_windows": missing_summary_windows,
        "window_timing_quality_counts": dict(window_timing_counter),
        "timing_by_window": timing_by_window,

        "lifetime_record_count": len(enriched_lifetime),
        "lifetime_timing_available_count": timing_available_count,
        "lifetime_refresh_available_count": refresh_available_count,
        "lifetime_temporal_alignment_quality_counts": dict(timing_quality_counter),

        "m19_candidate_count": len(enriched_m19),
        "m19_temporal_alignment_quality_counts": dict(m19_timing_quality_counter),

        "rules": {
            "good": "export_time_span_sec <= 300",
            "medium": "300 < export_time_span_sec <= 900",
            "weak": "export_time_span_sec > 900 or timing missing",
        },

        "semantic_boundary": {
            "mapping_strength": "weak",
            "strong_causal_claim_allowed": False,
            "do_not_interpret_export_time_as_validation_start": True,
        },
    }

    write_json(out_dir / "m18_timing_evidence_summary.json", timing_summary)
    write_json(report_dir / "latest_timing_evidence_summary.json", timing_summary)

    # 增强 convergence report json
    report = read_json(report_json_path)
    if isinstance(report, dict):
        report["timing_evidence_summary"] = {
            "window_timing_quality_counts": dict(window_timing_counter),
            "lifetime_temporal_alignment_quality_counts": dict(timing_quality_counter),
            "m19_temporal_alignment_quality_counts": dict(m19_timing_quality_counter),
            "timing_metadata_enhanced": True,
            "timing_evidence_note": (
                "M18 now includes validator export timing evidence from ValidatorCycleRecord v2. "
                "Weak alignment records remain candidate-only and do not allow strong causal interpretation."
            ),
        }
        write_json(out_dir / "convergence_baseline_report_with_timing.json", report)
        write_json(report_dir / "latest_convergence_baseline_report_with_timing.json", report)

    # 增强 markdown
    md = report_md_path.read_text(encoding="utf-8", errors="ignore") if report_md_path.exists() else ""
    md2 = md.rstrip() + "\n\n"
    md2 += "## Validator Cycle Timing Evidence\n\n"
    md2 += f"- timing_metadata_enhanced: `True`\n"
    md2 += f"- window_timing_quality_counts: `{dict(window_timing_counter)}`\n"
    md2 += f"- lifetime_temporal_alignment_quality_counts: `{dict(timing_quality_counter)}`\n"
    md2 += f"- m19_temporal_alignment_quality_counts: `{dict(m19_timing_quality_counter)}`\n"
    md2 += f"- missing_cycle_summary_windows: `{missing_summary_windows}`\n\n"
    md2 += "Interpretation boundary: validator export time is not validation start time. "
    md2 += "Records with weak or missing alignment should only be treated as candidate evidence.\n"

    (out_dir / "convergence_baseline_report_with_timing.md").write_text(md2, encoding="utf-8")
    (report_dir / "latest_convergence_baseline_report_with_timing.md").write_text(md2, encoding="utf-8")

    status = "PASS" if enriched_lifetime and timing_by_window else "FAIL"

    lines = [
        f"M18_TIMING_EVIDENCE_INTEGRATION={status}",
        f"generated_at_utc = {timing_summary['generated_at_utc']}",
        f"window_count = {timing_summary['window_count']}",
        f"lifetime_record_count = {timing_summary['lifetime_record_count']}",
        f"m19_candidate_count = {timing_summary['m19_candidate_count']}",
        f"window_timing_quality_counts = {dict(window_timing_counter)}",
        f"lifetime_temporal_alignment_quality_counts = {dict(timing_quality_counter)}",
        f"m19_temporal_alignment_quality_counts = {dict(m19_timing_quality_counter)}",
        f"missing_cycle_summary_windows = {missing_summary_windows}",
        f"strong_causal_claim_allowed = False",
        f"summary_path = {out_dir / 'm18_timing_evidence_summary.json'}",
        f"lifetime_with_timing = {out_lifetime}",
        f"m19_candidates_with_timing = {out_m19}",
    ]

    check_path = check_dir / "M18_TIMING_EVIDENCE_INTEGRATION_CHECK.txt"
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))

    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
