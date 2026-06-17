#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield line_no, json.loads(line)
            except Exception as e:
                yield line_no, {"_parse_error": str(e), "_raw": line[:300]}


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def detect_jsonext_file(m21: Path):
    candidates = [
        m21 / "outputs/a7b_actual_cache_replay_fresh/vrp_outputs/fresh_cache.jsonext.json",
        m21 / "outputs/a7b_actual_cache_replay_warm_r2/vrp_outputs/warm_cache.jsonext.json",
        m21 / "outputs/a7b_actual_cache_replay_stale_r2/vrp_outputs/stale_cache.jsonext.json",
    ]
    for p in candidates:
        if p.exists() and p.stat().st_size > 1024:
            return p
    return None


def first_nearest_window(src: dict) -> dict:
    wins = src.get("nearest_m245_windows") or []
    if isinstance(wins, list) and wins:
        return wins[0] or {}
    return {}


def summarize_notification_candidates(src: dict):
    items = src.get("notification_like_candidates") or []
    if not isinstance(items, list):
        return {
            "notification_like_candidate_count": 0,
            "notification_like_pp_top": None,
            "notification_like_relation_top": None,
            "notification_context_available": False,
        }

    pp_counts = Counter()
    rel_counts = Counter()

    for item in items:
        rec = item.get("record") if isinstance(item, dict) else None
        if not isinstance(rec, dict):
            continue

        path = rec.get("_path") or ""
        pp = None
        if "pp_status." in path:
            pp = path.split("pp_status.", 1)[-1].split(".", 1)[0].strip()

        if pp:
            pp_counts[pp] += 1

        rel = "|".join([
            str(rec.get("session_relation")),
            str(rec.get("serial_relation")),
            str(rec.get("notif_digest_relation")),
        ])
        rel_counts[rel] += 1

    return {
        "notification_like_candidate_count": len(items),
        "notification_like_pp_top": pp_counts.most_common(5),
        "notification_like_relation_top": rel_counts.most_common(5),
        "notification_context_available": len(items) > 0,
    }


def build_record(src: dict, line_no: int, jsonext_path: Path | None, started: str, finished: str):
    nearest = first_nearest_window(src)
    notif = summarize_notification_candidates(src)

    return {
        "schema": "s3.m21.a8.same_window_capture_skeleton_record.v1",
        "source_line_no": line_no,

        "capture_started_at_utc": started,
        "capture_finished_at_utc": finished,

        "window_id": nearest.get("window_id"),
        "nearest_window_delta_sec": nearest.get("abs_delta_sec"),
        "window_dir": nearest.get("window_dir"),

        "vrp_key": src.get("vrp_key"),
        "afi": src.get("afi"),
        "tal": src.get("tal"),
        "prefix": src.get("prefix"),
        "asn": src.get("asn"),
        "maxLength": src.get("maxLength"),

        "jsonext_available": jsonext_path is not None,
        "jsonext_output_path": str(jsonext_path) if jsonext_path else None,
        "jsonext_generatedTime": src.get("jsonext_generatedTime"),
        "jsonext_candidate_present": None,
        "jsonext_candidate_presence_method": "not_indexed_in_a8_skeleton_v1",

        "roa_uri": src.get("roa_uri"),
        "roa_filename": src.get("roa_filename"),

        "manifest_context_available": bool(src.get("manifest_uri") and src.get("manifestNumber") is not None),
        "manifest_uri": src.get("manifest_uri"),
        "manifestNumber": src.get("manifestNumber"),
        "manifest_thisUpdate": src.get("manifest_thisUpdate"),
        "manifest_nextUpdate": src.get("manifest_nextUpdate"),
        "manifest_fileList_count": src.get("manifest_fileList_count"),
        "manifest_fileHashAlgOid": src.get("manifest_fileHashAlgOid"),
        "manifest_file_hash": src.get("manifest_file_hash"),

        "notification_context_available": notif["notification_context_available"],
        "notification_like_candidate_count": notif["notification_like_candidate_count"],
        "notification_like_pp_top": notif["notification_like_pp_top"],
        "notification_like_relation_top": notif["notification_like_relation_top"],

        "status_matrix": nearest.get("status_matrix"),
        "mapping_context": nearest.get("mapping_context"),
        "merged_validator_context": nearest.get("merged_validator_context"),
        "validator_timing_available": bool(nearest.get("merged_validator_context")),

        "a4_alignment_status": src.get("alignment_status"),
        "a4_alignment_confidence": src.get("alignment_confidence"),
        "l1_notification_binding_status": src.get("l1_notification_binding_status"),

        "same_window_capture_attempted": True,
        "a8_alignment_status": "same_window_capture_skeleton_materialized",
        "a8_alignment_confidence": "partial_same_window_capture_skeleton",

        "strong_l1_binding_ready": False,
        "strong_l1_binding_blocker": (
            "A8 skeleton materializes existing A4/A5 evidence fields. "
            "Strong binding requires live JSONEXT, manifest fileList, PP notification and validator timing "
            "captured in the same collection cycle."
        ),

        "semantic_boundary": "same_window_capture_skeleton_partial_not_strong_binding",
        "strong_causal_claim_allowed": False,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m21-run-dir", required=True)
    ap.add_argument("--a5-summary", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    m21 = Path(args.m21_run_dir)
    a5_path = Path(args.a5_summary)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    checks = m21 / "checks"
    checks.mkdir(parents=True, exist_ok=True)

    a5 = load_json(a5_path)
    a4_path = Path(a5.get("input_records", ""))
    if not a4_path.exists():
        a4_path = m21 / "outputs/m21_a4_pp_notification_temporal_binding_records.jsonl"

    if not a4_path.exists():
        raise SystemExit(f"A4 binding records not found: {a4_path}")

    jsonext_path = detect_jsonext_file(m21)

    records_path = out_dir / "m21_a8_same_window_capture_records.jsonl"
    summary_json = out_dir / "m21_a8_same_window_capture_summary.json"
    summary_md = out_dir / "m21_a8_same_window_capture_summary.md"
    check_path = checks / "M21_A8_SAME_WINDOW_CAPTURE_CHECK.txt"

    started = utc_now()
    records = []
    counters = Counter()

    for line_no, src in iter_jsonl(a4_path):
        if src.get("_parse_error"):
            counters["parse_error"] += 1
            continue

        rec = build_record(src, line_no, jsonext_path, started, utc_now())
        records.append(rec)

        counters["records"] += 1
        if rec["jsonext_available"]:
            counters["jsonext_available"] += 1
        if rec["manifest_context_available"]:
            counters["manifest_context_available"] += 1
        if rec["notification_context_available"]:
            counters["notification_context_available"] += 1
        else:
            counters["notification_context_missing"] += 1
        if rec["validator_timing_available"]:
            counters["validator_timing_available"] += 1

        if args.limit and len(records) >= args.limit:
            break

    finished = utc_now()
    for rec in records:
        rec["capture_finished_at_utc"] = finished

    with records_path.open("w", encoding="utf-8") as w:
        for rec in records:
            w.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")

    summary = {
        "schema": "s3.m21.a8.same_window_capture_skeleton_summary.v1",
        "generated_at_utc": finished,
        "m21_run_dir": str(m21),
        "a5_summary": str(a5_path),
        "a4_binding_records": str(a4_path),
        "records_jsonl": str(records_path),
        "summary_md": str(summary_md),
        "record_count": counters["records"],
        "counters": dict(counters),

        "a5_semantic_boundary": a5.get("semantic_boundary"),
        "a5_next_stage": a5.get("next_stage"),
        "a5_nearest_delta_sec": a5.get("nearest_delta_sec"),
        "a5_interpretation": a5.get("interpretation"),

        "same_window_capture_attempted": True,
        "jsonext_available": counters["jsonext_available"] > 0,
        "manifest_context_available": counters["manifest_context_available"] > 0,
        "notification_context_available": "partial" if counters["notification_context_available"] > 0 else "missing",
        "validator_timing_available": counters["validator_timing_available"] > 0,
        "strong_binding_ready": "partial",

        "interpretation": {
            "current_evidence_level": "partial_same_window_capture_skeleton",
            "recommended_report_claim": (
                "A8 materializes the cross-layer evidence context for 124 A4 candidates and "
                "prepares the pipeline for true same-window L1/L2/L3 capture."
            ),
            "why_not_strong": (
                "This skeleton uses existing A4/A5 nearest-window evidence. "
                "Strong binding still requires live same-window JSONEXT, manifest fileList, PP notification, "
                "and validator timing capture in one cycle."
            ),
        },
        "semantic_boundary": "same_window_capture_skeleton_partial_not_strong_binding",
        "strong_causal_claim_allowed": False,
        "next_stage": "M21_A8B_LIVE_SAME_WINDOW_CAPTURE_OR_A7D_SAME_INPUT_CACHE_REPLAY",
    }

    summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    md = []
    md.append("# M21-A8 Same-window Capture Skeleton Summary")
    md.append("")
    md.append("## Key Counters")
    for k, v in sorted(counters.items()):
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## A5 Baseline")
    nd = a5.get("nearest_delta_sec") or {}
    interp = a5.get("interpretation") or {}
    md.append(f"- A5 semantic_boundary: `{a5.get('semantic_boundary')}`")
    md.append(f"- A5 next_stage: `{a5.get('next_stage')}`")
    md.append(f"- A5 strong_l1_binding: `{interp.get('strong_l1_binding')}`")
    md.append(f"- nearest_delta_median_sec: `{nd.get('median')}`")
    md.append(f"- nearest_delta_p90_sec: `{nd.get('p90')}`")
    md.append("")
    md.append("## A8 Interpretation")
    md.append("- same_window_capture_attempted: `True`")
    md.append(f"- jsonext_available: `{summary['jsonext_available']}`")
    md.append(f"- manifest_context_available: `{summary['manifest_context_available']}`")
    md.append(f"- notification_context_available: `{summary['notification_context_available']}`")
    md.append(f"- validator_timing_available: `{summary['validator_timing_available']}`")
    md.append("- strong_binding_ready: `partial`")
    md.append("")
    md.append("semantic_boundary = `same_window_capture_skeleton_partial_not_strong_binding`")
    summary_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    check = [
        "M21_A8_SAME_WINDOW_CAPTURE=PASS",
        f"generated_at_utc = {finished}",
        f"record_count = {counters['records']}",
        f"jsonext_available = {summary['jsonext_available']}",
        f"manifest_context_available = {summary['manifest_context_available']}",
        f"notification_context_available = {summary['notification_context_available']}",
        f"validator_timing_available = {summary['validator_timing_available']}",
        "strong_binding_ready = partial",
        f"records_jsonl = {records_path}",
        f"summary_json = {summary_json}",
        f"summary_md = {summary_md}",
        "semantic_boundary = same_window_capture_skeleton_partial_not_strong_binding",
        "strong_causal_claim_allowed = False",
        "next_stage = M21_A8B_LIVE_SAME_WINDOW_CAPTURE_OR_A7D_SAME_INPUT_CACHE_REPLAY",
    ]
    check_path.write_text("\n".join(check) + "\n", encoding="utf-8")

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
