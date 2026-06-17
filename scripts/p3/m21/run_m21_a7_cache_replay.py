#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield line_no, json.loads(line)
            except Exception as e:
                yield line_no, {"_parse_error": str(e), "_raw": line[:300]}


def load_by_key(path: Path, key: str = "vrp_key"):
    out = {}
    for _, rec in iter_jsonl(path):
        if isinstance(rec, dict) and not rec.get("_parse_error"):
            k = rec.get(key)
            if k:
                out[k] = rec
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--m21-run-dir", required=True)
    ap.add_argument("--m20-joined-records", required=True)
    ap.add_argument("--a3c-matches", required=True)
    ap.add_argument("--a4-bindings", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--max-candidates", type=int, default=20)
    args = ap.parse_args()

    m21_run_dir = Path(args.m21_run_dir)
    m20_joined_path = Path(args.m20_joined_records)
    a3c_path = Path(args.a3c_matches)
    a4_path = Path(args.a4_bindings)
    out_dir = Path(args.out_dir)

    out_dir.mkdir(parents=True, exist_ok=True)
    checks_dir = m21_run_dir / "checks"
    checks_dir.mkdir(parents=True, exist_ok=True)

    records_path = out_dir / "m21_a7_cache_replay_summary.jsonl"
    plan_path = out_dir / "m21_a7_cache_replay_plan_records.jsonl"
    summary_path = out_dir / "m21_a7_cache_replay_summary.json"
    check_path = checks_dir / "M21_A7_CACHE_REPLAY_DESIGN_OR_SMALL_BATCH.txt"

    m20_by_key = load_by_key(m20_joined_path)
    a3c_by_key = load_by_key(a3c_path)
    a4_by_key = load_by_key(a4_path)

    counters = Counter()
    cache_modes = [
        {
            "cache_mode": "fresh_cache",
            "expected_behavior": "validator_refetches_available_current_objects",
            "research_question": "Does a clean validator produce the same VRP for this ROA/manifest context?",
        },
        {
            "cache_mode": "warm_cache",
            "expected_behavior": "validator_reuses_existing_cache_then_refreshes",
            "research_question": "Does an already-populated cache converge to the same VRP output?",
        },
        {
            "cache_mode": "stale_cache",
            "expected_behavior": "validator_may_retain_objects_when_repository_or_delta_fetch_fails",
            "research_question": "Can retained cache objects preserve VRPs that are absent in fresh replay?",
        },
    ]

    selected_keys = []
    for _, rec in iter_jsonl(a4_path):
        if not isinstance(rec, dict) or rec.get("_parse_error"):
            continue
        k = rec.get("vrp_key")
        if not k:
            continue
        selected_keys.append(k)
        if len(selected_keys) >= args.max_candidates:
            break

    with records_path.open("w", encoding="utf-8") as summary_out, \
         plan_path.open("w", encoding="utf-8") as plan_out:

        for vrp_key in selected_keys:
            counters["candidate_selected"] += 1

            m20 = m20_by_key.get(vrp_key, {})
            a3c = a3c_by_key.get(vrp_key, {})
            a4 = a4_by_key.get(vrp_key, {})

            base = {
                "schema": "s3.m21.a7.cache_replay_candidate.v1",
                "vrp_key": vrp_key,
                "afi": a4.get("afi") or a3c.get("afi") or m20.get("afi"),
                "tal": a4.get("tal") or a3c.get("tal") or m20.get("tal"),
                "prefix": a4.get("prefix") or a3c.get("prefix") or m20.get("prefix"),
                "asn": a4.get("asn") or a3c.get("asn") or m20.get("asn"),
                "maxLength": a4.get("maxLength") or a3c.get("maxLength") or m20.get("maxLength"),

                "roa_uri": a4.get("roa_uri") or a3c.get("roa_uri") or m20.get("fetch_target_uri"),
                "manifest_uri": a4.get("manifest_uri") or a3c.get("manifest_uri"),
                "manifestNumber": a4.get("manifestNumber") or a3c.get("manifestNumber"),
                "manifest_thisUpdate": a4.get("manifest_thisUpdate") or a3c.get("manifest_thisUpdate"),
                "manifest_nextUpdate": a4.get("manifest_nextUpdate") or a3c.get("manifest_nextUpdate"),
                "manifest_file_hash": a4.get("manifest_file_hash") or a3c.get("manifest_file_hash"),
                "roa_filename": a4.get("roa_filename") or a3c.get("roa_filename"),
                "roa_filename_filelist_match": a3c.get("roa_filename_filelist_match"),

                "m20_join_status": m20.get("m20_join_status"),
                "m20_join_confidence": m20.get("m20_join_confidence"),
                "backfilled_roa_object_sha256": a3c.get("backfilled_roa_object_sha256") or m20.get("object_sha256"),
                "object_hash_status": a3c.get("object_hash_status"),

                "a4_alignment_status": a4.get("alignment_status"),
                "a4_alignment_confidence": a4.get("alignment_confidence"),
                "nearest_window_id": (a4.get("nearest_m245_windows") or [{}])[0].get("window_id"),
                "nearest_window_delta_sec": (a4.get("nearest_m245_windows") or [{}])[0].get("abs_delta_sec"),
                "notification_like_candidate_count": a4.get("notification_like_candidate_count"),
            }

            for mode in cache_modes:
                row = dict(base)
                row.update(mode)
                row["planned_replay_status"] = "not_executed"
                row["semantic_boundary"] = "cache_replay_plan_not_validator_execution"
                row["strong_causal_claim_allowed"] = False

                if mode["cache_mode"] == "fresh_cache":
                    row["expected_diff_hypothesis"] = "fresh_cache_may_drop_vrp_if_repository_fetch_or_manifest_validation_fails"
                elif mode["cache_mode"] == "warm_cache":
                    row["expected_diff_hypothesis"] = "warm_cache_may_match_current_output_if refresh succeeds"
                else:
                    row["expected_diff_hypothesis"] = "stale_cache_may_retain_previous_valid_roa_and_keep_vrp_visible"

                plan_out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                counters[f"plan_{mode['cache_mode']}"] += 1

            summary_row = dict(base)
            summary_row["cache_replay_modes_planned"] = [m["cache_mode"] for m in cache_modes]
            summary_row["cache_replay_executed"] = False
            summary_row["diff_result_available"] = False
            summary_row["why_not_executed"] = "This batch generates a replay design matrix. Actual fresh/warm/stale validator replay requires isolated Routinator cache directories and same-input repository snapshot."
            summary_row["semantic_boundary"] = "cache_replay_design_not_execution"
            summary_row["strong_causal_claim_allowed"] = False

            summary_out.write(json.dumps(summary_row, ensure_ascii=False, sort_keys=True) + "\n")
            counters["summary_records_written"] += 1

    summary = {
        "schema": "s3.m21.a7.cache_replay_design_summary.v1",
        "generated_at_utc": utc_now(),
        "m21_run_dir": str(m21_run_dir),
        "m20_joined_records": str(m20_joined_path),
        "a3c_matches": str(a3c_path),
        "a4_bindings": str(a4_path),
        "max_candidates": args.max_candidates,
        "counters": dict(counters),
        "outputs": {
            "summary_jsonl": str(records_path),
            "plan_jsonl": str(plan_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "interpretation": {
            "what_this_batch_does": "Builds a cache replay candidate matrix from existing VRP->ROA->manifest->window evidence.",
            "what_this_batch_does_not_do": "It does not execute Routinator replay yet.",
            "next_required_step": "Run isolated fresh/warm/stale Routinator cache experiments on selected candidate repositories or same-window snapshots.",
        },
        "semantic_boundary": "cache_replay_design_not_validator_execution",
        "strong_causal_claim_allowed": False,
        "next_stage": "M21_A7B_ACTUAL_CACHE_REPLAY_SMALL_BATCH",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M21_A7_CACHE_REPLAY_DESIGN_OR_SMALL_BATCH=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"candidate_selected = {counters['candidate_selected']}",
        f"summary_records_written = {counters['summary_records_written']}",
        f"plan_fresh_cache = {counters['plan_fresh_cache']}",
        f"plan_warm_cache = {counters['plan_warm_cache']}",
        f"plan_stale_cache = {counters['plan_stale_cache']}",
        f"summary_jsonl = {records_path}",
        f"plan_jsonl = {plan_path}",
        f"summary_json = {summary_path}",
        "cache_replay_executed = False",
        "semantic_boundary = cache_replay_design_not_validator_execution",
        "strong_causal_claim_allowed = False",
        "next_stage = M21_A7B_ACTUAL_CACHE_REPLAY_SMALL_BATCH",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
