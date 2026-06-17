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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets-jsonl", required=True)
    ap.add_argument("--backfilled-roa-index", required=True)
    ap.add_argument("--failure-records", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    targets_path = Path(args.targets_jsonl)
    roa_index_path = Path(args.backfilled_roa_index)
    failure_path = Path(args.failure_records)
    out_dir = Path(args.out_dir)

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    evidence = out_dir / "evidence_packs"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)

    joined_path = outputs / "m20_b3_joined_backfill_records.jsonl"
    case_path = outputs / "m20_case_study_candidates.jsonl"
    summary_path = outputs / "m20_b3_join_backfilled_objects_summary.json"
    check_path = checks / "M20_B3_JOIN_BACKFILLED_OBJECTS_CHECK.txt"

    success_by_key = {}
    failure_by_key = {}

    for _, r in iter_jsonl(roa_index_path):
        if isinstance(r, dict) and not r.get("_parse_error"):
            success_by_key[r.get("vrp_key")] = r

    for _, r in iter_jsonl(failure_path):
        if isinstance(r, dict) and not r.get("_parse_error"):
            failure_by_key[r.get("vrp_key")] = r

    counters = Counter()

    with joined_path.open("w", encoding="utf-8") as joined_out, \
         case_path.open("w", encoding="utf-8") as case_out:

        for _, target in iter_jsonl(targets_path):
            if not isinstance(target, dict) or target.get("_parse_error"):
                counters["target_parse_error"] += 1
                continue

            counters["target_count"] += 1
            vrp_key = target.get("vrp_key")

            success = success_by_key.get(vrp_key)
            failure = failure_by_key.get(vrp_key)

            if success:
                status = "backfilled_roa_object_available"
                confidence = "late_fetch_object_available"
                counters["backfilled_roa_object_available"] += 1

                joined = {
                    "schema": "s3.m20.b3.joined_backfill_record.v1",
                    "vrp_key": vrp_key,
                    "afi": target.get("afi"),
                    "tal": target.get("tal"),
                    "prefix": target.get("prefix"),
                    "asn": target.get("asn"),
                    "maxLength": target.get("maxLength"),

                    "m20_join_status": status,
                    "m20_join_confidence": confidence,

                    "fetch_target_uri": target.get("fetch_target_uri"),
                    "repository_base_uri": target.get("repository_base_uri"),
                    "source_host": target.get("source_host"),
                    "source_scheme": target.get("source_scheme"),

                    "local_object_path": success.get("local_object_path"),
                    "object_sha256": success.get("object_sha256"),
                    "object_size_bytes": success.get("object_size_bytes"),
                    "fetch_duration_sec": success.get("fetch_duration_sec"),

                    "validity": success.get("validity"),
                    "chainValidity": success.get("chainValidity"),
                    "stale": success.get("stale"),
                    "jsonext_generatedTime": success.get("jsonext_generatedTime"),

                    "failure_class": None,
                    "failure_reason": [],

                    "semantic_boundary": "late_backfilled_object_not_same_window_input",
                    "strong_causal_claim_allowed": False,
                }

                case_priority = "case_success_roa_object_backfilled"

            elif failure:
                status = "backfill_fetch_failed"
                confidence = "fetch_failure_observed"
                counters["backfill_fetch_failed"] += 1
                counters[f"failure_class_{failure.get('failure_class')}"] += 1

                joined = {
                    "schema": "s3.m20.b3.joined_backfill_record.v1",
                    "vrp_key": vrp_key,
                    "afi": target.get("afi"),
                    "tal": target.get("tal"),
                    "prefix": target.get("prefix"),
                    "asn": target.get("asn"),
                    "maxLength": target.get("maxLength"),

                    "m20_join_status": status,
                    "m20_join_confidence": confidence,

                    "fetch_target_uri": target.get("fetch_target_uri"),
                    "repository_base_uri": target.get("repository_base_uri"),
                    "source_host": target.get("source_host"),
                    "source_scheme": target.get("source_scheme"),

                    "local_object_path": None,
                    "object_sha256": None,
                    "object_size_bytes": None,
                    "fetch_duration_sec": failure.get("duration_sec"),

                    "validity": target.get("validity"),
                    "chainValidity": target.get("chainValidity"),
                    "stale": target.get("stale"),
                    "jsonext_generatedTime": target.get("jsonext_generatedTime"),

                    "failure_class": failure.get("failure_class"),
                    "failure_reason": [
                        "late_targeted_fetch_failed",
                        str(failure.get("failure_class")),
                    ],
                    "stderr_tail": failure.get("stderr_tail"),

                    "semantic_boundary": "late_targeted_fetch_failure_not_same_window_input",
                    "strong_causal_claim_allowed": False,
                }

                case_priority = "case_failure_repository_reachability"

            else:
                status = "no_fetch_record_found"
                confidence = "none"
                counters["no_fetch_record_found"] += 1

                joined = {
                    "schema": "s3.m20.b3.joined_backfill_record.v1",
                    "vrp_key": vrp_key,
                    "afi": target.get("afi"),
                    "tal": target.get("tal"),
                    "prefix": target.get("prefix"),
                    "asn": target.get("asn"),
                    "maxLength": target.get("maxLength"),

                    "m20_join_status": status,
                    "m20_join_confidence": confidence,
                    "fetch_target_uri": target.get("fetch_target_uri"),
                    "repository_base_uri": target.get("repository_base_uri"),
                    "source_host": target.get("source_host"),

                    "failure_class": "missing_fetch_record",
                    "failure_reason": ["no_fetch_record_found"],

                    "semantic_boundary": "missing_fetch_record_not_causal_attribution",
                    "strong_causal_claim_allowed": False,
                }

                case_priority = "case_missing_fetch_record"

            joined_out.write(json.dumps(joined, ensure_ascii=False, sort_keys=True) + "\n")

            case = {
                "schema": "s3.m20.case_study_candidate.v1",
                "vrp_key": vrp_key,
                "case_priority": case_priority,
                "m20_join_status": status,
                "source_host": target.get("source_host"),
                "repository_base_uri": target.get("repository_base_uri"),
                "prefix": target.get("prefix"),
                "asn": target.get("asn"),
                "maxLength": target.get("maxLength"),
                "tal": target.get("tal"),
                "fetch_target_uri": target.get("fetch_target_uri"),
                "semantic_boundary": joined.get("semantic_boundary"),
                "strong_causal_claim_allowed": False,
            }
            case_out.write(json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n")

    summary = {
        "schema": "s3.m20.b3.join_backfilled_objects_summary.v1",
        "generated_at_utc": utc_now(),
        "targets_jsonl": str(targets_path),
        "backfilled_roa_index": str(roa_index_path),
        "failure_records": str(failure_path),
        "counters": dict(counters),
        "outputs": {
            "joined_records_jsonl": str(joined_path),
            "case_study_candidates_jsonl": str(case_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "late_backfill_join_not_same_window_input",
        "strong_causal_claim_allowed": False,
        "next_stage": "M20_B4_EVIDENCE_PACK_AND_RESEARCH_SUMMARY",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M20_B3_JOIN_BACKFILLED_OBJECTS=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"target_count = {counters['target_count']}",
        f"backfilled_roa_object_available = {counters['backfilled_roa_object_available']}",
        f"backfill_fetch_failed = {counters['backfill_fetch_failed']}",
        f"failure_class_timeout = {counters['failure_class_timeout']}",
        f"no_fetch_record_found = {counters['no_fetch_record_found']}",
        f"joined_records_jsonl = {joined_path}",
        f"case_study_candidates_jsonl = {case_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = late_backfill_join_not_same_window_input",
        "strong_causal_claim_allowed = False",
        "next_stage = M20_B4_EVIDENCE_PACK_AND_RESEARCH_SUMMARY",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state_path = Path("data/p3_collector/m20_targeted_backfill/state/current_m20_b3_run.env")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        "\n".join([
            f'export M20_B3_OUT_DIR="{out_dir}"',
            f'export M20_B3_JOINED_RECORDS="{joined_path}"',
            f'export M20_B3_CASE_CANDIDATES="{case_path}"',
            f'export M20_B3_SUMMARY="{summary_path}"',
            f'export M20_B3_CHECK="{check_path}"',
            "",
        ]),
        encoding="utf-8",
    )

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
