#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
from typing import Any


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
    ap.add_argument("--mapping-records", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    mapping_records_path = Path(args.mapping_records)
    out_dir = Path(args.out_dir)

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)

    summary_path = outputs / "m19_mapping_coverage_summary.json"
    m20_candidates_path = outputs / "m20_targeted_backfill_candidates.jsonl"
    failure_records_path = outputs / "m19_mapping_failure_records.jsonl"
    check_path = checks / "M19_B5_MAPPING_COVERAGE_ACCEPTANCE.txt"

    counters = Counter()

    with m20_candidates_path.open("w", encoding="utf-8") as m20_out, \
         failure_records_path.open("w", encoding="utf-8") as fail_out:

        for _, rec in iter_jsonl(mapping_records_path):
            if not isinstance(rec, dict) or rec.get("_parse_error"):
                counters["parse_error"] += 1
                continue

            counters["input_candidate_count"] += 1

            status = rec.get("mapping_status") or "unknown"
            counters[f"mapping_status_{status}"] += 1

            if rec.get("roa_uri"):
                counters["mapped_to_roa_count"] += 1
            if rec.get("manifest_uri"):
                counters["mapped_to_manifest_count"] += 1
            if rec.get("pp_uri"):
                counters["mapped_to_pp_count"] += 1

            failure_reason = rec.get("failure_reason") or []
            for fr in failure_reason:
                counters[f"failure_{fr}"] += 1

            if status not in {"mapped_to_roa", "mapped_to_manifest", "mapped_to_pp"}:
                fail_out.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
                counters["failure_record_count"] += 1

                # 当前没有 PP URI 时，不做盲目 fetch，生成 M20 诊断候选。
                action_required = []
                if not rec.get("source_uri"):
                    action_required.append("jsonext_source_uri_required")
                if not rec.get("roa_uri"):
                    action_required.append("roa_candidate_required")
                if not rec.get("pp_uri"):
                    action_required.append("pp_uri_unavailable_for_direct_fetch")

                m20 = {
                    "schema": "s3.m20.targeted_backfill_candidate.v1",
                    "vrp_key": rec.get("vrp_key"),
                    "afi": rec.get("afi"),
                    "tal": rec.get("tal"),
                    "prefix": rec.get("prefix"),
                    "asn": rec.get("asn"),
                    "maxLength": rec.get("maxLength"),

                    "m19_mapping_status": status,
                    "m19_failure_reason": failure_reason,
                    "m19_diff_scope_status": rec.get("diff_scope_status"),

                    "target_hint": {
                        "source_uri": rec.get("source_uri"),
                        "roa_uri": rec.get("roa_uri"),
                        "manifest_uri": rec.get("manifest_uri"),
                        "pp_uri": rec.get("pp_uri"),
                    },

                    "action_required": action_required,
                    "priority": "high",
                    "fetch_ready": bool(rec.get("pp_uri") or rec.get("manifest_uri") or rec.get("roa_uri")),
                    "provenance": ["m19_mapping_failure", "m18_d7b_seed"],
                    "strong_causal_claim_allowed": False,
                }
                m20_out.write(json.dumps(m20, ensure_ascii=False, sort_keys=True) + "\n")
                counters["m20_backfill_candidate_count"] += 1
                if not m20["fetch_ready"]:
                    counters["m20_candidate_not_fetch_ready"] += 1

    input_count = counters["input_candidate_count"]
    coverage = {
        "mapped_to_roa_ratio": (counters["mapped_to_roa_count"] / input_count) if input_count else 0,
        "mapped_to_manifest_ratio": (counters["mapped_to_manifest_count"] / input_count) if input_count else 0,
        "mapped_to_pp_ratio": (counters["mapped_to_pp_count"] / input_count) if input_count else 0,
    }

    summary = {
        "schema": "s3.m19.b5.mapping_coverage_summary.v1",
        "generated_at_utc": utc_now(),
        "mapping_records": str(mapping_records_path),
        "counters": dict(counters),
        "coverage": coverage,
        "outputs": {
            "summary_json": str(summary_path),
            "m20_targeted_backfill_candidates": str(m20_candidates_path),
            "mapping_failure_records": str(failure_records_path),
            "check_txt": str(check_path),
        },
        "interpretation": {
            "source_uri_gap_observed": counters["failure_source_uri_missing_or_insufficient_in_raw_vrp"] > 0,
            "current_l2_roa_index_empty": counters["mapped_to_roa_count"] == 0,
            "m20_direct_fetch_ready": counters["m20_backfill_candidate_count"] - counters["m20_candidate_not_fetch_ready"],
        },
        "semantic_boundary": "mapping_coverage_candidate_level_not_causal_attribution",
        "strong_causal_claim_allowed": False,
        "next_stage": "M20_TARGETED_BACKFILL_OR_JSONEXT_SIDECAR",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M19_B5_MAPPING_COVERAGE=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"input_candidate_count = {input_count}",
        f"mapped_to_roa_count = {counters['mapped_to_roa_count']}",
        f"mapped_to_manifest_count = {counters['mapped_to_manifest_count']}",
        f"mapped_to_pp_count = {counters['mapped_to_pp_count']}",
        f"mapping_status_roa_candidate_not_found = {counters['mapping_status_roa_candidate_not_found']}",
        f"failure_source_uri_missing = {counters['failure_source_uri_missing_or_insufficient_in_raw_vrp']}",
        f"m20_backfill_candidate_count = {counters['m20_backfill_candidate_count']}",
        f"m20_candidate_not_fetch_ready = {counters['m20_candidate_not_fetch_ready']}",
        f"summary_json = {summary_path}",
        f"m20_targeted_backfill_candidates = {m20_candidates_path}",
        f"mapping_failure_records = {failure_records_path}",
        "semantic_boundary = mapping_coverage_candidate_level_not_causal_attribution",
        "strong_causal_claim_allowed = False",
        "next_stage = M20_TARGETED_BACKFILL_OR_JSONEXT_SIDECAR",
    ]
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state_path = Path("data/p3_collector/m19_roa_to_vrp/state/current_m19_run.env")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        "\n".join([
            f'export M19_RUN_DIR="{out_dir}"',
            f'export M19_MAPPING_RECORDS="{mapping_records_path}"',
            f'export M19_MAPPING_COVERAGE_SUMMARY="{summary_path}"',
            f'export M19_M20_TARGETS="{m20_candidates_path}"',
            f'export M19_MAPPING_FAILURE_RECORDS="{failure_records_path}"',
            "",
        ]),
        encoding="utf-8",
    )

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
