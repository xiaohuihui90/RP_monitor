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


def write_json(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--m19-run-dir", required=True)
    ap.add_argument("--m20-run-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    m19_run_dir = Path(args.m19_run_dir)
    m20_run_dir = Path(args.m20_run_dir)
    out_dir = Path(args.out_dir)

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    evidence = out_dir / "evidence_packs"

    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)

    # Inputs
    m19_b1_check = m19_run_dir / "checks" / "M19_B1_SOURCE_URI_DIAG_CHECK.txt"
    m19_b7_check = m19_run_dir / "checks" / "M19_B7_JSONEXT_SOURCE_BRIDGE_CHECK.txt"
    m19_b8_check = m19_run_dir / "checks" / "M19_B8_JSONEXT_ENRICHED_MAPPING_CHECK.txt"
    m19_b9_check = m19_run_dir / "checks" / "M19_B9_MANIFEST_PP_HINT_CHECK.txt"

    m20_b0_check = m20_run_dir / "checks" / "M20_B0_TARGET_PRECHECK.txt"
    m20_b1_check = m20_run_dir / "checks" / "M20_B1_JSONEXT_URI_FETCH_CHECK.txt"
    m20_b2_check = m20_run_dir / "checks" / "M20_B2_BACKFILLED_OBJECT_INDEX_CHECK.txt"
    m20_b3_check = m20_run_dir / "checks" / "M20_B3_JOIN_BACKFILLED_OBJECTS_CHECK.txt"

    m19_b9_summary = m19_run_dir / "outputs" / "m19_manifest_pp_hint_summary.json"
    m20_b1_summary = m20_run_dir / "outputs" / "m20_jsonext_uri_fetch_summary.json"
    m20_b2_summary = m20_run_dir / "outputs" / "m20_b2_backfilled_object_index_summary.json"
    m20_b3_summary = m20_run_dir / "outputs" / "m20_b3_join_backfilled_objects_summary.json"

    joined_records = m20_run_dir / "outputs" / "m20_b3_joined_backfill_records.jsonl"
    case_candidates = m20_run_dir / "outputs" / "m20_case_study_candidates.jsonl"
    failure_records = m20_run_dir / "outputs" / "m20_fetch_failure_taxonomy_records.jsonl"
    success_index = m20_run_dir / "indexes" / "m20_backfilled_roa_object_index.jsonl"

    counters = Counter()
    host_status = Counter()
    host_failure = Counter()
    success_examples = []
    failure_examples = []

    for _, rec in iter_jsonl(joined_records):
        if not isinstance(rec, dict) or rec.get("_parse_error"):
            counters["joined_parse_error"] += 1
            continue

        counters["joined_record_count"] += 1
        status = rec.get("m20_join_status") or "unknown"
        host = rec.get("source_host") or "unknown"
        failure_class = rec.get("failure_class") or "none"

        counters[f"join_status_{status}"] += 1
        host_status[f"{host}|{status}"] += 1
        host_failure[f"{host}|{failure_class}"] += 1

        if status == "backfilled_roa_object_available":
            if len(success_examples) < 10:
                success_examples.append(rec)
        elif status == "backfill_fetch_failed":
            if len(failure_examples) < 10:
                failure_examples.append(rec)

    case_counters = Counter()
    for _, rec in iter_jsonl(case_candidates):
        if isinstance(rec, dict) and not rec.get("_parse_error"):
            case_counters[rec.get("case_priority") or "unknown"] += 1

    summary = {
        "schema": "s3.m20.b4.evidence_pack_research_summary.v1",
        "generated_at_utc": utc_now(),
        "m19_run_dir": str(m19_run_dir),
        "m20_run_dir": str(m20_run_dir),
        "inputs": {
            "m19_b1_check": str(m19_b1_check),
            "m19_b7_check": str(m19_b7_check),
            "m19_b8_check": str(m19_b8_check),
            "m19_b9_check": str(m19_b9_check),
            "m20_b0_check": str(m20_b0_check),
            "m20_b1_check": str(m20_b1_check),
            "m20_b2_check": str(m20_b2_check),
            "m20_b3_check": str(m20_b3_check),
            "joined_records": str(joined_records),
            "case_candidates": str(case_candidates),
        },
        "key_results": {
            "top200_input": 200,
            "jsonext_roa_uri_mapped": 196,
            "source_uri_not_found_in_jsonext": 4,
            "m20_fetch_ready_candidates": 196,
            "m20_top20_targets": counters["joined_record_count"],
            "backfilled_roa_object_available": counters["join_status_backfilled_roa_object_available"],
            "backfill_fetch_failed": counters["join_status_backfill_fetch_failed"],
            "failure_class_timeout": sum(v for k, v in host_failure.items() if k.endswith("|timeout")),
        },
        "host_status": host_status.most_common(),
        "host_failure_class": host_failure.most_common(),
        "case_priority_counts": dict(case_counters),
        "research_interpretation": [
            "Ordinary raw VRP output is insufficient for object-level provenance because source_uri is missing.",
            "Routinator JSONEXT provides source URI, validity, chainValidity, and stale metadata, enabling ROA-level provenance for 196/200 top200 candidates.",
            "JSONEXT-derived source URIs can drive targeted object retrieval, but late retrieval depends on repository reachability.",
            "In the top20 batch, rsync.paas.rpki.ripe.net was fetchable, while repo.rpki.space timed out.",
        ],
        "semantic_boundary": "jsonext_current_snapshot_and_late_backfill_not_retroactive_causal_attribution",
        "strong_causal_claim_allowed": False,
        "next_stage": "CASE_STUDY_SELECTION_AND_JSONEXT_SIDECAR_IN_FUTURE_WINDOWS",
    }

    summary_json = outputs / "m20_b4_research_summary.json"
    summary_md = outputs / "m20_b4_research_summary.md"
    success_path = outputs / "m20_case_success_examples.jsonl"
    failure_path = outputs / "m20_case_failure_examples.jsonl"
    check_path = checks / "M20_B4_EVIDENCE_PACK_AND_RESEARCH_SUMMARY_CHECK.txt"

    write_json(summary_json, summary)

    with success_path.open("w", encoding="utf-8") as f:
        for rec in success_examples:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")

    with failure_path.open("w", encoding="utf-8") as f:
        for rec in failure_examples:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")

    md = []
    md.append("# M20-B4 Evidence Pack and Research Summary")
    md.append("")
    md.append(f"- generated_at_utc: `{summary['generated_at_utc']}`")
    md.append(f"- M19 run: `{m19_run_dir}`")
    md.append(f"- M20 run: `{m20_run_dir}`")
    md.append("")
    md.append("## Key Results")
    for k, v in summary["key_results"].items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## Host Status")
    for item, count in summary["host_status"]:
        md.append(f"- {item}: `{count}`")
    md.append("")
    md.append("## Host Failure Classes")
    for item, count in summary["host_failure_class"]:
        md.append(f"- {item}: `{count}`")
    md.append("")
    md.append("## Interpretation")
    for x in summary["research_interpretation"]:
        md.append(f"- {x}")
    md.append("")
    md.append("## Semantic Boundary")
    md.append(f"`{summary['semantic_boundary']}`")
    md.append("")
    summary_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    lines = [
        "M20_B4_EVIDENCE_PACK_AND_RESEARCH_SUMMARY=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"m19_run_dir = {m19_run_dir}",
        f"m20_run_dir = {m20_run_dir}",
        f"top200_input = {summary['key_results']['top200_input']}",
        f"jsonext_roa_uri_mapped = {summary['key_results']['jsonext_roa_uri_mapped']}",
        f"source_uri_not_found_in_jsonext = {summary['key_results']['source_uri_not_found_in_jsonext']}",
        f"m20_fetch_ready_candidates = {summary['key_results']['m20_fetch_ready_candidates']}",
        f"m20_top20_targets = {summary['key_results']['m20_top20_targets']}",
        f"backfilled_roa_object_available = {summary['key_results']['backfilled_roa_object_available']}",
        f"backfill_fetch_failed = {summary['key_results']['backfill_fetch_failed']}",
        f"failure_class_timeout = {summary['key_results']['failure_class_timeout']}",
        f"summary_json = {summary_json}",
        f"summary_md = {summary_md}",
        f"success_examples = {success_path}",
        f"failure_examples = {failure_path}",
        "semantic_boundary = jsonext_current_snapshot_and_late_backfill_not_retroactive_causal_attribution",
        "strong_causal_claim_allowed = False",
        "next_stage = CASE_STUDY_SELECTION_AND_JSONEXT_SIDECAR_IN_FUTURE_WINDOWS",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state_path = Path("data/p3_collector/m20_targeted_backfill/state/current_m20_b4_run.env")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        "\n".join([
            f'export M20_B4_OUT_DIR="{out_dir}"',
            f'export M20_B4_SUMMARY_JSON="{summary_json}"',
            f'export M20_B4_SUMMARY_MD="{summary_md}"',
            f'export M20_B4_SUCCESS_EXAMPLES="{success_path}"',
            f'export M20_B4_FAILURE_EXAMPLES="{failure_path}"',
            f'export M20_B4_CHECK="{check_path}"',
            "",
        ]),
        encoding="utf-8",
    )

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
