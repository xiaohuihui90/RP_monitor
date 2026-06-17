#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from s3lib.p0.jsonio import read_json, write_json
from s3lib.p0.timeutil import utc_now


def load_json(path: Path) -> dict[str, Any]:
    obj = read_json(path)
    return obj if isinstance(obj, dict) else {}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report-dir", default="data/p3_collector/m245_three_layer_baseline/reports")
    ap.add_argument("--acceptance-dir", default="data/p3_collector/m245_three_layer_baseline/p0_acceptance")
    ap.add_argument("--evidence-pack-root", default="data/p3_collector/m245_three_layer_baseline/evidence_packs")
    args = ap.parse_args()

    report_dir = Path(args.report_dir)
    acceptance_dir = Path(args.acceptance_dir)
    evidence_pack_root = Path(args.evidence_pack_root)
    acceptance_dir.mkdir(parents=True, exist_ok=True)

    stats = load_json(report_dir / "M16_three_layer_baseline_report.json")
    guardrail = load_json(report_dir / "M16_SEMANTIC_GUARDRAIL.json")
    raw_vrp = load_json(acceptance_dir / "p0_raw_vrp_retention_summary.json")
    h7 = load_json(acceptance_dir / "p0_h7_overlay_summary.json")
    validator_meta = load_json(acceptance_dir / "p0_validator_metadata_summary.json")
    evidence_summary = load_json(report_dir / "P0_basic_evidence_pack_summary.json")

    records = stats.get("records", [])
    if not isinstance(records, list):
        records = []

    m17_candidates = [r for r in records if isinstance(r, dict) and r.get("m17_candidate") is True]

    evidence_pack_count = evidence_summary.get("evidence_pack_count", 0)
    m17_evidence_pack_count = evidence_summary.get("m17_candidate_evidence_pack_count", 0)

    total_windows = stats.get("total_windows", 0)
    complete_3probe_windows = stats.get("complete_3probe_windows", 0)
    raw_vrp_ready_windows = stats.get("raw_vrp_ready_windows", 0)
    m17_candidate_windows = stats.get("m17_candidate_windows", 0)

    conditions = {
        "total_windows_gt_0": isinstance(total_windows, int) and total_windows > 0,
        "complete_3probe_windows_gt_0": isinstance(complete_3probe_windows, int) and complete_3probe_windows > 0,
        "h7_overlay_applied": h7.get("overlay_written_windows", 0) > 0,
        "mapping_strength_always_weak": h7.get("mapping_strength_always_weak") is True,
        "validator_cache_view_medium_eligible_always_false": h7.get("validator_cache_view_medium_eligible_always_false") is True,
        "raw_vrp_ready_windows_gt_0": isinstance(raw_vrp_ready_windows, int) and raw_vrp_ready_windows > 0,
        "raw_vrp_retention_ready": raw_vrp.get("ready_for_m17_vrp_entry_diff") is True,
        "validator_metadata_ready": validator_meta.get("metadata_pass_windows", 0) > 0,
        "evidence_pack_ready": isinstance(evidence_pack_count, int) and evidence_pack_count > 0,
        "m17_evidence_pack_ready": isinstance(m17_evidence_pack_count, int) and m17_evidence_pack_count > 0,
        "semantic_guardrail_pass": guardrail.get("no_forbidden_strong_claim") is True,
        "m17_candidate_windows_gt_0": isinstance(m17_candidate_windows, int) and m17_candidate_windows > 0,
    }

    final_status = "PASS" if all(conditions.values()) else "FAIL"

    result = {
        "schema": "s3.p0.final_acceptance.v1",
        "generated_at_utc": utc_now(),
        "final_status": final_status,
        "label": f"M16_FINAL_ACCEPTANCE={final_status}",
        "conditions": conditions,
        "summary": {
            "total_windows": total_windows,
            "complete_3probe_windows": complete_3probe_windows,
            "raw_vrp_ready_windows": raw_vrp_ready_windows,
            "m17_candidate_windows": m17_candidate_windows,
            "evidence_pack_count": evidence_pack_count,
            "m17_candidate_evidence_pack_count": m17_evidence_pack_count,
            "semantic_guardrail_violation_count": guardrail.get("violation_count"),
            "validator_metadata_pass_windows": validator_meta.get("metadata_pass_windows"),
        },
        "m17_candidates": m17_candidates,
        "ready_for_m17_vrp_entry_diff": final_status == "PASS",
        "next_stage": "M17_VRP_ENTRY_LEVEL_DIFF" if final_status == "PASS" else "P0_REPAIR_REQUIRED",
        "semantic_note": (
            "P0 acceptance only confirms three-layer baseline closure and M17 readiness. "
            "It does not assert strong causality, validator implementation divergence, "
            "or equality between observer object view and validator accepted input."
        ),
    }

    write_json(report_dir / "M16_FINAL_ACCEPTANCE.json", result)

    txt = [
        f"M16_FINAL_ACCEPTANCE={final_status}",
        f"generated_at_utc = {result['generated_at_utc']}",
        f"total_windows = {total_windows}",
        f"complete_3probe_windows = {complete_3probe_windows}",
        f"raw_vrp_ready_windows = {raw_vrp_ready_windows}",
        f"m17_candidate_windows = {m17_candidate_windows}",
        f"evidence_pack_count = {evidence_pack_count}",
        f"m17_candidate_evidence_pack_count = {m17_evidence_pack_count}",
        f"semantic_guardrail_pass = {conditions['semantic_guardrail_pass']}",
        f"ready_for_m17_vrp_entry_diff = {result['ready_for_m17_vrp_entry_diff']}",
        "",
        "conditions:",
    ]

    for k, v in conditions.items():
        txt.append(f"  {k} = {v}")

    txt.append("")
    txt.append("m17_candidates:")
    for r in m17_candidates:
        txt.append(
            f"  - {r.get('window_id')} "
            f"raw_vrp_ready={r.get('raw_vrp_ready')} "
            f"validation_output_status={r.get('validation_output_status')} "
            f"mapping_strength={r.get('mapping_strength')}"
        )

    (report_dir / "M16_FINAL_ACCEPTANCE.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")
    print("\n".join(txt))


if __name__ == "__main__":
    main()
