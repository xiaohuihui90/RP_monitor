#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def parse_kv_text(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def parse_status(path: Path, key_prefix: str) -> str:
    txt = read_text(path)
    m = re.search(rf"^{re.escape(key_prefix)}=(\S+)", txt, re.MULTILINE)
    return m.group(1) if m else "UNKNOWN"


def as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan-dir", required=True)
    ap.add_argument("--m17c-run-dir", required=True)
    ap.add_argument("--m18-run-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    plan_dir = Path(args.plan_dir)
    m17c_run_dir = Path(args.m17c_run_dir)
    m18_run_dir = Path(args.m18_run_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    plan_path = plan_dir / "m17_incremental_plan.json"
    plan_check = plan_dir / "M17_INCREMENTAL_PLAN_CHECK.txt"
    i2_pipeline_check = plan_dir / "M17_INCREMENTAL_I2_PIPELINE_CHECK.txt"
    i3_postprocess_check = plan_dir / "M17_INCREMENTAL_I3_POSTPROCESS_CHECK.txt"
    i4_refresh_check = plan_dir / "M17_INCREMENTAL_I4_M18_REFRESH_CHECK.txt"

    checks_dir = m17c_run_dir / "checks"
    i1_acc = checks_dir / "M17_INCREMENTAL_I1_PLAN_ACCEPTANCE.txt"
    i2_acc = checks_dir / "M17_INCREMENTAL_I2_PLAN_ACCEPTANCE.txt"
    i3_acc = checks_dir / "M17_INCREMENTAL_I3_POSTPROCESS_ACCEPTANCE.txt"
    i4_acc = checks_dir / "M17_INCREMENTAL_I4_M18_REFRESH_ACCEPTANCE.txt"
    i4b_acc = checks_dir / "M17_INCREMENTAL_I4B_M18_REPAIR_ACCEPTANCE.txt"

    m18_check_dir = m18_run_dir / "checks"
    m18_acceptance = m18_check_dir / "M18_ACCEPTANCE.txt"
    m18_timing_check = m18_check_dir / "M18_TIMING_EVIDENCE_INTEGRATION_CHECK.txt"
    m18_convergence_check = m18_check_dir / "M18_CONVERGENCE_REPORT_CHECK.txt"

    plan = read_json(plan_path)
    summary = plan.get("summary", {})

    window_count = as_int(plan.get("window_count"))
    run_window_count = as_int(summary.get("run_window_count"))
    skip_window_count = as_int(summary.get("skip_window_count"))
    repair_window_count = as_int(summary.get("repair_window_count"))
    blocked_window_count = as_int(summary.get("blocked_window_count"))

    # 工程优化收益：full mode 会对 selected windows 全部进入 M17 重计算；
    # incremental mode 本轮只对 run/repair 窗口进入重计算。
    incremental_compute_windows = run_window_count + repair_window_count
    full_compute_windows = window_count

    saved_window_count = max(0, full_compute_windows - incremental_compute_windows)
    skip_ratio = (saved_window_count / full_compute_windows) if full_compute_windows else 0.0

    # 注意：这是基于窗口数的 deterministic saving，不是 wall-clock benchmark。
    # wall-clock 受机器负载、IO、VRP 文件大小影响，后续可接入 run_collector_m17c_once.py 的真实 stage timing。
    estimated_compute_reduction_ratio = skip_ratio

    statuses = {
        "i1_plan_acceptance": parse_status(i1_acc, "M17_INCREMENTAL_I1_PLAN_ACCEPTANCE"),
        "i2_pipeline_acceptance": parse_status(i2_acc, "M17_INCREMENTAL_I2_PLAN_ACCEPTANCE"),
        "i3_postprocess_acceptance": parse_status(i3_acc, "M17_INCREMENTAL_I3_POSTPROCESS_ACCEPTANCE"),
        "i4_m18_refresh_acceptance": parse_status(i4_acc, "M17_INCREMENTAL_I4_M18_REFRESH_ACCEPTANCE"),
        "i4b_m18_repair_acceptance": parse_status(i4b_acc, "M17_INCREMENTAL_I4B_M18_REPAIR_ACCEPTANCE"),
        "m18_acceptance": parse_status(m18_acceptance, "M18_ACCEPTANCE"),
        "m18_timing_evidence": parse_status(m18_timing_check, "M18_TIMING_EVIDENCE_INTEGRATION"),
        "m18_convergence_report": parse_status(m18_convergence_check, "M18_CONVERGENCE_REPORT"),
    }

    required_pass = [
        statuses["i1_plan_acceptance"] == "PASS",
        statuses["i2_pipeline_acceptance"] == "PASS",
        statuses["i3_postprocess_acceptance"] == "PASS",
        statuses["i4_m18_refresh_acceptance"] == "PASS",
        statuses["i4b_m18_repair_acceptance"] == "PASS",
        statuses["m18_acceptance"] == "PASS",
        statuses["m18_timing_evidence"] == "PASS",
        statuses["m18_convergence_report"] == "PASS",
        blocked_window_count == 0,
        window_count > 0,
        incremental_compute_windows > 0,
        skip_window_count > 0,
    ]

    final_status = "PASS" if all(required_pass) else "FAIL"

    m18_accept_kv = parse_kv_text(m18_acceptance)
    m18_timing_kv = parse_kv_text(m18_timing_check)
    m18_convergence_kv = parse_kv_text(m18_convergence_check)

    report = {
        "schema": "s3.m17.incremental_timing_finalizer.v1",
        "generated_at_utc": utc_now(),
        "status": final_status,
        "target_window_id": plan.get("target_window_id"),
        "m17c_run_dir": str(m17c_run_dir),
        "m18_run_dir": str(m18_run_dir),
        "plan": {
            "window_count": window_count,
            "run_window_count": run_window_count,
            "skip_window_count": skip_window_count,
            "repair_window_count": repair_window_count,
            "blocked_window_count": blocked_window_count,
            "target_found": plan.get("target_found"),
            "force_current_window": plan.get("force_current_window"),
            "repair_missing_windows": plan.get("repair_missing_windows"),
        },
        "incremental_saving": {
            "full_compute_windows": full_compute_windows,
            "incremental_compute_windows": incremental_compute_windows,
            "saved_window_count": saved_window_count,
            "skip_ratio": round(skip_ratio, 6),
            "estimated_compute_reduction_ratio": round(estimated_compute_reduction_ratio, 6),
            "interpretation": "window_count_based_recompute_avoidance_not_wall_clock_benchmark",
        },
        "acceptance_statuses": statuses,
        "m18_summary": {
            "ready_window_count": as_int(m18_accept_kv.get("ready_window_count")),
            "merged_seed_record_count": as_int(m18_accept_kv.get("merged_seed_record_count")),
            "diff_lifetime_record_count": as_int(m18_accept_kv.get("diff_lifetime_record_count")),
            "persistent_candidate_count": as_int(m18_accept_kv.get("persistent_candidate_count")),
            "trailing_cache_candidate_count": as_int(m18_accept_kv.get("trailing_cache_candidate_count")),
            "m19_candidate_count": as_int(m18_accept_kv.get("m19_candidate_count")),
            "window_timing_quality_counts": m18_timing_kv.get("window_timing_quality_counts"),
            "lifetime_temporal_alignment_quality_counts": m18_timing_kv.get("lifetime_temporal_alignment_quality_counts"),
            "m19_temporal_alignment_quality_counts": m18_timing_kv.get("m19_temporal_alignment_quality_counts"),
        },
        "semantic_boundary": {
            "mapping_strength": m18_accept_kv.get("mapping_strength", "weak"),
            "strong_causal_claim_allowed": m18_accept_kv.get("strong_causal_claim_allowed", "False"),
            "accepted_object_set_available": "False",
            "note": "Only entry-level divergence/lifetime/convergence evidence is accepted. No strong ROA/PP causal claim is allowed in this batch.",
        },
        "input_files": {
            "plan_json": str(plan_path),
            "plan_check": str(plan_check),
            "i2_pipeline_check": str(i2_pipeline_check),
            "i3_postprocess_check": str(i3_postprocess_check),
            "i4_refresh_check": str(i4_refresh_check),
            "i4b_acceptance": str(i4b_acc),
            "m18_acceptance": str(m18_acceptance),
            "m18_timing_check": str(m18_timing_check),
            "m18_convergence_check": str(m18_convergence_check),
        },
        "next_stage": "M19_ROA_TO_VRP_MAPPING_PRECHECK" if final_status == "PASS" else "M17_INCREMENTAL_REPAIR_REQUIRED",
    }

    write_json(out_dir / "m17_incremental_i5_timing_finalizer_summary.json", report)

    md = []
    md.append("# M17 Incremental I5 Timing Finalizer")
    md.append("")
    md.append(f"- generated_at_utc: `{report['generated_at_utc']}`")
    md.append(f"- status: `{final_status}`")
    md.append(f"- target_window_id: `{report['target_window_id']}`")
    md.append("")
    md.append("## Incremental Saving")
    md.append("")
    for k, v in report["incremental_saving"].items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## Acceptance Statuses")
    md.append("")
    for k, v in statuses.items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## M18 Summary")
    md.append("")
    for k, v in report["m18_summary"].items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## Semantic Boundary")
    md.append("")
    for k, v in report["semantic_boundary"].items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append(f"next_stage: `{report['next_stage']}`")
    (out_dir / "m17_incremental_i5_timing_finalizer_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    txt = [
        f"M17_INCREMENTAL_I5_TIMING_FINALIZER={final_status}",
        f"generated_at_utc = {report['generated_at_utc']}",
        f"target_window_id = {report['target_window_id']}",
        f"window_count = {window_count}",
        f"full_compute_windows = {full_compute_windows}",
        f"incremental_compute_windows = {incremental_compute_windows}",
        f"saved_window_count = {saved_window_count}",
        f"skip_ratio = {round(skip_ratio, 6)}",
        f"estimated_compute_reduction_ratio = {round(estimated_compute_reduction_ratio, 6)}",
        f"m18_acceptance = {statuses['m18_acceptance']}",
        f"m19_candidate_count = {report['m18_summary']['m19_candidate_count']}",
        f"mapping_strength = {report['semantic_boundary']['mapping_strength']}",
        f"strong_causal_claim_allowed = {report['semantic_boundary']['strong_causal_claim_allowed']}",
        f"summary_json = {out_dir / 'm17_incremental_i5_timing_finalizer_summary.json'}",
        f"summary_md = {out_dir / 'm17_incremental_i5_timing_finalizer_summary.md'}",
        f"next_stage = {report['next_stage']}",
    ]

    (out_dir / "M17_INCREMENTAL_I5_TIMING_FINALIZER_CHECK.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")
    print("\n".join(txt))

    if final_status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
