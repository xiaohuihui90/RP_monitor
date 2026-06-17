#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_csv(path: Path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fields: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def norm_row(r: dict) -> dict:
    def g(*keys, default=""):
        for k in keys:
            v = r.get(k)
            if v not in (None, ""):
                return v
        return default

    return {
        "target_id": g("target_id", "id"),
        "target_priority": g("target_priority", "priority", "priority_class"),
        "input_evidence_level": g("input_evidence_level", "evidence_level"),
        "tal": g("tal", "tal_top"),
        "repo_host": g("repo_host"),
        "repo_base": g("repo_base"),
        "candidate_count": g("candidate_count", "candidates", default="0"),
        "unique_roa_count": g("unique_roa_count", "unique_roa", default="0"),
        "unique_prefix_count": g("unique_prefix_count", "unique_prefix", default="0"),
        "unique_asn_count": g("unique_asn_count", "unique_asn", default="0"),
        "amplification_candidate_per_roa": g("amplification_candidate_per_roa", "amplification", default=""),
        "capture_reason": g("capture_reason", "reason", "target_reason"),
        "semantic_boundary": g("semantic_boundary", default="m23b_f_panel_construction_not_measurement"),
    }


def load_targets(csv_path: Path, json_path: Path) -> list[dict]:
    rows = []
    if csv_path.exists():
        rows = read_csv(csv_path)
    elif json_path.exists():
        data = json.loads(json_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            rows = data.get("targets", [])
        elif isinstance(data, list):
            rows = data
    return [norm_row(r) for r in rows if isinstance(r, dict)]


def main():
    root = Path.cwd()

    m21 = Path(os.environ.get(
        "M21_RUN_DIR",
        "data/p3_collector/m21_manifest_pp_alignment/history/m21_a1_roa_repository_listing_20260607T144706Z",
    ))
    m23b_out = Path(os.environ.get("M23B_OUT", m21 / "outputs/m23b_five_tal_candidate_aware_live_capture"))
    m23b_d_out = Path(os.environ.get("M23B_D_OUT", m23b_out / "m23b_d_high_impact_same_window_capture"))
    m23b_f_out = Path(os.environ.get("M23B_F_OUT", m23b_out / "m23b_f_longitudinal_scheduler"))

    dirs = [
        m23b_f_out,
        m23b_f_out / "state",
        m23b_f_out / "state" / "locks",
        m23b_f_out / "logs",
        m23b_f_out / "logs" / "hourly_census",
        m23b_f_out / "logs" / "high_impact_capture",
        m23b_f_out / "logs" / "daily_summary",
        m23b_f_out / "logs" / "paper_tables",
        m23b_f_out / "logs" / "health_check",
        m23b_f_out / "hourly_census",
        m23b_f_out / "high_impact_capture",
        m23b_f_out / "daily_summary",
        m23b_f_out / "paper_tables",
        m23b_f_out / "paper_tables" / "latest",
        m23b_f_out / "panels",
        m23b_f_out / "checks",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)

    panel_fields = [
        "target_id", "target_priority", "input_evidence_level", "tal",
        "repo_host", "repo_base", "candidate_count", "unique_roa_count",
        "unique_prefix_count", "unique_asn_count", "amplification_candidate_per_roa",
        "capture_reason", "semantic_boundary",
    ]

    # Panel A: 40-target core panel
    panel_a_csv_in = m23b_out / "m23b_pp_census_target_set.csv"
    panel_a_json_in = m23b_out / "m23b_pp_census_target_set.json"
    panel_a = load_targets(panel_a_csv_in, panel_a_json_in)

    panel_a_all = m23b_f_out / "panels" / "panel_a_core_40.csv"
    panel_a_fetchable = m23b_f_out / "panels" / "panel_a_core_40_fetchable.csv"
    write_csv(panel_a_all, panel_a, panel_fields)
    write_csv(panel_a_fetchable, [r for r in panel_a if r.get("repo_base")], panel_fields)

    # Panel D: high-impact 14 target panel
    panel_d_in = m23b_d_out / "m23b_d_same_window_target_list.csv"
    if panel_d_in.exists():
        panel_d = [norm_row(r) for r in read_csv(panel_d_in)]
    else:
        # Fallback: P0 + P1 candidate_count >= 10
        panel_d = []
        for r in panel_a:
            try:
                cnt = int(float(r.get("candidate_count") or 0))
            except Exception:
                cnt = 0
            if r.get("repo_base") and (r.get("target_priority") == "P0" or cnt >= 10):
                panel_d.append(r)

    panel_d_out = m23b_f_out / "panels" / "panel_d_high_impact_14.csv"
    write_csv(panel_d_out, panel_d, panel_fields)

    # Copy original target list for traceability
    if panel_d_in.exists():
        shutil.copy2(panel_d_in, m23b_f_out / "panels" / "panel_d_source_m23b_d_same_window_target_list.csv")

    scripts = {
        "run_m23b_d_same_window_capture_once.py": root / "scripts/p3/m23b/run_m23b_d_same_window_capture_once.py",
        "analyze_m23b_d_longitudinal_features.py": root / "scripts/p3/m23b/analyze_m23b_d_longitudinal_features.py",
    }
    script_status = {k: v.exists() for k, v in scripts.items()}

    state = {
        "schema": "s3.m23b.f.scheduler_state.v1",
        "created_at_utc": utc_now(),
        "m21_run_dir": str(m21),
        "m23b_out": str(m23b_out),
        "m23b_d_out": str(m23b_d_out),
        "m23b_f_out": str(m23b_f_out),
        "panel_a_count": len(panel_a),
        "panel_a_fetchable_count": sum(1 for r in panel_a if r.get("repo_base")),
        "panel_d_count": len(panel_d),
        "script_status": script_status,
        "semantic_boundary": "m23b_f_initialization_not_measurement",
    }

    (m23b_f_out / "state" / "scheduler_state.json").write_text(
        json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    pass_cond = (
        len(panel_a) > 0
        and len(panel_d) > 0
        and script_status.get("run_m23b_d_same_window_capture_once.py", False)
    )

    check = "\n".join([
        "M23B_F0_INIT=PASS" if pass_cond else "M23B_F0_INIT=FAIL",
        f"created_at_utc = {state['created_at_utc']}",
        f"panel_a_count = {state['panel_a_count']}",
        f"panel_a_fetchable_count = {state['panel_a_fetchable_count']}",
        f"panel_d_count = {state['panel_d_count']}",
        f"panel_a_core = {panel_a_all}",
        f"panel_a_fetchable = {panel_a_fetchable}",
        f"panel_d_high_impact = {panel_d_out}",
        f"state_json = {m23b_f_out / 'state' / 'scheduler_state.json'}",
        f"script_status = {script_status}",
        "semantic_boundary = m23b_f_initialization_not_measurement",
        "next_stage = M23B_F1_HOURLY_CENSUS_AND_F2_HIGH_IMPACT_CAPTURE",
        "",
    ])
    (m23b_f_out / "checks" / "M23B_F0_INIT_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
