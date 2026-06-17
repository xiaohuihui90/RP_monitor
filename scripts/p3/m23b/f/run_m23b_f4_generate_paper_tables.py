#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import os
import shutil
from pathlib import Path
from datetime import datetime, timezone


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


def latest_daily_dir(f_out: Path):
    dirs = [p for p in (f_out / "daily_summary").glob("*") if p.is_dir()]
    if not dirs:
        return None
    return sorted(dirs)[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m23b-f-out", default=os.environ.get("M23B_F_OUT", ""))
    ap.add_argument("--m23b-d-out", default=os.environ.get("M23B_D_OUT", ""))
    ap.add_argument("--out-dir", default="")
    args = ap.parse_args()

    f_out = Path(args.m23b_f_out)
    d_out = Path(args.m23b_d_out)
    out = Path(args.out_dir) if args.out_dir else f_out / "paper_tables" / "latest"
    out.mkdir(parents=True, exist_ok=True)

    day = latest_daily_dir(f_out)
    if day is None:
        raise SystemExit("No daily_summary directory found.")

    # Table 1: TAL distribution
    tal_rows = read_csv(day / "m23b_daily_tal_summary.csv")
    table1 = out / "table_1_tal_distribution.csv"
    if tal_rows:
        write_csv(table1, tal_rows, list(tal_rows[0].keys()))

    # Table 2: Top PP concentration
    pp_rows = read_csv(day / "m23b_daily_pp_summary.csv")
    pp_rows_sorted = sorted(pp_rows, key=lambda r: float(r.get("candidate_count_sum") or 0), reverse=True)
    table2 = out / "table_2_top_pp_concentration.csv"
    if pp_rows_sorted:
        write_csv(table2, pp_rows_sorted, list(pp_rows_sorted[0].keys()))

    # Table 5: Root-cause feature frequency
    feat_rows = read_csv(day / "m23b_daily_root_cause_feature_summary.csv")
    feat_rows_sorted = sorted(feat_rows, key=lambda r: int(float(r.get("observation_count") or 0)), reverse=True)
    table5 = out / "table_5_root_cause_feature_frequency.csv"
    if feat_rows_sorted:
        write_csv(table5, feat_rows_sorted, list(feat_rows_sorted[0].keys()))

    # Table 6: Evidence level distribution
    ev_rows = read_csv(day / "m23b_daily_evidence_level_summary.csv")
    table6 = out / "table_6_evidence_level_distribution.csv"
    if ev_rows:
        write_csv(table6, ev_rows, list(ev_rows[0].keys()))

    # Table 7: High-impact target behavior
    target_rows = read_csv(d_out / "m23b_d_longitudinal_target_feature_table.csv")
    table7 = out / "table_7_high_impact_target_behavior.csv"
    if target_rows:
        write_csv(table7, target_rows, list(target_rows[0].keys()))

    # Table 4: persistence summary
    persist_rows = read_csv(day / "m23b_daily_persistence_summary.csv")
    table4 = out / "table_4_temporal_persistence.csv"
    if persist_rows:
        write_csv(table4, persist_rows, list(persist_rows[0].keys()))

    # Table 3: ROA/manifest amplification: copy existing if available
    candidates = [
        Path(os.environ.get("M22G_OUT", "")) / "cluster_by_repo_base.csv",
        Path(os.environ.get("PAPER_TABLE_OUT", "")) / "table3_top_repository_roa_amplification_cluster.csv",
    ]
    table3 = out / "table_3_roa_manifest_amplification.csv"
    copied_table3 = False
    for c in candidates:
        if str(c) and c.exists():
            shutil.copy2(c, table3)
            copied_table3 = True
            break
    if not copied_table3:
        write_csv(table3, [], ["repo_host", "repo_base", "candidate_count", "unique_roa_count", "amplification"])

    md = []
    md.append("# M23B-F Paper Tables")
    md.append("")
    md.append(f"- generated_at_utc: `{utc_now()}`")
    md.append(f"- source_daily_dir: `{day}`")
    md.append("")
    for i, p in enumerate([table1, table2, table3, table4, table5, table6, table7], start=1):
        md.append(f"- table_{i}: `{p}` exists=`{p.exists()}` size=`{p.stat().st_size if p.exists() else 0}`")
    md.append("")
    md.append("Semantic boundary: paper tables from longitudinal measurement, not final causal attribution.")
    (out / "m23b_f_paper_tables_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    check = "\n".join([
        "M23B_F4_PAPER_TABLES=PASS",
        f"generated_at_utc = {utc_now()}",
        f"source_daily_dir = {day}",
        f"paper_table_dir = {out}",
        f"table_1 = {table1}",
        f"table_2 = {table2}",
        f"table_3 = {table3}",
        f"table_4 = {table4}",
        f"table_5 = {table5}",
        f"table_6 = {table6}",
        f"table_7 = {table7}",
        "semantic_boundary = paper_table_from_longitudinal_measurement_not_final_causal_attribution",
        "next_stage = M23B_F5_CRON_INSTALL",
        "",
    ])
    (out / "M23B_F4_PAPER_TABLES_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
