#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_csv(path: Path):
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fields: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def to_int(x):
    try:
        return int(float(str(x)))
    except Exception:
        return 0


def to_float(x):
    try:
        return float(str(x))
    except Exception:
        return 0.0


def main():
    out = Path(os.environ["M23B_OUT"])
    records_csv = out / "m23b_lightweight_pp_census_records.csv"
    rows = read_csv(records_csv)

    # 1. failed / warning targets
    bad = [
        r for r in rows
        if r.get("rsync_list_status") != "success"
        or r.get("manifest_parse_status") not in ("parsed", "not_attempted")
        or r.get("connection_limit_error") == "True"
        or r.get("timeout_error") == "True"
        or r.get("fetch_failure_type") not in ("", "success_or_not_attempted")
    ]

    bad_rows = []
    for r in bad:
        bad_rows.append({
            "target_id": r.get("target_id", ""),
            "target_priority": r.get("target_priority", ""),
            "tal": r.get("tal", ""),
            "repo_host": r.get("repo_host", ""),
            "repo_base": r.get("repo_base", ""),
            "candidate_count": r.get("candidate_count", ""),
            "unique_roa_count": r.get("unique_roa_count", ""),
            "amplification_candidate_per_roa": r.get("amplification_candidate_per_roa", ""),
            "rsync_list_status": r.get("rsync_list_status", ""),
            "manifest_fetch_status": r.get("manifest_fetch_status", ""),
            "manifest_parse_status": r.get("manifest_parse_status", ""),
            "fetch_failure_type": r.get("fetch_failure_type", ""),
            "connection_limit_error": r.get("connection_limit_error", ""),
            "timeout_error": r.get("timeout_error", ""),
            "semantic_boundary": "single_probe_lightweight_census_failure_feature_not_same_window_attribution",
        })

    write_csv(
        out / "m23b_lightweight_pp_census_failed_targets.csv",
        bad_rows,
        [
            "target_id", "target_priority", "tal", "repo_host", "repo_base",
            "candidate_count", "unique_roa_count", "amplification_candidate_per_roa",
            "rsync_list_status", "manifest_fetch_status", "manifest_parse_status",
            "fetch_failure_type", "connection_limit_error", "timeout_error",
            "semantic_boundary",
        ],
    )

    # 2. repo host concentration table
    by_host = defaultdict(list)
    for r in rows:
        host = r.get("repo_host", "") or "UNMAPPED_OR_EMPTY"
        by_host[host].append(r)

    host_rows = []
    for host, rs in by_host.items():
        candidate_sum = sum(to_int(r.get("candidate_count")) for r in rs)
        failed_count = sum(1 for r in rs if r.get("rsync_list_status") != "success")
        conn_limit_count = sum(1 for r in rs if r.get("connection_limit_error") == "True")
        parsed_count = sum(1 for r in rs if r.get("manifest_parse_status") == "parsed")
        target_count = len(rs)
        tal_c = Counter(r.get("tal", "") for r in rs)
        priority_c = Counter(r.get("target_priority", "") for r in rs)

        host_rows.append({
            "repo_host": host,
            "target_count": target_count,
            "candidate_count_sum": candidate_sum,
            "manifest_parsed_count": parsed_count,
            "rsync_failed_count": failed_count,
            "connection_limit_error_count": conn_limit_count,
            "rsync_success_ratio": round((target_count - failed_count) / target_count, 4) if target_count else 0,
            "manifest_parsed_ratio": round(parsed_count / target_count, 4) if target_count else 0,
            "tal_distribution": repr(tal_c.most_common()),
            "priority_distribution": repr(priority_c.most_common()),
        })

    host_rows.sort(key=lambda x: (-x["candidate_count_sum"], -x["target_count"], x["repo_host"]))

    write_csv(
        out / "m23b_pp_concentration_and_reachability_table.csv",
        host_rows,
        [
            "repo_host", "target_count", "candidate_count_sum", "manifest_parsed_count",
            "rsync_failed_count", "connection_limit_error_count",
            "rsync_success_ratio", "manifest_parsed_ratio",
            "tal_distribution", "priority_distribution",
        ],
    )

    # 3. TAL table
    by_tal = defaultdict(list)
    for r in rows:
        tal = r.get("tal", "") or "unknown"
        by_tal[tal].append(r)

    tal_rows = []
    for tal, rs in by_tal.items():
        candidate_sum = sum(to_int(r.get("candidate_count")) for r in rs)
        target_count = len(rs)
        repo_hosts = set(r.get("repo_host", "") for r in rs if r.get("repo_host"))
        repo_bases = set(r.get("repo_base", "") for r in rs if r.get("repo_base"))
        parsed_count = sum(1 for r in rs if r.get("manifest_parse_status") == "parsed")
        conn_limit_count = sum(1 for r in rs if r.get("connection_limit_error") == "True")
        source_gap_count = sum(1 for r in rs if r.get("fetch_failure_type") == "source_provenance_gap_no_repo_base")
        max_amp = max([to_float(r.get("amplification_candidate_per_roa")) for r in rs] or [0.0])

        tal_rows.append({
            "tal": tal,
            "target_count": target_count,
            "candidate_count_sum": candidate_sum,
            "unique_repo_host_count": len(repo_hosts),
            "unique_repo_base_count": len(repo_bases),
            "manifest_parsed_count": parsed_count,
            "manifest_parsed_ratio": round(parsed_count / target_count, 4) if target_count else 0,
            "connection_limit_error_count": conn_limit_count,
            "source_provenance_gap_target_count": source_gap_count,
            "max_amplification_candidate_per_roa": max_amp,
            "top_repo_host_by_candidate": Counter({r.get("repo_host",""): to_int(r.get("candidate_count")) for r in rs}).most_common(5),
        })

    tal_rows.sort(key=lambda x: (-x["candidate_count_sum"], x["tal"]))

    write_csv(
        out / "m23b_tal_lightweight_feature_table.csv",
        tal_rows,
        [
            "tal", "target_count", "candidate_count_sum", "unique_repo_host_count",
            "unique_repo_base_count", "manifest_parsed_count", "manifest_parsed_ratio",
            "connection_limit_error_count", "source_provenance_gap_target_count",
            "max_amplification_candidate_per_roa", "top_repo_host_by_candidate",
        ],
    )

    # 4. root-cause feature table v1 from C census
    rc_rows = []
    for r in rows:
        c1 = to_float(r.get("amplification_candidate_per_roa")) >= 10
        c4 = r.get("connection_limit_error") == "True" or r.get("rsync_list_status") != "success"
        c6 = r.get("fetch_failure_type") == "source_provenance_gap_no_repo_base" or r.get("input_evidence_level") == "E0_VRP_ONLY"
        c2 = r.get("manifest_parse_status") == "parsed" and r.get("manifest_fileList_count") not in ("", None)

        rc_rows.append({
            "target_id": r.get("target_id", ""),
            "target_priority": r.get("target_priority", ""),
            "tal": r.get("tal", ""),
            "repo_host": r.get("repo_host", ""),
            "repo_base": r.get("repo_base", ""),
            "candidate_count": r.get("candidate_count", ""),
            "amplification_candidate_per_roa": r.get("amplification_candidate_per_roa", ""),
            "C1_roa_fanout_amplification": c1,
            "C2_manifest_publication_cluster_feature": c2,
            "C3_manifest_version_skew_feature": "unknown_requires_repeated_or_same_window_capture",
            "C4_pp_reachability_feature": c4,
            "C5_cache_trailing_feature": "unknown_requires_validator_timing",
            "C6_source_provenance_gap_feature": c6,
            "observed_fetch_failure_type": r.get("fetch_failure_type", ""),
            "evidence_level_after_census": r.get("evidence_level", ""),
            "requires_same_window_validation": True,
            "semantic_boundary": "root_cause_feature_from_single_probe_lightweight_census_not_final_cause",
        })

    write_csv(
        out / "m23b_root_cause_feature_table_from_lightweight_census.csv",
        rc_rows,
        [
            "target_id", "target_priority", "tal", "repo_host", "repo_base",
            "candidate_count", "amplification_candidate_per_roa",
            "C1_roa_fanout_amplification",
            "C2_manifest_publication_cluster_feature",
            "C3_manifest_version_skew_feature",
            "C4_pp_reachability_feature",
            "C5_cache_trailing_feature",
            "C6_source_provenance_gap_feature",
            "observed_fetch_failure_type",
            "evidence_level_after_census",
            "requires_same_window_validation",
            "semantic_boundary",
        ],
    )

    summary = {
        "schema": "s3.m23b.lightweight_census_analysis.v1",
        "generated_at_utc": utc_now(),
        "target_count": len(rows),
        "bad_or_warning_count": len(bad_rows),
        "repo_host_count": len(by_host),
        "tal_count": len(by_tal),
        "by_bad_repo_host": dict(Counter(r["repo_host"] for r in bad_rows)),
        "by_bad_tal": dict(Counter(r["tal"] for r in bad_rows)),
        "by_bad_failure_type": dict(Counter(r["fetch_failure_type"] for r in bad_rows)),
        "outputs": {
            "failed_targets_csv": str(out / "m23b_lightweight_pp_census_failed_targets.csv"),
            "pp_concentration_table_csv": str(out / "m23b_pp_concentration_and_reachability_table.csv"),
            "tal_feature_table_csv": str(out / "m23b_tal_lightweight_feature_table.csv"),
            "root_cause_table_csv": str(out / "m23b_root_cause_feature_table_from_lightweight_census.csv"),
        },
        "semantic_boundary": "analysis_from_single_probe_lightweight_census_not_same_window_multi_probe_attribution",
    }

    (out / "m23b_lightweight_census_analysis_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    md = []
    md.append("# M23B Lightweight Census Analysis Summary")
    md.append("")
    md.append(f"- target_count: `{len(rows)}`")
    md.append(f"- bad_or_warning_count: `{len(bad_rows)}`")
    md.append(f"- repo_host_count: `{len(by_host)}`")
    md.append(f"- tal_count: `{len(by_tal)}`")
    md.append(f"- by_bad_repo_host: `{summary['by_bad_repo_host']}`")
    md.append(f"- by_bad_tal: `{summary['by_bad_tal']}`")
    md.append(f"- by_bad_failure_type: `{summary['by_bad_failure_type']}`")
    md.append("")
    md.append("## Top PP concentration")
    for r in host_rows[:15]:
        md.append(
            f"- {r['repo_host']}: targets=`{r['target_count']}`, candidates=`{r['candidate_count_sum']}`, "
            f"parsed=`{r['manifest_parsed_count']}`, failed=`{r['rsync_failed_count']}`, "
            f"conn_limit=`{r['connection_limit_error_count']}`"
        )
    md.append("")
    md.append("## TAL features")
    for r in tal_rows:
        md.append(
            f"- {r['tal']}: targets=`{r['target_count']}`, candidates=`{r['candidate_count_sum']}`, "
            f"repo_hosts=`{r['unique_repo_host_count']}`, parsed_ratio=`{r['manifest_parsed_ratio']}`, "
            f"conn_limit=`{r['connection_limit_error_count']}`, source_gap=`{r['source_provenance_gap_target_count']}`"
        )
    md.append("")
    md.append("Semantic boundary: single-probe lightweight census analysis, not same-window multi-probe attribution.")
    (out / "m23b_lightweight_census_analysis_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    check = "\n".join([
        "M23B_C3_LIGHTWEIGHT_CENSUS_ANALYSIS=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"target_count = {len(rows)}",
        f"bad_or_warning_count = {len(bad_rows)}",
        f"failed_targets_csv = {out / 'm23b_lightweight_pp_census_failed_targets.csv'}",
        f"pp_concentration_table_csv = {out / 'm23b_pp_concentration_and_reachability_table.csv'}",
        f"tal_feature_table_csv = {out / 'm23b_tal_lightweight_feature_table.csv'}",
        f"root_cause_table_csv = {out / 'm23b_root_cause_feature_table_from_lightweight_census.csv'}",
        f"summary_md = {out / 'm23b_lightweight_census_analysis_summary.md'}",
        "semantic_boundary = analysis_from_single_probe_lightweight_census_not_same_window_multi_probe_attribution",
        "next_stage = M23B_D_HIGH_IMPACT_SAME_WINDOW_CAPTURE",
        "",
    ])
    (out / "M23B_C3_LIGHTWEIGHT_CENSUS_ANALYSIS_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
