#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def parse_time(s: str):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


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


def num(v):
    try:
        return float(v or 0)
    except Exception:
        return 0.0


def feature_for_row(r: dict, target_hint: dict[str, str]) -> str:
    tid = r.get("target_id", "")
    if tid in target_hint and target_hint[tid]:
        return target_hint[tid]

    ft = r.get("fetch_failure_type", "")
    if ft == "server_side_max_connections" or str(r.get("connection_limit_error")).lower() == "true":
        return "C4_INTERMITTENT_PP_CAPACITY_LIMIT"
    if ft == "rsync_error":
        return "C4_INTERMITTENT_RSYNC_FETCH_ISSUE"
    if ft == "timeout" or str(r.get("timeout_error")).lower() == "true":
        return "C4_PP_REACHABILITY_OR_CAPACITY_LIMIT"
    if not r.get("repo_base"):
        return "C6_SOURCE_PROVENANCE_GAP"
    if r.get("manifestNumber"):
        return "E3_LIVE_PP_CENSUS_OBSERVED"
    return "INSUFFICIENT_OR_MIXED_EVIDENCE"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m23b-f-out", default=os.environ.get("M23B_F_OUT", ""))
    ap.add_argument("--m23b-d-out", default=os.environ.get("M23B_D_OUT", ""))
    ap.add_argument("--date", default="")
    args = ap.parse_args()

    f_out = Path(args.m23b_f_out)
    d_out = Path(args.m23b_d_out)

    now = utc_now()
    date_str = args.date or now.date().isoformat()
    day_dir = f_out / "daily_summary" / date_str
    day_dir.mkdir(parents=True, exist_ok=True)

    since = now - timedelta(hours=24)

    # Target hint from latest longitudinal target table.
    target_hint = {}
    for r in read_csv(d_out / "m23b_d_longitudinal_target_feature_table.csv"):
        target_hint[r.get("target_id", "")] = r.get("root_cause_feature_hint", "")

    observations = []

    # F1 hourly census observations.
    for p in sorted((f_out / "hourly_census").glob("*/records.csv")):
        for r in read_csv(p):
            t = parse_time(r.get("capture_time_utc", "") or r.get("run_time_utc", ""))
            if t is None or t >= since:
                r = dict(r)
                r["source_stage"] = "F1_hourly_census"
                observations.append(r)

    # F2 high-impact observations.
    for r in read_csv(d_out / "m23b_d_same_window_capture_records.csv"):
        t = parse_time(r.get("capture_time_utc", ""))
        if t is None or t >= since:
            r = dict(r)
            r["source_stage"] = "F2_high_impact_capture"
            observations.append(r)

    for r in observations:
        r["feature_name"] = feature_for_row(r, target_hint)
        if not r.get("evidence_level"):
            r["evidence_level"] = "E4_REPEATED_SINGLE_NODE_CAPTURE" if r.get("source_stage") == "F2_high_impact_capture" else "E3_LIVE_PP_CENSUS"

    # PP summary
    pp_groups = defaultdict(list)
    for r in observations:
        key = (r.get("repo_host", ""), r.get("repo_base", ""), r.get("tal", ""))
        pp_groups[key].append(r)

    pp_rows = []
    for (host, base, tal), rs in sorted(pp_groups.items()):
        target_ids = sorted(set(r.get("target_id", "") for r in rs if r.get("target_id")))
        candidate_sum = sum(num(r.get("candidate_count")) for r in {r.get("target_id", ""): r for r in rs}.values())
        obs = len(rs)
        failed = sum(1 for r in rs if r.get("rsync_list_status") == "failed" or r.get("manifest_fetch_status") == "failed")
        parsed = sum(1 for r in rs if r.get("manifest_parse_status") == "parsed" or r.get("manifestNumber"))
        conn = sum(1 for r in rs if str(r.get("connection_limit_error")).lower() == "true" or r.get("fetch_failure_type") == "server_side_max_connections")
        rsync_err = sum(1 for r in rs if r.get("fetch_failure_type") == "rsync_error")
        timeout = sum(1 for r in rs if r.get("fetch_failure_type") == "timeout" or str(r.get("timeout_error")).lower() == "true")
        features = Counter(r.get("feature_name", "") for r in rs)
        pp_rows.append({
            "date": date_str,
            "repo_host": host,
            "repo_base": base,
            "tal": tal,
            "target_count": len(target_ids),
            "candidate_count_sum": round(candidate_sum, 4),
            "observation_count": obs,
            "failure_count": failed,
            "failure_ratio": round(failed / obs, 4) if obs else 0,
            "parse_count": parsed,
            "parse_ratio": round(parsed / obs, 4) if obs else 0,
            "connection_limit_count": conn,
            "connection_limit_ratio": round(conn / obs, 4) if obs else 0,
            "rsync_error_count": rsync_err,
            "rsync_error_ratio": round(rsync_err / obs, 4) if obs else 0,
            "timeout_count": timeout,
            "dominant_root_cause_feature": features.most_common(1)[0][0] if features else "",
            "representative_targets": ";".join(target_ids[:10]),
            "semantic_boundary": "longitudinal_single_node_measurement_not_final_causal_attribution",
        })

    pp_fields = [
        "date", "repo_host", "repo_base", "tal", "target_count", "candidate_count_sum",
        "observation_count", "failure_count", "failure_ratio", "parse_count", "parse_ratio",
        "connection_limit_count", "connection_limit_ratio", "rsync_error_count", "rsync_error_ratio",
        "timeout_count", "dominant_root_cause_feature", "representative_targets", "semantic_boundary",
    ]
    write_csv(day_dir / "m23b_daily_pp_summary.csv", pp_rows, pp_fields)

    # TAL summary
    tal_groups = defaultdict(list)
    for r in observations:
        tal_groups[r.get("tal", "")].append(r)

    tal_rows = []
    for tal, rs in sorted(tal_groups.items()):
        obs = len(rs)
        hosts = sorted(set(r.get("repo_host", "") for r in rs if r.get("repo_host")))
        bases = sorted(set(r.get("repo_base", "") for r in rs if r.get("repo_base")))
        target_ids = sorted(set(r.get("target_id", "") for r in rs if r.get("target_id")))
        features = Counter(r.get("feature_name", "") for r in rs)
        candidate_by_host = defaultdict(float)
        for r in rs:
            candidate_by_host[r.get("repo_host", "")] += num(r.get("candidate_count"))
        total_c = sum(candidate_by_host.values())
        top_values = sorted(candidate_by_host.values(), reverse=True)
        top1 = top_values[0] / total_c if total_c and top_values else 0
        top5 = sum(top_values[:5]) / total_c if total_c and top_values else 0
        tal_rows.append({
            "date": date_str,
            "tal": tal,
            "target_count": len(target_ids),
            "candidate_count_sum": round(total_c, 4),
            "observation_count": obs,
            "unique_repo_host_count": len(hosts),
            "unique_repo_base_count": len(bases),
            "failure_ratio": round(sum(1 for r in rs if r.get("rsync_list_status") == "failed") / obs, 4) if obs else 0,
            "top_1_pp_share": round(top1, 4),
            "top_5_pp_share": round(top5, 4),
            "dominant_root_cause_feature": features.most_common(1)[0][0] if features else "",
            "semantic_boundary": "longitudinal_single_node_measurement_not_final_causal_attribution",
        })

    tal_fields = [
        "date", "tal", "target_count", "candidate_count_sum", "observation_count",
        "unique_repo_host_count", "unique_repo_base_count", "failure_ratio",
        "top_1_pp_share", "top_5_pp_share", "dominant_root_cause_feature", "semantic_boundary",
    ]
    write_csv(day_dir / "m23b_daily_tal_summary.csv", tal_rows, tal_fields)

    # Root cause feature summary
    feat_groups = defaultdict(list)
    for r in observations:
        feat_groups[r.get("feature_name", "")].append(r)

    feat_rows = []
    for feat, rs in sorted(feat_groups.items()):
        targets = sorted(set(r.get("target_id", "") for r in rs if r.get("target_id")))
        tals = sorted(set(r.get("tal", "") for r in rs if r.get("tal")))
        hosts = sorted(set(r.get("repo_host", "") for r in rs if r.get("repo_host")))
        evid = sorted(set(r.get("evidence_level", "") for r in rs if r.get("evidence_level")))
        candidate_sum = sum(num(r.get("candidate_count")) for r in {r.get("target_id", ""): r for r in rs}.values())
        feat_rows.append({
            "date": date_str,
            "feature_name": feat,
            "target_count": len(targets),
            "observation_count": len(rs),
            "candidate_count_sum": round(candidate_sum, 4),
            "affected_tal_count": len(tals),
            "affected_repo_host_count": len(hosts),
            "representative_targets": ";".join(targets[:10]),
            "evidence_levels": ";".join(evid),
            "requires_rrdp": str(feat in {"C3_MANIFEST_VERSION_OR_FILELIST_EVOLUTION", "C4_INTERMITTENT_PP_CAPACITY_LIMIT", "C4_INTERMITTENT_RSYNC_FETCH_ISSUE"}),
            "requires_multi_probe": str(feat not in {"STABLE_PUBLICATION_CLUSTER", "E3_LIVE_PP_CENSUS_OBSERVED"}),
            "semantic_boundary": "longitudinal_single_node_measurement_not_final_causal_attribution",
        })

    feat_fields = [
        "date", "feature_name", "target_count", "observation_count", "candidate_count_sum",
        "affected_tal_count", "affected_repo_host_count", "representative_targets",
        "evidence_levels", "requires_rrdp", "requires_multi_probe", "semantic_boundary",
    ]
    write_csv(day_dir / "m23b_daily_root_cause_feature_summary.csv", feat_rows, feat_fields)

    # Evidence level summary
    ev_counter = Counter(r.get("evidence_level", "") for r in observations)
    ev_rows = [{"date": date_str, "evidence_level": k, "observation_count": v} for k, v in sorted(ev_counter.items())]
    write_csv(day_dir / "m23b_daily_evidence_level_summary.csv", ev_rows, ["date", "evidence_level", "observation_count"])

    # Simple persistence summary from D target table
    target_feat_rows = read_csv(Path(os.environ.get("M23B_D_OUT", "")) / "m23b_d_longitudinal_target_feature_table.csv")
    persistence_rows = []
    for r in target_feat_rows:
        persistence_rows.append({
            "date": date_str,
            "target_id": r.get("target_id", ""),
            "repo_host": r.get("repo_host", ""),
            "tal": r.get("tal", ""),
            "capture_count": r.get("capture_count", ""),
            "success_count": r.get("success_count", ""),
            "failed_count": r.get("failed_count", ""),
            "manifest_numbers": r.get("manifest_numbers", ""),
            "fileList_counts": r.get("fileList_counts", ""),
            "root_cause_feature_hint": r.get("root_cause_feature_hint", ""),
            "semantic_boundary": "repeated_single_node_live_capture_not_multi_probe_same_window_attribution",
        })
    persist_fields = [
        "date", "target_id", "repo_host", "tal", "capture_count", "success_count",
        "failed_count", "manifest_numbers", "fileList_counts", "root_cause_feature_hint", "semantic_boundary",
    ]
    write_csv(day_dir / "m23b_daily_persistence_summary.csv", persistence_rows, persist_fields)

    # Markdown summary
    md = []
    md.append("# M23B-F Daily Longitudinal Summary")
    md.append("")
    md.append(f"- date: `{date_str}`")
    md.append(f"- generated_at_utc: `{utc_now().isoformat().replace('+00:00','Z')}`")
    md.append(f"- observation_count_24h: `{len(observations)}`")
    md.append(f"- pp_group_count: `{len(pp_rows)}`")
    md.append(f"- tal_count: `{len(tal_rows)}`")
    md.append(f"- root_cause_feature_count: `{len(feat_rows)}`")
    md.append("")
    md.append("## Top PP groups")
    for r in sorted(pp_rows, key=lambda x: num(x["candidate_count_sum"]), reverse=True)[:20]:
        md.append(
            f"- `{r['repo_host']}` tal=`{r['tal']}` targets=`{r['target_count']}` "
            f"obs=`{r['observation_count']}` failure_ratio=`{r['failure_ratio']}` "
            f"feature=`{r['dominant_root_cause_feature']}`"
        )
    md.append("")
    md.append("## TAL summary")
    for r in tal_rows:
        md.append(
            f"- `{r['tal']}` targets=`{r['target_count']}` obs=`{r['observation_count']}` "
            f"top1_pp_share=`{r['top_1_pp_share']}` feature=`{r['dominant_root_cause_feature']}`"
        )
    md.append("")
    md.append("## Root-cause features")
    for r in sorted(feat_rows, key=lambda x: int(x["observation_count"]), reverse=True):
        md.append(
            f"- `{r['feature_name']}` targets=`{r['target_count']}` obs=`{r['observation_count']}` "
            f"candidate_sum=`{r['candidate_count_sum']}`"
        )
    md.append("")
    md.append("Semantic boundary: longitudinal single-node measurement, not final causal attribution.")

    (day_dir / "m23b_daily_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    check = "\n".join([
        "M23B_F3_DAILY_SUMMARY=PASS" if len(observations) > 0 else "M23B_F3_DAILY_SUMMARY=WARNING_EMPTY",
        f"date = {date_str}",
        f"observation_count_24h = {len(observations)}",
        f"pp_group_count = {len(pp_rows)}",
        f"tal_count = {len(tal_rows)}",
        f"root_cause_feature_count = {len(feat_rows)}",
        f"daily_dir = {day_dir}",
        f"summary_md = {day_dir / 'm23b_daily_summary.md'}",
        "semantic_boundary = longitudinal_single_node_measurement_not_final_causal_attribution",
        "next_stage = M23B_F4_PAPER_TABLES",
        "",
    ])
    (day_dir / "M23B_F3_DAILY_SUMMARY_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
