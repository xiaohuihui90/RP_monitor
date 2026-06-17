#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from collections import defaultdict, Counter
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


def uniq_nonempty(values):
    return sorted(set(v for v in values if v not in ("", None)))


def is_parsed(r):
    return r.get("manifest_parse_status") == "parsed" or bool(r.get("manifestNumber"))


def classify_target(rs):
    statuses = [r.get("rsync_list_status", "") for r in rs]
    failures = [r.get("fetch_failure_type", "") for r in rs]
    mft_nums = uniq_nonempty([r.get("manifestNumber", "") for r in rs])
    filelists = uniq_nonempty([r.get("manifest_fileList_count", "") for r in rs])

    conn_count = sum(1 for r in rs if r.get("connection_limit_error") in ("True", "true", True))
    rsync_error_count = sum(1 for r in rs if r.get("fetch_failure_type") == "rsync_error")
    failed_count = sum(1 for r in rs if r.get("rsync_list_status") != "success")
    success_count = sum(1 for r in rs if r.get("rsync_list_status") == "success")
    parsed_count = sum(1 for r in rs if is_parsed(r))

    hints = []
    if conn_count > 0 and success_count > 0:
        hints.append("C4_INTERMITTENT_PP_CAPACITY_LIMIT")
    elif conn_count > 0:
        hints.append("C4_PP_CAPACITY_LIMIT_OBSERVED")

    if rsync_error_count > 0 and success_count > 0:
        hints.append("C4_INTERMITTENT_RSYNC_FETCH_ISSUE")
    elif rsync_error_count > 0:
        hints.append("C4_RSYNC_FETCH_ISSUE_OBSERVED")

    if len(mft_nums) > 1 or len(filelists) > 1:
        hints.append("C3_MANIFEST_VERSION_OR_FILELIST_EVOLUTION")

    if failed_count == 0 and parsed_count == len(rs) and len(mft_nums) == 1 and len(filelists) == 1:
        hints.append("STABLE_PUBLICATION_CLUSTER")

    if not hints:
        hints.append("INSUFFICIENT_OR_MIXED_EVIDENCE")

    return {
        "success_count": success_count,
        "failed_count": failed_count,
        "parsed_count": parsed_count,
        "connection_limit_count": conn_count,
        "rsync_error_count": rsync_error_count,
        "manifest_numbers": ";".join(mft_nums),
        "fileList_counts": ";".join(filelists),
        "status_changed": len(set(statuses)) > 1,
        "manifestNumber_changed": len(mft_nums) > 1,
        "fileList_changed": len(filelists) > 1,
        "root_cause_feature_hint": "+".join(hints),
    }


def main():
    out = Path(os.environ["M23B_D_OUT"])
    records_csv = out / "m23b_d_same_window_capture_records.csv"
    rows = read_csv(records_csv)

    if not rows:
        raise SystemExit("no records")

    by_target = defaultdict(list)
    by_host = defaultdict(list)

    for r in rows:
        by_target[r.get("target_id", "")].append(r)
        by_host[r.get("repo_host", "")].append(r)

    target_rows = []
    for target_id, rs in sorted(by_target.items()):
        rs = sorted(rs, key=lambda x: x.get("capture_time_utc", ""))
        first = rs[0]
        cls = classify_target(rs)

        target_rows.append({
            "target_id": target_id,
            "repo_host": first.get("repo_host", ""),
            "tal": first.get("tal", ""),
            "target_priority": first.get("target_priority", ""),
            "candidate_count": first.get("candidate_count", ""),
            "unique_roa_count": first.get("unique_roa_count", ""),
            "unique_prefix_count": first.get("unique_prefix_count", ""),
            "amplification_candidate_per_roa": first.get("amplification_candidate_per_roa", ""),
            "capture_count": len(rs),
            "first_capture_time_utc": rs[0].get("capture_time_utc", ""),
            "last_capture_time_utc": rs[-1].get("capture_time_utc", ""),
            "success_count": cls["success_count"],
            "failed_count": cls["failed_count"],
            "parsed_count": cls["parsed_count"],
            "connection_limit_count": cls["connection_limit_count"],
            "rsync_error_count": cls["rsync_error_count"],
            "manifest_numbers": cls["manifest_numbers"],
            "fileList_counts": cls["fileList_counts"],
            "status_changed": cls["status_changed"],
            "manifestNumber_changed": cls["manifestNumber_changed"],
            "fileList_changed": cls["fileList_changed"],
            "root_cause_feature_hint": cls["root_cause_feature_hint"],
            "status_sequence": " -> ".join(r.get("rsync_list_status", "") for r in rs),
            "failure_sequence": " -> ".join(r.get("fetch_failure_type", "") or "OK" for r in rs),
            "manifestNumber_sequence": " -> ".join(r.get("manifestNumber", "") or "-" for r in rs),
            "fileList_sequence": " -> ".join(r.get("manifest_fileList_count", "") or "-" for r in rs),
            "semantic_boundary": "repeated_single_node_live_capture_not_multi_probe_same_window_attribution",
        })

    host_rows = []
    for host, rs in sorted(by_host.items()):
        capture_ids = sorted(set(r.get("capture_id", "") for r in rs))
        targets = sorted(set(r.get("target_id", "") for r in rs))
        conn_count = sum(1 for r in rs if r.get("connection_limit_error") in ("True", "true", True))
        rsync_error_count = sum(1 for r in rs if r.get("fetch_failure_type") == "rsync_error")
        failed_count = sum(1 for r in rs if r.get("rsync_list_status") != "success")
        parsed_count = sum(1 for r in rs if is_parsed(r))

        host_rows.append({
            "repo_host": host,
            "target_count": len(targets),
            "capture_count": len(capture_ids),
            "observation_count": len(rs),
            "parsed_count": parsed_count,
            "failed_count": failed_count,
            "connection_limit_count": conn_count,
            "rsync_error_count": rsync_error_count,
            "parse_ratio": round(parsed_count / len(rs), 4) if rs else 0,
            "failure_ratio": round(failed_count / len(rs), 4) if rs else 0,
            "connection_limit_ratio": round(conn_count / len(rs), 4) if rs else 0,
            "rsync_error_ratio": round(rsync_error_count / len(rs), 4) if rs else 0,
            "semantic_boundary": "host_level_summary_from_repeated_single_node_capture",
        })

    target_fields = [
        "target_id", "repo_host", "tal", "target_priority",
        "candidate_count", "unique_roa_count", "unique_prefix_count", "amplification_candidate_per_roa",
        "capture_count", "first_capture_time_utc", "last_capture_time_utc",
        "success_count", "failed_count", "parsed_count",
        "connection_limit_count", "rsync_error_count",
        "manifest_numbers", "fileList_counts",
        "status_changed", "manifestNumber_changed", "fileList_changed",
        "root_cause_feature_hint",
        "status_sequence", "failure_sequence", "manifestNumber_sequence", "fileList_sequence",
        "semantic_boundary",
    ]
    target_csv = out / "m23b_d_longitudinal_target_feature_table.csv"
    write_csv(target_csv, target_rows, target_fields)

    host_fields = [
        "repo_host", "target_count", "capture_count", "observation_count",
        "parsed_count", "failed_count", "connection_limit_count", "rsync_error_count",
        "parse_ratio", "failure_ratio", "connection_limit_ratio", "rsync_error_ratio",
        "semantic_boundary",
    ]
    host_csv = out / "m23b_d_longitudinal_host_feature_table.csv"
    write_csv(host_csv, host_rows, host_fields)

    summary = {
        "schema": "s3.m23b.d.longitudinal_features.v1",
        "generated_at_utc": utc_now(),
        "record_count": len(rows),
        "target_count": len(target_rows),
        "host_count": len(host_rows),
        "capture_count": len(set(r.get("capture_id", "") for r in rows)),
        "by_root_cause_feature_hint": dict(Counter(r["root_cause_feature_hint"] for r in target_rows)),
        "target_feature_csv": str(target_csv),
        "host_feature_csv": str(host_csv),
        "semantic_boundary": "repeated_single_node_live_capture_not_multi_probe_same_window_attribution",
    }

    (out / "m23b_d_longitudinal_feature_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    md = []
    md.append("# M23B-D Longitudinal Feature Summary")
    md.append("")
    md.append(f"- generated_at_utc: `{summary['generated_at_utc']}`")
    md.append(f"- record_count: `{summary['record_count']}`")
    md.append(f"- target_count: `{summary['target_count']}`")
    md.append(f"- host_count: `{summary['host_count']}`")
    md.append(f"- capture_count: `{summary['capture_count']}`")
    md.append(f"- by_root_cause_feature_hint: `{summary['by_root_cause_feature_hint']}`")
    md.append("")
    md.append("## Target features")
    for r in target_rows:
        md.append(
            f"- `{r['target_id']}` host=`{r['repo_host']}` captures=`{r['capture_count']}` "
            f"success=`{r['success_count']}` failed=`{r['failed_count']}` "
            f"mft#=`{r['manifest_numbers']}` fileList=`{r['fileList_counts']}` "
            f"hint=`{r['root_cause_feature_hint']}`"
        )
    md.append("")
    md.append("## Host features")
    for r in host_rows:
        md.append(
            f"- `{r['repo_host']}` targets=`{r['target_count']}` obs=`{r['observation_count']}` "
            f"parse_ratio=`{r['parse_ratio']}` failure_ratio=`{r['failure_ratio']}` "
            f"conn_limit_ratio=`{r['connection_limit_ratio']}` rsync_error_ratio=`{r['rsync_error_ratio']}`"
        )
    md.append("")
    md.append("Semantic boundary: repeated single-node live capture, not multi-probe same-window attribution.")

    summary_md = out / "m23b_d_longitudinal_feature_summary.md"
    summary_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    check = "\n".join([
        "M23B_D_LONGITUDINAL_FEATURE_ANALYSIS=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"record_count = {summary['record_count']}",
        f"target_count = {summary['target_count']}",
        f"host_count = {summary['host_count']}",
        f"capture_count = {summary['capture_count']}",
        f"target_feature_csv = {target_csv}",
        f"host_feature_csv = {host_csv}",
        f"summary_md = {summary_md}",
        "semantic_boundary = repeated_single_node_live_capture_not_multi_probe_same_window_attribution",
        "next_stage = M23B_D_RRDP_NOTIFICATION_URI_DISCOVERY",
        "",
    ])

    (out / "M23B_D_LONGITUDINAL_FEATURE_ANALYSIS_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
