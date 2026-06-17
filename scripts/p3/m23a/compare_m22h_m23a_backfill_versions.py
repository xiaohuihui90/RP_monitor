#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import os
from pathlib import Path


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
        return int(x)
    except Exception:
        return None


def main():
    m22h_out = Path(os.environ["M22H_OUT"])
    m23a_out = Path(os.environ["M23A_OUT"])

    m22h = read_csv(m22h_out / "m22h_repo_manifest_summary.csv")
    m23a = read_csv(m23a_out / "m23a_repo_level_summary.csv")

    m22h_by_repo = {r["repo_base"]: r for r in m22h}
    rows = []

    for cur in m23a:
        repo = cur["repo_base"]
        old = m22h_by_repo.get(repo, {})

        old_mn = to_int(old.get("manifestNumber", ""))
        cur_mn = to_int(cur.get("current_manifestNumber", ""))

        old_fl = to_int(old.get("manifest_fileList_count", ""))
        cur_fl = to_int(cur.get("current_manifest_fileList_count", ""))

        manifest_number_delta = ""
        filelist_count_delta = ""

        if old_mn is not None and cur_mn is not None:
            manifest_number_delta = cur_mn - old_mn
        if old_fl is not None and cur_fl is not None:
            filelist_count_delta = cur_fl - old_fl

        version_change_observed = (
            manifest_number_delta not in ("", 0)
            or filelist_count_delta not in ("", 0)
            or old.get("manifest_thisUpdate", "") != cur.get("current_manifest_thisUpdate", "")
        )

        rows.append({
            "repo_rank": cur.get("repo_rank", ""),
            "repo_host": cur.get("repo_host", ""),
            "repo_base": repo,
            "candidate_count": cur.get("candidate_count", ""),
            "unique_roa_count": cur.get("unique_roa_count", ""),
            "m22h_manifest": old.get("selected_manifest_name", ""),
            "m22h_manifestNumber": old.get("manifestNumber", ""),
            "m22h_thisUpdate": old.get("manifest_thisUpdate", ""),
            "m22h_nextUpdate": old.get("manifest_nextUpdate", ""),
            "m22h_fileList_count": old.get("manifest_fileList_count", ""),
            "m23a_manifest": cur.get("current_manifest_filename", ""),
            "m23a_manifestNumber": cur.get("current_manifestNumber", ""),
            "m23a_thisUpdate": cur.get("current_manifest_thisUpdate", ""),
            "m23a_nextUpdate": cur.get("current_manifest_nextUpdate", ""),
            "m23a_fileList_count": cur.get("current_manifest_fileList_count", ""),
            "manifest_number_delta": manifest_number_delta,
            "filelist_count_delta": filelist_count_delta,
            "version_change_observed": version_change_observed,
            "m23a_fetch_status": cur.get("current_manifest_fetch_status", ""),
            "m23a_parse_status": cur.get("current_manifest_parse_status", ""),
            "m23a_filelist_match_ratio": cur.get("filelist_match_ratio", ""),
            "m23a_hash_match_ratio": cur.get("hash_match_ratio", ""),
            "root_cause_feature_update": (
                "manifest_version_change_observed"
                if version_change_observed and cur.get("current_manifest_fetch_status") == "success"
                else "fetch_failure_observed"
                if cur.get("current_manifest_fetch_status") != "success"
                else "stable_current_backfill"
            ),
            "semantic_boundary": "longitudinal_post_diff_backfill_comparison_not_same_window_causal_attribution",
        })

    fields = [
        "repo_rank", "repo_host", "repo_base", "candidate_count", "unique_roa_count",
        "m22h_manifest", "m22h_manifestNumber", "m22h_thisUpdate", "m22h_nextUpdate", "m22h_fileList_count",
        "m23a_manifest", "m23a_manifestNumber", "m23a_thisUpdate", "m23a_nextUpdate", "m23a_fileList_count",
        "manifest_number_delta", "filelist_count_delta", "version_change_observed",
        "m23a_fetch_status", "m23a_parse_status", "m23a_filelist_match_ratio", "m23a_hash_match_ratio",
        "root_cause_feature_update", "semantic_boundary",
    ]

    out_csv = m23a_out / "m23a_longitudinal_m22h_vs_m23a_manifest_compare.csv"
    write_csv(out_csv, rows, fields)

    md = []
    md.append("# M23A Longitudinal Compare: M22H vs M23A")
    md.append("")
    md.append("| Repo | M22H manifestNumber | M23A manifestNumber | ΔmanifestNumber | M22H fileList | M23A fileList | ΔfileList | feature |")
    md.append("|---|---:|---:|---:|---:|---:|---:|---|")
    for r in rows:
        md.append(
            f"| {r['repo_host']} | {r['m22h_manifestNumber']} | {r['m23a_manifestNumber']} | "
            f"{r['manifest_number_delta']} | {r['m22h_fileList_count']} | {r['m23a_fileList_count']} | "
            f"{r['filelist_count_delta']} | {r['root_cause_feature_update']} |"
        )
    md.append("")
    md.append("Semantic boundary: longitudinal post-diff comparison, not same-window historical causal attribution.")
    out_md = m23a_out / "m23a_longitudinal_m22h_vs_m23a_manifest_compare.md"
    out_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    check = "\n".join([
        "M23A_LONGITUDINAL_COMPARE=PASS",
        f"row_count = {len(rows)}",
        f"compare_csv = {out_csv}",
        f"compare_md = {out_md}",
        "semantic_boundary = longitudinal_post_diff_backfill_comparison_not_same_window_causal_attribution",
        "",
    ])
    (m23a_out / "M23A_LONGITUDINAL_COMPARE_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
