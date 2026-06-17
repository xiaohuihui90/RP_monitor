#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from collections import Counter, defaultdict
from urllib.parse import urlparse
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def safe_str(x):
    if x is None:
        return ""
    return str(x)


def uri_host(uri: str) -> str:
    if not uri:
        return ""
    return urlparse(uri).netloc


def uri_base(uri: str) -> str:
    if not uri:
        return ""
    return uri.rsplit("/", 1)[0] + "/" if "/" in uri else uri


def uri_filename(uri: str) -> str:
    if not uri:
        return ""
    return uri.rsplit("/", 1)[-1]


def parse_repository_identity(uri: str) -> dict:
    """
    Example:
    rsync://rsync.paas.rpki.ripe.net/repository/89270f6c-a3fe-4299-b079-309ed97f3824/0/foo.roa

    repository_uuid = 89270f6c-a3fe-4299-b079-309ed97f3824
    repo_subdir = 0
    """
    out = {
        "repo_host": "",
        "repo_base": "",
        "repository_uuid": "",
        "repo_subdir": "",
        "repository_identity": "",
    }
    if not uri:
        return out

    u = urlparse(uri)
    out["repo_host"] = u.netloc
    out["repo_base"] = uri_base(uri)

    parts = [p for p in u.path.split("/") if p]
    # Common path: /repository/<uuid>/<subdir>/<file>
    try:
        idx = parts.index("repository")
        if len(parts) > idx + 1:
            out["repository_uuid"] = parts[idx + 1]
        if len(parts) > idx + 2:
            out["repo_subdir"] = parts[idx + 2]
    except ValueError:
        pass

    out["repository_identity"] = "|".join([
        out["repo_host"],
        out["repository_uuid"],
        out["repo_subdir"],
    ]).strip("|")
    return out


def get_first_existing(o: dict, keys: list[str]) -> str:
    for k in keys:
        v = o.get(k)
        if v not in (None, "", [], {}):
            return str(v)
    return ""


def get_ca_like_id(o: dict, repo_id: dict) -> str:
    """
    优先使用记录中可能存在的 CA/证书相关字段。
    如果没有，则退化为 repository-level CA-like identifier。
    """
    ca_subject = get_first_existing(o, [
        "ca_subject",
        "issuer_subject",
        "subject",
        "manifest_ee_subject",
        "issuer",
        "certificate_subject",
    ])
    ca_ski = get_first_existing(o, [
        "ca_ski",
        "ski",
        "subject_key_identifier",
        "manifest_aki",
        "authority_key_identifier",
    ])
    sia = get_first_existing(o, [
        "sia",
        "ca_repository",
        "repository_sia",
        "rpki_manifest_sia",
    ])

    if ca_subject:
        return f"subject={ca_subject}"
    if ca_ski:
        return f"keyid={ca_ski}"
    if sia:
        return f"sia={sia}"

    return f"repo_id={repo_id.get('repository_identity') or repo_id.get('repo_base')}"


def normalize_record(o: dict) -> dict:
    roa_uri = safe_str(o.get("roa_uri"))
    manifest_uri = safe_str(o.get("manifest_uri"))

    primary_uri = roa_uri or manifest_uri
    repo_id = parse_repository_identity(primary_uri)

    rec = {
        "vrp_key": safe_str(o.get("vrp_key")),
        "tal": safe_str(o.get("tal")),
        "afi": safe_str(o.get("afi")),
        "prefix": safe_str(o.get("prefix")),
        "asn": safe_str(o.get("asn")),
        "maxLength": safe_str(o.get("maxLength")),
        "roa_uri": roa_uri,
        "roa_filename": safe_str(o.get("roa_filename")) or uri_filename(roa_uri),
        "manifest_uri": manifest_uri,
        "manifest_filename": uri_filename(manifest_uri),
        "repo_host": repo_id["repo_host"],
        "repo_base": repo_id["repo_base"],
        "repository_uuid": repo_id["repository_uuid"],
        "repo_subdir": repo_id["repo_subdir"],
        "repository_identity": repo_id["repository_identity"],
        "ca_like_id": get_ca_like_id(o, repo_id),
        "manifestNumber": safe_str(o.get("manifestNumber")),
        "manifest_thisUpdate": safe_str(o.get("manifest_thisUpdate")),
        "manifest_nextUpdate": safe_str(o.get("manifest_nextUpdate")),
        "manifest_file_hash": safe_str(o.get("manifest_file_hash")),
        "manifest_fileList_count": safe_str(o.get("manifest_fileList_count")),
        "window_id": safe_str(o.get("window_id")),
        "nearest_window_delta_sec": safe_str(o.get("nearest_window_delta_sec")),
        "jsonext_available": bool(o.get("jsonext_available")),
        "manifest_context_available": bool(o.get("manifest_context_available")),
        "notification_context_available": bool(o.get("notification_context_available")),
        "validator_timing_available": bool(o.get("validator_timing_available")),
    }

    # notification-like relation summary
    rel_top = o.get("notification_like_relation_top") or []
    pp_top = o.get("notification_like_pp_top") or []
    rec["notification_relation_top"] = ";".join([f"{a}:{b}" for a, b in rel_top])
    rec["notification_pp_top"] = ";".join([f"{a}:{b}" for a, b in pp_top])

    return rec


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def top_counter_rows(counter: Counter, key_name: str, value_name: str = "count") -> list[dict]:
    return [{key_name: k, value_name: v} for k, v in counter.most_common()]


def build_cluster_rows(records: list[dict], cluster_key: str) -> list[dict]:
    groups = defaultdict(list)
    for r in records:
        groups[r.get(cluster_key, "")].append(r)

    rows = []
    for key, rs in groups.items():
        tal = Counter(r["tal"] for r in rs)
        asn = Counter(r["asn"] for r in rs)
        prefix = Counter(r["prefix"] for r in rs)
        roa = Counter(r["roa_uri"] for r in rs)
        mft = Counter(r["manifest_uri"] for r in rs)
        mnum = Counter(r["manifestNumber"] for r in rs)
        thisu = Counter(r["manifest_thisUpdate"] for r in rs)
        nextu = Counter(r["manifest_nextUpdate"] for r in rs)
        win = Counter(r["window_id"] for r in rs)
        ca = Counter(r["ca_like_id"] for r in rs)

        deltas = []
        for r in rs:
            try:
                deltas.append(float(r["nearest_window_delta_sec"]))
            except Exception:
                pass
        deltas.sort()

        row = {
            "cluster_key": key,
            "cluster_type": cluster_key,
            "candidate_count": len(rs),
            "unique_vrp_key_count": len(set(r["vrp_key"] for r in rs)),
            "unique_roa_uri_count": len(roa),
            "unique_manifest_uri_count": len(mft),
            "unique_asn_count": len(asn),
            "unique_prefix_count": len(prefix),
            "unique_manifestNumber_count": len(mnum),
            "unique_thisUpdate_count": len(thisu),
            "unique_nextUpdate_count": len(nextu),
            "unique_window_count": len(win),
            "unique_ca_like_id_count": len(ca),
            "tal_top": repr(tal.most_common(5)),
            "asn_top": repr(asn.most_common(10)),
            "prefix_top": repr(prefix.most_common(10)),
            "manifestNumber_top": repr(mnum.most_common(10)),
            "thisUpdate_top": repr(thisu.most_common(5)),
            "nextUpdate_top": repr(nextu.most_common(5)),
            "window_top": repr(win.most_common(10)),
            "ca_like_id_top": repr(ca.most_common(5)),
            "delta_min": deltas[0] if deltas else "",
            "delta_median": deltas[int((len(deltas)-1)*0.5)] if deltas else "",
            "delta_p90": deltas[int((len(deltas)-1)*0.9)] if deltas else "",
            "delta_max": deltas[-1] if deltas else "",
            "case_study_priority": "",
            "case_study_reason": "",
        }

        # 简单 case study priority 规则
        reasons = []
        score = 0
        if len(rs) >= 50:
            score += 5
            reasons.append("large_cluster_ge_50")
        elif len(rs) >= 10:
            score += 3
            reasons.append("medium_cluster_ge_10")
        elif len(rs) >= 3:
            score += 1
            reasons.append("small_cluster_ge_3")

        if len(mft) == 1:
            score += 2
            reasons.append("single_manifest_uri")
        if len(mnum) == 1:
            score += 2
            reasons.append("single_manifestNumber")
        if len(thisu) == 1 and len(nextu) == 1:
            score += 1
            reasons.append("same_manifest_time_window")
        if len(ca) == 1:
            score += 1
            reasons.append("single_ca_like_id")
        if len(win) <= 2:
            score += 1
            reasons.append("few_nearest_windows")

        if score >= 9:
            row["case_study_priority"] = "P0"
        elif score >= 6:
            row["case_study_priority"] = "P1"
        elif score >= 3:
            row["case_study_priority"] = "P2"
        else:
            row["case_study_priority"] = "P3"
        row["case_study_reason"] = ",".join(reasons)

        rows.append(row)

    rows.sort(key=lambda x: (x["case_study_priority"], -int(x["candidate_count"])))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a8-jsonl", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    a8 = Path(args.a8_jsonl)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_records = list(iter_jsonl(a8))
    records = [normalize_record(o) for o in raw_records]

    # Basic counters
    counters = {
        "tal": Counter(r["tal"] for r in records),
        "repo_host": Counter(r["repo_host"] for r in records),
        "repo_base": Counter(r["repo_base"] for r in records),
        "repository_identity": Counter(r["repository_identity"] for r in records),
        "manifest_uri": Counter(r["manifest_uri"] for r in records),
        "manifestNumber": Counter(r["manifestNumber"] for r in records),
        "manifest_thisUpdate": Counter(r["manifest_thisUpdate"] for r in records),
        "manifest_nextUpdate": Counter(r["manifest_nextUpdate"] for r in records),
        "roa_uri": Counter(r["roa_uri"] for r in records),
        "roa_filename": Counter(r["roa_filename"] for r in records),
        "asn": Counter(r["asn"] for r in records),
        "prefix": Counter(r["prefix"] for r in records),
        "window_id": Counter(r["window_id"] for r in records),
        "ca_like_id": Counter(r["ca_like_id"] for r in records),
    }

    # Write normalized records
    record_fields = [
        "vrp_key", "tal", "afi", "prefix", "asn", "maxLength",
        "roa_uri", "roa_filename",
        "manifest_uri", "manifest_filename",
        "repo_host", "repo_base", "repository_uuid", "repo_subdir", "repository_identity",
        "ca_like_id",
        "manifestNumber", "manifest_thisUpdate", "manifest_nextUpdate",
        "manifest_file_hash", "manifest_fileList_count",
        "window_id", "nearest_window_delta_sec",
        "jsonext_available", "manifest_context_available",
        "notification_context_available", "validator_timing_available",
        "notification_relation_top", "notification_pp_top",
    ]
    write_csv(out_dir / "a8_normalized_candidate_records.csv", records, record_fields)

    # Write counter CSVs
    counter_files = {}
    for name, counter in counters.items():
        p = out_dir / f"dist_{name}.csv"
        write_csv(p, top_counter_rows(counter, name), [name, "count"])
        counter_files[name] = str(p)

    # Cluster tables
    cluster_tables = {}
    for key in [
        "repo_base",
        "manifest_uri",
        "manifestNumber",
        "repository_identity",
        "ca_like_id",
        "window_id",
    ]:
        rows = build_cluster_rows(records, key)
        p = out_dir / f"cluster_by_{key}.csv"
        fieldnames = [
            "cluster_type", "cluster_key", "candidate_count",
            "unique_vrp_key_count", "unique_roa_uri_count", "unique_manifest_uri_count",
            "unique_asn_count", "unique_prefix_count",
            "unique_manifestNumber_count", "unique_thisUpdate_count", "unique_nextUpdate_count",
            "unique_window_count", "unique_ca_like_id_count",
            "tal_top", "asn_top", "prefix_top",
            "manifestNumber_top", "thisUpdate_top", "nextUpdate_top",
            "window_top", "ca_like_id_top",
            "delta_min", "delta_median", "delta_p90", "delta_max",
            "case_study_priority", "case_study_reason",
        ]
        write_csv(p, rows, fieldnames)
        cluster_tables[key] = str(p)

    # Build summary JSON/MD
    summary = {
        "schema": "s3.m21.a8.case_study_cluster_stats.v1",
        "generated_at_utc": utc_now(),
        "input": str(a8),
        "record_count": len(records),
        "unique_vrp_key_count": len(set(r["vrp_key"] for r in records)),
        "unique_roa_uri_count": len(counters["roa_uri"]),
        "unique_manifest_uri_count": len(counters["manifest_uri"]),
        "unique_repo_base_count": len(counters["repo_base"]),
        "unique_ca_like_id_count": len(counters["ca_like_id"]),
        "top": {
            "tal": counters["tal"].most_common(20),
            "repo_host": counters["repo_host"].most_common(20),
            "repo_base": counters["repo_base"].most_common(20),
            "manifest_uri": counters["manifest_uri"].most_common(20),
            "manifestNumber": counters["manifestNumber"].most_common(20),
            "manifest_thisUpdate": counters["manifest_thisUpdate"].most_common(20),
            "manifest_nextUpdate": counters["manifest_nextUpdate"].most_common(20),
            "ca_like_id": counters["ca_like_id"].most_common(20),
            "asn": counters["asn"].most_common(20),
            "prefix": counters["prefix"].most_common(20),
            "window_id": counters["window_id"].most_common(20),
        },
        "counter_files": counter_files,
        "cluster_tables": cluster_tables,
        "semantic_boundary": (
            "cluster_analysis_for_high_priority_candidate_subset_not_global_prevalence"
        ),
        "ca_info_note": (
            "If explicit CA certificate subject/SKI/AKI fields are absent in A8 records, "
            "ca_like_id falls back to repository_identity derived from ROA/manifest URI."
        ),
    }

    (out_dir / "a8_case_study_cluster_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    repo_rows = build_cluster_rows(records, "repo_base")
    manifest_rows = build_cluster_rows(records, "manifest_uri")

    md = []
    md.append("# A8 High-priority Candidate Cluster Statistics")
    md.append("")
    md.append("## Scope")
    md.append(f"- record_count: `{summary['record_count']}`")
    md.append(f"- unique_vrp_key_count: `{summary['unique_vrp_key_count']}`")
    md.append(f"- unique_roa_uri_count: `{summary['unique_roa_uri_count']}`")
    md.append(f"- unique_manifest_uri_count: `{summary['unique_manifest_uri_count']}`")
    md.append(f"- unique_repo_base_count: `{summary['unique_repo_base_count']}`")
    md.append(f"- unique_ca_like_id_count: `{summary['unique_ca_like_id_count']}`")
    md.append("")
    md.append("## Top Repository Base")
    for k, v in summary["top"]["repo_base"][:10]:
        md.append(f"- `{k}`: `{v}`")
    md.append("")
    md.append("## Top Manifest URI")
    for k, v in summary["top"]["manifest_uri"][:10]:
        md.append(f"- `{k}`: `{v}`")
    md.append("")
    md.append("## Top Manifest Number")
    for k, v in summary["top"]["manifestNumber"][:10]:
        md.append(f"- `{k}`: `{v}`")
    md.append("")
    md.append("## Top CA-like Identifier")
    for k, v in summary["top"]["ca_like_id"][:10]:
        md.append(f"- `{k}`: `{v}`")
    md.append("")
    md.append("## Recommended Case-study Clusters by repo_base")
    for r in repo_rows[:10]:
        md.append(
            f"- `{r['case_study_priority']}` count=`{r['candidate_count']}`, "
            f"unique_roa=`{r['unique_roa_uri_count']}`, "
            f"unique_manifest=`{r['unique_manifest_uri_count']}`, "
            f"manifestNumber={r['manifestNumber_top']}, "
            f"repo=`{r['cluster_key']}`, "
            f"reason=`{r['case_study_reason']}`"
        )
    md.append("")
    md.append("## Recommended Case-study Clusters by manifest_uri")
    for r in manifest_rows[:10]:
        md.append(
            f"- `{r['case_study_priority']}` count=`{r['candidate_count']}`, "
            f"unique_roa=`{r['unique_roa_uri_count']}`, "
            f"manifestNumber={r['manifestNumber_top']}, "
            f"thisUpdate={r['thisUpdate_top']}, "
            f"manifest=`{r['cluster_key']}`, "
            f"reason=`{r['case_study_reason']}`"
        )
    md.append("")
    md.append("## Interpretation")
    md.append("- These statistics describe the current A8 high-priority candidate subset, not global RPKI prevalence.")
    md.append("- Repository/manifest clustering suggests that multiple VRP candidates may correspond to a smaller number of repository-level or manifest-level event clusters.")
    md.append("- Case-study priority is heuristic and should be validated with live same-window capture and targeted PP backfill.")
    md.append("")
    (out_dir / "a8_case_study_cluster_summary.md").write_text("\n".join(md), encoding="utf-8")

    check = "\n".join([
        "M21_A8_CASE_STUDY_CLUSTER_STATS=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"record_count = {summary['record_count']}",
        f"unique_vrp_key_count = {summary['unique_vrp_key_count']}",
        f"unique_roa_uri_count = {summary['unique_roa_uri_count']}",
        f"unique_manifest_uri_count = {summary['unique_manifest_uri_count']}",
        f"unique_repo_base_count = {summary['unique_repo_base_count']}",
        f"unique_ca_like_id_count = {summary['unique_ca_like_id_count']}",
        f"summary_json = {out_dir / 'a8_case_study_cluster_summary.json'}",
        f"summary_md = {out_dir / 'a8_case_study_cluster_summary.md'}",
        f"cluster_by_repo_base = {cluster_tables['repo_base']}",
        f"cluster_by_manifest_uri = {cluster_tables['manifest_uri']}",
        "semantic_boundary = cluster_analysis_for_high_priority_candidate_subset_not_global_prevalence",
        "next_stage = targeted_pp_backfill_or_live_same_window_capture",
        "",
    ])
    (out_dir / "M21_A8_CASE_STUDY_CLUSTER_STATS_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
