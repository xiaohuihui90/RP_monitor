#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


WINDOW_RE = re.compile(r"win_(\d{8}T\d{6}Z)_")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(s: str):
    if not s:
        return None
    s = str(s).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y%m%dT%H%M%SZ"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return None


def parse_window_time(window_id: str):
    if not window_id:
        return None
    m = WINDOW_RE.search(str(window_id))
    if not m:
        return None
    return parse_utc(m.group(1))


def read_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def repo_host(repo_base: str) -> str:
    try:
        return urlparse(repo_base).netloc
    except Exception:
        return ""


def filename_from_uri(uri: str) -> str:
    return (uri or "").rstrip("/").rsplit("/", 1)[-1]


def first_nonempty(row: dict, keys: list[str]) -> str:
    for k in keys:
        v = row.get(k)
        if v not in (None, "", "None", "null"):
            return str(v)
    return ""


def collect_original_windows(rows: list[dict]) -> tuple[list[str], bool, str, str]:
    window_keys = [
        "window_id",
        "target_window_id",
        "collector_window_id",
        "source_window_id",
        "first_window_id",
        "last_window_id",
        "m17_window_id",
        "m18_window_id",
    ]

    wins = []
    times = []
    for r in rows:
        for k in window_keys:
            v = r.get(k)
            if v and str(v) not in wins:
                wins.append(str(v))
                t = parse_window_time(str(v))
                if t:
                    times.append(t)

    if not times:
        return wins, False, "", ""

    first = min(times).strftime("%Y-%m-%dT%H:%M:%SZ")
    last = max(times).strftime("%Y-%m-%dT%H:%M:%SZ")
    return wins, True, first, last


def temporal_boundary(rows: list[dict], capture_time: str) -> dict:
    wins, timing_ok, first_seen, last_seen = collect_original_windows(rows)
    cap_dt = parse_utc(capture_time)
    first_dt = parse_utc(first_seen)
    last_dt = parse_utc(last_seen)

    delta_first = ""
    delta_last = ""
    if cap_dt and first_dt:
        delta_first = int((cap_dt - first_dt).total_seconds())
    if cap_dt and last_dt:
        delta_last = int((cap_dt - last_dt).total_seconds())

    return {
        "original_window_ids": wins,
        "original_window_count": len(wins),
        "original_timing_available": timing_ok,
        "original_first_seen_utc": first_seen,
        "original_last_seen_utc": last_seen,
        "capture_time_utc": capture_time,
        "delta_from_original_first_seen_sec": delta_first,
        "delta_from_original_last_seen_sec": delta_last,
        "temporal_delta_available": bool(delta_first != "" or delta_last != ""),
        "is_post_diff_backfill": True,
        "is_same_window_capture": False,
        "evidence_temporal_level": "L3_TARGETED_PP_BACKFILL_PLAN",
        "semantic_boundary": "post_diff_targeted_pp_backfill_plan_not_historical_causal_attribution",
    }


def top_counter(c: Counter, n: int = 10):
    return [{"value": k, "count": v} for k, v in c.most_common(n)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m22h-records-csv", required=True)
    ap.add_argument("--m22h-repo-summary-csv", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--top-n", type=int, default=3)
    args = ap.parse_args()

    records_csv = Path(args.m22h_records_csv)
    repo_summary_csv = Path(args.m22h_repo_summary_csv)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    records = read_csv(records_csv)
    repo_summary = read_csv(repo_summary_csv)
    capture_time = utc_now()

    top_repos = repo_summary[: args.top_n]
    targets = []
    candidate_seed_rows = []
    roa_seed_rows = []
    warnings = []

    for rr in top_repos:
        repo_base = rr.get("repo_base", "")
        repo_records = [r for r in records if r.get("repo_base") == repo_base]
        if not repo_records:
            warnings.append(f"no_records_for_repo:{repo_base}")
            continue

        repo_rank = rr.get("repo_rank", str(len(targets) + 1))
        target_id = f"m23a_target_repo_{repo_rank}"
        host = repo_host(repo_base)

        tal_c = Counter(r.get("tal", "") for r in repo_records if r.get("tal"))
        prefix_c = Counter(r.get("prefix", "") for r in repo_records if r.get("prefix"))
        asn_c = Counter(r.get("asn", "") for r in repo_records if r.get("asn"))
        maxlen_c = Counter(r.get("maxLength", "") for r in repo_records if r.get("maxLength"))
        roa_c = Counter(r.get("roa_uri", "") for r in repo_records if r.get("roa_uri"))
        manifest_c = Counter(r.get("selected_manifest_uri", "") for r in repo_records if r.get("selected_manifest_uri"))
        vrp_c = Counter(r.get("vrp_key", "") for r in repo_records if r.get("vrp_key"))

        candidate_count = len(repo_records)
        unique_roa_count = len(roa_c)
        amplification = round(candidate_count / unique_roa_count, 4) if unique_roa_count else 0

        tb = temporal_boundary(repo_records, capture_time)
        if not tb["original_timing_available"]:
            warnings.append(f"original_timing_missing_for_repo_rank_{repo_rank}")

        manifest_uri = rr.get("selected_manifest_uri", first_nonempty(repo_records[0], ["selected_manifest_uri", "manifest_uri"]))
        manifest_name = rr.get("selected_manifest_name", filename_from_uri(manifest_uri))
        manifest_number = rr.get("manifestNumber", first_nonempty(repo_records[0], ["manifestNumber"]))
        manifest_this = rr.get("manifest_thisUpdate", first_nonempty(repo_records[0], ["manifest_thisUpdate"]))
        manifest_next = rr.get("manifest_nextUpdate", first_nonempty(repo_records[0], ["manifest_nextUpdate"]))
        manifest_filelist_count = rr.get("manifest_fileList_count", first_nonempty(repo_records[0], ["manifest_fileList_count"]))

        filelist_match_count = sum(1 for r in repo_records if str(r.get("manifest_filelist_match")) == "True")
        hash_checked_count = sum(1 for r in repo_records if r.get("manifest_hash_match_fetched_roa") in ("True", "False"))
        hash_match_count = sum(1 for r in repo_records if r.get("manifest_hash_match_fetched_roa") == "True")
        filelist_match_ratio = round(filelist_match_count / candidate_count, 4) if candidate_count else 0
        hash_match_ratio = round(hash_match_count / hash_checked_count, 4) if hash_checked_count else 0

        roa_targets = []
        for roa_uri, roa_cnt in roa_c.most_common():
            sub = [r for r in repo_records if r.get("roa_uri") == roa_uri]
            sub_prefix_c = Counter(r.get("prefix", "") for r in sub if r.get("prefix"))
            sub_asn_c = Counter(r.get("asn", "") for r in sub if r.get("asn"))
            sub_maxlen_c = Counter(r.get("maxLength", "") for r in sub if r.get("maxLength"))
            hyp_roa_fanout = roa_cnt >= 10

            roa_obj = {
                "roa_uri": roa_uri,
                "roa_filename": filename_from_uri(roa_uri),
                "candidate_count_for_roa": roa_cnt,
                "unique_prefix_count": len(sub_prefix_c),
                "unique_asn_count": len(sub_asn_c),
                "unique_maxLength_count": len(sub_maxlen_c),
                "asn_top": top_counter(sub_asn_c, 10),
                "maxLength_top": top_counter(sub_maxlen_c, 10),
                "prefixes": sorted(sub_prefix_c.keys()),
                "vrp_keys": sorted(set(r.get("vrp_key", "") for r in sub if r.get("vrp_key"))),
                "roa_amplification_factor": roa_cnt,
                "hypothesis_roa_fanout_amplification": hyp_roa_fanout,
            }
            roa_targets.append(roa_obj)

            roa_seed_rows.append({
                "target_id": target_id,
                "repo_rank": repo_rank,
                "repo_host": host,
                "repo_base": repo_base,
                "manifest_uri": manifest_uri,
                "manifest_filename": manifest_name,
                "manifestNumber": manifest_number,
                "roa_uri": roa_uri,
                "roa_filename": filename_from_uri(roa_uri),
                "candidate_count_for_roa": roa_cnt,
                "unique_prefix_count": len(sub_prefix_c),
                "unique_asn_count": len(sub_asn_c),
                "unique_maxLength_count": len(sub_maxlen_c),
                "asn_top": repr(sub_asn_c.most_common(10)),
                "maxLength_top": repr(sub_maxlen_c.most_common(10)),
                "roa_amplification_factor": roa_cnt,
                "hypothesis_roa_fanout_amplification": hyp_roa_fanout,
                "evidence_temporal_level": tb["evidence_temporal_level"],
                "semantic_boundary": tb["semantic_boundary"],
            })

        manifest_publication_cluster = (
            len(manifest_c) == 1
            and filelist_match_ratio == 1.0
            and hash_match_ratio == 1.0
            and candidate_count >= 30
        )

        root_seed = {
            "C1_ROA_FANOUT_AMPLIFICATION": {
                "value": any(r["hypothesis_roa_fanout_amplification"] for r in roa_targets),
                "confidence_hint": "high" if any(r["hypothesis_roa_fanout_amplification"] for r in roa_targets) else "low",
                "requires_same_window_validation": False,
            },
            "C2_MANIFEST_PUBLICATION_CLUSTER": {
                "value": manifest_publication_cluster,
                "confidence_hint": "high" if manifest_publication_cluster else "low",
                "requires_same_window_validation": False,
            },
            "C3_MANIFEST_VERSION_SKEW_CANDIDATE": {
                "value": "unknown",
                "confidence_hint": "unknown",
                "requires_same_window_validation": True,
            },
            "C4_PP_FETCH_REACHABILITY_CANDIDATE": {
                "value": "unknown",
                "confidence_hint": "unknown",
                "requires_same_window_validation": True,
            },
            "C5_CACHE_TRAILING_CANDIDATE": {
                "value": "unknown",
                "confidence_hint": "unknown",
                "requires_same_window_validation": True,
            },
            "C6_SOURCE_PROVENANCE_GAP_CANDIDATE": {
                "value": False,
                "confidence_hint": "not_applicable_for_m22h_mapped_p0_targets",
                "requires_historical_jsonext": False,
            },
        }

        target = {
            "target_id": target_id,
            "target_priority": "P0",
            "repo_rank": repo_rank,
            "repo_host": host,
            "repo_base": repo_base,
            "candidate_count": candidate_count,
            "unique_vrp_key_count": len(vrp_c),
            "unique_roa_count": unique_roa_count,
            "unique_prefix_count": len(prefix_c),
            "unique_asn_count": len(asn_c),
            "unique_manifest_count": len(manifest_c),
            "amplification_candidate_per_roa": amplification,
            "tal_distribution": top_counter(tal_c, 10),
            "asn_distribution_top": top_counter(asn_c, 20),
            "maxLength_distribution": top_counter(maxlen_c, 20),
            "manifest": {
                "manifest_uri": manifest_uri,
                "manifest_filename": manifest_name,
                "manifestNumber": manifest_number,
                "manifest_thisUpdate": manifest_this,
                "manifest_nextUpdate": manifest_next,
                "manifest_fileList_count": manifest_filelist_count,
                "manifest_filelist_match_count": filelist_match_count,
                "manifest_filelist_match_ratio": filelist_match_ratio,
                "hash_checked_count": hash_checked_count,
                "hash_match_count": hash_match_count,
                "hash_match_ratio": hash_match_ratio,
            },
            "temporal_boundary": tb,
            "roa_targets": roa_targets,
            "backfill_tasks": [
                "rsync_list_repo_base",
                "fetch_selected_manifest",
                "extract_manifest_econtent",
                "parse_manifest_filelist",
                "fetch_target_roas",
                "compare_manifest_hash_with_fetched_roa_hash",
                "optional_rrdp_notification_fetch_if_uri_available",
                "optional_current_jsonext_presence_check",
                "optional_validator_timing_snapshot",
            ],
            "same_window_capture_targets": {
                "same_window_capture_required": True,
                "target_repo_base": repo_base,
                "target_manifest_uri": manifest_uri,
                "target_roa_uris": sorted(roa_c.keys()),
                "target_vrp_keys": sorted(vrp_c.keys()),
                "target_prefixes": sorted(prefix_c.keys()),
            },
            "root_cause_hypothesis_seed": root_seed,
        }

        targets.append(target)

        for r in repo_records:
            candidate_seed_rows.append({
                "target_id": target_id,
                "repo_rank": repo_rank,
                "repo_host": host,
                "repo_base": repo_base,
                "manifest_uri": manifest_uri,
                "manifest_filename": manifest_name,
                "manifestNumber": manifest_number,
                "manifest_thisUpdate": manifest_this,
                "manifest_nextUpdate": manifest_next,
                "vrp_key": r.get("vrp_key", ""),
                "tal": r.get("tal", ""),
                "afi": r.get("afi", ""),
                "prefix": r.get("prefix", ""),
                "asn": r.get("asn", ""),
                "maxLength": r.get("maxLength", ""),
                "roa_uri": r.get("roa_uri", ""),
                "roa_filename": filename_from_uri(r.get("roa_uri", "")),
                "manifest_filelist_match": r.get("manifest_filelist_match", ""),
                "manifest_hash_match_fetched_roa": r.get("manifest_hash_match_fetched_roa", ""),
                "original_window_ids": ";".join(tb["original_window_ids"]),
                "original_timing_available": tb["original_timing_available"],
                "original_first_seen_utc": tb["original_first_seen_utc"],
                "original_last_seen_utc": tb["original_last_seen_utc"],
                "capture_time_utc": tb["capture_time_utc"],
                "delta_from_original_first_seen_sec": tb["delta_from_original_first_seen_sec"],
                "delta_from_original_last_seen_sec": tb["delta_from_original_last_seen_sec"],
                "is_post_diff_backfill": tb["is_post_diff_backfill"],
                "is_same_window_capture": tb["is_same_window_capture"],
                "evidence_temporal_level": tb["evidence_temporal_level"],
                "semantic_boundary": tb["semantic_boundary"],
            })

    plan = {
        "schema": "s3.m23a.targeted_pp_backfill_plan.v1",
        "created_at_utc": capture_time,
        "input_records_csv": str(records_csv),
        "input_repo_summary_csv": str(repo_summary_csv),
        "top_n": args.top_n,
        "target_count": len(targets),
        "candidate_seed_count": len(candidate_seed_rows),
        "roa_seed_count": len(roa_seed_rows),
        "targets": targets,
        "warnings": warnings,
        "semantic_boundary": "post_diff_targeted_pp_backfill_plan_not_historical_causal_attribution",
        "next_stage": "M23A_BATCH2_EXECUTE_TARGETED_PP_BACKFILL",
    }

    (out / "m23a_targeted_pp_backfill_plan.json").write_text(
        json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    candidate_fields = [
        "target_id", "repo_rank", "repo_host", "repo_base",
        "manifest_uri", "manifest_filename", "manifestNumber",
        "manifest_thisUpdate", "manifest_nextUpdate",
        "vrp_key", "tal", "afi", "prefix", "asn", "maxLength",
        "roa_uri", "roa_filename",
        "manifest_filelist_match", "manifest_hash_match_fetched_roa",
        "original_window_ids", "original_timing_available",
        "original_first_seen_utc", "original_last_seen_utc",
        "capture_time_utc",
        "delta_from_original_first_seen_sec",
        "delta_from_original_last_seen_sec",
        "is_post_diff_backfill", "is_same_window_capture",
        "evidence_temporal_level", "semantic_boundary",
    ]
    write_csv(out / "m23a_targeted_pp_backfill_candidate_seed.csv", candidate_seed_rows, candidate_fields)

    roa_fields = [
        "target_id", "repo_rank", "repo_host", "repo_base",
        "manifest_uri", "manifest_filename", "manifestNumber",
        "roa_uri", "roa_filename",
        "candidate_count_for_roa",
        "unique_prefix_count", "unique_asn_count", "unique_maxLength_count",
        "asn_top", "maxLength_top",
        "roa_amplification_factor",
        "hypothesis_roa_fanout_amplification",
        "evidence_temporal_level", "semantic_boundary",
    ]
    write_csv(out / "m23a_targeted_pp_backfill_roa_seed.csv", roa_seed_rows, roa_fields)

    md = []
    md.append("# M23A Targeted PP Backfill Plan")
    md.append("")
    md.append(f"- created_at_utc: `{capture_time}`")
    md.append(f"- target_count: `{len(targets)}`")
    md.append(f"- candidate_seed_count: `{len(candidate_seed_rows)}`")
    md.append(f"- roa_seed_count: `{len(roa_seed_rows)}`")
    md.append("- semantic_boundary: `post_diff_targeted_pp_backfill_plan_not_historical_causal_attribution`")
    md.append("")
    md.append("## Targets")
    for t in targets:
        md.append("")
        md.append(f"### {t['target_id']}")
        md.append(f"- repo_rank: `{t['repo_rank']}`")
        md.append(f"- repo_host: `{t['repo_host']}`")
        md.append(f"- repo_base: `{t['repo_base']}`")
        md.append(f"- candidates: `{t['candidate_count']}`")
        md.append(f"- unique_roa: `{t['unique_roa_count']}`")
        md.append(f"- unique_prefix: `{t['unique_prefix_count']}`")
        md.append(f"- unique_asn: `{t['unique_asn_count']}`")
        md.append(f"- amplification_candidate_per_roa: `{t['amplification_candidate_per_roa']}`")
        md.append(f"- manifest: `{t['manifest']['manifest_filename']}`")
        md.append(f"- manifestNumber: `{t['manifest']['manifestNumber']}`")
        md.append(f"- manifest_thisUpdate: `{t['manifest']['manifest_thisUpdate']}`")
        md.append(f"- manifest_nextUpdate: `{t['manifest']['manifest_nextUpdate']}`")
        md.append(f"- manifest_filelist_match_ratio: `{t['manifest']['manifest_filelist_match_ratio']}`")
        md.append(f"- hash_match_ratio: `{t['manifest']['hash_match_ratio']}`")
        md.append(f"- original_timing_available: `{t['temporal_boundary']['original_timing_available']}`")
        md.append(f"- evidence_temporal_level: `{t['temporal_boundary']['evidence_temporal_level']}`")
        md.append("")
        md.append("Top ROA targets:")
        for r in t["roa_targets"][:10]:
            md.append(
                f"- `{r['roa_filename']}`: candidates=`{r['candidate_count_for_roa']}`, "
                f"unique_prefix=`{r['unique_prefix_count']}`, fanout_hypothesis=`{r['hypothesis_roa_fanout_amplification']}`"
            )
    if warnings:
        md.append("")
        md.append("## Warnings")
        for w in warnings:
            md.append(f"- {w}")

    (out / "m23a_targeted_pp_backfill_plan.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    status = "PASS" if targets and candidate_seed_rows and roa_seed_rows else "FAIL"
    check = "\n".join([
        f"M23A_BATCH1_INIT_PLAN={status}",
        f"created_at_utc = {capture_time}",
        f"target_count = {len(targets)}",
        f"candidate_seed_count = {len(candidate_seed_rows)}",
        f"roa_seed_count = {len(roa_seed_rows)}",
        f"warning_count = {len(warnings)}",
        f"plan_json = {out / 'm23a_targeted_pp_backfill_plan.json'}",
        f"plan_md = {out / 'm23a_targeted_pp_backfill_plan.md'}",
        f"candidate_seed_csv = {out / 'm23a_targeted_pp_backfill_candidate_seed.csv'}",
        f"roa_seed_csv = {out / 'm23a_targeted_pp_backfill_roa_seed.csv'}",
        "semantic_boundary = post_diff_targeted_pp_backfill_plan_not_historical_causal_attribution",
        "next_stage = M23A_BATCH2_EXECUTE_TARGETED_PP_BACKFILL",
        "",
    ])
    (out / "M23A_BATCH1_INIT_PLAN_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
