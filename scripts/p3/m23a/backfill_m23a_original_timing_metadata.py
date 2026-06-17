#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import os
import re
from pathlib import Path
from datetime import datetime, timezone


WINDOW_RE = re.compile(r"win_(\d{8}T\d{6}Z)_")


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


def key_of(r):
    return "|".join([
        r.get("vrp_key", ""),
        r.get("roa_uri", ""),
        r.get("prefix", ""),
        r.get("asn", ""),
        r.get("maxLength", ""),
    ])


def first_nonempty(r, keys):
    for k in keys:
        v = r.get(k)
        if v not in (None, "", "None", "null"):
            return str(v)
    return ""


def main():
    m23a_out = Path(os.environ["M23A_OUT"])
    detail_dir = Path(os.environ["M22G2_DETAIL_OUT"])

    seed_csv = m23a_out / "m23a_targeted_pp_backfill_candidate_seed.csv"
    plan_json = m23a_out / "m23a_targeted_pp_backfill_plan.json"

    seeds = read_csv(seed_csv)

    detail_files = [
        detail_dir / "case1_repo_cluster_vrp_detail.csv",
        detail_dir / "case2_repo_cluster_vrp_detail.csv",
        detail_dir / "case3_repo_cluster_vrp_detail.csv",
    ]

    detail_rows = []
    for p in detail_files:
        detail_rows.extend(read_csv(p))

    detail_index = {}
    for r in detail_rows:
        detail_index[key_of(r)] = r

    enriched = []
    hit = 0
    duration_hit = 0
    probe_hit = 0
    window_hit = 0

    capture_time = ""
    if seeds:
        capture_time = seeds[0].get("capture_time_utc", "")

    cap_dt = parse_utc(capture_time)

    for s in seeds:
        k = key_of(s)
        d = detail_index.get(k, {})

        if d:
            hit += 1

        duration_windows = first_nonempty(d, ["global_duration_windows"])
        duration_seconds = first_nonempty(d, ["global_duration_seconds_approx"])
        probe_seen_count = first_nonempty(d, ["probe_seen_count"])
        seen_probe_set = first_nonempty(d, ["seen_probe_set"])

        if duration_windows or duration_seconds:
            duration_hit += 1
        if probe_seen_count or seen_probe_set:
            probe_hit += 1

        original_window_ids = []
        times = []
        for kk in [
            "window_id",
            "target_window_id",
            "collector_window_id",
            "source_window_id",
            "first_window_id",
            "last_window_id",
            "m17_window_id",
            "m18_window_id",
        ]:
            v = d.get(kk)
            if v:
                original_window_ids.append(v)
                t = parse_window_time(v)
                if t:
                    times.append(t)

        if original_window_ids:
            window_hit += 1

        first_seen = ""
        last_seen = ""
        if times:
            first_seen = min(times).strftime("%Y-%m-%dT%H:%M:%SZ")
            last_seen = max(times).strftime("%Y-%m-%dT%H:%M:%SZ")

        delta_first = ""
        delta_last = ""
        if cap_dt and first_seen:
            delta_first = int((cap_dt - parse_utc(first_seen)).total_seconds())
        if cap_dt and last_seen:
            delta_last = int((cap_dt - parse_utc(last_seen)).total_seconds())

        out = dict(s)
        out.update({
            "timing_backfill_match": bool(d),
            "global_duration_windows": duration_windows,
            "global_duration_seconds_approx": duration_seconds,
            "probe_seen_count": probe_seen_count,
            "seen_probe_set": seen_probe_set,
            "original_window_ids": ";".join(original_window_ids) if original_window_ids else s.get("original_window_ids", ""),
            "original_timing_available": bool(times),
            "original_first_seen_utc": first_seen,
            "original_last_seen_utc": last_seen,
            "delta_from_original_first_seen_sec": delta_first,
            "delta_from_original_last_seen_sec": delta_last,
            "temporal_delta_available": bool(delta_first != "" or delta_last != ""),
            "timing_backfill_source": "m22g2_top_cluster_details",
        })
        enriched.append(out)

    fields = list(enriched[0].keys()) if enriched else []
    out_csv = m23a_out / "m23a_targeted_pp_backfill_candidate_seed_with_timing.csv"
    write_csv(out_csv, enriched, fields)

    # update plan warnings summary only, do not overwrite original plan semantics
    plan = json.loads(plan_json.read_text(encoding="utf-8"))
    plan["timing_backfill"] = {
        "source": "m22g2_top_cluster_details",
        "candidate_seed_count": len(seeds),
        "detail_row_count": len(detail_rows),
        "join_hit_count": hit,
        "duration_hit_count": duration_hit,
        "probe_hit_count": probe_hit,
        "window_hit_count": window_hit,
        "temporal_delta_available_count": sum(1 for r in enriched if r.get("temporal_delta_available") is True),
        "output_csv": str(out_csv),
    }

    plan_out = m23a_out / "m23a_targeted_pp_backfill_plan_with_timing.json"
    plan_out.write_text(json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    md = []
    md.append("# M23A Original Timing Metadata Backfill")
    md.append("")
    md.append(f"- candidate_seed_count: `{len(seeds)}`")
    md.append(f"- detail_row_count: `{len(detail_rows)}`")
    md.append(f"- join_hit_count: `{hit}`")
    md.append(f"- duration_hit_count: `{duration_hit}`")
    md.append(f"- probe_hit_count: `{probe_hit}`")
    md.append(f"- window_hit_count: `{window_hit}`")
    md.append(f"- temporal_delta_available_count: `{sum(1 for r in enriched if r.get('temporal_delta_available') is True)}`")
    md.append("")
    md.append("Note: if window_hit_count is 0, historical duration/probe metadata was recovered but exact original window timing remains unavailable.")
    (m23a_out / "m23a_original_timing_backfill_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    check = "\n".join([
        "M23A_ORIGINAL_TIMING_BACKFILL=PASS",
        f"candidate_seed_count = {len(seeds)}",
        f"detail_row_count = {len(detail_rows)}",
        f"join_hit_count = {hit}",
        f"duration_hit_count = {duration_hit}",
        f"probe_hit_count = {probe_hit}",
        f"window_hit_count = {window_hit}",
        f"timing_enriched_csv = {out_csv}",
        f"plan_with_timing_json = {plan_out}",
        "semantic_boundary = timing_metadata_backfill_from_local_candidate_details_not_same_window_capture",
        "",
    ])
    (m23a_out / "M23A_ORIGINAL_TIMING_BACKFILL_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
