#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from collections import Counter
from urllib.parse import urlparse
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def uri_base(uri: str) -> str:
    if not uri:
        return ""
    return uri.rsplit("/", 1)[0] + "/" if "/" in uri else uri


def uri_host(uri: str) -> str:
    if not uri:
        return ""
    return urlparse(uri).netloc


def duration_bucket(seconds):
    try:
        s = float(seconds)
    except Exception:
        return "unknown"
    if s < 3600:
        return "<1h"
    if s < 6 * 3600:
        return "1h-6h"
    if s < 24 * 3600:
        return "6h-24h"
    if s < 7 * 24 * 3600:
        return "1d-7d"
    return ">=7d"


def windows_bucket(w):
    try:
        x = int(w)
    except Exception:
        return "unknown"
    if x <= 1:
        return "1"
    if x <= 2:
        return "2"
    if x <= 4:
        return "3-4"
    if x <= 8:
        return "5-8"
    return ">=9"


def probe_bucket(n):
    try:
        x = int(n)
    except Exception:
        return "unknown"
    if x <= 1:
        return "1-probe"
    if x == 2:
        return "2-probe"
    if x >= 3:
        return "3-probe"
    return "unknown"


def load_m19_roa_level(path: Path) -> dict:
    out = {}
    for o in iter_jsonl(path):
        key = o.get("vrp_key")
        if not key:
            continue
        # 字段名在不同批次可能不同，因此做宽松判断。
        roa_uri = (
            o.get("roa_uri")
            or o.get("source_uri")
            or o.get("jsonext_source_uri")
            or o.get("fetch_target_uri")
        )
        mapped = bool(roa_uri) or bool(o.get("mapped_to_roa_uri_via_jsonext"))
        out[key] = {
            "roa_uri": roa_uri or "",
            "roa_level_available": mapped,
            "jsonext_generatedTime": o.get("jsonext_generatedTime") or "",
            "m19_status": o.get("mapping_status") or o.get("m19_status") or "",
        }
    return out


def load_a8(path: Path) -> dict:
    out = {}
    for o in iter_jsonl(path):
        key = o.get("vrp_key")
        if not key:
            continue

        roa_uri = o.get("roa_uri") or ""
        manifest_uri = o.get("manifest_uri") or ""
        repo_uri = roa_uri or manifest_uri

        out[key] = {
            "roa_uri": roa_uri,
            "repo_host": uri_host(repo_uri),
            "repo_base": uri_base(repo_uri),
            "manifest_uri": manifest_uri,
            "manifestNumber": str(o.get("manifestNumber") or ""),
            "manifest_thisUpdate": o.get("manifest_thisUpdate") or "",
            "manifest_nextUpdate": o.get("manifest_nextUpdate") or "",
            "manifest_file_hash": o.get("manifest_file_hash") or "",
            "manifest_context_available": bool(o.get("manifest_context_available")),
            "notification_context_available": bool(o.get("notification_context_available")),
            "validator_timing_available": bool(o.get("validator_timing_available")),
            "window_id": o.get("window_id") or "",
            "nearest_window_delta_sec": o.get("nearest_window_delta_sec"),
            "strong_l1_binding_ready": bool(o.get("strong_l1_binding_ready")),
            "semantic_boundary": o.get("semantic_boundary") or "",
            "notification_relation_top": ";".join([f"{a}:{b}" for a, b in (o.get("notification_like_relation_top") or [])]),
            "notification_pp_top": ";".join([f"{a}:{b}" for a, b in (o.get("notification_like_pp_top") or [])]),
        }
    return out


def evidence_level(seed: dict, m19: dict | None, a8: dict | None) -> str:
    if a8:
        if a8.get("strong_l1_binding_ready"):
            return "same-window-level"
        if a8.get("window_id") and a8.get("notification_context_available"):
            return "nearest-window-level"
        if a8.get("manifest_context_available") or a8.get("manifest_uri"):
            return "manifest-level"
        if a8.get("roa_uri"):
            return "ROA-level"
    if m19 and m19.get("roa_level_available"):
        return "ROA-level"
    return "VRP-only"


def write_csv(path: Path, rows: list[dict], fields: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def counter_rows(counter: Counter, key_name: str):
    return [{key_name: k, "count": v} for k, v in counter.most_common()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-jsonl", required=True)
    ap.add_argument("--m19-enriched", required=True)
    ap.add_argument("--a8-jsonl", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    seed_path = Path(args.seed_jsonl)
    m19_map = load_m19_roa_level(Path(args.m19_enriched))
    a8_map = load_a8(Path(args.a8_jsonl))

    out_dir = Path(args.out_dir) / args.label
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []

    counters = {
        "tal": Counter(),
        "repo_host": Counter(),
        "repo_base": Counter(),
        "manifestNumber": Counter(),
        "manifest_uri": Counter(),
        "prefix": Counter(),
        "asn": Counter(),
        "maxLength": Counter(),
        "evidence_level": Counter(),
        "transient_or_persistent": Counter(),
        "probe_seen_count": Counter(),
        "duration_windows_bucket": Counter(),
        "duration_seconds_bucket": Counter(),
        "trailing_cache_candidate_v1": Counter(),
        "window_id": Counter(),
        "nearest_delta_bucket": Counter(),
    }

    for seed in iter_jsonl(seed_path):
        key = seed.get("vrp_key")
        if not key:
            continue

        m19 = m19_map.get(key)
        a8 = a8_map.get(key)
        level = evidence_level(seed, m19, a8)

        row = {
            "measurement_label": args.label,
            "vrp_key": key,
            "afi": seed.get("afi", ""),
            "tal": seed.get("tal", ""),
            "prefix": seed.get("prefix", ""),
            "asn": seed.get("asn", ""),
            "maxLength": seed.get("maxLength", ""),

            "global_duration_windows": seed.get("global_duration_windows", ""),
            "global_duration_seconds_approx": seed.get("global_duration_seconds_approx", ""),
            "duration_windows_bucket": windows_bucket(seed.get("global_duration_windows")),
            "duration_seconds_bucket": duration_bucket(seed.get("global_duration_seconds_approx")),
            "probe_seen_count": seed.get("probe_seen_count", ""),
            "probe_seen_bucket": probe_bucket(seed.get("probe_seen_count")),
            "seen_probe_set": ",".join(seed.get("seen_probe_set") or []),
            "transient_or_persistent": seed.get("transient_or_persistent", ""),
            "trailing_cache_candidate_v1": seed.get("trailing_cache_candidate_v1", ""),
            "m18_d7b_score": seed.get("m18_d7b_score", ""),
            "m18_d7b_score_reasons": ",".join(seed.get("m18_d7b_score_reasons") or []),
            "m19_mapping_priority": seed.get("m19_mapping_priority", ""),
            "m19_mapping_reason": ",".join(seed.get("m19_mapping_reason") or []),

            "evidence_level": level,

            "roa_uri": "",
            "repo_host": "",
            "repo_base": "",
            "manifest_uri": "",
            "manifestNumber": "",
            "manifest_thisUpdate": "",
            "manifest_nextUpdate": "",
            "manifest_file_hash": "",
            "window_id": "",
            "nearest_window_delta_sec": "",
            "notification_relation_top": "",
            "notification_pp_top": "",
            "semantic_boundary": "",
        }

        if m19:
            row["roa_uri"] = m19.get("roa_uri", "") or row["roa_uri"]

        if a8:
            for k, v in a8.items():
                if k in row:
                    row[k] = v

        rows.append(row)

        # counters
        counters["tal"][row["tal"]] += 1
        counters["prefix"][row["prefix"]] += 1
        counters["asn"][row["asn"]] += 1
        counters["maxLength"][str(row["maxLength"])] += 1
        counters["evidence_level"][row["evidence_level"]] += 1
        counters["transient_or_persistent"][row["transient_or_persistent"]] += 1
        counters["probe_seen_count"][str(row["probe_seen_count"])] += 1
        counters["duration_windows_bucket"][row["duration_windows_bucket"]] += 1
        counters["duration_seconds_bucket"][row["duration_seconds_bucket"]] += 1
        counters["trailing_cache_candidate_v1"][str(row["trailing_cache_candidate_v1"])] += 1

        if row["repo_host"]:
            counters["repo_host"][row["repo_host"]] += 1
        if row["repo_base"]:
            counters["repo_base"][row["repo_base"]] += 1
        if row["manifestNumber"]:
            counters["manifestNumber"][row["manifestNumber"]] += 1
        if row["manifest_uri"]:
            counters["manifest_uri"][row["manifest_uri"]] += 1
        if row["window_id"]:
            counters["window_id"][row["window_id"]] += 1

        try:
            d = float(row["nearest_window_delta_sec"])
            if d <= 600:
                bucket = "<=10min"
            elif d <= 1800:
                bucket = "10-30min"
            elif d <= 3600:
                bucket = "30-60min"
            else:
                bucket = ">60min"
            counters["nearest_delta_bucket"][bucket] += 1
        except Exception:
            counters["nearest_delta_bucket"]["unknown"] += 1

    fields = [
        "measurement_label", "vrp_key", "afi", "tal", "prefix", "asn", "maxLength",
        "global_duration_windows", "global_duration_seconds_approx",
        "duration_windows_bucket", "duration_seconds_bucket",
        "probe_seen_count", "probe_seen_bucket", "seen_probe_set",
        "transient_or_persistent", "trailing_cache_candidate_v1",
        "m18_d7b_score", "m18_d7b_score_reasons",
        "m19_mapping_priority", "m19_mapping_reason",
        "evidence_level",
        "roa_uri", "repo_host", "repo_base",
        "manifest_uri", "manifestNumber", "manifest_thisUpdate", "manifest_nextUpdate",
        "manifest_file_hash", "window_id", "nearest_window_delta_sec",
        "notification_relation_top", "notification_pp_top", "semantic_boundary",
    ]

    master_csv = out_dir / "six_dimension_master_table.csv"
    write_csv(master_csv, rows, fields)

    # Write counter CSVs
    counter_files = {}
    for name, counter in counters.items():
        p = out_dir / f"dist_{name}.csv"
        write_csv(p, counter_rows(counter, name), [name, "count"])
        counter_files[name] = str(p)

    summary = {
        "schema": "s3.m22.six_dimension_measurement_stats.v1",
        "generated_at_utc": utc_now(),
        "label": args.label,
        "seed_jsonl": str(seed_path),
        "m19_enriched": str(args.m19_enriched),
        "a8_jsonl": str(args.a8_jsonl),
        "record_count": len(rows),
        "top": {
            name: counter.most_common(20)
            for name, counter in counters.items()
        },
        "counter_files": counter_files,
        "master_csv": str(master_csv),
        "interpretation": {
            "tal_note": "TAL distribution is determined by the selected seed set. top200 may be RIPE-biased; top1000 currently includes RIPE and LACNIC.",
            "evidence_note": "ROA-level comes from M19 JSONEXT mapping; manifest/nearest-window levels come from A8 records; same-window-level requires future A8B live same-window capture.",
            "scope_note": "This is a candidate-level measurement, not global RPKI prevalence.",
        },
    }

    summary_json = out_dir / "six_dimension_summary.json"
    summary_md = out_dir / "six_dimension_summary.md"
    check_txt = out_dir / "M22_SIX_DIMENSION_STATS_CHECK.txt"

    summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    md = []
    md.append(f"# Six-dimension Measurement Statistics: {args.label}")
    md.append("")
    md.append(f"- record_count: `{len(rows)}`")
    md.append("")
    for name in [
        "tal", "repo_host", "repo_base", "manifestNumber", "manifest_uri",
        "prefix", "asn", "maxLength", "duration_windows_bucket",
        "duration_seconds_bucket", "probe_seen_count",
        "trailing_cache_candidate_v1", "evidence_level", "window_id",
        "nearest_delta_bucket",
    ]:
        md.append(f"## {name}")
        for k, v in counters[name].most_common(20):
            md.append(f"- `{k}`: `{v}`")
        md.append("")
    md.append("## Interpretation")
    md.append("- This table supports candidate-level six-dimension measurement.")
    md.append("- Same-window-level evidence is expected to be zero until A8B live same-window capture is implemented.")
    md.append("- Repository/manifest statistics are only available for candidates that reached A8 or manifest-level evidence.")
    summary_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    check_txt.write_text(
        "\n".join([
            "M22_SIX_DIMENSION_STATS=PASS",
            f"generated_at_utc = {summary['generated_at_utc']}",
            f"label = {args.label}",
            f"record_count = {len(rows)}",
            f"master_csv = {master_csv}",
            f"summary_json = {summary_json}",
            f"summary_md = {summary_md}",
            "semantic_boundary = candidate_level_measurement_not_global_prevalence",
            "next_stage = TAL_STRATIFIED_EXPANSION_AND_A8B_LIVE_SAME_WINDOW_CAPTURE",
            "",
        ]),
        encoding="utf-8",
    )

    print(check_txt.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
