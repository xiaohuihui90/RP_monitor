#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone

FIVE_TALS = ["afrinic", "apnic", "arin", "lacnic", "ripe"]
AFIS = ["ipv4", "ipv6"]


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue
    except Exception:
        return


def norm_tal(x):
    return str(x or "").strip().lower()


def norm_afi(x):
    return str(x or "").strip().lower()


def norm_asn(x):
    s = str(x or "").strip()
    if not s:
        return ""
    if s.upper().startswith("AS"):
        s = s[2:]
    if s.isdigit():
        return f"AS{s}"
    return ""


def valid_prefix(x):
    s = str(x or "").strip()
    if not s:
        return ""
    try:
        return str(ipaddress.ip_network(s, strict=False))
    except Exception:
        return ""


def parse_key_or_fields(o: dict):
    """
    支持两种 vrp_key 顺序：
    A: afi|tal|prefix|asn|maxLength
    B: tal|afi|prefix|asn|maxLength
    同时支持显式字段。
    """

    # 先尝试显式字段
    afi = norm_afi(o.get("afi"))
    tal = norm_tal(o.get("tal"))
    prefix = valid_prefix(o.get("prefix"))
    asn = norm_asn(o.get("asn"))
    maxlen = str(o.get("maxLength") or o.get("max_length") or o.get("maxlength") or "").strip()

    if afi in AFIS and tal in FIVE_TALS and prefix and asn and maxlen:
        asn_num = asn[2:]
        return {
            "afi": afi,
            "tal": tal,
            "prefix": prefix,
            "asn": asn,
            "maxLength": maxlen,
            "vrp_key": f"{afi}|{tal}|{prefix}|{asn_num}|{maxlen}",
            "parse_mode": "explicit_fields",
        }

    # 再尝试 vrp_key
    key = str(o.get("vrp_key") or "").strip()
    parts = key.split("|")
    if len(parts) != 5:
        return None

    p0, p1, p2, p3, p4 = [x.strip() for x in parts]

    # A: afi|tal|prefix|asn|maxLength
    if norm_afi(p0) in AFIS and norm_tal(p1) in FIVE_TALS:
        afi = norm_afi(p0)
        tal = norm_tal(p1)
        prefix = valid_prefix(p2)
        asn = norm_asn(p3)
        maxlen = p4
        if prefix and asn and maxlen:
            return {
                "afi": afi,
                "tal": tal,
                "prefix": prefix,
                "asn": asn,
                "maxLength": maxlen,
                "vrp_key": f"{afi}|{tal}|{prefix}|{asn[2:]}|{maxlen}",
                "parse_mode": "vrp_key_afi_tal_prefix_asn_maxlen",
            }

    # B: tal|afi|prefix|asn|maxLength
    if norm_tal(p0) in FIVE_TALS and norm_afi(p1) in AFIS:
        tal = norm_tal(p0)
        afi = norm_afi(p1)
        prefix = valid_prefix(p2)
        asn = norm_asn(p3)
        maxlen = p4
        if prefix and asn and maxlen:
            return {
                "afi": afi,
                "tal": tal,
                "prefix": prefix,
                "asn": asn,
                "maxLength": maxlen,
                "vrp_key": f"{afi}|{tal}|{prefix}|{asn[2:]}|{maxlen}",
                "parse_mode": "vrp_key_tal_afi_prefix_asn_maxlen",
            }

    return None


def is_persistent_like(o: dict):
    tp = str(o.get("transient_or_persistent") or "").lower()
    if "persistent" in tp:
        return True

    reasons = [str(x).lower() for x in (o.get("m18_d7b_score_reasons") or [])]
    if any("persistent" in r for r in reasons):
        return True

    try:
        if int(o.get("global_duration_windows") or 0) >= 3:
            return True
    except Exception:
        pass

    try:
        if float(o.get("global_duration_seconds_approx") or 0) >= 7200:
            return True
    except Exception:
        pass

    return False


def score_record(o: dict):
    try:
        return float(o.get("m18_d7b_score"))
    except Exception:
        pass

    score = 0.0

    if is_persistent_like(o):
        score += 50

    try:
        score += min(int(o.get("global_duration_windows") or 0), 20) * 5
    except Exception:
        pass

    try:
        seconds = float(o.get("global_duration_seconds_approx") or 0)
        if seconds >= 7 * 24 * 3600:
            score += 50
        elif seconds >= 24 * 3600:
            score += 30
        elif seconds >= 7200:
            score += 10
    except Exception:
        pass

    try:
        score += int(o.get("probe_seen_count") or 0) * 10
    except Exception:
        pass

    if str(o.get("trailing_cache_candidate_v1")).lower() == "true":
        score += 20

    return score


def normalize_record(o: dict, source_file: Path):
    parsed = parse_key_or_fields(o)
    if not parsed:
        return None

    rec = {
        "schema": "s3.m22c.tal_stratified_candidate.v2",
        "source_file": str(source_file),
        **parsed,

        "global_duration_windows": o.get("global_duration_windows"),
        "global_duration_seconds_approx": o.get("global_duration_seconds_approx"),
        "probe_seen_count": o.get("probe_seen_count"),
        "seen_probe_set": o.get("seen_probe_set") or [],
        "transient_or_persistent": o.get("transient_or_persistent"),
        "trailing_cache_candidate_v1": o.get("trailing_cache_candidate_v1"),
        "m18_d7b_score": o.get("m18_d7b_score"),
        "m18_d7b_score_reasons": o.get("m18_d7b_score_reasons") or [],
        "m19_mapping_priority": o.get("m19_mapping_priority"),
        "m19_mapping_reason": o.get("m19_mapping_reason") or [],

        "persistent_like": is_persistent_like(o),
        "m22c_score": score_record(o),
        "semantic_boundary": "tal_stratified_candidate_sampling_not_causal_attribution",
    }
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--roots", nargs="+", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--per-tal", type=int, default=200)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_by_key = {}
    parse_mode_counter = Counter()
    rejected = Counter()
    source_counter = Counter()

    for root_s in args.roots:
        root = Path(root_s)
        if not root.exists():
            continue
        for p in root.rglob("*.jsonl"):
            for o in iter_jsonl(p):
                if not isinstance(o, dict):
                    continue
                rec = normalize_record(o, p)
                if not rec:
                    rejected["parse_failed_or_invalid_candidate"] += 1
                    continue
                source_counter[str(p)] += 1
                parse_mode_counter[rec["parse_mode"]] += 1

                key = rec["vrp_key"]
                old = all_by_key.get(key)
                if old is None or rec["m22c_score"] > old["m22c_score"]:
                    all_by_key[key] = rec

    all_records = list(all_by_key.values())
    persistent_records = [r for r in all_records if r["persistent_like"]]

    by_tal = defaultdict(list)
    for r in persistent_records:
        by_tal[r["tal"]].append(r)

    selected = []
    for tal in FIVE_TALS:
        rs = sorted(by_tal.get(tal, []), key=lambda x: x["m22c_score"], reverse=True)
        selected.extend(rs[:args.per_tal])

    def write_jsonl(path: Path, rows):
        with path.open("w", encoding="utf-8") as w:
            for r in rows:
                w.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    pool_all = out_dir / "m22c_v2_candidate_pool_all.jsonl"
    pool_persistent = out_dir / "m22c_v2_candidate_pool_persistent.jsonl"
    stratified = out_dir / f"m22c_v2_tal_stratified_candidates_per_tal_{args.per_tal}.jsonl"

    write_jsonl(pool_all, sorted(all_records, key=lambda x: (x["tal"], -x["m22c_score"], x["vrp_key"])))
    write_jsonl(pool_persistent, sorted(persistent_records, key=lambda x: (x["tal"], -x["m22c_score"], x["vrp_key"])))
    write_jsonl(stratified, selected)

    c_all = Counter(r["tal"] for r in all_records)
    c_persistent = Counter(r["tal"] for r in persistent_records)
    c_selected = Counter(r["tal"] for r in selected)

    summary = {
        "schema": "s3.m22c.tal_stratified_candidate_sampling_summary.v2",
        "generated_at_utc": utc_now(),
        "roots": args.roots,
        "unique_candidate_count_all": len(all_records),
        "unique_candidate_count_persistent": len(persistent_records),
        "selected_count": len(selected),
        "per_tal": args.per_tal,
        "five_tal_all_distribution": {tal: c_all.get(tal, 0) for tal in FIVE_TALS},
        "five_tal_persistent_distribution": {tal: c_persistent.get(tal, 0) for tal in FIVE_TALS},
        "five_tal_selected_distribution": {tal: c_selected.get(tal, 0) for tal in FIVE_TALS},
        "parse_mode_counter": dict(parse_mode_counter),
        "rejected_counter": dict(rejected),
        "source_file_top20": source_counter.most_common(20),
        "outputs": {
            "candidate_pool_all": str(pool_all),
            "candidate_pool_persistent": str(pool_persistent),
            "tal_stratified_candidates": str(stratified),
        },
        "semantic_boundary": "candidate_pool_sampling_not_global_prevalence",
    }

    summary_json = out_dir / "m22c_v2_tal_stratified_candidate_sampling_summary.json"
    summary_md = out_dir / "m22c_v2_tal_stratified_candidate_sampling_summary.md"
    check_txt = out_dir / "M22C_V2_TAL_STRATIFIED_CANDIDATE_SAMPLING_CHECK.txt"

    summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    md = []
    md.append("# M22C-v2 TAL-stratified Persistent Candidate Sampling")
    md.append("")
    md.append(f"- unique_candidate_count_all: `{len(all_records)}`")
    md.append(f"- unique_candidate_count_persistent: `{len(persistent_records)}`")
    md.append(f"- selected_count: `{len(selected)}`")
    md.append(f"- per_tal: `{args.per_tal}`")
    md.append("")
    md.append("## Five TAL Distribution: All Candidate Pool")
    for tal in FIVE_TALS:
        md.append(f"- {tal}: `{c_all.get(tal, 0)}`")
    md.append("")
    md.append("## Five TAL Distribution: Persistent Candidate Pool")
    for tal in FIVE_TALS:
        md.append(f"- {tal}: `{c_persistent.get(tal, 0)}`")
    md.append("")
    md.append("## Five TAL Distribution: Selected TAL-stratified Sample")
    for tal in FIVE_TALS:
        md.append(f"- {tal}: `{c_selected.get(tal, 0)}`")
    md.append("")
    md.append("## Parse Modes")
    for k, v in parse_mode_counter.most_common():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## Interpretation")
    md.append("- v2 fixes mixed VRP-key order issues: it supports both afi|tal|prefix|asn|maxLength and tal|afi|prefix|asn|maxLength.")
    md.append("- This is still candidate-level sampling, not global RPKI prevalence.")
    summary_md.write_text("\n".join(md) + "\n", encoding="utf-8")

    check_txt.write_text(
        "\n".join([
            "M22C_V2_TAL_STRATIFIED_CANDIDATE_SAMPLING=PASS",
            f"generated_at_utc = {summary['generated_at_utc']}",
            f"unique_candidate_count_all = {len(all_records)}",
            f"unique_candidate_count_persistent = {len(persistent_records)}",
            f"selected_count = {len(selected)}",
            f"per_tal = {args.per_tal}",
            f"five_tal_all_distribution = {summary['five_tal_all_distribution']}",
            f"five_tal_persistent_distribution = {summary['five_tal_persistent_distribution']}",
            f"five_tal_selected_distribution = {summary['five_tal_selected_distribution']}",
            f"candidate_pool_all = {pool_all}",
            f"candidate_pool_persistent = {pool_persistent}",
            f"tal_stratified_candidates = {stratified}",
            f"summary_json = {summary_json}",
            f"summary_md = {summary_md}",
            "semantic_boundary = candidate_pool_sampling_not_global_prevalence",
            "next_stage = RUN_SIX_DIMENSION_STATS_ON_M22C_V2_TAL_STRATIFIED_SAMPLE",
            "",
        ]),
        encoding="utf-8",
    )

    print(check_txt.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
