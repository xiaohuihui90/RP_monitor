#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone


FIVE_TALS = ["afrinic", "apnic", "arin", "lacnic", "ripe"]


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


def normalize_asn(x):
    if x is None:
        return ""
    s = str(x).strip()
    if not s:
        return ""
    if s.upper().startswith("AS"):
        return "AS" + s[2:]
    return "AS" + s


def normalize_tal(x):
    if x is None:
        return ""
    return str(x).strip().lower()


def build_vrp_key(o):
    if o.get("vrp_key"):
        return str(o["vrp_key"])

    afi = o.get("afi")
    tal = normalize_tal(o.get("tal"))
    prefix = o.get("prefix")
    asn = o.get("asn")
    maxlen = o.get("maxLength") or o.get("max_length") or o.get("maxlength")

    if afi and tal and prefix and asn is not None and maxlen is not None:
        asn_s = str(asn)
        if asn_s.upper().startswith("AS"):
            asn_s = asn_s[2:]
        return f"{afi}|{tal}|{prefix}|{asn_s}|{maxlen}"
    return ""


def is_candidate_like(o):
    key = build_vrp_key(o)
    if not key:
        return False
    # 至少要有 TAL / prefix / ASN / maxLength 可恢复
    parts = key.split("|")
    return len(parts) == 5 and parts[1] and parts[2] and parts[3] and parts[4]


def is_persistent_like(o):
    """
    当前 persistent 判断采用宽松规则：
    1. transient_or_persistent 包含 persistent；
    2. 或 global_duration_windows >= 3；
    3. 或 global_duration_seconds_approx >= 2h；
    4. 或 m18_d7b_score_reasons 里包含 persistent_divergence_candidate_v1。
    """
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


def score_record(o):
    """
    用于 TAL 内排序。优先使用 m18_d7b_score；
    若没有，则用 duration/probe/cache heuristic 近似打分。
    """
    try:
        return float(o.get("m18_d7b_score"))
    except Exception:
        pass

    score = 0.0
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
    if o.get("trailing_cache_candidate_v1") is True or str(o.get("trailing_cache_candidate_v1")).lower() == "true":
        score += 20
    if is_persistent_like(o):
        score += 50
    return score


def normalize_record(o, source_file):
    key = build_vrp_key(o)
    parts = key.split("|")
    afi, tal, prefix, asn_num, maxlen = parts if len(parts) == 5 else ("", "", "", "", "")

    out = {
        "schema": "s3.m22c.tal_stratified_candidate.v1",
        "source_file": str(source_file),
        "vrp_key": key,
        "afi": o.get("afi") or afi,
        "tal": normalize_tal(o.get("tal") or tal),
        "prefix": o.get("prefix") or prefix,
        "asn": normalize_asn(o.get("asn") or asn_num),
        "maxLength": str(o.get("maxLength") or o.get("max_length") or o.get("maxlength") or maxlen),

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
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--roots", nargs="+", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--per-tal", type=int, default=200)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_by_key = {}
    source_files = []

    for root_s in args.roots:
        root = Path(root_s)
        if not root.exists():
            continue
        for p in root.rglob("*.jsonl"):
            source_files.append(str(p))
            for o in iter_jsonl(p):
                if not isinstance(o, dict):
                    continue
                if not is_candidate_like(o):
                    continue
                rec = normalize_record(o, p)
                key = rec["vrp_key"]
                if not key:
                    continue

                # 同一个 vrp_key 多来源时保留分数最高、字段更完整的一条
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

    # 也保留所有非标准/未知 TAL，便于排查
    other_tals = sorted(set(by_tal.keys()) - set(FIVE_TALS))
    for tal in other_tals:
        rs = sorted(by_tal[tal], key=lambda x: x["m22c_score"], reverse=True)
        selected.extend(rs[:args.per_tal])

    def write_jsonl(path, rows):
        with path.open("w", encoding="utf-8") as w:
            for r in rows:
                w.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    pool_all = out_dir / "m22c_candidate_pool_all.jsonl"
    pool_persistent = out_dir / "m22c_candidate_pool_persistent.jsonl"
    stratified = out_dir / f"m22c_tal_stratified_candidates_per_tal_{args.per_tal}.jsonl"

    write_jsonl(pool_all, sorted(all_records, key=lambda x: (x["tal"], -x["m22c_score"], x["vrp_key"])))
    write_jsonl(pool_persistent, sorted(persistent_records, key=lambda x: (x["tal"], -x["m22c_score"], x["vrp_key"])))
    write_jsonl(stratified, selected)

    c_all = Counter(r["tal"] for r in all_records)
    c_persistent = Counter(r["tal"] for r in persistent_records)
    c_selected = Counter(r["tal"] for r in selected)

    summary = {
        "schema": "s3.m22c.tal_stratified_candidate_sampling_summary.v1",
        "generated_at_utc": utc_now(),
        "roots": args.roots,
        "source_file_count": len(source_files),
        "unique_candidate_count_all": len(all_records),
        "unique_candidate_count_persistent": len(persistent_records),
        "selected_count": len(selected),
        "per_tal": args.per_tal,
        "five_tal_all_distribution": {tal: c_all.get(tal, 0) for tal in FIVE_TALS},
        "five_tal_persistent_distribution": {tal: c_persistent.get(tal, 0) for tal in FIVE_TALS},
        "five_tal_selected_distribution": {tal: c_selected.get(tal, 0) for tal in FIVE_TALS},
        "all_tal_distribution_top20": c_all.most_common(20),
        "persistent_tal_distribution_top20": c_persistent.most_common(20),
        "selected_tal_distribution_top20": c_selected.most_common(20),
        "outputs": {
            "candidate_pool_all": str(pool_all),
            "candidate_pool_persistent": str(pool_persistent),
            "tal_stratified_candidates": str(stratified),
        },
        "interpretation": {
            "note": "If a TAL has zero candidates, it means no candidate satisfying the current scan/filter was found in existing data, not global absence of RPKI divergence.",
            "next_stage": "Run six-dimension stats on tal_stratified_candidates and extend M19/M21 attribution for non-RIPE/LACNIC candidates.",
        },
        "semantic_boundary": "candidate_pool_sampling_not_global_prevalence",
    }

    summary_json = out_dir / "m22c_tal_stratified_candidate_sampling_summary.json"
    summary_md = out_dir / "m22c_tal_stratified_candidate_sampling_summary.md"
    check_txt = out_dir / "M22C_TAL_STRATIFIED_CANDIDATE_SAMPLING_CHECK.txt"

    summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    md = []
    md.append("# M22C TAL-stratified Persistent Candidate Sampling")
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
    md.append("## Interpretation")
    md.append("- This is based on existing local candidate/diff/lifetime data.")
    md.append("- Zero count for a TAL means the current data and filter did not expose persistent candidates for that TAL.")
    md.append("- This does not prove global absence of divergence for that TAL.")
    md.append("- Next step is to run six-dimensional statistics and then extend M19/M21 attribution for selected candidates.")
    md.append("")
    summary_md.write_text("\n".join(md), encoding="utf-8")

    check_txt.write_text(
        "\n".join([
            "M22C_TAL_STRATIFIED_CANDIDATE_SAMPLING=PASS",
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
            "next_stage = RUN_SIX_DIMENSION_STATS_ON_TAL_STRATIFIED_SAMPLE",
            "",
        ]),
        encoding="utf-8",
    )

    print(check_txt.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
