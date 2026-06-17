#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                yield {"_parse_error": True, "_line_no": line_no, "_raw": line[:300]}


def normalize_asn(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    if not s:
        return ""
    if s.upper().startswith("AS"):
        return "AS" + s[2:]
    return "AS" + s


def parse_vrp_key(vrp_key: str) -> dict[str, str]:
    """
    支持两种 key：
    1) afi|tal|prefix|asn|maxLength
       例如 ipv6|ripe|2a14:e603::/32|199152|32
    2) tal|prefix|asn|maxLength
       旧格式兼容。
    """
    parts = str(vrp_key or "").split("|")

    if len(parts) >= 5:
        afi, tal, prefix, asn, maxlen = parts[:5]
        return {
            "afi": afi,
            "tal": tal,
            "prefix": prefix,
            "asn": normalize_asn(asn),
            "maxLength": maxlen,
        }

    if len(parts) == 4:
        tal, prefix, asn, maxlen = parts
        afi = "ipv6" if ":" in prefix else "ipv4"
        return {
            "afi": afi,
            "tal": tal,
            "prefix": prefix,
            "asn": normalize_asn(asn),
            "maxLength": maxlen,
        }

    return {
        "afi": "",
        "tal": "",
        "prefix": "",
        "asn": "",
        "maxLength": "",
    }


def safe_int(v: Any, default: int = 0) -> int:
    try:
        if v is None:
            return default
        return int(v)
    except Exception:
        return default


def score_candidate(r: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    cls = str(r.get("transient_or_persistent") or "")
    probe_seen_count = safe_int(r.get("probe_seen_count"), 0)
    duration_windows = safe_int(r.get("global_duration_windows"), 0)
    duration_sec = safe_int(r.get("global_duration_seconds_approx"), 0)
    trailing_v1 = bool(r.get("trailing_cache_candidate_v1"))

    if cls == "persistent_divergence_candidate_v1":
        score += 80
        reasons.append("persistent_divergence_candidate_v1")
    elif cls == "persistent_or_large_lag_candidate_v1":
        score += 70
        reasons.append("persistent_or_large_lag_candidate_v1")
    elif cls == "single_probe_only_candidate":
        score += 20
        reasons.append("single_probe_only_candidate")
    elif cls == "transient_temporal_skew_candidate":
        score += 5
        reasons.append("transient_temporal_skew_candidate")
    elif cls == "not_observed_in_canonical":
        score -= 40
        reasons.append("not_observed_in_canonical_penalty")

    if probe_seen_count >= 3:
        score += 25
        reasons.append("seen_in_three_probes")
    elif probe_seen_count == 2:
        score += 15
        reasons.append("seen_in_two_probes")
    elif probe_seen_count == 1:
        score -= 5
        reasons.append("seen_in_one_probe_only")
    else:
        score -= 30
        reasons.append("not_seen_in_probe_canonical")

    if duration_windows > 0:
        bonus = min(duration_windows * 6, 50)
        score += bonus
        reasons.append(f"duration_windows_bonus_{bonus}")

    if duration_sec >= 7200:
        score += 10
        reasons.append("duration_seconds_ge_2h")

    if trailing_v1:
        score += 8
        reasons.append("trailing_cache_candidate_v1_heuristic")

    return score, reasons


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--high-priority-jsonl", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--top-n", type=int, default=1000)
    ap.add_argument("--top-small-n", type=int, default=200)
    ap.add_argument("--per-af-tal-cap", type=int, default=500)
    ap.add_argument("--per-asn-cap", type=int, default=30)
    args = ap.parse_args()

    in_path = Path(args.high_priority_jsonl)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    scored = []
    counters = Counter()
    input_by_af_tal = Counter()
    input_by_tal = Counter()
    input_by_asn = Counter()
    input_by_class = Counter()

    for r in iter_jsonl(in_path):
        if not isinstance(r, dict) or r.get("_parse_error"):
            counters["parse_error_or_invalid"] += 1
            continue

        counters["input_records"] += 1

        key = r.get("vrp_key", "")
        fixed = parse_vrp_key(key)

        score, reasons = score_candidate(r)

        r2 = dict(r)
        r2.update(fixed)
        r2["m18_d7b_score"] = score
        r2["m18_d7b_score_reasons"] = reasons
        r2["m18_d7b_field_fix"] = "parsed_from_vrp_key"
        r2["m18_d7b_selection_scope"] = "candidate_level_not_causal_attribution"

        scored.append(r2)

        af_tal = f"{fixed['afi']}|{fixed['tal']}"
        input_by_af_tal[af_tal] += 1
        input_by_tal[fixed["tal"] or "unknown"] += 1
        input_by_asn[fixed["asn"] or "unknown"] += 1
        input_by_class[str(r.get("transient_or_persistent") or "unknown")] += 1

    scored.sort(
        key=lambda x: (
            safe_int(x.get("m18_d7b_score")),
            safe_int(x.get("global_duration_windows")),
            safe_int(x.get("probe_seen_count")),
            str(x.get("vrp_key") or ""),
        ),
        reverse=True,
    )

    selected = []
    selected_keys = set()
    af_tal_used = Counter()
    asn_used = Counter()

    for r in scored:
        if len(selected) >= args.top_n:
            break

        key = r.get("vrp_key")
        af_tal = f"{r.get('afi') or 'unknown'}|{r.get('tal') or 'unknown'}"
        asn = str(r.get("asn") or "unknown")

        if key in selected_keys:
            continue
        if af_tal_used[af_tal] >= args.per_af_tal_cap:
            continue
        if asn_used[asn] >= args.per_asn_cap:
            continue

        selected.append(r)
        selected_keys.add(key)
        af_tal_used[af_tal] += 1
        asn_used[asn] += 1

    for r in scored:
        if len(selected) >= args.top_n:
            break
        key = r.get("vrp_key")
        if key in selected_keys:
            continue
        selected.append(r)
        selected_keys.add(key)

    top_n = selected[:args.top_n]
    top_small = selected[:args.top_small_n]

    topn_path = out_dir / f"M18_to_M19_seed_candidates_fixed_top{args.top_n}.jsonl"
    top_small_path = out_dir / f"M18_to_M19_seed_candidates_fixed_top{args.top_small_n}.jsonl"
    summary_path = out_dir / "M18_to_M19_seed_candidates_fixed_summary.json"
    check_path = out_dir / "M18_D7B_M19_CANDIDATE_THINNING_FIXED_CHECK.txt"

    with topn_path.open("w", encoding="utf-8") as f:
        for r in top_n:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    with top_small_path.open("w", encoding="utf-8") as f:
        for r in top_small:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    selected_by_af_tal = Counter(f"{r.get('afi') or 'unknown'}|{r.get('tal') or 'unknown'}" for r in top_n)
    selected_by_tal = Counter(str(r.get("tal") or "unknown") for r in top_n)
    selected_by_asn = Counter(str(r.get("asn") or "unknown") for r in top_n)
    selected_by_class = Counter(str(r.get("transient_or_persistent") or "unknown") for r in top_n)

    summary = {
        "schema": "s3.m18.d7b.m19_candidate_thinning_fixed_fields.summary.v1",
        "generated_at_utc": utc_now(),
        "input_high_priority_jsonl": str(in_path),
        "input_records": counters["input_records"],
        "selected_top_n_count": len(top_n),
        "selected_top_small_count": len(top_small),
        "top_n": args.top_n,
        "top_small_n": args.top_small_n,
        "per_af_tal_cap": args.per_af_tal_cap,
        "per_asn_cap": args.per_asn_cap,
        "score_range": {
            "max": top_n[0].get("m18_d7b_score") if top_n else None,
            "min": top_n[-1].get("m18_d7b_score") if top_n else None,
        },
        "input_by_af_tal_top20": input_by_af_tal.most_common(20),
        "input_by_tal_top20": input_by_tal.most_common(20),
        "input_by_asn_top20": input_by_asn.most_common(20),
        "input_by_class": dict(input_by_class),
        "selected_by_af_tal_top20": selected_by_af_tal.most_common(20),
        "selected_by_tal_top20": selected_by_tal.most_common(20),
        "selected_by_asn_top20": selected_by_asn.most_common(20),
        "selected_by_class": dict(selected_by_class),
        "outputs": {
            "top_n_jsonl": str(topn_path),
            "top_small_jsonl": str(top_small_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "candidate_thinning_not_causal_attribution",
        "strong_causal_claim_allowed": False,
        "next_stage": "M19_ROA_TO_VRP_MAPPING_PRECHECK",
    }

    write_json(summary_path, summary)

    lines = [
        "M18_D7B_M19_CANDIDATE_THINNING_FIXED=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"input_records = {summary['input_records']}",
        f"selected_top_n_count = {summary['selected_top_n_count']}",
        f"selected_top_small_count = {summary['selected_top_small_count']}",
        f"score_max = {summary['score_range']['max']}",
        f"score_min = {summary['score_range']['min']}",
        f"selected_by_af_tal_top20 = {summary['selected_by_af_tal_top20']}",
        f"selected_by_tal_top20 = {summary['selected_by_tal_top20']}",
        f"selected_by_asn_top20 = {summary['selected_by_asn_top20']}",
        f"top_n_jsonl = {topn_path}",
        f"top_small_jsonl = {top_small_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = candidate_thinning_not_causal_attribution",
        "strong_causal_claim_allowed = False",
        "next_stage = M19_ROA_TO_VRP_MAPPING_PRECHECK",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state = Path("data/p3_collector/m18_deep_analysis/state/current_m18_d7b_run.env")
    state.write_text(
        "\n".join([
            f'export M18_D7B_OUT_DIR="{out_dir}"',
            f'export M18_D7B_CHECK="{check_path}"',
            f'export M18_D7B_SUMMARY="{summary_path}"',
            f'export M18_D7B_TOPN="{topn_path}"',
            f'export M18_D7B_TOP_SMALL="{top_small_path}"',
            "",
        ]),
        encoding="utf-8",
    )

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
