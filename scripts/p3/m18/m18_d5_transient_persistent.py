#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path, default=None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return default


def iter_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                yield {
                    "_parse_error": True,
                    "_line_no": line_no,
                    "_raw": line[:300],
                }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trailing-cache-json", required=True)
    ap.add_argument("--lifetime-json", required=True)
    ap.add_argument("--pair-lag-json", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    trailing_path = Path(args.trailing_cache_json)
    lifetime_path = Path(args.lifetime_json)
    pair_lag_path = Path(args.pair_lag_json)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    records_path = out_dir / "m18_transient_persistent_records.jsonl"
    summary_path = out_dir / "m18_transient_persistent_summary.json"
    check_path = out_dir / "M18_D5_TRANSIENT_PERSISTENT_CHECK.txt"

    # 1. 先聚合 probe-pair lag，避免把 152MB 全量放入内存。
    lag_by_key: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "pair_record_count": 0,
        "max_abs_first_seen_lag_sec": 0,
        "max_abs_last_seen_lag_sec": 0,
        "first_seen_lag_values": [],
        "last_seen_lag_values": [],
        "pair_names": set(),
    })

    pair_lag_record_count = 0
    for r in iter_jsonl(pair_lag_path):
        if not isinstance(r, dict) or r.get("_parse_error"):
            continue

        key = r.get("vrp_key")
        if not key:
            continue

        pair_lag_record_count += 1
        item = lag_by_key[key]
        item["pair_record_count"] += 1

        pair = r.get("probe_pair")
        if pair:
            item["pair_names"].add(pair)

        first_lag = r.get("first_seen_lag_sec_left_minus_right")
        last_lag = r.get("last_seen_lag_sec_left_minus_right")

        if isinstance(first_lag, int):
            item["first_seen_lag_values"].append(first_lag)
            item["max_abs_first_seen_lag_sec"] = max(item["max_abs_first_seen_lag_sec"], abs(first_lag))

        if isinstance(last_lag, int):
            item["last_seen_lag_values"].append(last_lag)
            item["max_abs_last_seen_lag_sec"] = max(item["max_abs_last_seen_lag_sec"], abs(last_lag))

    # 2. trailing cache 当前只读取 summary，注意 D4 目前是 v1 字段预留，不能当确认原因。
    trailing_summary = read_json(trailing_path, {})
    trailing_v1_summary = trailing_summary.get("trailing_v1_summary", {}) if isinstance(trailing_summary, dict) else {}

    counters = Counter()
    records_written = 0

    with records_path.open("w", encoding="utf-8") as out:
        for r in iter_jsonl(lifetime_path):
            if not isinstance(r, dict) or r.get("_parse_error"):
                continue

            key = r.get("vrp_key")
            if not key:
                continue

            counters["input_lifetime_records"] += 1

            probe_seen_count = int(r.get("probe_seen_count") or 0)
            global_duration_windows = int(r.get("global_duration_windows") or 0)
            global_duration_seconds = r.get("global_duration_seconds_approx")

            lag = lag_by_key.get(key, {})
            max_abs_first_lag = int(lag.get("max_abs_first_seen_lag_sec") or 0)
            max_abs_last_lag = int(lag.get("max_abs_last_seen_lag_sec") or 0)
            pair_record_count = int(lag.get("pair_record_count") or 0)
            pair_names = sorted(lag.get("pair_names") or [])

            # 当前 D4 只是字段预留；这里保守标成 weak heuristic。
            trailing_cache_candidate_v1 = bool(
                key in trailing_v1_summary
                and probe_seen_count >= 1
                and (
                    global_duration_windows >= 2
                    or max_abs_last_lag >= 600
                )
            )

            # 动态 transient / persistent v1 规则：
            # - 未在 canonical 看到：not_observed_in_canonical，不能直接说 transient 或 persistent。
            # - 单 probe：single_probe_only_candidate，需要后续确认是否采样/解析/真实差异。
            # - 1~2 个窗口：transient_candidate。
            # - >=3 个窗口或 first_seen lag 很大：persistent_candidate_v1。
            if probe_seen_count == 0:
                classification = "not_observed_in_canonical"
                priority = "low"
                reasons = ["diff_key_not_seen_in_any_probe_canonical"]
            elif probe_seen_count == 1:
                classification = "single_probe_only_candidate"
                priority = "normal"
                reasons = ["diff_key_seen_in_single_probe_only"]
            elif global_duration_windows <= 2 and max_abs_first_lag < 7200:
                classification = "transient_temporal_skew_candidate"
                priority = "low"
                reasons = ["short_lifetime", "small_or_moderate_first_seen_lag"]
            elif global_duration_windows >= 3:
                classification = "persistent_divergence_candidate_v1"
                priority = "high"
                reasons = ["duration_windows_ge_3"]
            elif max_abs_first_lag >= 7200:
                classification = "persistent_or_large_lag_candidate_v1"
                priority = "high"
                reasons = ["large_probe_pair_first_seen_lag_ge_2h"]
            else:
                classification = "normal_priority_temporal_candidate"
                priority = "normal"
                reasons = ["default_candidate"]

            if trailing_cache_candidate_v1 and priority == "low":
                priority = "normal"
                reasons.append("trailing_cache_candidate_v1_heuristic")

            record = {
                "schema": "s3.m18.dynamic_transient_persistent.v1",
                "vrp_key": key,
                "tal": r.get("tal"),
                "prefix": r.get("prefix"),
                "asn": r.get("asn"),
                "maxLength": r.get("maxLength"),

                "probe_seen_count": probe_seen_count,
                "seen_probe_set": r.get("seen_probe_set"),
                "missing_probe_set": r.get("missing_probe_set"),

                "global_duration_windows": global_duration_windows,
                "global_duration_seconds_approx": global_duration_seconds,

                "probe_pair_lag": {
                    "pair_record_count": pair_record_count,
                    "pair_names": pair_names,
                    "max_abs_first_seen_lag_sec": max_abs_first_lag,
                    "max_abs_last_seen_lag_sec": max_abs_last_lag,
                },

                "trailing_cache_candidate_v1": trailing_cache_candidate_v1,
                "trailing_cache_supported": False,
                "trailing_cache_confirmed": False,
                "missing_evidence_for_supported_or_confirmed": [
                    "jsonext_source_uri",
                    "repository_metrics",
                    "cache_index",
                    "same_input_replay",
                ],

                "transient_or_persistent": classification,
                "m19_mapping_priority": priority,
                "m19_mapping_reason": reasons,

                "semantic_boundary": "candidate_classification_not_causal_attribution",
            }

            counters[f"classification_{classification}"] += 1
            counters[f"m19_priority_{priority}"] += 1
            if trailing_cache_candidate_v1:
                counters["trailing_cache_candidate_v1"] += 1

            out.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            records_written += 1

    summary = {
        "schema": "s3.m18.dynamic_transient_persistent.summary.v1",
        "generated_at_utc": utc_now(),
        "lifetime_json": str(lifetime_path),
        "pair_lag_json": str(pair_lag_path),
        "trailing_cache_json": str(trailing_path),
        "records_written": records_written,
        "pair_lag_record_count": pair_lag_record_count,
        "counters": dict(counters),
        "outputs": {
            "records_jsonl": str(records_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "candidate_classification_not_causal_attribution",
        "strong_causal_claim_allowed": False,
        "next_stage": "M18_D6_SUMMARY",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M18_D5_TRANSIENT_PERSISTENT=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"records_written = {records_written}",
        f"pair_lag_record_count = {pair_lag_record_count}",
        f"classification_not_observed_in_canonical = {counters['classification_not_observed_in_canonical']}",
        f"classification_single_probe_only_candidate = {counters['classification_single_probe_only_candidate']}",
        f"classification_transient_temporal_skew_candidate = {counters['classification_transient_temporal_skew_candidate']}",
        f"classification_persistent_divergence_candidate_v1 = {counters['classification_persistent_divergence_candidate_v1']}",
        f"classification_persistent_or_large_lag_candidate_v1 = {counters['classification_persistent_or_large_lag_candidate_v1']}",
        f"trailing_cache_candidate_v1 = {counters['trailing_cache_candidate_v1']}",
        f"m19_priority_high = {counters['m19_priority_high']}",
        f"m19_priority_normal = {counters['m19_priority_normal']}",
        f"m19_priority_low = {counters['m19_priority_low']}",
        f"records_jsonl = {records_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = candidate_classification_not_causal_attribution",
        "strong_causal_claim_allowed = False",
        "next_stage = M18_D6_SUMMARY",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state = Path("data/p3_collector/m18_deep_analysis/state/current_m18_d5_run.env")
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(
        "\n".join([
            f'export M18_D5_OUT_DIR="{out_dir}"',
            f'export M18_D5_RECORDS="{records_path}"',
            f'export M18_D5_SUMMARY="{summary_path}"',
            f'export M18_D5_CHECK="{check_path}"',
            "",
        ]),
        encoding="utf-8",
    )

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
