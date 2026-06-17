#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
from statistics import mean, median
from typing import Any


PROBES = ["probe-cd", "probe-bj", "probe-sg"]
PROBE_PAIRS = [
    ("probe-cd", "probe-bj"),
    ("probe-cd", "probe-sg"),
    ("probe-bj", "probe-sg"),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_window_time(window_id: str | None) -> datetime | None:
    if not window_id:
        return None
    m = re.search(r"win_(\d{8}T\d{6}Z)_10m", window_id)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


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


def safe_int_seconds(a: str | None, b: str | None) -> int | None:
    da = parse_window_time(a)
    db = parse_window_time(b)
    if not da or not db:
        return None
    return int((da - db).total_seconds())


def summarize_numbers(values: list[int]) -> dict[str, Any]:
    if not values:
        return {
            "count": 0,
            "min": None,
            "max": None,
            "mean": None,
            "median": None,
            "abs_mean": None,
            "abs_median": None,
        }

    abs_values = [abs(x) for x in values]
    return {
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "mean": mean(values),
        "median": median(values),
        "abs_mean": mean(abs_values),
        "abs_median": median(abs_values),
    }


def lag_direction(lag_sec: int | None, left: str, right: str) -> str:
    if lag_sec is None:
        return "unknown"
    if lag_sec == 0:
        return "aligned"
    if lag_sec > 0:
        return f"{left}_later_than_{right}"
    return f"{left}_earlier_than_{right}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lifetime-json", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    lifetime_path = Path(args.lifetime_json)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    records_path = out_dir / "m18_probe_pair_lag_records.jsonl"
    summary_path = out_dir / "m18_probe_pair_lag_summary.json"
    check_path = out_dir / "M18_D3_PROBE_PAIR_LAG_CHECK.txt"

    counters = Counter()
    pair_first_lags: dict[str, list[int]] = defaultdict(list)
    pair_last_lags: dict[str, list[int]] = defaultdict(list)
    pair_duration_delta_windows: dict[str, list[int]] = defaultdict(list)
    pair_direction_counts: dict[str, Counter] = defaultdict(Counter)

    records_written = 0

    with records_path.open("w", encoding="utf-8") as out:
        for rec in iter_jsonl(lifetime_path):
            if not isinstance(rec, dict) or rec.get("_parse_error"):
                continue

            counters["input_records"] += 1

            vrp_key = rec.get("vrp_key")
            first_seen = rec.get("first_seen_by_probe") or {}
            last_seen = rec.get("last_seen_by_probe") or {}
            duration_by_probe = rec.get("duration_by_probe") or {}
            seen_probe_set = set(rec.get("seen_probe_set") or [])

            if len(seen_probe_set) < 2:
                counters["skip_seen_probe_lt_2"] += 1
                continue

            for left, right in PROBE_PAIRS:
                if left not in seen_probe_set or right not in seen_probe_set:
                    counters[f"skip_pair_missing_{left}_vs_{right}"] += 1
                    continue

                left_first = first_seen.get(left)
                right_first = first_seen.get(right)
                left_last = last_seen.get(left)
                right_last = last_seen.get(right)

                first_lag_sec = safe_int_seconds(left_first, right_first)
                last_lag_sec = safe_int_seconds(left_last, right_last)

                left_dur = duration_by_probe.get(left, {})
                right_dur = duration_by_probe.get(right, {})
                left_dur_win = left_dur.get("duration_windows")
                right_dur_win = right_dur.get("duration_windows")

                duration_delta_windows = None
                if isinstance(left_dur_win, int) and isinstance(right_dur_win, int):
                    duration_delta_windows = left_dur_win - right_dur_win

                pair_name = f"{left}_vs_{right}"

                if first_lag_sec is not None:
                    pair_first_lags[pair_name].append(first_lag_sec)
                    pair_direction_counts[pair_name][lag_direction(first_lag_sec, left, right)] += 1

                if last_lag_sec is not None:
                    pair_last_lags[pair_name].append(last_lag_sec)

                if duration_delta_windows is not None:
                    pair_duration_delta_windows[pair_name].append(duration_delta_windows)

                lag_record = {
                    "schema": "s3.m18.probe_pair_lag.v1",
                    "vrp_key": vrp_key,
                    "tal": rec.get("tal"),
                    "prefix": rec.get("prefix"),
                    "asn": rec.get("asn"),
                    "maxLength": rec.get("maxLength"),

                    "probe_pair": pair_name,
                    "left_probe": left,
                    "right_probe": right,

                    "left_first_seen_window": left_first,
                    "right_first_seen_window": right_first,
                    "first_seen_lag_sec_left_minus_right": first_lag_sec,
                    "first_seen_lag_direction": lag_direction(first_lag_sec, left, right),

                    "left_last_seen_window": left_last,
                    "right_last_seen_window": right_last,
                    "last_seen_lag_sec_left_minus_right": last_lag_sec,
                    "last_seen_lag_direction": lag_direction(last_lag_sec, left, right),

                    "left_duration_windows": left_dur_win,
                    "right_duration_windows": right_dur_win,
                    "duration_delta_windows_left_minus_right": duration_delta_windows,

                    "global_duration_windows": rec.get("global_duration_windows"),
                    "global_duration_seconds_approx": rec.get("global_duration_seconds_approx"),

                    "semantic_boundary": "probe_pair_lag_observation_not_causal_attribution",
                }

                out.write(json.dumps(lag_record, ensure_ascii=False, sort_keys=True) + "\n")
                records_written += 1
                counters["records_written"] += 1
                counters[f"pair_records_{pair_name}"] += 1

    pair_summaries = {}

    for pair_name in [f"{a}_vs_{b}" for a, b in PROBE_PAIRS]:
        pair_summaries[pair_name] = {
            "first_seen_lag_sec": summarize_numbers(pair_first_lags[pair_name]),
            "last_seen_lag_sec": summarize_numbers(pair_last_lags[pair_name]),
            "duration_delta_windows_left_minus_right": summarize_numbers(pair_duration_delta_windows[pair_name]),
            "first_seen_direction_counts": dict(pair_direction_counts[pair_name]),
        }

    summary = {
        "schema": "s3.m18.probe_pair_lag.summary.v1",
        "generated_at_utc": utc_now(),
        "lifetime_json": str(lifetime_path),
        "out_dir": str(out_dir),
        "records_written": records_written,
        "counters": dict(counters),
        "pair_summaries": pair_summaries,
        "outputs": {
            "records_jsonl": str(records_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "probe_pair_lag_observation_not_causal_attribution",
        "next_stage": "M18_D4_TRAILING_CACHE_LAYER",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M18_D3_PROBE_PAIR_LAG=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"lifetime_json = {lifetime_path}",
        f"records_written = {records_written}",
        f"input_records = {counters['input_records']}",
        f"skip_seen_probe_lt_2 = {counters['skip_seen_probe_lt_2']}",
    ]

    for pair_name in [f"{a}_vs_{b}" for a, b in PROBE_PAIRS]:
        ps = pair_summaries[pair_name]
        lines.append(f"{pair_name}_record_count = {counters[f'pair_records_{pair_name}']}")
        lines.append(f"{pair_name}_first_lag_abs_mean_sec = {ps['first_seen_lag_sec']['abs_mean']}")
        lines.append(f"{pair_name}_first_lag_abs_median_sec = {ps['first_seen_lag_sec']['abs_median']}")
        lines.append(f"{pair_name}_first_seen_direction_counts = {ps['first_seen_direction_counts']}")

    lines += [
        f"records_jsonl = {records_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = probe_pair_lag_observation_not_causal_attribution",
        "next_stage = M18_D4_TRAILING_CACHE_LAYER",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state = Path("data/p3_collector/m18_deep_analysis/state/current_m18_d3_run.env")
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(
        "\n".join([
            f'export M18_D3_OUT_DIR="{out_dir}"',
            f'export M18_D3_RECORDS="{records_path}"',
            f'export M18_D3_SUMMARY="{summary_path}"',
            f'export M18_D3_CHECK="{check_path}"',
            "",
        ]),
        encoding="utf-8",
    )

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
