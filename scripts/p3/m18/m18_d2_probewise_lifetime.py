#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, Counter
from typing import Any


PROBES = ["probe-cd", "probe-bj", "probe-sg"]


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


def parse_window_time(window_id: str) -> datetime | None:
    m = re.search(r"win_(\d{8}T\d{6}Z)_10m", window_id)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def normalize_asn(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    if not s:
        return ""
    if s.upper().startswith("AS"):
        return "AS" + s[2:]
    return "AS" + s


def normalize_maxlen(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip()


def get_first(d: dict[str, Any], keys: list[str], default=None):
    for k in keys:
        if k in d and d[k] not in [None, ""]:
            return d[k]
    return default


def vrp_key_from_dict(d: dict[str, Any]) -> str | None:
    """
    尽量兼容 M17 canonical / diff record 的多种字段命名。
    标准 key: tal|prefix|asn|maxLength
    """
    if not isinstance(d, dict):
        return None

    for k in ["vrp_key", "key", "canonical_key"]:
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()

    # 兼容 nested vrp
    for nk in ["vrp", "added_vrp", "removed_vrp", "before", "after", "entry"]:
        if isinstance(d.get(nk), dict):
            k = vrp_key_from_dict(d[nk])
            if k:
                return k

    tal = get_first(d, ["tal", "ta", "trust_anchor", "trustAnchor", "rir", "source_tal"], "")
    prefix = get_first(d, ["prefix", "ip_prefix", "route_prefix", "vrp_prefix"], "")
    asn = get_first(d, ["asn", "origin_asn", "origin", "originAS", "origin_as"], "")
    max_len = get_first(d, ["maxLength", "max_length", "maxlength", "maxlen", "max_len"], "")

    if prefix and asn:
        return "|".join([
            str(tal).strip(),
            str(prefix).strip(),
            normalize_asn(asn),
            normalize_maxlen(max_len),
        ])

    return None


def extract_vrp_keys_from_any(obj: Any) -> set[str]:
    """
    从 diff record 中递归提取可能的 VRP key。
    支持:
      - flat record
      - added_vrp / removed_vrp
      - added_vrps / removed_vrps / changed_vrps list
      - before / after
    """
    keys: set[str] = set()

    if isinstance(obj, dict):
        k = vrp_key_from_dict(obj)
        if k:
            keys.add(k)

        for name in [
            "vrp", "added_vrp", "removed_vrp", "changed_vrp",
            "before", "after", "old", "new",
            "added_vrps", "removed_vrps", "changed_vrps",
            "items", "records", "diffs",
        ]:
            if name in obj:
                keys |= extract_vrp_keys_from_any(obj[name])

    elif isinstance(obj, list):
        for x in obj:
            keys |= extract_vrp_keys_from_any(x)

    return keys


def split_vrp_key(key: str) -> dict[str, str]:
    parts = key.split("|")
    if len(parts) >= 4:
        return {
            "tal": parts[0],
            "prefix": parts[1],
            "asn": parts[2],
            "maxLength": parts[3],
        }
    return {
        "tal": "",
        "prefix": key,
        "asn": "",
        "maxLength": "",
    }


def infer_probe_id_from_path(path: Path) -> str:
    name = path.name
    for p in PROBES:
        if p in name:
            return p
    m = re.search(r"(probe-[a-z]+)", str(path))
    return m.group(1) if m else "unknown_probe"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inventory-json", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--m17-root", default="data/p3_collector/m17_vrp_entry_diff/history")
    args = ap.parse_args()

    inventory_path = Path(args.inventory_json)
    out_dir = Path(args.out_dir)
    m17_root = Path(args.m17_root)

    out_dir.mkdir(parents=True, exist_ok=True)

    inv = read_json(inventory_path, {})
    if not isinstance(inv, dict):
        raise SystemExit(f"inventory_json_not_object: {inventory_path}")

    windows = []
    for r in inv.get("records", []):
        if not isinstance(r, dict):
            continue
        if r.get("m18_d2_probewise_lifetime_ready") is True:
            wid = r.get("window_id")
            if isinstance(wid, str):
                windows.append(wid)

    windows = sorted(set(windows), key=lambda w: parse_window_time(w) or datetime.min.replace(tzinfo=timezone.utc))

    # Step 1: 读取每个窗口的 diff keys
    window_diff_keys: dict[str, set[str]] = {}
    all_diff_keys: set[str] = set()
    diff_record_count_by_window: dict[str, int] = {}

    for wid in windows:
        m17_out = m17_root / f"m17_window_{wid}" / "outputs"
        diff_path = m17_out / "vrp_entry_diff_records.jsonl"

        keys: set[str] = set()
        n = 0
        for rec in iter_jsonl(diff_path):
            if isinstance(rec, dict) and rec.get("_parse_error"):
                continue
            n += 1
            keys |= extract_vrp_keys_from_any(rec)

        window_diff_keys[wid] = keys
        all_diff_keys |= keys
        diff_record_count_by_window[wid] = n

    # Step 2: 基于 canonical_vrp_records_probe-*.jsonl 判断每个 diff key 在各 probe 的出现窗口
    presence: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    canonical_scanned_records = 0
    canonical_matched_records = 0
    canonical_file_count = 0

    for wid in windows:
        m17_out = m17_root / f"m17_window_{wid}" / "outputs"
        canonical_files = sorted(m17_out.glob("canonical_vrp_records_probe-*.jsonl"))

        # 当前窗口只关心全局 diff key；如果全局为空，则退化为本窗口 diff key。
        target_keys = all_diff_keys or window_diff_keys.get(wid, set())

        for path in canonical_files:
            canonical_file_count += 1
            probe_id = infer_probe_id_from_path(path)

            for rec in iter_jsonl(path):
                if isinstance(rec, dict) and rec.get("_parse_error"):
                    continue

                canonical_scanned_records += 1
                k = vrp_key_from_dict(rec)
                if not k:
                    continue

                if k in target_keys:
                    presence[k][probe_id].add(wid)
                    canonical_matched_records += 1

    # Step 3: 输出 probe-wise lifetime records
    records_path = out_dir / "m18_probewise_lifetime_records.jsonl"
    summary_path = out_dir / "m18_probewise_lifetime_summary.json"
    check_path = out_dir / "M18_D2_PROBEWISE_LIFETIME_CHECK.txt"

    counters = Counter()
    records_written = 0

    with records_path.open("w", encoding="utf-8") as f:
        for key in sorted(all_diff_keys):
            key_parts = split_vrp_key(key)

            first_seen_by_probe = {}
            last_seen_by_probe = {}
            duration_by_probe = {}
            observed_windows_by_probe = {}
            missing_probe_set = []
            seen_probe_set = []

            all_seen_windows = set()

            for probe in PROBES:
                wins = sorted(
                    presence.get(key, {}).get(probe, set()),
                    key=lambda w: parse_window_time(w) or datetime.min.replace(tzinfo=timezone.utc),
                )
                if wins:
                    seen_probe_set.append(probe)
                    all_seen_windows.update(wins)

                    first_seen_by_probe[probe] = wins[0]
                    last_seen_by_probe[probe] = wins[-1]
                    duration_by_probe[probe] = {
                        "duration_windows": len(wins),
                        "first_seen_utc": parse_window_time(wins[0]).isoformat().replace("+00:00", "Z") if parse_window_time(wins[0]) else None,
                        "last_seen_utc": parse_window_time(wins[-1]).isoformat().replace("+00:00", "Z") if parse_window_time(wins[-1]) else None,
                    }
                    observed_windows_by_probe[probe] = wins
                else:
                    missing_probe_set.append(probe)

            all_seen_windows_sorted = sorted(
                all_seen_windows,
                key=lambda w: parse_window_time(w) or datetime.min.replace(tzinfo=timezone.utc),
            )

            global_first = all_seen_windows_sorted[0] if all_seen_windows_sorted else None
            global_last = all_seen_windows_sorted[-1] if all_seen_windows_sorted else None

            global_first_dt = parse_window_time(global_first) if global_first else None
            global_last_dt = parse_window_time(global_last) if global_last else None
            duration_seconds = None
            if global_first_dt and global_last_dt:
                # 同窗口出现也记为一个 10m observation window 的近似持续时间
                duration_seconds = int((global_last_dt - global_first_dt).total_seconds()) + 600

            record = {
                "schema": "s3.m18.probewise_lifetime.v1",
                "vrp_key": key,
                **key_parts,

                "seen_probe_set": seen_probe_set,
                "missing_probe_set": missing_probe_set,
                "probe_seen_count": len(seen_probe_set),

                "first_seen_by_probe": first_seen_by_probe,
                "last_seen_by_probe": last_seen_by_probe,
                "duration_by_probe": duration_by_probe,
                "observed_windows_by_probe": observed_windows_by_probe,

                "global_first_seen_window": global_first,
                "global_last_seen_window": global_last,
                "global_duration_windows": len(all_seen_windows_sorted),
                "global_duration_seconds_approx": duration_seconds,

                "window_scope_count": len(windows),
                "selected_window_scope": windows,

                "ready_for_probe_pair_lag": len(seen_probe_set) >= 2,
                "ready_for_trailing_cache_v1": True,

                "semantic_boundary": "lifetime_level_observation_not_causal_attribution",
            }

            if len(seen_probe_set) >= 2:
                counters["ready_for_probe_pair_lag"] += 1
            if len(seen_probe_set) == 1:
                counters["single_probe_only"] += 1
            if len(seen_probe_set) == 0:
                counters["not_seen_in_canonical"] += 1

            counters[f"probe_seen_count_{len(seen_probe_set)}"] += 1

            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            records_written += 1

    summary = {
        "schema": "s3.m18.probewise_lifetime.summary.v1",
        "generated_at_utc": utc_now(),
        "inventory_json": str(inventory_path),
        "m17_root": str(m17_root),
        "out_dir": str(out_dir),
        "selected_window_count": len(windows),
        "selected_windows": windows,
        "diff_key_count": len(all_diff_keys),
        "records_written": records_written,
        "diff_record_count_by_window": diff_record_count_by_window,
        "canonical_file_count": canonical_file_count,
        "canonical_scanned_records": canonical_scanned_records,
        "canonical_matched_records": canonical_matched_records,
        "counters": dict(counters),
        "outputs": {
            "records_jsonl": str(records_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "lifetime_level_observation_not_causal_attribution",
        "next_stage": "M18_D3_PROBE_PAIR_LAG",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M18_D2_PROBEWISE_LIFETIME=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"inventory_json = {inventory_path}",
        f"selected_window_count = {len(windows)}",
        f"diff_key_count = {len(all_diff_keys)}",
        f"records_written = {records_written}",
        f"canonical_file_count = {canonical_file_count}",
        f"canonical_scanned_records = {canonical_scanned_records}",
        f"canonical_matched_records = {canonical_matched_records}",
        f"ready_for_probe_pair_lag = {counters['ready_for_probe_pair_lag']}",
        f"single_probe_only = {counters['single_probe_only']}",
        f"not_seen_in_canonical = {counters['not_seen_in_canonical']}",
        f"records_jsonl = {records_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = lifetime_level_observation_not_causal_attribution",
        "next_stage = M18_D3_PROBE_PAIR_LAG",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # state env
    state = Path("data/p3_collector/m18_deep_analysis/state/current_m18_d2_run.env")
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(
        "\n".join([
            f'export M18_D2_OUT_DIR="{out_dir}"',
            f'export M18_D2_RECORDS="{records_path}"',
            f'export M18_D2_SUMMARY="{summary_path}"',
            f'export M18_D2_CHECK="{check_path}"',
            "",
        ]),
        encoding="utf-8",
    )

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()

from scripts.p3.m18.hooks.m18_impact_hook import compute_impact

def attach_control_plane_impact(records):

    impacted = []

    for r in records:

        imp = compute_impact(r)

        r["control_plane_impact"] = imp["impact"]
        r["impact_score"] = imp["score"]

        impacted.append(r)

    return impacted

