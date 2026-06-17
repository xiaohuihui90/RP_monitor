#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def file_nonempty(path: Path) -> bool:
    return path.exists() and path.is_file() and path.stat().st_size > 0


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def iter_jsonl(path: Path):
    if not file_nonempty(path):
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def write_jsonl(path: Path, rows) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    return n


def parse_status(path: Path, key: str) -> str:
    txt = read_text(path)
    m = re.search(rf"^{re.escape(key)}=(\S+)", txt, re.M)
    return m.group(1) if m else "UNKNOWN"


def parse_kv(path: Path) -> dict[str, str]:
    out = {}
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def latest_pass_m18_run(m18_root: Path) -> Path | None:
    runs = []
    for p in sorted(m18_root.glob("history/*/checks/M18_ACCEPTANCE.txt")):
        if parse_status(p, "M18_ACCEPTANCE") == "PASS":
            runs.append(p.parent.parent)
    return runs[-1] if runs else None


def flatten_keys(obj: Any, prefix: str = "", max_depth: int = 5) -> set[str]:
    if max_depth < 0:
        return set()
    out = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            kk = str(k)
            full = f"{prefix}.{kk}" if prefix else kk
            out.add(full)
            out |= flatten_keys(v, full, max_depth - 1)
    elif isinstance(obj, list):
        for x in obj[:10]:
            out |= flatten_keys(x, prefix, max_depth - 1)
    return out


def get_nested(obj: Any, keys: list[str], default=None):
    for key in keys:
        cur = obj
        ok = True
        for part in key.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok:
            return cur
    return default


def as_int(x: Any, default: int = 0) -> int:
    try:
        if x is None:
            return default
        return int(float(str(x)))
    except Exception:
        return default


def as_bool(x: Any) -> bool:
    if isinstance(x, bool):
        return x
    if x is None:
        return False
    return str(x).strip().lower() in {"1", "true", "yes", "y", "pass"}


def canonical_vrp_key(rec: dict[str, Any]) -> str:
    explicit = get_nested(rec, [
        "vrp_key", "key", "canonical_vrp_key", "diff_key",
        "vrp.vrp_key", "record.vrp_key",
    ])
    if explicit:
        return str(explicit)

    tal = get_nested(rec, ["tal", "ta", "vrp.tal", "vrp.ta", "record.tal", "record.ta"], "unknown_tal")
    prefix = get_nested(rec, ["prefix", "vrp.prefix", "record.prefix"], "unknown_prefix")
    max_len = get_nested(rec, ["maxLength", "max_length", "max_len", "vrp.maxLength", "record.maxLength"], "unknown_maxLength")
    asn = get_nested(rec, ["asn", "origin_asn", "origin", "vrp.asn", "record.asn"], "unknown_asn")
    return f"{tal}|{prefix}|{max_len}|{asn}"


def classify_lifetime(rec: dict[str, Any]) -> dict[str, Any]:
    duration_windows = as_int(get_nested(rec, [
        "duration_windows",
        "lifetime.duration_windows",
        "window_span",
        "seen_window_count",
        "window_count",
    ]), default=0)

    first_seen = get_nested(rec, ["first_seen_window", "first_window_id", "first_seen.window_id", "first_seen"])
    last_seen = get_nested(rec, ["last_seen_window", "last_window_id", "last_seen.window_id", "last_seen"])

    diff_type = str(get_nested(rec, [
        "diff_type", "event_type", "change_type", "lifetime.diff_type", "status",
    ], "")).lower()

    temporal_quality = str(get_nested(rec, [
        "temporal_alignment_quality", "timing.temporal_alignment_quality", "alignment_quality",
    ], "unknown"))

    validator_cycle_timing_available = as_bool(get_nested(rec, [
        "validator_cycle_timing_available", "timing.validator_cycle_timing_available",
    ], False))

    refresh_context_available = as_bool(get_nested(rec, [
        "refresh_context_available", "timing.refresh_context_available",
    ], False))

    trailing_existing = as_bool(get_nested(rec, [
        "trailing_cache_candidate", "is_trailing_cache_candidate", "classification.trailing_cache_candidate",
    ], False))

    persistent_existing = as_bool(get_nested(rec, [
        "persistent_divergence_candidate", "is_persistent_candidate", "classification.persistent_divergence_candidate",
    ], False))

    benign_temporal_skew_candidate = False
    new_vrp_propagation_skew_candidate = False
    trailing_cache_candidate = trailing_existing
    persistent_divergence_candidate = persistent_existing

    if duration_windows > 0 and duration_windows <= 2:
        benign_temporal_skew_candidate = True

    if "add" in diff_type and duration_windows > 0 and duration_windows <= 2:
        new_vrp_propagation_skew_candidate = True

    if duration_windows >= 3:
        persistent_divergence_candidate = True

    if any(x in diff_type for x in ["removed", "delete", "deletion", "withdraw"]):
        if duration_windows >= 2 or temporal_quality in {"weak", "unknown"}:
            trailing_cache_candidate = True

    if persistent_divergence_candidate or trailing_cache_candidate:
        m19_mapping_priority = "high"
    elif benign_temporal_skew_candidate:
        m19_mapping_priority = "low"
    else:
        m19_mapping_priority = "normal"

    return {
        "duration_windows": duration_windows,
        "first_seen_window": first_seen,
        "last_seen_window": last_seen,
        "diff_type": diff_type or "unknown",
        "temporal_alignment_quality": temporal_quality,
        "validator_cycle_timing_available": validator_cycle_timing_available,
        "refresh_context_available": refresh_context_available,
        "benign_temporal_skew_candidate": benign_temporal_skew_candidate,
        "new_vrp_propagation_skew_candidate": new_vrp_propagation_skew_candidate,
        "trailing_cache_candidate": trailing_cache_candidate,
        "persistent_divergence_candidate": persistent_divergence_candidate,
        "m19_mapping_priority": m19_mapping_priority,
    }


def extract_timing_fields(rec: dict[str, Any]) -> dict[str, Any]:
    return {
        "validation_start_time": get_nested(rec, [
            "validation_start_time", "validation_started_at_utc",
            "timing.validation_start_time", "timing.validation_started_at_utc",
        ]),
        "validation_end_time": get_nested(rec, [
            "validation_end_time", "validation_finished_at_utc",
            "timing.validation_end_time", "timing.validation_finished_at_utc",
        ]),
        "vrp_export_time": get_nested(rec, [
            "vrp_export_time", "vrp_export_finished_at_utc",
            "timing.vrp_export_time", "timing.raw_vrp_export_finished_at_utc",
        ]),
        "last_successful_update": get_nested(rec, [
            "last_successful_update", "repository_status.last_successful_update", "timing.last_successful_update",
        ]),
        "raw_vrp_path": get_nested(rec, [
            "raw_vrp_path", "timing.raw_vrp_path", "probe.raw_vrp_path",
        ]),
        "repository_status": get_nested(rec, [
            "repository_status", "timing.repository_status",
        ]),
        "cache_snapshot_path": get_nested(rec, [
            "cache_snapshot_path", "cache_index_path", "timing.cache_snapshot_path",
        ]),
    }


def collect_validator_cycle_inventory(m17_root: Path, m245_root: Path) -> list[dict[str, Any]]:
    rows = []

    for p in sorted(m17_root.glob("history/m17_window_*/outputs/validator_cycle_records.jsonl")):
        window_id = p.parent.parent.name.replace("m17_window_", "")
        cnt = 0
        timing_available = 0
        raw_path_available = 0
        sample_keys = set()

        for rec in iter_jsonl(p):
            cnt += 1
            sample_keys |= flatten_keys(rec, max_depth=3)
            timing = extract_timing_fields(rec)
            if timing["vrp_export_time"] or timing["validation_start_time"] or timing["validation_end_time"]:
                timing_available += 1
            if timing["raw_vrp_path"]:
                raw_path_available += 1

        rows.append({
            "source": "m17_validator_cycle_records",
            "path": str(p),
            "window_id": window_id,
            "record_count": cnt,
            "timing_available_count": timing_available,
            "raw_vrp_path_available_count": raw_path_available,
            "sample_keys": sorted(sample_keys)[:100],
        })

    for p in sorted(m245_root.glob("**/probe_m17c_once_timing.json")):
        try:
            obj = read_json(p)
        except Exception:
            continue
        rows.append({
            "source": "probe_m17c_once_timing",
            "path": str(p),
            "window_id": obj.get("window_id"),
            "probe_id": obj.get("probe_id"),
            "record_count": 1,
            "timing_available_count": 1 if obj.get("probe_once_finished_at_utc") else 0,
            "raw_vrp_path_available_count": 1 if obj.get("raw_vrp_path") else 0,
            "probe_once_duration_sec": obj.get("probe_once_duration_sec"),
            "raw_vrp_export_duration_sec": obj.get("raw_vrp_export_duration_sec"),
            "raw_vrp_upload_duration_sec": obj.get("raw_vrp_upload_duration_sec"),
            "validator_update_mode": obj.get("validator_update_mode"),
            "routinator_service_mode": obj.get("routinator_service_mode"),
            "ntp_sync_status": obj.get("ntp_sync_status"),
        })

    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--m18-run-dir", default="")
    ap.add_argument("--m18-root", default="data/p3_collector/m18_diff_lifetime")
    ap.add_argument("--m17-root", default="data/p3_collector/m17_vrp_entry_diff")
    ap.add_argument("--m245-root", default="data")
    ap.add_argument("--out-root", default="data/p3_collector/m18_cache_aware_convergence")
    ap.add_argument("--run-id", default="")
    args = ap.parse_args()

    m18_root = Path(args.m18_root)
    m17_root = Path(args.m17_root)
    m245_root = Path(args.m245_root)
    out_root = Path(args.out_root)

    m18_run_dir = Path(args.m18_run_dir) if args.m18_run_dir else latest_pass_m18_run(m18_root)
    if not m18_run_dir:
        raise SystemExit("NO_PASS_M18_RUN_FOUND")

    run_id = args.run_id or f"m18_cache_aware_v2_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = out_root / "history" / run_id
    out_dir = run_dir / "outputs"
    check_dir = run_dir / "checks"

    for d in [out_dir, check_dir, out_root / "state"]:
        d.mkdir(parents=True, exist_ok=True)

    m18_acceptance = m18_run_dir / "checks" / "M18_ACCEPTANCE.txt"
    m18_out = m18_run_dir / "outputs"

    lifetime_candidates = [
        m18_out / "vrp_diff_lifetime_records_with_timing.jsonl",
        m18_out / "vrp_diff_lifetime_records.jsonl",
        m18_out / "m19_mapping_candidates_with_timing.jsonl",
        m18_out / "m19_mapping_candidates.jsonl",
    ]

    lifetime_path = next((p for p in lifetime_candidates if file_nonempty(p)), None)
    if not lifetime_path:
        raise SystemExit("NO_LIFETIME_OR_M19_CANDIDATE_INPUT_FOUND")

    records_out = out_dir / "m18_cache_aware_vrp_lifetime_records.jsonl"

    counters = Counter()
    by_duration_bucket = Counter()
    by_temporal_quality = Counter()
    by_diff_type = Counter()
    by_priority = Counter()

    def build_rows():
        for rec in iter_jsonl(lifetime_path):
            counters["input_record_count"] += 1
            vrp_key = canonical_vrp_key(rec)
            cls = classify_lifetime(rec)
            timing = extract_timing_fields(rec)

            by_temporal_quality[cls["temporal_alignment_quality"]] += 1
            by_diff_type[cls["diff_type"]] += 1
            by_priority[cls["m19_mapping_priority"]] += 1

            d = cls["duration_windows"]
            if d <= 0:
                bucket = "unknown_or_zero"
            elif d <= 2:
                bucket = "1_2_windows"
            elif d <= 5:
                bucket = "3_5_windows"
            else:
                bucket = "gt_5_windows"
            by_duration_bucket[bucket] += 1

            for k in [
                "benign_temporal_skew_candidate",
                "new_vrp_propagation_skew_candidate",
                "trailing_cache_candidate",
                "persistent_divergence_candidate",
            ]:
                if cls[k]:
                    counters[f"{k}_count"] += 1

            if cls["validator_cycle_timing_available"]:
                counters["validator_cycle_timing_available_count"] += 1
            if cls["refresh_context_available"]:
                counters["refresh_context_available_count"] += 1
            if timing["raw_vrp_path"]:
                counters["raw_vrp_path_available_count"] += 1
            if timing["cache_snapshot_path"]:
                counters["cache_snapshot_path_available_count"] += 1
            if timing["repository_status"]:
                counters["repository_status_available_count"] += 1

            yield {
                "schema": "s3.m18.cache_aware_vrp_lifetime_record.v2",
                "run_id": run_id,
                "source_lifetime_path": str(lifetime_path),
                "vrp_key": vrp_key,

                "duration_windows": cls["duration_windows"],
                "first_seen_window": cls["first_seen_window"],
                "last_seen_window": cls["last_seen_window"],
                "diff_type": cls["diff_type"],

                "benign_temporal_skew_candidate": cls["benign_temporal_skew_candidate"],
                "new_vrp_propagation_skew_candidate": cls["new_vrp_propagation_skew_candidate"],
                "trailing_cache_candidate": cls["trailing_cache_candidate"],
                "persistent_divergence_candidate": cls["persistent_divergence_candidate"],
                "m19_mapping_priority": cls["m19_mapping_priority"],

                "temporal_alignment_quality": cls["temporal_alignment_quality"],
                "validator_cycle_timing_available": cls["validator_cycle_timing_available"],
                "refresh_context_available": cls["refresh_context_available"],

                "validation_start_time": timing["validation_start_time"],
                "validation_end_time": timing["validation_end_time"],
                "vrp_export_time": timing["vrp_export_time"],
                "last_successful_update": timing["last_successful_update"],
                "raw_vrp_path": timing["raw_vrp_path"],
                "repository_status": timing["repository_status"],
                "cache_snapshot_path": timing["cache_snapshot_path"],

                "mapping_strength": "weak",
                "strong_causal_claim_allowed": False,
                "classification_scope": "candidate_only",
            }

    output_record_count = write_jsonl(records_out, build_rows())

    cycle_inventory = collect_validator_cycle_inventory(m17_root, m245_root)
    cycle_inventory_path = out_dir / "m18_cache_aware_validator_cycle_inventory.jsonl"
    write_jsonl(cycle_inventory_path, cycle_inventory)

    cycle_source_counter = Counter(x.get("source", "unknown") for x in cycle_inventory)
    acceptance_kv = parse_kv(m18_acceptance)

    summary = {
        "schema": "s3.m18.cache_aware_convergence_summary.v2",
        "generated_at_utc": utc_now(),
        "status": "PASS",
        "run_id": run_id,
        "run_dir": str(run_dir),
        "m18_run_dir": str(m18_run_dir),
        "m18_acceptance": str(m18_acceptance),
        "m18_acceptance_status": parse_status(m18_acceptance, "M18_ACCEPTANCE"),
        "source_lifetime_path": str(lifetime_path),
        "input_record_count": counters["input_record_count"],
        "output_record_count": output_record_count,
        "candidate_counts": {
            "benign_temporal_skew_candidate_count": counters["benign_temporal_skew_candidate_count"],
            "new_vrp_propagation_skew_candidate_count": counters["new_vrp_propagation_skew_candidate_count"],
            "trailing_cache_candidate_count": counters["trailing_cache_candidate_count"],
            "persistent_divergence_candidate_count": counters["persistent_divergence_candidate_count"],
        },
        "timing_availability": {
            "validator_cycle_timing_available_count": counters["validator_cycle_timing_available_count"],
            "refresh_context_available_count": counters["refresh_context_available_count"],
            "raw_vrp_path_available_count": counters["raw_vrp_path_available_count"],
            "repository_status_available_count": counters["repository_status_available_count"],
            "cache_snapshot_path_available_count": counters["cache_snapshot_path_available_count"],
        },
        "duration_buckets": dict(by_duration_bucket),
        "by_temporal_alignment_quality": dict(by_temporal_quality),
        "by_diff_type": dict(by_diff_type),
        "m19_priority_distribution": dict(by_priority),
        "validator_cycle_inventory": {
            "record_count": len(cycle_inventory),
            "by_source": dict(cycle_source_counter),
            "path": str(cycle_inventory_path),
        },
        "semantic_boundary": {
            "mapping_strength": acceptance_kv.get("mapping_strength", "weak"),
            "strong_causal_claim_allowed": False,
            "cache_aware_classification_scope": "candidate_only",
        },
        "limitations": [
            "This batch classifies cache/lifetime patterns as candidates only.",
            "cache_snapshot_path may be unavailable for historical windows.",
            "repository_status may be unavailable until jsonext/cache-index enhancement is added.",
            "Do not treat late cache observations as same-round validator input evidence.",
        ],
        "next_stage": "P2_M19_OBJECT_INDEX_AND_WEAK_MAPPING",
    }

    write_json(out_dir / "m18_cache_aware_convergence_summary.json", summary)

    md = []
    md.append("# M18 Cache-aware Convergence v2 Summary")
    md.append("")
    md.append(f"- generated_at_utc: `{summary['generated_at_utc']}`")
    md.append(f"- status: `{summary['status']}`")
    md.append(f"- run_id: `{run_id}`")
    md.append(f"- source_lifetime_path: `{lifetime_path}`")
    md.append(f"- input_record_count: `{summary['input_record_count']}`")
    md.append(f"- output_record_count: `{summary['output_record_count']}`")
    md.append("")
    md.append("## Candidate counts")
    for k, v in summary["candidate_counts"].items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## Timing availability")
    for k, v in summary["timing_availability"].items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## M19 priority distribution")
    for k, v in summary["m19_priority_distribution"].items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append(f"next_stage: `{summary['next_stage']}`")
    (out_dir / "m18_cache_aware_convergence_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    lines = [
        "M18_CACHE_AWARE_CONVERGENCE_V2=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"run_id = {run_id}",
        f"m18_run_dir = {m18_run_dir}",
        f"m18_acceptance_status = {summary['m18_acceptance_status']}",
        f"source_lifetime_path = {lifetime_path}",
        f"input_record_count = {summary['input_record_count']}",
        f"output_record_count = {summary['output_record_count']}",
        f"benign_temporal_skew_candidate_count = {summary['candidate_counts']['benign_temporal_skew_candidate_count']}",
        f"new_vrp_propagation_skew_candidate_count = {summary['candidate_counts']['new_vrp_propagation_skew_candidate_count']}",
        f"trailing_cache_candidate_count = {summary['candidate_counts']['trailing_cache_candidate_count']}",
        f"persistent_divergence_candidate_count = {summary['candidate_counts']['persistent_divergence_candidate_count']}",
        f"validator_cycle_timing_available_count = {summary['timing_availability']['validator_cycle_timing_available_count']}",
        f"refresh_context_available_count = {summary['timing_availability']['refresh_context_available_count']}",
        f"raw_vrp_path_available_count = {summary['timing_availability']['raw_vrp_path_available_count']}",
        f"repository_status_available_count = {summary['timing_availability']['repository_status_available_count']}",
        f"cache_snapshot_path_available_count = {summary['timing_availability']['cache_snapshot_path_available_count']}",
        f"validator_cycle_inventory_count = {len(cycle_inventory)}",
        f"records_jsonl = {records_out}",
        f"validator_cycle_inventory_jsonl = {cycle_inventory_path}",
        f"summary_json = {out_dir / 'm18_cache_aware_convergence_summary.json'}",
        f"summary_md = {out_dir / 'm18_cache_aware_convergence_summary.md'}",
        "mapping_strength = weak",
        "strong_causal_claim_allowed = False",
        "classification_scope = candidate_only",
        "next_stage = P2_M19_OBJECT_INDEX_AND_WEAK_MAPPING",
    ]

    check_path = check_dir / "M18_CACHE_AWARE_CONVERGENCE_CHECK.txt"
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state_path = out_root / "state" / "current_m18_cache_aware_run.env"
    state_path.write_text(
        "\n".join([
            f'export M18_CACHE_RUN_ID="{run_id}"',
            f'export M18_CACHE_RUN_DIR="{run_dir}"',
            f'export M18_CACHE_OUT_DIR="{out_dir}"',
            f'export M18_CACHE_CHECK_DIR="{check_dir}"',
            f'export M18_CACHE_RECORDS="{records_out}"',
            f'export M18_CACHE_SUMMARY="{out_dir / "m18_cache_aware_convergence_summary.json"}"',
            "",
        ]),
        encoding="utf-8",
    )

    print("\n".join(lines))


if __name__ == "__main__":
    main()
