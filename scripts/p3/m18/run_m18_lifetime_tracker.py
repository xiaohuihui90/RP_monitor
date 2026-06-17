#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def iter_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def sha256_text(s: str) -> str:
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


def parse_vrp_key(vrp_key: str) -> dict[str, str]:
    """
    Expected M17 key format:
      afi|tal|prefix|asn|maxLength
    Example:
      ipv4|apnic|103.135.112.0/22|134196|22
    """
    parts = str(vrp_key or "").split("|")
    if len(parts) >= 5:
        return {
            "afi": parts[0],
            "tal": parts[1],
            "prefix": parts[2],
            "asn": parts[3],
            "maxLength": parts[4],
            "vrp_key": "|".join(parts[:5]),
            "parse_status": "ok",
        }

    return {
        "afi": "unknown",
        "tal": "unknown",
        "prefix": "unknown",
        "asn": "unknown",
        "maxLength": "unknown",
        "vrp_key": str(vrp_key or "unknown|unknown|unknown|unknown|unknown"),
        "parse_status": "failed",
    }


def normalize_event_type(r: dict[str, Any]) -> str:
    event_type = str(r.get("event_type") or "").lower()
    diff_type = str(r.get("diff_type") or "").lower()

    if event_type in {"added", "removed", "changed"}:
        return event_type

    if "add" in event_type or "add" in diff_type:
        return "added"
    if "remove" in event_type or "remove" in diff_type:
        return "removed"
    if "change" in event_type or "change" in diff_type or "modify" in diff_type:
        return "changed"

    # M17 convention: only_in_left / only_in_right are already interpreted in event_type
    if diff_type in {"only_in_left", "only_in_right"}:
        return "removed"

    return "unknown"


def consecutive_count(indices: list[int]) -> int:
    if not indices:
        return 0

    longest = 1
    cur = 1

    for a, b in zip(indices, indices[1:]):
        if b == a + 1:
            cur += 1
        else:
            longest = max(longest, cur)
            cur = 1

    return max(longest, cur)


def classify_temporal(
    *,
    event_type: str,
    seen_count: int,
    consecutive: int,
    resolved: bool,
    last_seen_is_last_window: bool,
    in_large_scale_window: bool,
) -> str:
    if in_large_scale_window and seen_count == 1:
        return "large_scale_event_candidate"

    if seen_count == 1:
        return "benign_temporal_skew_candidate"

    if event_type == "removed" and last_seen_is_last_window and seen_count >= 2:
        return "suspicious_persistent_loss_candidate"

    if last_seen_is_last_window and seen_count >= 2:
        return "persistent_divergence_candidate"

    if resolved and seen_count >= 2:
        if event_type == "removed":
            return "trailing_cache_candidate"
        return "delayed_convergence_candidate"

    if consecutive >= 2:
        return "repeated_diff_candidate"

    return "unknown_temporal_candidate"


def m19_priority(rec: dict[str, Any]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    tc = rec.get("temporal_class")
    event_type = rec.get("event_type")

    if tc in {"persistent_divergence_candidate", "suspicious_persistent_loss_candidate"}:
        reasons.append(str(tc))
        return "high", reasons

    if event_type == "changed":
        reasons.append("changed_vrp")
        return "high", reasons

    if rec.get("seen_window_count", 0) >= 2:
        reasons.append("repeated_diff")
        return "medium", reasons

    if tc == "large_scale_event_candidate":
        reasons.append("large_scale_event_sample_candidate")
        return "medium", reasons

    return "low", ["single_window_or_low_priority"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--check-dir", required=True)
    ap.add_argument("--window-interval-minutes", type=int, default=60)
    ap.add_argument("--window-size-minutes", type=int, default=10)
    args = ap.parse_args()

    manifest_path = Path(args.manifest)
    out_dir = Path(args.out_dir)
    check_dir = Path(args.check_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    check_dir.mkdir(parents=True, exist_ok=True)

    manifest = read_json(manifest_path)
    windows = manifest.get("windows", [])
    window_ids = [w.get("window_id") for w in windows if w.get("window_id")]
    window_index = {wid: i for i, wid in enumerate(window_ids)}
    last_index = len(window_ids) - 1

    # window quality
    window_quality: dict[str, str | None] = {}
    for w in windows:
        wid = w.get("window_id")
        qpath = Path(w.get("quality_annotation", ""))
        q = None
        if qpath.exists():
            try:
                qobj = read_json(qpath)
                q = qobj.get("m17_window_quality")
            except Exception:
                q = None
        window_quality[wid] = q

    merged_rows: list[dict[str, Any]] = []
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)

    parse_status_counter = Counter()
    event_counter_raw = Counter()

    for w in windows:
        wid = w.get("window_id")
        seed_path = Path(w.get("m18_lifetime_seed_records", ""))

        for r in iter_jsonl(seed_path):
            if not isinstance(r, dict):
                continue

            vrp_key = str(r.get("vrp_key") or "")
            parsed = parse_vrp_key(vrp_key)
            event_type = normalize_event_type(r)
            probe_pair = str(r.get("probe_pair") or "unknown|unknown")

            # window-independent key
            diff_key = "|".join([
                probe_pair,
                event_type,
                parsed["afi"],
                parsed["tal"],
                parsed["prefix"],
                parsed["asn"],
                parsed["maxLength"],
            ])

            diff_id = sha256_text(diff_key)

            row = {
                "schema": "s3.m18.merged_lifetime_seed_record.v1",
                "window_id": wid,
                "window_index": window_index.get(wid),
                "diff_id": diff_id,
                "diff_key": diff_key,
                "probe_pair": probe_pair,
                "event_type": event_type,
                "diff_type": r.get("diff_type"),
                "vrp_key": parsed["vrp_key"],
                "afi": parsed["afi"],
                "tal": parsed["tal"],
                "prefix": parsed["prefix"],
                "asn": parsed["asn"],
                "maxLength": parsed["maxLength"],
                "vrp_key_parse_status": parsed["parse_status"],
                "m17_window_quality": window_quality.get(wid),
                "source_seed": r,
            }

            merged_rows.append(row)
            groups[diff_id].append(row)
            parse_status_counter[parsed["parse_status"]] += 1
            event_counter_raw[event_type] += 1

    lifetime_records: list[dict[str, Any]] = []
    persistent_candidates: list[dict[str, Any]] = []
    trailing_candidates: list[dict[str, Any]] = []
    m19_candidates: list[dict[str, Any]] = []

    temporal_counts = Counter()
    event_counts = Counter()
    tal_counts = Counter()
    asn_counts = Counter()
    prefix_counts = Counter()

    for diff_id, rows in groups.items():
        rows = sorted(rows, key=lambda x: (x.get("window_index") is None, x.get("window_index", 10**9)))
        first = rows[0]

        indices = sorted(set(r["window_index"] for r in rows if r.get("window_index") is not None))
        seen_windows = [window_ids[i] for i in indices]
        seen_count = len(indices)
        consecutive = consecutive_count(indices)

        first_idx = indices[0] if indices else None
        last_idx = indices[-1] if indices else None
        last_seen_is_last_window = last_idx == last_index
        resolved = bool(last_idx is not None and last_idx < last_index)
        resolved_window = window_ids[last_idx + 1] if resolved and (last_idx + 1) < len(window_ids) else None

        in_large = any(
            str(r.get("m17_window_quality") or "").startswith("diagnostic_large_scale")
            for r in rows
        )

        event_type = first["event_type"]
        temporal_class = classify_temporal(
            event_type=event_type,
            seen_count=seen_count,
            consecutive=consecutive,
            resolved=resolved,
            last_seen_is_last_window=last_seen_is_last_window,
            in_large_scale_window=in_large,
        )

        lower = max(0, (seen_count - 1) * args.window_interval_minutes)
        upper = max(args.window_interval_minutes, seen_count * args.window_interval_minutes)

        rec = {
            "schema": "s3.m18.vrp_diff_lifetime_record.v1",
            "diff_id": diff_id,
            "diff_key": first["diff_key"],
            "vrp_key": first["vrp_key"],
            "event_type": event_type,
            "diff_type": event_type,
            "probe_pair": first["probe_pair"],

            "afi": first["afi"],
            "tal": first["tal"],
            "prefix": first["prefix"],
            "asn": first["asn"],
            "maxLength": first["maxLength"],

            "first_seen_window": seen_windows[0] if seen_windows else None,
            "last_seen_window": seen_windows[-1] if seen_windows else None,
            "seen_windows": seen_windows,
            "seen_window_count": seen_count,
            "consecutive_window_count": consecutive,

            "resolved": resolved,
            "resolved_window": resolved_window,

            "window_interval_minutes": args.window_interval_minutes,
            "window_size_minutes": args.window_size_minutes,
            "duration_lower_bound_minutes": lower,
            "duration_upper_bound_minutes": upper,
            "measurement_uncertainty_minutes": args.window_interval_minutes,

            "temporal_class": temporal_class,
            "convergence_direction": (
                "addition_convergence" if event_type == "added"
                else "deletion_convergence" if event_type == "removed"
                else "modification_convergence" if event_type == "changed"
                else "unknown"
            ),

            "quality_flags": sorted(set(
                str(r.get("m17_window_quality"))
                for r in rows
                if r.get("m17_window_quality")
            )),

            "validator_cycle_available": True,
            "effective_input_summary_available": True,
            "mapping_strength": "weak",
            "strong_causal_claim_allowed": False,
        }

        priority, reasons = m19_priority(rec)
        rec["m19_candidate_priority"] = priority
        rec["m19_candidate_reason"] = reasons
        rec["recommended_next_stage"] = (
            "M19_ROA_MAPPING_CANDIDATE"
            if priority in {"high", "medium"}
            else "M18_OBSERVE_ONLY"
        )

        lifetime_records.append(rec)

        temporal_counts[temporal_class] += 1
        event_counts[event_type] += 1
        tal_counts[first["tal"]] += 1
        asn_counts[first["asn"]] += 1
        prefix_counts[first["prefix"]] += 1

        if temporal_class in {"persistent_divergence_candidate", "suspicious_persistent_loss_candidate"}:
            persistent_candidates.append(rec)

        if temporal_class == "trailing_cache_candidate":
            trailing_candidates.append(rec)

        if priority in {"high", "medium"}:
            m19_candidates.append({
                "schema": "s3.m18.m19_mapping_candidate.v1",
                "diff_id": rec["diff_id"],
                "diff_key": rec["diff_key"],
                "vrp_key": rec["vrp_key"],
                "event_type": rec["event_type"],
                "probe_pair": rec["probe_pair"],
                "afi": rec["afi"],
                "tal": rec["tal"],
                "prefix": rec["prefix"],
                "asn": rec["asn"],
                "maxLength": rec["maxLength"],
                "temporal_class": rec["temporal_class"],
                "seen_window_count": rec["seen_window_count"],
                "consecutive_window_count": rec["consecutive_window_count"],
                "candidate_priority": priority,
                "candidate_reason": reasons,
                "mapping_strength": "weak",
                "recommended_next_stage": "M19_ROA_TO_VRP_MAPPING",
            })

    large_scale_timeline = []
    for w in windows:
        wid = w.get("window_id")
        q = window_quality.get(wid)
        if q and str(q).startswith("diagnostic_large_scale"):
            large_scale_timeline.append({
                "window_id": wid,
                "m17_window_quality": q,
            })

    summary = {
        "schema": "s3.m18.lifetime_tracker_summary.v2",
        "generated_at_utc": utc_now(),
        "status": "PASS" if lifetime_records else "FAIL",
        "manifest_path": str(manifest_path),
        "window_count": len(window_ids),
        "merged_seed_record_count": len(merged_rows),
        "lifetime_record_count": len(lifetime_records),
        "persistent_candidate_count": len(persistent_candidates),
        "trailing_cache_candidate_count": len(trailing_candidates),
        "m19_candidate_count": len(m19_candidates),
        "vrp_key_parse_status_counts": dict(parse_status_counter),
        "raw_event_type_counts": dict(event_counter_raw),
        "temporal_class_counts": dict(temporal_counts),
        "event_type_counts": dict(event_counts),
        "top_tal": tal_counts.most_common(20),
        "top_asn": asn_counts.most_common(20),
        "top_prefix": prefix_counts.most_common(20),
        "large_scale_event_timeline": large_scale_timeline,
        "semantic_boundary": {
            "mapping_strength": "weak",
            "strong_causal_claim_allowed": False,
            "accepted_object_set_available": False,
        },
    }

    write_jsonl(out_dir / "merged_lifetime_seed_records.jsonl", merged_rows)
    write_jsonl(out_dir / "vrp_diff_lifetime_records.jsonl", lifetime_records)
    write_jsonl(out_dir / "persistent_divergence_candidates.jsonl", persistent_candidates)
    write_jsonl(out_dir / "trailing_cache_candidates.jsonl", trailing_candidates)
    write_jsonl(out_dir / "m19_mapping_candidates.jsonl", m19_candidates)
    write_json(out_dir / "large_scale_event_timeline.json", large_scale_timeline)
    write_json(out_dir / "m18_lifetime_tracker_summary.json", summary)

    txt = [
        f"M18_LIFETIME_TRACKER={summary['status']}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"window_count = {summary['window_count']}",
        f"merged_seed_record_count = {summary['merged_seed_record_count']}",
        f"lifetime_record_count = {summary['lifetime_record_count']}",
        f"persistent_candidate_count = {summary['persistent_candidate_count']}",
        f"trailing_cache_candidate_count = {summary['trailing_cache_candidate_count']}",
        f"m19_candidate_count = {summary['m19_candidate_count']}",
        f"vrp_key_parse_status_counts = {summary['vrp_key_parse_status_counts']}",
        f"mapping_strength = weak",
        f"strong_causal_claim_allowed = False",
        f"summary_path = {out_dir / 'm18_lifetime_tracker_summary.json'}",
    ]

    (check_dir / "M18_LIFETIME_TRACKER_CHECK.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")
    print("\n".join(txt))

    if summary["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

from scripts.p3.m18.m18_d2_probewise_lifetime import attach_control_plane_impact

def run_with_impact(records):

    enriched = attach_control_plane_impact(records)

    total = len(enriched)
    impact = sum(1 for r in enriched if r.get("control_plane_impact"))

    print("TOTAL =", total)
    print("IMPACT =", impact)

    return enriched

