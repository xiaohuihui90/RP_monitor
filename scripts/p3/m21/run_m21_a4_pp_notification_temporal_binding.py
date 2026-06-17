#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield line_no, json.loads(line)
            except Exception as e:
                yield line_no, {"_parse_error": str(e), "_raw": line[:300]}


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def parse_manifest_time(s: str | None):
    if not s:
        return None
    # DER GeneralizedTime, e.g. 20260607010428Z
    try:
        return datetime.strptime(s, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def parse_window_time_from_path(path: Path):
    m = re.search(r"m245_window_(win_\d{8}T\d{6}Z_10m)", str(path))
    if not m:
        return None, None
    win = m.group(1)
    ts = win[len("win_"):-len("_10m")]
    try:
        dt = datetime.strptime(ts, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        return win, dt
    except Exception:
        return win, None


def collect_windows(m245_history: Path):
    windows = []
    for p in sorted(m245_history.glob("m245_window_*")):
        if not p.is_dir():
            continue
        win, dt = parse_window_time_from_path(p)
        if not win or not dt:
            continue
        outputs = p / "outputs"
        windows.append({
            "window_id": win,
            "window_dt": dt,
            "window_dir": str(p),
            "status_matrix": str(outputs / "M245_three_layer_status_matrix.json"),
            "mapping_context": str(outputs / "M245_mapping_context.json"),
            "merged_validator_context": str(outputs / "M245_merged_validator_context.json"),
        })
    return windows


def scan_notification_like_fields(obj):
    out = []

    def walk(x, path="$"):
        if isinstance(x, dict):
            keys = {str(k).lower(): k for k in x.keys()}
            has_session = any("session" in k for k in keys)
            has_serial = any("serial" in k for k in keys)
            has_notif = any("notif" in k or "notification" in k for k in keys)

            if has_session or has_serial or has_notif:
                rec = {}
                for lk, k in keys.items():
                    if any(t in lk for t in ["session", "serial", "notif", "notification", "digest", "uri", "url"]):
                        v = x.get(k)
                        if isinstance(v, (str, int, float, bool)) or v is None:
                            rec[str(k)] = v
                if rec:
                    rec["_path"] = path
                    out.append(rec)

            for k, v in x.items():
                walk(v, f"{path}.{k}")
        elif isinstance(x, list):
            for i, v in enumerate(x):
                walk(v, f"{path}[{i}]")

    walk(obj)
    return out


def nearest_windows(target_dt, windows, limit=5, max_abs_hours=24):
    if target_dt is None:
        return []

    rows = []
    for w in windows:
        d = abs((w["window_dt"] - target_dt).total_seconds())
        if d <= max_abs_hours * 3600:
            rows.append((d, w))
    rows.sort(key=lambda x: x[0])

    out = []
    for d, w in rows[:limit]:
        out.append({
            "window_id": w["window_id"],
            "window_dir": w["window_dir"],
            "abs_delta_sec": int(d),
            "status_matrix": w["status_matrix"],
            "mapping_context": w["mapping_context"],
            "merged_validator_context": w["merged_validator_context"],
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a3c-matches", required=True)
    ap.add_argument("--m245-history", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--max-window-abs-hours", type=int, default=24)
    args = ap.parse_args()

    a3c_path = Path(args.a3c_matches)
    m245_history = Path(args.m245_history)
    out_dir = Path(args.out_dir)

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    indexes = out_dir / "indexes"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)
    indexes.mkdir(parents=True, exist_ok=True)

    records_path = outputs / "m21_a4_pp_notification_temporal_binding_records.jsonl"
    notification_index_path = indexes / "m21_a4_l1_notification_like_index.jsonl"
    summary_path = outputs / "m21_a4_pp_notification_temporal_binding_summary.json"
    check_path = checks / "M21_A4_PP_NOTIFICATION_TEMPORAL_BINDING_CHECK.txt"

    windows = collect_windows(m245_history)

    counters = Counter()
    notification_like_records = []

    # Build lightweight L1 notification-like index from existing M245 JSON files.
    with notification_index_path.open("w", encoding="utf-8") as idx_out:
        for w in windows:
            counters["m245_window_count"] += 1
            for key in ["status_matrix", "mapping_context", "merged_validator_context"]:
                p = Path(w[key])
                if not p.exists():
                    continue
                obj = read_json(p)
                if obj is None:
                    continue
                found = scan_notification_like_fields(obj)
                for rec in found:
                    row = {
                        "schema": "s3.m21.a4.l1_notification_like_index.v1",
                        "window_id": w["window_id"],
                        "source_file": str(p),
                        "source_kind": key,
                        "record": rec,
                        "semantic_boundary": "field_name_based_l1_notification_candidate_not_confirmed",
                        "strong_causal_claim_allowed": False,
                    }
                    idx_out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                    notification_like_records.append(row)
                    counters["notification_like_record_count"] += 1

    # Group notification-like by window for quick lookup.
    notif_by_window = {}
    for r in notification_like_records:
        notif_by_window.setdefault(r["window_id"], []).append(r)

    with records_path.open("w", encoding="utf-8") as out:
        for _, r in iter_jsonl(a3c_path):
            if not isinstance(r, dict) or r.get("_parse_error"):
                counters["a3c_parse_error"] += 1
                continue

            counters["candidate_count"] += 1

            if not r.get("roa_filename_filelist_match"):
                counters["skip_no_manifest_filelist_match"] += 1
                continue

            counters["manifest_filelist_matched_candidate_count"] += 1

            this_dt = parse_manifest_time(r.get("manifest_thisUpdate"))
            next_dt = parse_manifest_time(r.get("manifest_nextUpdate"))
            nearest = nearest_windows(
                this_dt,
                windows,
                limit=5,
                max_abs_hours=args.max_window_abs_hours,
            )

            if nearest:
                counters["candidate_with_temporal_window_candidate"] += 1
            else:
                counters["candidate_without_temporal_window_candidate"] += 1

            notification_candidates = []
            for w in nearest:
                notification_candidates.extend(notif_by_window.get(w["window_id"], [])[:5])

            if notification_candidates:
                counters["candidate_with_notification_like_context"] += 1
                l1_status = "l1_notification_like_context_found"
                alignment_status = "l3_to_manifest_filelist_to_l1_window_candidate"
                alignment_confidence = "medium_late_temporal_window"
            else:
                counters["candidate_without_notification_like_context"] += 1
                l1_status = "no_l1_notification_like_context_found"
                alignment_status = "l3_to_manifest_filelist_only"
                alignment_confidence = "medium_manifest_only"

            rec = {
                "schema": "s3.m21.a4.pp_notification_temporal_binding_record.v1",
                "vrp_key": r.get("vrp_key"),
                "afi": r.get("afi"),
                "tal": r.get("tal"),
                "prefix": r.get("prefix"),
                "asn": r.get("asn"),
                "maxLength": r.get("maxLength"),

                "roa_uri": r.get("roa_uri"),
                "roa_filename": r.get("roa_filename"),
                "manifest_uri": r.get("manifest_uri"),
                "manifestNumber": r.get("manifestNumber"),
                "manifest_thisUpdate": r.get("manifest_thisUpdate"),
                "manifest_nextUpdate": r.get("manifest_nextUpdate"),
                "manifest_fileHashAlgOid": r.get("manifest_fileHashAlgOid"),
                "manifest_fileList_count": r.get("manifest_fileList_count"),
                "manifest_file_hash": r.get("manifest_file_hash"),

                "nearest_m245_windows": nearest,
                "l1_notification_binding_status": l1_status,
                "notification_like_candidate_count": len(notification_candidates),
                "notification_like_candidates": notification_candidates[:10],

                "alignment_status": alignment_status,
                "alignment_confidence": alignment_confidence,

                "semantic_boundary": "late_manifest_to_l1_window_candidate_not_same_window_strong_binding",
                "strong_causal_claim_allowed": False,
            }
            out.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
            counters["records_written"] += 1

    summary = {
        "schema": "s3.m21.a4.pp_notification_temporal_binding_summary.v1",
        "generated_at_utc": utc_now(),
        "a3c_matches": str(a3c_path),
        "m245_history": str(m245_history),
        "counters": dict(counters),
        "outputs": {
            "binding_records": str(records_path),
            "notification_like_index": str(notification_index_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "interpretation": {
            "a4_is_strong_l1_binding": False,
            "reason": "This stage binds manifest metadata to nearest M245 windows and notification-like context only. Strong binding requires same-window JSONEXT/manifest/notification capture.",
        },
        "semantic_boundary": "late_manifest_to_l1_window_candidate_not_same_window_strong_binding",
        "strong_causal_claim_allowed": False,
        "next_stage": "M21_A5_ALIGNMENT_CONFIDENCE_SUMMARY",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M21_A4_PP_NOTIFICATION_TEMPORAL_BINDING=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"m245_window_count = {counters['m245_window_count']}",
        f"notification_like_record_count = {counters['notification_like_record_count']}",
        f"candidate_count = {counters['candidate_count']}",
        f"manifest_filelist_matched_candidate_count = {counters['manifest_filelist_matched_candidate_count']}",
        f"candidate_with_temporal_window_candidate = {counters['candidate_with_temporal_window_candidate']}",
        f"candidate_with_notification_like_context = {counters['candidate_with_notification_like_context']}",
        f"records_written = {counters['records_written']}",
        f"binding_records = {records_path}",
        f"notification_like_index = {notification_index_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = late_manifest_to_l1_window_candidate_not_same_window_strong_binding",
        "strong_causal_claim_allowed = False",
        "next_stage = M21_A5_ALIGNMENT_CONFIDENCE_SUMMARY",
    ]
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
