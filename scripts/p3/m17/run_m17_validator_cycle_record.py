#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def read_jsonl_count(path: Path | None) -> int | None:
    if not path or not path.exists():
        return None
    count = 0
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


def get_probe_meta(validator_meta: dict[str, Any], probe_id: str) -> dict[str, Any]:
    pmeta = validator_meta.get("probe_metadata", {})
    if isinstance(pmeta, dict) and isinstance(pmeta.get(probe_id), dict):
        return pmeta[probe_id]
    return {}


def find_raw_vrp_file(raw_probe_dir: Path) -> Path | None:
    files = sorted(raw_probe_dir.glob("*_raw_vrp.json"))
    return files[0] if files else None


def parse_time(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def seconds_between(a: str | None, b: str | None) -> float | None:
    da = parse_time(a)
    db = parse_time(b)
    if not da or not db:
        return None
    return (db - da).total_seconds()


def temporal_alignment_quality(export_time_span_sec: float | None, timing_complete: bool) -> str:
    if export_time_span_sec is None:
        return "unknown"
    if not timing_complete:
        return "weak"
    if export_time_span_sec <= 300:
        return "good"
    if export_time_span_sec <= 900:
        return "medium"
    return "weak"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--m245-history-root", default="data/p3_collector/m245_three_layer_baseline/history")
    ap.add_argument("--m17-root", default="data/p3_collector/m17_vrp_entry_diff/history")
    args = ap.parse_args()

    window_id = args.window_id
    m245_dir = Path(args.m245_history_root) / f"m245_window_{window_id}"
    m17_dir = Path(args.m17_root) / f"m17_window_{window_id}"
    out_dir = m17_dir / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)

    validator_meta_path = m245_dir / "outputs" / "validator_runtime_metadata.json"
    validator_meta = read_json(validator_meta_path)
    if not isinstance(validator_meta, dict):
        validator_meta = {}

    canonical_manifest_path = out_dir / "canonical_vrp_manifest.json"
    canonical_manifest = read_json(canonical_manifest_path)
    if not isinstance(canonical_manifest, dict):
        canonical_manifest = {}

    canonical_by_probe = canonical_manifest.get("probes", {})
    if not isinstance(canonical_by_probe, dict):
        canonical_by_probe = {}

    raw_root = m245_dir / "outputs" / "raw_vrp"

    records: list[dict[str, Any]] = []
    warnings: list[str] = []

    export_start_times = []
    export_end_times = []
    export_durations = []
    ntp_by_probe = {}
    refresh_available_by_probe = {}

    for raw_probe_dir in sorted(raw_root.glob("probe-*")):
        if not raw_probe_dir.is_dir():
            continue

        probe_id = raw_probe_dir.name

        raw_manifest_path = raw_probe_dir / "raw_vrp_export_manifest.json"
        raw_check_path = raw_probe_dir / "raw_vrp_export_check.txt"
        timing_path = raw_probe_dir / "probe_m17c_once_timing.json"

        raw_manifest = read_json(raw_manifest_path)
        if not isinstance(raw_manifest, dict):
            raw_manifest = {}
            warnings.append(f"{probe_id}:raw_vrp_export_manifest_missing_or_bad")

        timing = read_json(timing_path)
        timing_metadata_available = isinstance(timing, dict)

        if not timing_metadata_available:
            timing = {}
            warnings.append(f"{probe_id}:probe_m17c_once_timing_missing")

        raw_vrp_file = find_raw_vrp_file(raw_probe_dir)
        probe_meta = get_probe_meta(validator_meta, probe_id)

        canonical_info = canonical_by_probe.get(probe_id, {})
        if not isinstance(canonical_info, dict):
            canonical_info = {}

        canonical_path = Path(canonical_info.get("canonical_vrp_path", "")) if canonical_info.get("canonical_vrp_path") else None
        canonical_count = read_jsonl_count(canonical_path)

        raw_vrp_size = None
        raw_vrp_hash = None
        if raw_vrp_file and raw_vrp_file.exists():
            raw_vrp_size = raw_vrp_file.stat().st_size
            raw_vrp_hash = sha256_file(raw_vrp_file)

        vrp_count = probe_meta.get("vrp_count") or raw_manifest.get("vrp_count_guess") or canonical_count
        raw_guess = raw_manifest.get("vrp_count_guess")

        consistency = "unknown"
        if vrp_count is not None and raw_guess is not None:
            try:
                consistency = "consistent" if abs(int(vrp_count) - int(raw_guess)) <= 10 else "mismatch"
            except Exception:
                consistency = "unknown"

        # P0/P1: 当前可靠记录 export cycle；update cycle 先保守置空，除非未来能从 API/log 取到。
        export_started = timing.get("raw_vrp_export_started_at_utc")
        export_finished = timing.get("raw_vrp_export_finished_at_utc")
        export_duration = timing.get("raw_vrp_export_duration_sec")

        upload_started = timing.get("raw_vrp_upload_started_at_utc")
        upload_finished = timing.get("raw_vrp_upload_finished_at_utc")
        upload_duration = timing.get("raw_vrp_upload_duration_sec")

        if export_started:
            export_start_times.append(export_started)
        if export_finished:
            export_end_times.append(export_finished)
        if isinstance(export_duration, (int, float)):
            export_durations.append(float(export_duration))

        ntp_status = timing.get("ntp_sync_status") if timing_metadata_available else "unknown"
        ntp_by_probe[probe_id] = ntp_status

        validator_refresh_context_available = False
        last_refresh_at_utc = None
        refresh_age_sec = None

        # 如果已有 metadata 里有相关字段，保守读取；没有就 null。
        for k in ["last_successful_refresh_at_utc", "last_refresh_at_utc", "last_successful_update"]:
            if probe_meta.get(k):
                last_refresh_at_utc = probe_meta.get(k)
                break

        if probe_meta.get("refresh_age_sec") is not None:
            refresh_age_sec = probe_meta.get("refresh_age_sec")
        elif probe_meta.get("cache_age_sec") is not None:
            refresh_age_sec = probe_meta.get("cache_age_sec")

        if last_refresh_at_utc is not None or refresh_age_sec is not None:
            validator_refresh_context_available = True

        refresh_available_by_probe[probe_id] = validator_refresh_context_available

        record = {
            "schema": "s3.m17.validator_cycle_record.v2",
            "generated_at_utc": utc_now(),
            "window_id": window_id,
            "probe_id": probe_id,

            "validator_cycle_record_type": "export_cycle_with_partial_update_context",

            "validator": probe_meta.get("validator") or raw_manifest.get("validator") or "routinator",
            "validator_version": probe_meta.get("validator_version") or raw_manifest.get("validator_version"),
            "validator_update_mode": probe_meta.get("validator_update_mode") or timing.get("validator_update_mode") or "noupdate",
            "validator_update_policy": "observation_window_noupdate",

            "raw_vrp_path": str(raw_vrp_file) if raw_vrp_file else None,
            "raw_vrp_sha256": raw_vrp_hash,
            "raw_vrp_size_bytes": raw_vrp_size,
            "vrp_count": vrp_count,
            "raw_vrp_vrp_count_guess": raw_guess,
            "canonical_vrp_count": canonical_count,
            "vrp_count_consistency": consistency,

            "suspicious_low_count": probe_meta.get("suspicious_low_count"),
            "validation_output_quality": probe_meta.get("validation_output_quality"),
            "metadata_quality": probe_meta.get("metadata_quality"),
            "raw_vrp_export_status": raw_manifest.get("status"),
            "raw_vrp_format": raw_manifest.get("format"),

            "export_cycle": {
                "export_started_at_utc": export_started,
                "export_finished_at_utc": export_finished,
                "export_duration_sec": export_duration,
                "validator_update_mode": probe_meta.get("validator_update_mode") or timing.get("validator_update_mode") or "noupdate",
                "raw_vrp_path": str(raw_vrp_file) if raw_vrp_file else None,
                "vrp_count": vrp_count,
                "raw_vrp_size_bytes": raw_vrp_size,
            },

            "probe_timing": {
                "timing_metadata_available": timing_metadata_available,
                "probe_once_started_at_utc": timing.get("probe_once_started_at_utc"),
                "probe_once_finished_at_utc": timing.get("probe_once_finished_at_utc"),
                "probe_once_duration_sec": timing.get("probe_once_duration_sec"),

                "m245_collect_started_at_utc": timing.get("m245_collect_started_at_utc"),
                "m245_collect_finished_at_utc": timing.get("m245_collect_finished_at_utc"),
                "m245_collect_duration_sec": timing.get("m245_collect_duration_sec"),

                "raw_vrp_upload_started_at_utc": upload_started,
                "raw_vrp_upload_finished_at_utc": upload_finished,
                "raw_vrp_upload_duration_sec": upload_duration,

                "probe_date_utc_at_start": timing.get("probe_date_utc_at_start"),
                "probe_date_utc_at_finish": timing.get("probe_date_utc_at_finish"),
                "ntp_sync_status": ntp_status,
                "ntp_service_status": timing.get("ntp_service_status"),
                "clock_offset_hint_sec": timing.get("clock_offset_hint_sec"),
                "routinator_service_mode": timing.get("routinator_service_mode") or "cli_cache_export",
            },

            "validator_update_cycle": {
                "validator_refresh_context_available": validator_refresh_context_available,
                "cycle_id": None,
                "validation_start_time": None,
                "validation_end_time": None,
                "validation_duration_ms": None,
                "last_successful_update": last_refresh_at_utc,
                "last_refresh_at_utc": last_refresh_at_utc,
                "refresh_age_sec": refresh_age_sec,
                "download_duration_ms": None,
                "processing_duration_ms": None,
                "polling_interval_hint_sec": None,
                "repository_status_available": False,
                "failed_repository_count": None,
                "stale_repository_count": None,
            },

            "evidence_boundary": {
                "update_cycle_not_fully_observed": not validator_refresh_context_available,
                "do_not_interpret_export_time_as_validation_start": True,
                "accepted_object_set_available": False,
                "mapping_strength": "weak",
                "strong_causal_claim_allowed": False,
            },

            "source_files": {
                "raw_vrp_export_manifest": str(raw_manifest_path),
                "raw_vrp_export_check": str(raw_check_path),
                "probe_m17c_once_timing": str(timing_path),
                "validator_runtime_metadata": str(validator_meta_path),
                "canonical_vrp_manifest": str(canonical_manifest_path),
            },

            # flat fields for backward compatibility
            "timing_metadata_available": timing_metadata_available,
            "export_started_at_utc": export_started,
            "export_finished_at_utc": export_finished,
            "export_duration_sec": export_duration,
            "probe_once_started_at_utc": timing.get("probe_once_started_at_utc"),
            "probe_once_finished_at_utc": timing.get("probe_once_finished_at_utc"),
            "probe_once_duration_sec": timing.get("probe_once_duration_sec"),
            "validator_refresh_context_available": validator_refresh_context_available,
            "last_refresh_at_utc": last_refresh_at_utc,
            "refresh_age_sec": refresh_age_sec,
            "routinator_service_mode": timing.get("routinator_service_mode") or "cli_cache_export",
            "ntp_sync_status": ntp_status,
            "clock_offset_hint_sec": timing.get("clock_offset_hint_sec"),

            "accepted_object_set_available": False,
            "mapping_strength_candidate": "weak",
            "strong_causal_claim_allowed": False,
        }

        records.append(record)

    def min_dt(xs: list[str]) -> str | None:
        parsed = [(parse_time(x), x) for x in xs if parse_time(x)]
        if not parsed:
            return None
        return min(parsed, key=lambda t: t[0])[1]

    def max_dt(xs: list[str]) -> str | None:
        parsed = [(parse_time(x), x) for x in xs if parse_time(x)]
        if not parsed:
            return None
        return max(parsed, key=lambda t: t[0])[1]

    earliest_export_start = min_dt(export_start_times)
    latest_export_start = max_dt(export_start_times)
    export_time_span_sec = seconds_between(earliest_export_start, latest_export_start)

    timing_complete = len(records) >= 3 and all(r.get("timing_metadata_available") for r in records)
    alignment = temporal_alignment_quality(export_time_span_sec, timing_complete)

    status = "PASS" if len(records) >= 3 else "FAIL"

    summary = {
        "schema": "s3.m17.validator_cycle_summary.v2",
        "generated_at_utc": utc_now(),
        "window_id": window_id,
        "status": status,
        "cycle_record_count": len(records),
        "probe_count": len({r["probe_id"] for r in records}),
        "validator_update_mode_set": sorted(set(str(r.get("validator_update_mode")) for r in records)),

        "vrp_counts_by_probe": {r["probe_id"]: r.get("vrp_count") for r in records},
        "canonical_counts_by_probe": {r["probe_id"]: r.get("canonical_vrp_count") for r in records},
        "suspicious_low_count_by_probe": {r["probe_id"]: r.get("suspicious_low_count") for r in records},
        "validation_output_quality_by_probe": {r["probe_id"]: r.get("validation_output_quality") for r in records},

        "timing_metadata_complete": timing_complete,
        "timing_metadata_available_by_probe": {r["probe_id"]: r.get("timing_metadata_available") for r in records},
        "earliest_export_started_at_utc": earliest_export_start,
        "latest_export_started_at_utc": latest_export_start,
        "export_time_span_sec": export_time_span_sec,
        "max_export_duration_sec": max(export_durations) if export_durations else None,
        "min_export_duration_sec": min(export_durations) if export_durations else None,
        "temporal_alignment_quality": alignment,

        "ntp_sync_status_by_probe": ntp_by_probe,
        "validator_refresh_context_available_by_probe": refresh_available_by_probe,
        "validator_refresh_context_available_all": all(refresh_available_by_probe.values()) if refresh_available_by_probe else False,

        "warnings": warnings,

        "accepted_object_set_available": False,
        "mapping_strength_candidate": "weak",
        "strong_causal_claim_allowed": False,
        "evidence_boundary": {
            "update_cycle_not_fully_observed": not (all(refresh_available_by_probe.values()) if refresh_available_by_probe else False),
            "do_not_interpret_export_time_as_validation_start": True,
            "mapping_strength": "weak",
        },
    }

    write_jsonl(out_dir / "validator_cycle_records.jsonl", records)
    write_json(out_dir / "validator_cycle_summary.json", summary)

    txt = [
        f"M17_VALIDATOR_CYCLE_RECORD={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"window_id = {window_id}",
        f"cycle_record_count = {summary['cycle_record_count']}",
        f"probe_count = {summary['probe_count']}",
        f"validator_update_mode_set = {summary['validator_update_mode_set']}",
        f"timing_metadata_complete = {summary['timing_metadata_complete']}",
        f"export_time_span_sec = {summary['export_time_span_sec']}",
        f"temporal_alignment_quality = {summary['temporal_alignment_quality']}",
        f"validator_refresh_context_available_all = {summary['validator_refresh_context_available_all']}",
        f"accepted_object_set_available = False",
        f"mapping_strength_candidate = weak",
        f"strong_causal_claim_allowed = False",
        f"warnings = {warnings}",
        f"records_path = {out_dir / 'validator_cycle_records.jsonl'}",
        f"summary_path = {out_dir / 'validator_cycle_summary.json'}",
    ]

    (out_dir / "M17_validator_cycle_record_check.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")
    print("\n".join(txt))


if __name__ == "__main__":
    main()
