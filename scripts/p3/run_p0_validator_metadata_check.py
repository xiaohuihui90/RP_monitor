#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from s3lib.p0.jsonio import read_json, read_jsonl, write_json
from s3lib.p0.scanner import scan_window_dirs, window_id_from_dir
from s3lib.p0.timeutil import utc_now


PROBE_IDS = ("probe-bj", "probe-cd", "probe-sg")


def load_json(path: Path) -> Any | None:
    return read_json(path)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return read_jsonl(path)


def first_present(*values: Any) -> Any:
    for v in values:
        if v is not None:
            return v
    return None


def find_probe_ids(status_matrix: dict[str, Any], raw_import_manifest: dict[str, Any] | None) -> list[str]:
    probes: set[str] = set()

    if raw_import_manifest:
        for p in raw_import_manifest.get("installed_probes", []) or []:
            if isinstance(p, str):
                probes.add(p)

    for key in ["probe_status", "probe_health", "probes"]:
        v = status_matrix.get(key)
        if isinstance(v, dict):
            for k in v:
                if isinstance(k, str) and k.startswith("probe-"):
                    probes.add(k)

    for section in status_matrix.values():
        if isinstance(section, dict):
            for k in section:
                if isinstance(k, str) and k.startswith("probe-"):
                    probes.add(k)

    if not probes:
        probes.update(PROBE_IDS)

    return sorted(probes)


def index_records_by_probe(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        probe_id = r.get("probe_id") or r.get("probe") or r.get("source_probe")
        if isinstance(probe_id, str):
            out.setdefault(probe_id, []).append(r)
    return out


def get_nested(d: dict[str, Any], *keys: str) -> Any:
    cur: Any = d
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def raw_vrp_by_probe(window_dir: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    raw_root = window_dir / "outputs" / "raw_vrp"

    for manifest_path in raw_root.glob("probe-*/raw_vrp_export_manifest.json"):
        obj = read_json(manifest_path)
        if not isinstance(obj, dict):
            continue

        probe_id = obj.get("probe_id") or manifest_path.parent.name
        if not isinstance(probe_id, str):
            continue

        result[probe_id] = {
            "raw_vrp_available": True,
            "raw_vrp_manifest_path": str(manifest_path),
            "raw_vrp_path": obj.get("raw_vrp_path"),
            "raw_vrp_size_bytes": obj.get("raw_vrp_size_bytes"),
            "raw_vrp_sha256": obj.get("raw_vrp_sha256"),
            "raw_vrp_format": obj.get("format"),
            "raw_vrp_vrp_count_guess": obj.get("vrp_count_guess"),
            "raw_vrp_export_status": obj.get("status"),
        }

    return result


def compact_probe_metadata(
    probe_id: str,
    status_matrix: dict[str, Any],
    validation_records: list[dict[str, Any]],
    validator_context_records: list[dict[str, Any]],
    raw_info: dict[str, Any] | None,
) -> dict[str, Any]:
    vo = status_matrix.get("validation_output")
    vc = status_matrix.get("validator_cache_view")
    probe_health = status_matrix.get("probe_health")
    probe_status = status_matrix.get("probe_status")

    validation_by_probe = index_records_by_probe(validation_records)
    context_by_probe = index_records_by_probe(validator_context_records)

    validation_rec = validation_by_probe.get(probe_id, [{}])[-1] if validation_by_probe.get(probe_id) else {}
    context_rec = context_by_probe.get(probe_id, [{}])[-1] if context_by_probe.get(probe_id) else {}

    raw_info = raw_info or {}

    # Pull from status matrix when its schema has by-probe dicts.
    vrp_count_by_probe = get_nested(vo, "vrp_count_by_probe") if isinstance(vo, dict) else None
    vrp_root_by_probe = get_nested(vo, "vrp_root_by_probe") if isinstance(vo, dict) else None
    suspicious_by_probe = get_nested(vo, "suspicious_low_count_by_probe") if isinstance(vo, dict) else None
    quality_by_probe = get_nested(vo, "validation_output_quality_by_probe") if isinstance(vo, dict) else None
    validator_version_by_probe = get_nested(vo, "validator_version_by_probe") if isinstance(vo, dict) else None

    metadata = {
        "probe_id": probe_id,

        "probe_status": probe_status.get(probe_id) if isinstance(probe_status, dict) else None,
        "probe_health": probe_health.get(probe_id) if isinstance(probe_health, dict) else None,

        "validator": first_present(
            validation_rec.get("validator"),
            context_rec.get("validator"),
            "routinator",
        ),
        "validator_version": first_present(
            validation_rec.get("validator_version"),
            context_rec.get("validator_version"),
            validator_version_by_probe.get(probe_id) if isinstance(validator_version_by_probe, dict) else None,
        ),
        "validator_update_mode": first_present(
            validation_rec.get("validator_update_mode"),
            validation_rec.get("update_mode"),
            context_rec.get("validator_update_mode"),
            context_rec.get("update_mode"),
        ),
        "validation_output_quality": first_present(
            validation_rec.get("validation_output_quality"),
            quality_by_probe.get(probe_id) if isinstance(quality_by_probe, dict) else None,
        ),
        "suspicious_low_count": first_present(
            validation_rec.get("suspicious_low_count"),
            suspicious_by_probe.get(probe_id) if isinstance(suspicious_by_probe, dict) else None,
        ),
        "vrp_count": first_present(
            validation_rec.get("vrp_count"),
            vrp_count_by_probe.get(probe_id) if isinstance(vrp_count_by_probe, dict) else None,
            raw_info.get("raw_vrp_vrp_count_guess"),
        ),
        "vrp_root": first_present(
            validation_rec.get("vrp_root"),
            validation_rec.get("vrp_digest"),
            vrp_root_by_probe.get(probe_id) if isinstance(vrp_root_by_probe, dict) else None,
        ),

        "cache_health": first_present(
            context_rec.get("cache_health"),
            context_rec.get("validator_cache_health"),
        ),
        "last_successful_refresh_at_utc": first_present(
            context_rec.get("last_successful_refresh_at_utc"),
            context_rec.get("last_refresh_at_utc"),
            context_rec.get("last_update_done"),
        ),
        "cache_age_sec": first_present(
            context_rec.get("cache_age_sec"),
            context_rec.get("validator_cache_age_sec"),
        ),
        "refresh_duration_sec": first_present(
            context_rec.get("refresh_duration_sec"),
            context_rec.get("validator_refresh_duration_sec"),
        ),
        "validation_duration_sec": first_present(
            validation_rec.get("vrp_export_duration_sec"),
            validation_rec.get("validation_duration_sec"),
            context_rec.get("validation_duration_sec"),
        ),

        "validator_cache_view_status": first_present(
            context_rec.get("validator_cache_view_status"),
            get_nested(vc, "status") if isinstance(vc, dict) else None,
            "observed_but_unstable",
        ),
        "validator_cache_view_medium_eligible": False,
        "accepted_object_set_available": False,

        **raw_info,
    }

    important_fields = [
        "validator",
        "validator_version",
        "validator_update_mode",
        "validation_output_quality",
        "suspicious_low_count",
        "vrp_count",
        "raw_vrp_available",
        "raw_vrp_path",
    ]

    missing = []
    for key in important_fields:
        if metadata.get(key) is None:
            missing.append(key)

    metadata["missing_important_fields"] = missing
    metadata["metadata_quality"] = "ok" if not missing else "partial"

    return metadata


def build_window_metadata(window_dir: Path) -> dict[str, Any]:
    window_id = window_id_from_dir(window_dir)

    status_matrix = load_json(window_dir / "outputs" / "M245_three_layer_status_matrix.json")
    if not isinstance(status_matrix, dict):
        status_matrix = {}

    raw_import_manifest = load_json(window_dir / "outputs" / "raw_vrp_import_manifest.json")
    if not isinstance(raw_import_manifest, dict):
        raw_import_manifest = None

    validation_records = load_jsonl(window_dir / "indexes" / "merged_validation_output_light_records.jsonl")
    validator_context_records = load_jsonl(window_dir / "indexes" / "merged_validator_context_records.jsonl")

    probes = find_probe_ids(status_matrix, raw_import_manifest)
    raw_by_probe = raw_vrp_by_probe(window_dir)

    probe_metadata = {
        probe_id: compact_probe_metadata(
            probe_id=probe_id,
            status_matrix=status_matrix,
            validation_records=validation_records,
            validator_context_records=validator_context_records,
            raw_info=raw_by_probe.get(probe_id),
        )
        for probe_id in probes
    }

    raw_ready = all(probe_metadata[p].get("raw_vrp_available") is True for p in probes)

    partial_probes = [
        p for p, m in probe_metadata.items()
        if m.get("metadata_quality") != "ok"
    ]

    result = {
        "schema": "s3.p0.validator_runtime_metadata.v1",
        "generated_at_utc": utc_now(),
        "window_id": window_id,
        "window_dir": str(window_dir),
        "probe_count": len(probes),
        "probes": probes,
        "raw_vrp_ready": raw_ready,
        "validator_cache_view_status": "observed_but_unstable",
        "mapping_strength": "weak",
        "strong_attribution_allowed": False,
        "validator_cache_view_medium_eligible": False,
        "accepted_object_set_available": False,
        "probe_metadata": probe_metadata,
        "partial_probe_count": len(partial_probes),
        "partial_probes": partial_probes,
        "metadata_status": "PASS" if raw_ready and len(partial_probes) == 0 else "PARTIAL" if probe_metadata else "FAIL",
    }

    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--history-root", default="data/p3_collector/m245_three_layer_baseline/history")
    parser.add_argument("--out-dir", default="data/p3_collector/m245_three_layer_baseline/p0_acceptance")
    args = parser.parse_args()

    history_root = Path(args.history_root)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    windows = scan_window_dirs(history_root)

    records = []
    pass_count = 0
    partial_count = 0
    fail_count = 0
    raw_ready_count = 0

    for window_dir in windows:
        meta = build_window_metadata(window_dir)
        write_json(window_dir / "outputs" / "validator_runtime_metadata.json", meta)

        status = meta.get("metadata_status")
        if status == "PASS":
            pass_count += 1
        elif status == "PARTIAL":
            partial_count += 1
        else:
            fail_count += 1

        if meta.get("raw_vrp_ready"):
            raw_ready_count += 1

        records.append({
            "window_id": meta.get("window_id"),
            "window_dir": meta.get("window_dir"),
            "metadata_status": status,
            "probe_count": meta.get("probe_count"),
            "raw_vrp_ready": meta.get("raw_vrp_ready"),
            "partial_probe_count": meta.get("partial_probe_count"),
            "partial_probes": meta.get("partial_probes"),
        })

    status = "PASS" if pass_count > 0 else "PARTIAL" if partial_count > 0 else "FAIL"

    summary = {
        "schema": "s3.p0.validator_metadata_summary.v1",
        "generated_at_utc": utc_now(),
        "status": status,
        "history_root": str(history_root),
        "windows_scanned": len(windows),
        "metadata_pass_windows": pass_count,
        "metadata_partial_windows": partial_count,
        "metadata_fail_windows": fail_count,
        "raw_vrp_ready_windows": raw_ready_count,
        "records": records,
    }

    write_json(out_dir / "p0_validator_metadata_summary.json", summary)

    txt = [
        f"P0_VALIDATOR_METADATA={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"history_root = {summary['history_root']}",
        f"windows_scanned = {summary['windows_scanned']}",
        f"metadata_pass_windows = {summary['metadata_pass_windows']}",
        f"metadata_partial_windows = {summary['metadata_partial_windows']}",
        f"metadata_fail_windows = {summary['metadata_fail_windows']}",
        f"raw_vrp_ready_windows = {summary['raw_vrp_ready_windows']}",
    ]

    (out_dir / "p0_validator_metadata_summary.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")
    print("\n".join(txt))


if __name__ == "__main__":
    main()
