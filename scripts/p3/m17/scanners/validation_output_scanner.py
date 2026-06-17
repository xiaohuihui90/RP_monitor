#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts.p3.m17.scanners.common import (
    PROBES,
    flatten_dict,
    infer_probe_id_from_path,
    iter_files,
    safe_read_json,
    seconds_skew,
    unique_nonempty,
)


COUNT_KEYS = [
    "vrp_count",
    "roa_count",
    "router_key_count",
    "aspa_count",
]

ROOT_KEYS = [
    "vrp_root",
    "vrp_digest",
    "router_key_root",
    "router_key_digest",
    "aspa_root",
    "aspa_digest",
]

CONFIG_KEYS = [
    "validator_version",
    "routinator_version",
    "config_fingerprint",
    "stable_config_fingerprint",
    "runtime_process_fingerprint",
    "tal_set_digest",
]


def looks_like_output_record(flat: Dict[str, Any]) -> bool:
    keys = set(k.split(".")[-1] for k in flat.keys())
    if keys.intersection(COUNT_KEYS):
        return True
    if keys.intersection(ROOT_KEYS):
        return True
    if keys.intersection(CONFIG_KEYS):
        return True
    if "last_update_done" in keys:
        return True
    return False


def extract_value(flat: Dict[str, Any], key: str) -> Any:
    for k, v in flat.items():
        if k.split(".")[-1] == key:
            return v
    return None


def collect_records_from_json(path: Path, obj: Any) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []

    if isinstance(obj, dict) and isinstance(obj.get("per_probe"), dict):
        for probe, value in obj["per_probe"].items():
            if isinstance(value, dict):
                flat = flatten_dict(value)
                rec = {"probe_id": probe, "source_file": str(path)}
                for key in COUNT_KEYS + ROOT_KEYS + CONFIG_KEYS + ["last_update_done"]:
                    val = extract_value(flat, key)
                    if val is not None:
                        rec[key] = val
                if looks_like_output_record(flat):
                    records.append(rec)

    def walk(x: Any, inherited_probe: Optional[str] = None) -> None:
        if isinstance(x, dict):
            probe = x.get("probe_id") or x.get("probe") or inherited_probe
            if probe is None:
                probe = infer_probe_id_from_path(path)

            flat = flatten_dict(x)
            if looks_like_output_record(flat):
                rec = {
                    "probe_id": str(probe) if probe else "unknown_probe",
                    "source_file": str(path),
                }
                for key in COUNT_KEYS + ROOT_KEYS + CONFIG_KEYS + ["last_update_done"]:
                    val = extract_value(flat, key)
                    if val is not None:
                        rec[key] = val
                records.append(rec)

            for v in x.values():
                walk(v, probe)

        elif isinstance(x, list):
            for v in x:
                walk(v, inherited_probe)

    walk(obj)

    dedup = {}
    for r in records:
        key = (
            r.get("probe_id"),
            r.get("source_file"),
            tuple(sorted((k, str(v)) for k, v in r.items() if k not in {"source_file"})),
        )
        dedup[key] = r

    return list(dedup.values())


def find_validation_records(collector_root: Path, *, max_files: int = 300) -> List[Dict[str, Any]]:
    files = iter_files(
        collector_root,
        suffixes=(".json",),
        include_substrings=[
            "validator",
            "output_summary",
            "vrp",
            "routinator",
            "cache_source_compare",
            "config_context",
            "repository_status",
            "m14",
            "m15",
            "m16",
        ],
        max_files=max_files,
        max_depth=9,
    )

    records: List[Dict[str, Any]] = []
    for p in files:
        obj = safe_read_json(p)
        if obj is None:
            continue
        records.extend(collect_records_from_json(p, obj))

    return records


def group_latest_by_probe(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for r in records:
        probe = r.get("probe_id") or "unknown_probe"
        if probe not in PROBES:
            continue
        if probe not in out:
            out[probe] = r
        else:
            old_score = len(out[probe].keys())
            new_score = len(r.keys())
            if new_score > old_score:
                out[probe] = r
    return out


def values_by_probe(latest: Dict[str, Dict[str, Any]], key: str) -> Dict[str, Any]:
    out = {}
    for probe, r in latest.items():
        if key in r and r[key] not in (None, ""):
            out[probe] = r[key]
    return out


def scan_validation_output(
    *,
    collector_root: Path,
    validator: str = "routinator",
    strong_cycle_skew_seconds: int = 120,
) -> Dict[str, Any]:
    records = find_validation_records(collector_root)
    latest = group_latest_by_probe(records)

    signals: List[Dict[str, Any]] = []

    count_diff = {}
    for key in COUNT_KEYS:
        vals = values_by_probe(latest, key)
        uniques = unique_nonempty(vals.values())
        if len(uniques) > 1:
            count_diff[key] = vals

    if count_diff:
        last_update = values_by_probe(latest, "last_update_done")
        skew = seconds_skew(last_update.values())

        temporal_class = "validator_cycle_skew_likely" if skew is not None and skew > strong_cycle_skew_seconds else "not_assessed"

        signals.append({
            "layer": "validation_output_view",
            "anomaly_type": "V1_VALIDATOR_OUTPUT_COUNT_DIVERGENCE",
            "severity": "warning",
            "probes": sorted(latest.keys()),
            "validators": [validator],
            "trigger_signals": {
                "count_diff": count_diff,
                "last_update_done": last_update,
                "validator_cycle_skew_seconds": skew,
            },
            "temporal_skew_class": temporal_class,
            "requires_resample": True,
            "context_summary": {
                "latest_by_probe": latest,
                "record_count": len(records),
            },
        })

    root_diff = {}
    for key in ROOT_KEYS:
        vals = values_by_probe(latest, key)
        uniques = unique_nonempty(vals.values())
        if len(uniques) > 1:
            root_diff[key] = vals

    if root_diff:
        last_update = values_by_probe(latest, "last_update_done")
        skew = seconds_skew(last_update.values())
        temporal_class = "validator_cycle_skew_likely" if skew is not None and skew > strong_cycle_skew_seconds else "not_assessed"

        signals.append({
            "layer": "validation_output_view",
            "anomaly_type": "V2_VALIDATOR_OUTPUT_ROOT_DIVERGENCE",
            "severity": "high",
            "probes": sorted(latest.keys()),
            "validators": [validator],
            "trigger_signals": {
                "root_diff": root_diff,
                "last_update_done": last_update,
                "validator_cycle_skew_seconds": skew,
            },
            "temporal_skew_class": temporal_class,
            "requires_resample": True,
            "context_summary": {
                "latest_by_probe": latest,
                "record_count": len(records),
            },
        })

    last_update = values_by_probe(latest, "last_update_done")
    skew = seconds_skew(last_update.values())
    if skew is not None and skew > strong_cycle_skew_seconds:
        signals.append({
            "layer": "validation_output_view",
            "anomaly_type": "V4_VALIDATOR_CYCLE_SKEW",
            "severity": "warning",
            "probes": sorted(latest.keys()),
            "validators": [validator],
            "trigger_signals": {
                "last_update_done": last_update,
                "validator_cycle_skew_seconds": skew,
            },
            "temporal_skew_class": "validator_cycle_skew_likely",
            "requires_resample": True,
            "context_summary": {
                "latest_by_probe": latest,
                "record_count": len(records),
            },
        })

    config_diff = {}
    for key in CONFIG_KEYS:
        vals = values_by_probe(latest, key)
        uniques = unique_nonempty(vals.values())
        if len(uniques) > 1:
            config_diff[key] = vals

    if config_diff:
        signals.append({
            "layer": "validation_output_view",
            "anomaly_type": "V5_VALIDATOR_CONFIG_DRIFT",
            "severity": "warning",
            "probes": sorted(latest.keys()),
            "validators": [validator],
            "trigger_signals": {
                "config_diff": config_diff,
            },
            "temporal_skew_class": "not_temporal_skew",
            "requires_resample": False,
            "context_summary": {
                "latest_by_probe": latest,
                "record_count": len(records),
            },
        })

    return {
        "scanner": "validation_output_scanner",
        "record_count": len(records),
        "probe_count": len(latest),
        "signal_count": len(signals),
        "signals": signals,
        "latest_by_probe": latest,
    }
