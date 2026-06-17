#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts.p3.m17.scanners.common import (
    PROBES,
    OBJECT_ROOT_WHITELIST,
    collect_sha256_roots,
    infer_object_export_from_path,
    infer_probe_id_from_path,
    infer_snapshot_group_from_path,
    iter_files,
    latest_group_dir,
    safe_read_json,
    unique_nonempty,
)


def classify_root_key(root_key: str) -> tuple[str, str, str]:
    k = root_key.lower()

    if "object_set_root" in k or "effective_object_root" in k or "all_object_root" in k or "semantic_object_root" in k:
        return "O1_OBJECT_ROOT_DIVERGENCE", "high", "object_root_divergent_requires_diff"

    if "mft" in k or "manifest" in k:
        return "O2_MFT_ROOT_DIVERGENCE", "warning", "manifest_version_skew_possible"

    if "roa_vrp_key" in k:
        return "O3_ROA_ROOT_DIVERGENCE", "critical", "not_temporal_skew"

    if "roa" in k:
        return "O3_ROA_ROOT_DIVERGENCE", "high", "not_assessed"

    if "cer" in k or "certificate" in k or "chain" in k or "resource" in k:
        return "O4_CER_ROOT_DIVERGENCE", "high", "not_assessed"

    if "crl" in k:
        return "O5_CRL_ROOT_DIVERGENCE", "high", "crl_freshness_skew_possible"

    return "O6_AUXILIARY_OBJECT_ROOT_DIVERGENCE", "warning", "not_assessed"


def collect_probe_roots(object_group: Path) -> Dict[str, Dict[str, Any]]:
    per_probe: Dict[str, Dict[str, Any]] = {}

    for probe in PROBES:
        probe_dir = object_group / probe / "object"
        if not probe_dir.exists():
            probe_dir = object_group / probe

        if not probe_dir.exists():
            per_probe[probe] = {
                "probe_id": probe,
                "exists": False,
                "summary_files": [],
                "roots": {},
            }
            continue

        files = iter_files(
            probe_dir,
            suffixes=(".json",),
            include_substrings=["summary", "root", "acceptance", "snapshot", "semantic", "rollup", "gate"],
            max_files=200,
            max_depth=5,
        )

        roots: Dict[str, str] = {}
        summaries: List[str] = []

        for p in files:
            obj = safe_read_json(p)
            if obj is None:
                continue
            summaries.append(str(p))
            roots.update(collect_sha256_roots(obj, whitelist_only=True))

        per_probe[probe] = {
            "probe_id": probe,
            "exists": True,
            "summary_files": summaries,
            "roots": roots,
        }

    return per_probe


def build_root_diff_summary(per_probe: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    keys = sorted(set().union(*[set(v.get("roots", {}).keys()) for v in per_probe.values()]))
    root_keys: Dict[str, Any] = {}

    for key in keys:
        values_by_probe = {}
        for probe, info in per_probe.items():
            value = (info.get("roots") or {}).get(key)
            if value:
                values_by_probe[probe] = value

        uniques = unique_nonempty(values_by_probe.values())

        root_keys[key] = {
            "values_by_probe": values_by_probe,
            "unique_count": len(uniques),
            "aligned": len(uniques) <= 1 if values_by_probe else None,
        }

    return {
        "root_keys": root_keys,
        "divergent_root_keys": [
            k for k, v in root_keys.items()
            if v.get("unique_count", 0) > 1
        ],
    }


def scan_object_view(
    *,
    collector_root: Path,
    object_group_dir: Optional[str] = None,
    max_context_age_seconds: int = 86400,
) -> Dict[str, Any]:
    group = latest_group_dir(collector_root, object_group_dir)

    if group is None:
        return {
            "scanner": "object_view_scanner",
            "object_group_dir": None,
            "signal_count": 0,
            "signals": [],
            "warning": "object_group_dir_not_found",
        }

    per_probe = collect_probe_roots(group)
    diff_summary = build_root_diff_summary(per_probe)

    missing = [p for p, info in per_probe.items() if not info.get("exists")]
    signals: List[Dict[str, Any]] = []

    snapshot_group_id = infer_snapshot_group_from_path(group)
    object_export_id = infer_object_export_from_path(group)

    if missing:
        signals.append({
            "layer": "object_view",
            "anomaly_type": "O7_OBJECT_EXPORT_MISSING_OR_STALE",
            "severity": "warning",
            "snapshot_group_id": snapshot_group_id,
            "object_export_id": object_export_id,
            "probes": PROBES,
            "validators": ["routinator"],
            "trigger_signals": {
                "object_group_dir": str(group),
                "missing_probes": missing,
            },
            "temporal_skew_class": "context_stale",
            "requires_resample": True,
            "context_summary": {
                "object_group_dir": str(group),
                "per_probe": per_probe,
                "diff_summary": diff_summary,
            },
        })

    for root_key in diff_summary.get("divergent_root_keys", []):
        anomaly_type, severity, temporal_class = classify_root_key(root_key)
        signals.append({
            "layer": "object_view",
            "anomaly_type": anomaly_type,
            "severity": severity,
            "snapshot_group_id": snapshot_group_id,
            "object_export_id": object_export_id,
            "probes": PROBES,
            "validators": ["routinator"],
            "trigger_signals": {
                "object_group_dir": str(group),
                "root_key": root_key,
                "values_by_probe": diff_summary["root_keys"][root_key]["values_by_probe"],
            },
            "temporal_skew_class": temporal_class,
            "requires_resample": temporal_class not in {"not_temporal_skew"},
            "context_summary": {
                "object_group_dir": str(group),
                "per_probe": per_probe,
                "diff_summary": diff_summary,
            },
        })

    return {
        "scanner": "object_view_scanner",
        "object_group_dir": str(group),
        "snapshot_group_id": snapshot_group_id,
        "object_export_id": object_export_id,
        "probe_count": len(per_probe),
        "divergent_root_key_count": len(diff_summary.get("divergent_root_keys", [])),
        "signal_count": len(signals),
        "signals": signals,
        "object_summary": {
            "object_group_dir": str(group),
            "per_probe": per_probe,
            "diff_summary": diff_summary,
        },
    }
