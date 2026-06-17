#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts.p3.m17.scanners.common import (
    dt_to_iso,
    first_value,
    infer_probe_id_from_path,
    iter_files,
    normalize_status,
    parse_dt,
    seconds_skew,
    serials_nearby,
    safe_read_jsonl,
    unique_nonempty,
)


def normalize_announced_row(row: Dict[str, Any], path: Path) -> Optional[Dict[str, Any]]:
    pp_id = first_value(row, ["pp_id", "rir", "repository", "repo_id"])
    probe_id = first_value(row, ["probe_id", "probe"]) or infer_probe_id_from_path(path)

    session_id = first_value(row, ["session_id", "sessionId", "rrdp_session_id"])
    serial = first_value(row, ["serial", "rrdp_serial"])
    notif_digest = first_value(row, [
        "notif_digest",
        "notification_digest",
        "notification_xml_sha256",
        "notification_sha256",
        "digest",
    ])

    fetch_status = normalize_status(first_value(row, ["fetch_status", "status", "result"]))
    observed_at = first_value(row, [
        "observed_at_utc",
        "generated_at_utc",
        "created_at_utc",
        "timestamp",
        "time_utc",
        "collected_at_utc",
    ])

    http_status = first_value(row, ["http_status", "status_code"])
    latency_ms = first_value(row, ["latency_ms", "elapsed_ms", "duration_ms"])
    failure_stage = first_value(row, ["failure_stage", "stage"])
    error_class = first_value(row, ["error_class", "error", "exception_class"])

    if not pp_id and not session_id and not serial and not notif_digest and fetch_status == "unknown":
        return None

    return {
        "source_file": str(path),
        "pp_id": str(pp_id) if pp_id is not None else "unknown_pp",
        "probe_id": str(probe_id) if probe_id is not None else "unknown_probe",
        "session_id": session_id,
        "serial": serial,
        "notif_digest": notif_digest,
        "fetch_status": fetch_status,
        "observed_at_utc": observed_at,
        "http_status": http_status,
        "latency_ms": latency_ms,
        "failure_stage": failure_stage,
        "error_class": error_class,
    }


def find_announced_rows(collector_root: Path, *, max_files: int = 80) -> List[Dict[str, Any]]:
    files = iter_files(
        collector_root,
        suffixes=(".jsonl",),
        include_names=["announced_view_records.jsonl", "level1_records.jsonl"],
        include_substrings=["announced_view", "level1"],
        max_files=max_files,
        max_depth=9,
    )

    rows: List[Dict[str, Any]] = []
    for p in files:
        for row in safe_read_jsonl(p, max_lines=20000):
            norm = normalize_announced_row(row, p)
            if norm:
                rows.append(norm)

    return rows


def latest_by_pp_probe(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    out: Dict[str, Dict[str, Dict[str, Any]]] = {}

    for r in rows:
        pp = r.get("pp_id") or "unknown_pp"
        probe = r.get("probe_id") or "unknown_probe"
        cur = out.setdefault(pp, {}).get(probe)

        new_dt = parse_dt(r.get("observed_at_utc"))
        cur_dt = parse_dt(cur.get("observed_at_utc")) if cur else None

        if cur is None or (new_dt and cur_dt and new_dt > cur_dt) or (new_dt and not cur_dt):
            out.setdefault(pp, {})[probe] = r
        elif cur is None:
            out.setdefault(pp, {})[probe] = r

    return out


def signal_for_pp(pp_id: str, probe_rows: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    signals: List[Dict[str, Any]] = []
    rows = list(probe_rows.values())

    probes = sorted([r.get("probe_id") for r in rows if r.get("probe_id")])
    statuses = {r.get("probe_id"): r.get("fetch_status") for r in rows}
    sessions = {r.get("probe_id"): r.get("session_id") for r in rows}
    serials = {r.get("probe_id"): r.get("serial") for r in rows}
    digests = {r.get("probe_id"): r.get("notif_digest") for r in rows}
    times = {r.get("probe_id"): r.get("observed_at_utc") for r in rows}

    success_rows = [r for r in rows if r.get("fetch_status") == "success"]
    failed_rows = [r for r in rows if r.get("fetch_status") not in {"success", "unknown"}]

    if failed_rows:
        signals.append({
            "layer": "advertised_view",
            "anomaly_type": "A1_NOTIFICATION_FETCH_FAILURE",
            "severity": "warning",
            "pp_id": pp_id,
            "probes": probes,
            "validators": ["routinator"],
            "trigger_signals": {
                "statuses": statuses,
                "failures": failed_rows[:10],
            },
            "temporal_skew_class": "not_assessed",
            "requires_resample": True,
            "context_rows": rows,
        })

    if len(success_rows) >= 2:
        unique_sessions = unique_nonempty([r.get("session_id") for r in success_rows])
        unique_serials = unique_nonempty([r.get("serial") for r in success_rows])
        unique_digests = unique_nonempty([r.get("notif_digest") for r in success_rows])

        same_session = len(unique_sessions) == 1
        same_serial = len(unique_serials) == 1

        if same_session and same_serial and len(unique_digests) > 1:
            signals.append({
                "layer": "advertised_view",
                "anomaly_type": "A2_NOTIFICATION_DIGEST_DIVERGENCE",
                "severity": "high",
                "pp_id": pp_id,
                "probes": probes,
                "validators": ["routinator"],
                "trigger_signals": {
                    "session_id": unique_sessions[0],
                    "serial": unique_serials[0],
                    "digests": digests,
                },
                "temporal_skew_class": "not_temporal_skew",
                "requires_resample": False,
                "context_rows": rows,
            })

        elif len(unique_sessions) > 1 or len(unique_serials) > 1:
            skew = seconds_skew([r.get("observed_at_utc") for r in success_rows])
            temporal_class = "normal_rrdp_version_skew_likely" if same_session and serials_nearby(unique_serials) else "insufficient_temporal_context"

            signals.append({
                "layer": "advertised_view",
                "anomaly_type": "A3_RRDP_VERSION_SKEW",
                "severity": "warning",
                "pp_id": pp_id,
                "probes": probes,
                "validators": ["routinator"],
                "trigger_signals": {
                    "sessions": sessions,
                    "serials": serials,
                    "digests": digests,
                    "observed_at_utc": times,
                    "max_probe_time_skew_seconds": skew,
                },
                "temporal_skew_class": temporal_class,
                "requires_resample": True,
                "context_rows": rows,
            })

    return signals


def scan_advertised_view(
    *,
    collector_root: Path,
    window_seconds: int = 300,
    max_files: int = 80,
) -> Dict[str, Any]:
    rows = find_announced_rows(collector_root, max_files=max_files)
    by_pp_probe = latest_by_pp_probe(rows)

    signals: List[Dict[str, Any]] = []
    for pp_id, probe_rows in sorted(by_pp_probe.items()):
        if len(probe_rows) < 2:
            continue
        signals.extend(signal_for_pp(pp_id, probe_rows))

    return {
        "scanner": "advertised_view_scanner",
        "input_record_count": len(rows),
        "pp_count": len(by_pp_probe),
        "signal_count": len(signals),
        "signals": signals,
    }
