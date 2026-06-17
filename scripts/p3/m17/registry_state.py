#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts.p3.m17.registry import make_event_fingerprint
from scripts.p3.m17.io_utils import append_jsonl, write_json


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def registry_path(out_root: Path) -> Path:
    return Path(out_root) / "anomaly_event_registry.jsonl"


def read_registry_rows(out_root: Path) -> List[Dict[str, Any]]:
    p = registry_path(out_root)
    if not p.exists():
        return []

    rows: List[Dict[str, Any]] = []
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def row_from_event(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "event_id": event.get("event_id"),
        "event_fingerprint": event.get("event_fingerprint"),
        "first_seen_utc": event.get("first_seen_utc"),
        "last_seen_utc": event.get("last_seen_utc"),
        "occurrence_count": event.get("occurrence_count", 1),
        "layer": event.get("layer"),
        "anomaly_type": event.get("anomaly_type"),
        "severity": event.get("severity"),
        "temporal_skew_class": (event.get("temporal_context") or {}).get("temporal_skew_class"),
        "status": event.get("current_status"),
        "workspace": event.get("workspace"),
    }


def append_registry_event(out_root: Path, event: Dict[str, Any]) -> None:
    append_jsonl(registry_path(out_root), row_from_event(event))


def fingerprint_for_signal(signal: Dict[str, Any]) -> str:
    return make_event_fingerprint(
        layer=signal.get("layer"),
        anomaly_type=signal.get("anomaly_type"),
        pp_id=signal.get("pp_id"),
        repo_host=signal.get("repo_host"),
        snapshot_group_id=signal.get("snapshot_group_id"),
        object_export_id=signal.get("object_export_id"),
        probes=signal.get("probes") or [],
        validators=signal.get("validators") or [],
        trigger_signals=signal.get("trigger_signals") or {},
    )


def find_existing_workspace_for_signal(out_root: Path, signal: Dict[str, Any]) -> Optional[Path]:
    fp = fingerprint_for_signal(signal)
    rows = read_registry_rows(out_root)

    for row in reversed(rows):
        if row.get("event_fingerprint") != fp:
            continue

        ws = row.get("workspace")
        if not ws:
            continue

        p = Path(ws)
        if p.exists() and (p / "anomaly_event.json").exists():
            return p

    return None


def update_existing_workspace_occurrence(
    *,
    out_root: Path,
    workspace: Path,
    signal: Dict[str, Any],
) -> Dict[str, Any]:
    workspace = Path(workspace)
    event_path = workspace / "anomaly_event.json"
    event = read_json(event_path)

    now = utc_now_iso()

    event["last_seen_utc"] = now
    event["occurrence_count"] = int(event.get("occurrence_count") or 1) + 1
    event["trigger_signals"] = signal.get("trigger_signals") or event.get("trigger_signals") or {}

    tc = event.get("temporal_context") or {}
    if signal.get("temporal_skew_class"):
        tc["temporal_skew_class"] = signal.get("temporal_skew_class")
    if "requires_resample" in signal:
        tc["requires_resample"] = bool(signal.get("requires_resample"))
    tc["e4_confirmation_allowed"] = False
    event["temporal_context"] = tc

    event["current_status"] = event.get("current_status") or "MANUAL_ATTRIBUTION_READY"

    write_json(event_path, event)

    history_row = {
        "ts_utc": now,
        "type": "dedup_occurrence_update",
        "occurrence_count": event.get("occurrence_count"),
        "layer": event.get("layer"),
        "anomaly_type": event.get("anomaly_type"),
        "temporal_skew_class": tc.get("temporal_skew_class"),
        "signal_digest": signal.get("trigger_signals"),
    }
    append_jsonl(workspace / "occurrence_history.jsonl", history_row)

    append_registry_event(out_root, event)

    return event


def compact_registry(out_root: Path) -> Dict[str, Any]:
    rows = read_registry_rows(out_root)

    grouped: Dict[str, Dict[str, Any]] = {}

    for row in rows:
        key = row.get("event_fingerprint") or row.get("event_id")
        if not key:
            continue

        cur = grouped.get(key)
        if cur is None:
            grouped[key] = dict(row)
            grouped[key]["registry_row_count"] = 1
            continue

        cur["registry_row_count"] = int(cur.get("registry_row_count") or 1) + 1

        if row.get("first_seen_utc") and (
            not cur.get("first_seen_utc") or row.get("first_seen_utc") < cur.get("first_seen_utc")
        ):
            cur["first_seen_utc"] = row.get("first_seen_utc")

        if row.get("last_seen_utc") and (
            not cur.get("last_seen_utc") or row.get("last_seen_utc") > cur.get("last_seen_utc")
        ):
            cur["last_seen_utc"] = row.get("last_seen_utc")

        cur["occurrence_count"] = max(
            int(cur.get("occurrence_count") or 1),
            int(row.get("occurrence_count") or 1),
        )

        for k in ["event_id", "workspace", "status", "severity", "temporal_skew_class"]:
            if row.get(k):
                cur[k] = row.get(k)

    compacted = sorted(
        grouped.values(),
        key=lambda x: x.get("last_seen_utc") or x.get("first_seen_utc") or "",
        reverse=True,
    )

    compacted_path = Path(out_root) / "anomaly_event_registry_compacted.jsonl"
    with compacted_path.open("w", encoding="utf-8") as f:
        for row in compacted:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=False) + "\n")

    index = {
        "schema": "s3.m17.registry_index.v1",
        "generated_at_utc": utc_now_iso(),
        "out_root": str(out_root),
        "raw_row_count": len(rows),
        "unique_event_count": len(compacted),
        "events": compacted,
    }

    write_json(Path(out_root) / "registry_index.json", index)

    return {
        "raw_row_count": len(rows),
        "unique_event_count": len(compacted),
        "compacted_path": str(compacted_path),
        "index_path": str(Path(out_root) / "registry_index.json"),
    }


def update_status(
    *,
    workspace: Path,
    status: str,
    note: str,
    actor: str = "manual",
) -> Dict[str, Any]:
    workspace = Path(workspace)
    event_path = workspace / "anomaly_event.json"
    event = read_json(event_path)

    if not event:
        raise RuntimeError(f"cannot read anomaly_event.json: {event_path}")

    now = utc_now_iso()
    old_status = event.get("current_status")

    event["current_status"] = status
    event["last_status_update_utc"] = now

    write_json(event_path, event)

    row = {
        "ts_utc": now,
        "actor": actor,
        "old_status": old_status,
        "new_status": status,
        "note": note,
    }
    append_jsonl(workspace / "status_history.jsonl", row)

    return {
        "event_id": event.get("event_id"),
        "workspace": str(workspace),
        "old_status": old_status,
        "new_status": status,
        "note": note,
        "status_history": str(workspace / "status_history.jsonl"),
    }
