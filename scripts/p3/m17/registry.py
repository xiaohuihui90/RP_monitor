#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.p3.m17.io_utils import append_jsonl, write_text


def stable_json_digest(obj: Any) -> str:
    raw = json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def make_event_fingerprint(
    *,
    layer: str,
    anomaly_type: str,
    pp_id: str | None,
    repo_host: str | None,
    snapshot_group_id: str | None,
    object_export_id: str | None,
    probes: List[str],
    validators: List[str],
    trigger_signals: Dict[str, Any],
) -> str:
    base = {
        "layer": layer,
        "anomaly_type": anomaly_type,
        "pp_id": pp_id,
        "repo_host": repo_host,
        "snapshot_group_id": snapshot_group_id,
        "object_export_id": object_export_id,
        "probes": sorted(probes or []),
        "validators": sorted(validators or []),
        "trigger_signals": trigger_signals or {},
    }
    return stable_json_digest(base)


def append_registry(
    *,
    registry_path: Path,
    event: Dict[str, Any],
) -> None:
    row = {
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
    append_jsonl(registry_path, row)


def write_registry_readme(out_root: Path) -> None:
    text = """# M17 anomaly registry

This directory stores M17 anomaly events.

Key files:
- anomaly_event_registry.jsonl: append-only anomaly registry
- anom_*/: per-event evidence workspace

M17-A creates synthetic/manual anomaly workspaces for smoke testing.
Later M17 batches will add automatic scanners for advertised_view, object_view, and validation_output_view.
"""
    write_text(out_root / "README.md", text)
