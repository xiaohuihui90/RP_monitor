#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional


@dataclass
class AnomalyEvent:
    schema: str = "s3.m17.anomaly_event.v1"

    event_id: str = ""
    event_fingerprint: str = ""
    created_at_utc: str = ""
    first_seen_utc: str = ""
    last_seen_utc: str = ""
    occurrence_count: int = 1

    layer: str = ""
    anomaly_type: str = ""
    severity: str = "warning"

    window_id: Optional[str] = None
    snapshot_group_id: Optional[str] = None
    object_export_id: Optional[str] = None

    pp_id: Optional[str] = None
    repo_host: Optional[str] = None
    probes: List[str] = field(default_factory=list)
    validators: List[str] = field(default_factory=list)

    trigger_signals: Dict[str, Any] = field(default_factory=dict)
    temporal_context: Dict[str, Any] = field(default_factory=dict)

    current_status: str = "MANUAL_ATTRIBUTION_READY"
    manual_attribution_ready: bool = True
    auto_attribution_supported: bool = False
    e4_confirmation_allowed: bool = False

    workspace: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WorkspacePaths:
    workspace: str
    anomaly_event: str
    metadata: str
    layer_context_summary: str
    related_files: str
    recommended_manual_actions: str
    commands_sh: str
    initial_decision: str
    temporal_context_dir: str
    advertised_view_dir: str
    object_view_dir: str
    validation_output_view_dir: str
    manual_results_dir: str
    reproduce_dir: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
