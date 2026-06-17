#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts.p3.m17.io_utils import ensure_dir, write_json, write_text
from scripts.p3.m17.models import AnomalyEvent, WorkspacePaths
from scripts.p3.m17.registry import append_registry, make_event_fingerprint, write_registry_readme
from scripts.p3.m17.time_utils import utc_now_iso, utc_compact


VALID_LAYERS = {
    "advertised_view",
    "object_view",
    "validation_output_view",
    "cross_layer",
}


def default_temporal_context(
    *,
    window_seconds: Optional[int] = None,
    temporal_skew_class: str = "not_assessed",
    requires_resample: bool = False,
    e4_confirmation_allowed: bool = False,
) -> Dict[str, Any]:
    return {
        "schema": "s3.m17.temporal_context.v1",
        "window_start_utc": None,
        "window_end_utc": None,
        "window_seconds": window_seconds,
        "probe_observation_times": {},
        "max_probe_time_skew_seconds": None,
        "rrdp_versions": {},
        "validator_last_update_done": {},
        "validator_cycle_skew_seconds": None,
        "object_context_age_seconds": None,
        "validation_output_context_age_seconds": None,
        "temporal_skew_class": temporal_skew_class,
        "requires_resample": requires_resample,
        "resample_after_seconds": window_seconds,
        "confidence": "not_assessed",
        "e4_confirmation_allowed": e4_confirmation_allowed,
    }


def default_layer_context_summary(event_id: str, layer: str) -> Dict[str, Any]:
    return {
        "schema": "s3.m17.layer_context_summary.v1",
        "event_id": event_id,
        "advertised_view": {
            "available": layer == "advertised_view",
            "status": "not_collected",
            "session_id_aligned": None,
            "serial_aligned": None,
            "notif_digest_aligned": None,
            "fetch_success_ratio": None,
            "context_age_seconds": None,
        },
        "object_view": {
            "available": layer == "object_view",
            "status": "not_collected",
            "object_context_stale": None,
            "all_object_root_aligned": None,
            "type_roots": {},
        },
        "validation_output_view": {
            "available": layer == "validation_output_view",
            "status": "not_collected",
            "vrp_count_aligned": None,
            "vrp_root_aligned": None,
            "validator_cycle_skew_seconds": None,
            "validator_config_aligned": None,
        },
        "skew_assessment": {
            "overall_temporal_skew_class": "not_assessed",
            "requires_resample": False,
            "e4_confirmation_allowed": False,
        },
    }


def recommended_actions_for_layer(layer: str, anomaly_type: str) -> Dict[str, Any]:
    actions: List[Dict[str, Any]] = []

    if layer == "advertised_view":
        actions.extend([
            {
                "action_id": "inspect_advertised_view_context",
                "layer": "advertised_view",
                "priority": "high",
                "implemented": True,
                "description": "Inspect Level-1 records, session_id, serial, notif_digest, fetch_status, latency, failure_stage, and error_class.",
            },
            {
                "action_id": "run_l2_notif_refs_or_path_evidence",
                "layer": "advertised_view",
                "priority": "medium",
                "implemented": "existing_or_partial",
                "description": "Run L2 notification references or path evidence collection if the anomaly is persistent or high severity.",
            },
        ])

    if layer == "object_view":
        actions.extend([
            {
                "action_id": "inspect_object_root_summary",
                "layer": "object_view",
                "priority": "high",
                "implemented": True,
                "description": "Inspect available object root and semantic root summaries.",
            },
            {
                "action_id": "run_all_object_pairwise_compare",
                "layer": "object_view",
                "priority": "high",
                "implemented": "planned_m18_m19",
                "description": "Run all-object URI/hash compare and generate object_diff_index.",
            },
            {
                "action_id": "run_frozen_semantic_diff_for_skew_check",
                "layer": "object_view",
                "priority": "medium",
                "implemented": "planned_m19",
                "description": "Run frozen semantic diff for MFT/ROA/CER/CRL diff objects.",
            },
        ])

    if layer == "validation_output_view":
        actions.extend([
            {
                "action_id": "inspect_validator_output_summary",
                "layer": "validation_output_view",
                "priority": "high",
                "implemented": True,
                "description": "Inspect vrp_count, router_key_count, aspa_count, last_update_done, repository_status, and validator config context.",
            },
            {
                "action_id": "run_synchronized_vrp_export",
                "layer": "validation_output_view",
                "priority": "high",
                "implemented": "partial",
                "description": "Export full VRP after validator cycles are comparable; do not confirm E4 before cycle skew is resolved.",
            },
            {
                "action_id": "run_canonical_vrp_diff",
                "layer": "validation_output_view",
                "priority": "medium",
                "implemented": "planned_m21",
                "description": "Run canonical VRP entry-level diff.",
            },
        ])

    actions.append({
        "action_id": "attach_manual_results",
        "layer": layer,
        "priority": "medium",
        "implemented": True,
        "description": "Place manually generated evidence files under manual_results/ and update anomaly status.",
    })

    return {
        "schema": "s3.m17.recommended_manual_actions.v1",
        "event_id": None,
        "anomaly_type": anomaly_type,
        "actions": actions,
    }


def initial_decision_text(
    *,
    layer: str,
    anomaly_type: str,
    severity: str,
    temporal_skew_class: str,
    requires_resample: bool,
) -> str:
    if temporal_skew_class not in {"not_assessed", "not_temporal_skew"} or requires_resample:
        decision = "TEMPORAL_SKEW_CANDIDATE"
        confirmed = "false"
        reason = (
            "The anomaly may be caused by normal temporal version skew, stale object context, "
            "or validator cycle skew. M17 does not perform final attribution. "
            "Resampling, synchronized export, or manual inspection is required."
        )
    else:
        decision = "MANUAL_ATTRIBUTION_REQUIRED"
        confirmed = "unknown"
        reason = (
            "M17 detected an anomaly signal and prepared an evidence workspace. "
            "Manual object diff, semantic diff, or validator output diff may be required."
        )

    return f"""M17_INITIAL_DECISION={decision}

layer = {layer}
anomaly_type = {anomaly_type}
severity = {severity}

confirmed_anomaly = {confirmed}
e4_confirmation_allowed = false
requires_resample = {str(requires_resample).lower()}

reason = {reason}

recommended_next_steps:
1. Inspect anomaly_event.json.
2. Inspect temporal_context/version_skew_assessment.json.
3. Inspect layer_context_summary.json.
4. Inspect recommended_manual_actions.json.
5. Run commands.sh manually if deeper analysis is needed.
"""


def commands_template(workspace: Path) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail

cd ~/s3_stage3_v3_code
source ~/.bashrc || true
conda activate s3-radar

export PYTHONNOUSERSITE=1
export PYTHONPATH="$PWD:${{PYTHONPATH:-}}"
export WORKSPACE="{workspace}"

echo "========== STEP 1: INSPECT ANOMALY =========="
python scripts/p3/m17/cli/inspect_anomaly_event.py --workspace "$WORKSPACE"

echo
echo "========== STEP 2: TEMPORAL CONTEXT =========="
cat "$WORKSPACE/temporal_context/version_skew_assessment.json" \\
  | python -m json.tool \\
  | sed -n '1,240p'

echo
echo "========== STEP 3: LAYER CONTEXT =========="
cat "$WORKSPACE/layer_context_summary.json" \\
  | python -m json.tool \\
  | sed -n '1,240p'

echo
echo "========== STEP 4: RECOMMENDED ACTIONS =========="
cat "$WORKSPACE/recommended_manual_actions.json" \\
  | python -m json.tool \\
  | sed -n '1,240p'

echo
echo "========== OPTIONAL OBJECT DIFF PLACEHOLDER =========="
echo "# Later M18/M19 command placeholder:"
echo "# python scripts/p3/m19/run_object_diff_index.py --workspace \\"$WORKSPACE\\""

echo
echo "========== OPTIONAL VALIDATION OUTPUT DIFF PLACEHOLDER =========="
echo "# Later M21 command placeholder:"
echo "# python scripts/p3/m21/run_canonical_vrp_diff.py --workspace \\"$WORKSPACE\\""
"""


def build_workspace(
    *,
    out_root: Path,
    event_id: Optional[str],
    layer: str,
    anomaly_type: str,
    severity: str,
    snapshot_group_id: Optional[str] = None,
    object_export_id: Optional[str] = None,
    pp_id: Optional[str] = None,
    repo_host: Optional[str] = None,
    probes: Optional[List[str]] = None,
    validators: Optional[List[str]] = None,
    trigger_signals: Optional[Dict[str, Any]] = None,
    temporal_skew_class: str = "not_assessed",
    requires_resample: bool = False,
    window_seconds: Optional[int] = 300,
) -> Dict[str, Any]:
    if layer not in VALID_LAYERS:
        raise ValueError(f"invalid layer={layer}; valid={sorted(VALID_LAYERS)}")

    now = utc_now_iso()
    if not event_id:
        event_id = f"anom_{utc_compact()}_{layer}_{anomaly_type}".replace("/", "_")

    workspace = out_root / event_id

    dirs = {
        "temporal_context": workspace / "temporal_context",
        "advertised_view": workspace / "advertised_view",
        "object_view": workspace / "object_view",
        "validation_output_view": workspace / "validation_output_view",
        "manual_results": workspace / "manual_results",
        "reproduce": workspace / "reproduce",
    }

    ensure_dir(workspace)
    for d in dirs.values():
        ensure_dir(d)

    trigger_signals = trigger_signals or {}
    probes = probes or ["probe-cd", "probe-bj", "probe-sg"]
    validators = validators or ["routinator"]

    temporal_context = default_temporal_context(
        window_seconds=window_seconds,
        temporal_skew_class=temporal_skew_class,
        requires_resample=requires_resample,
        e4_confirmation_allowed=False,
    )

    fingerprint = make_event_fingerprint(
        layer=layer,
        anomaly_type=anomaly_type,
        pp_id=pp_id,
        repo_host=repo_host,
        snapshot_group_id=snapshot_group_id,
        object_export_id=object_export_id,
        probes=probes,
        validators=validators,
        trigger_signals=trigger_signals,
    )

    event = AnomalyEvent(
        event_id=event_id,
        event_fingerprint=fingerprint,
        created_at_utc=now,
        first_seen_utc=now,
        last_seen_utc=now,
        occurrence_count=1,
        layer=layer,
        anomaly_type=anomaly_type,
        severity=severity,
        snapshot_group_id=snapshot_group_id,
        object_export_id=object_export_id,
        pp_id=pp_id,
        repo_host=repo_host,
        probes=probes,
        validators=validators,
        trigger_signals=trigger_signals,
        temporal_context=temporal_context,
        current_status="MANUAL_ATTRIBUTION_READY",
        manual_attribution_ready=True,
        auto_attribution_supported=False,
        e4_confirmation_allowed=False,
        workspace=str(workspace),
    ).to_dict()

    paths = WorkspacePaths(
        workspace=str(workspace),
        anomaly_event=str(workspace / "anomaly_event.json"),
        metadata=str(workspace / "metadata.json"),
        layer_context_summary=str(workspace / "layer_context_summary.json"),
        related_files=str(workspace / "related_files.json"),
        recommended_manual_actions=str(workspace / "recommended_manual_actions.json"),
        commands_sh=str(workspace / "commands.sh"),
        initial_decision=str(workspace / "initial_decision.txt"),
        temporal_context_dir=str(dirs["temporal_context"]),
        advertised_view_dir=str(dirs["advertised_view"]),
        object_view_dir=str(dirs["object_view"]),
        validation_output_view_dir=str(dirs["validation_output_view"]),
        manual_results_dir=str(dirs["manual_results"]),
        reproduce_dir=str(dirs["reproduce"]),
    ).to_dict()

    metadata = {
        "schema": "s3.m17.workspace_metadata.v1",
        "created_at_utc": now,
        "event_id": event_id,
        "workspace_paths": paths,
        "note": "M17-A workspace smoke. Later M17 batches will populate scanner-derived contexts.",
    }

    layer_context = default_layer_context_summary(event_id, layer)
    layer_context["skew_assessment"] = {
        "overall_temporal_skew_class": temporal_skew_class,
        "requires_resample": requires_resample,
        "e4_confirmation_allowed": False,
    }

    related_files = {
        "schema": "s3.m17.related_files.v1",
        "event_id": event_id,
        "advertised_view": {},
        "object_view": {},
        "validation_output_view": {},
        "note": "M17-A placeholder. Scanner batches will add real related files.",
    }

    actions = recommended_actions_for_layer(layer, anomaly_type)
    actions["event_id"] = event_id

    version_skew_assessment = {
        "schema": "s3.m17.version_skew_assessment.v1",
        "event_id": event_id,
        "assessment": {
            "advertised_view_skew": {
                "class": "not_assessed",
                "reason": "M17-A workspace smoke does not scan Level-1 records.",
                "confidence": "not_assessed",
            },
            "object_view_skew": {
                "class": "not_assessed",
                "reason": "M17-A workspace smoke does not scan object roots.",
                "confidence": "not_assessed",
            },
            "validation_output_skew": {
                "class": "not_assessed",
                "reason": "M17-A workspace smoke does not scan validator outputs.",
                "confidence": "not_assessed",
            },
        },
        "overall_temporal_skew_class": temporal_skew_class,
        "requires_resample": requires_resample,
    }

    observation_timeline = {
        "schema": "s3.m17.observation_timeline.v1",
        "event_id": event_id,
        "records": [],
    }

    resample_plan = {
        "schema": "s3.m17.resample_plan.v1",
        "event_id": event_id,
        "enabled": bool(requires_resample),
        "grace_period_seconds": window_seconds,
        "max_resample_attempts": 2,
        "target_layers": [layer],
        "confirmation_rule": "same anomaly persists across two consecutive windows",
        "downgrade_rule": "signals converge in the next window",
    }

    convergence_check = {
        "schema": "s3.m17.convergence_check.v1",
        "event_id": event_id,
        "status": "not_run",
        "note": "Convergence check is reserved for later M17 batches.",
    }

    write_json(workspace / "metadata.json", metadata)
    write_json(workspace / "anomaly_event.json", event)
    write_json(workspace / "layer_context_summary.json", layer_context)
    write_json(workspace / "related_files.json", related_files)
    write_json(workspace / "recommended_manual_actions.json", actions)

    write_json(dirs["temporal_context"] / "observation_timeline.json", observation_timeline)
    write_json(dirs["temporal_context"] / "version_skew_assessment.json", version_skew_assessment)
    write_json(dirs["temporal_context"] / "resample_plan.json", resample_plan)
    write_json(dirs["temporal_context"] / "convergence_check.json", convergence_check)

    write_text(workspace / "initial_decision.txt", initial_decision_text(
        layer=layer,
        anomaly_type=anomaly_type,
        severity=severity,
        temporal_skew_class=temporal_skew_class,
        requires_resample=requires_resample,
    ))

    cmd = commands_template(workspace)
    write_text(workspace / "commands.sh", cmd)
    os.chmod(workspace / "commands.sh", 0o755)

    write_text(dirs["advertised_view"] / "README.md", "M17 advertised_view evidence directory.\n")
    write_text(
        dirs["object_view"] / "manual_object_diff_README.md",
        "M17 object_view evidence directory. Later M18/M19 results can be attached here or under manual_results/.\n",
    )
    write_text(
        dirs["validation_output_view"] / "manual_vrp_diff_README.md",
        "M17 validation_output_view evidence directory. Later M21 VRP diff results can be attached here or under manual_results/.\n",
    )
    write_text(dirs["manual_results"] / ".gitkeep", "")
    write_text(dirs["reproduce"] / "commands.sh", cmd)
    os.chmod(dirs["reproduce"] / "commands.sh", 0o755)

    registry_path = out_root / "anomaly_event_registry.jsonl"
    append_registry(registry_path=registry_path, event=event)
    write_registry_readme(out_root)

    return {
        "event": event,
        "workspace": str(workspace),
        "registry_path": str(registry_path),
        "paths": paths,
    }
