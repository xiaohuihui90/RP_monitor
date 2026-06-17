#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def load_scanner_signal(workspace: Path, layer: str) -> Dict[str, Any]:
    candidates = [
        workspace / layer / "scanner_signal.json",
        workspace / "advertised_view" / "scanner_signal.json",
        workspace / "object_view" / "scanner_signal.json",
        workspace / "validation_output_view" / "scanner_signal.json",
    ]

    for p in candidates:
        obj = read_json(p)
        if obj.get("signal"):
            return obj.get("signal") or {}

    return {}


def _base_actions(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {
            "action_id": "inspect_event_summary",
            "priority": "high",
            "layer": event.get("layer"),
            "implemented": True,
            "description": "Inspect anomaly_event.json, layer_context_summary.json, and temporal evidence summary.",
            "command_hint": "bash manual_evidence/manual_commands.sh",
            "expected_output": "Understand anomaly layer, type, temporal decision, and context freshness.",
        },
        {
            "action_id": "record_manual_notes",
            "priority": "medium",
            "layer": event.get("layer"),
            "implemented": True,
            "description": "Fill manual_results/notes_template.md with analyst observations and final manual conclusion.",
            "command_hint": "cp manual_results/notes_template.md manual_results/notes.md",
            "expected_output": "manual_results/notes.md",
        },
    ]


def _advertised_actions(event: Dict[str, Any], signal: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomaly_type = event.get("anomaly_type")
    actions = []

    actions.append({
        "action_id": "inspect_level1_records",
        "priority": "high",
        "layer": "advertised_view",
        "implemented": True,
        "description": "Inspect per-probe Level-1 RRDP fields: session_id, serial, notif_digest, fetch_status, failure_stage, error_class.",
        "command_hint": "cat advertised_view/level1_records.jsonl | sed -n '1,120p'",
        "expected_output": "Identify whether anomaly is fetch failure, serial skew, or digest divergence.",
    })

    if anomaly_type == "A3_RRDP_VERSION_SKEW":
        actions.append({
            "action_id": "check_rrdp_temporal_skew",
            "priority": "high",
            "layer": "advertised_view",
            "implemented": True,
            "description": "Check whether different serials share the same session_id and are monotonic/nearby, then resample after one polling interval.",
            "command_hint": "cat temporal_context/version_skew_assessment.json | python -m json.tool",
            "expected_output": "Decide whether this is normal RRDP version propagation skew.",
        })

    if anomaly_type == "A2_NOTIFICATION_DIGEST_DIVERGENCE":
        actions.append({
            "action_id": "run_l2_notification_refs",
            "priority": "high",
            "layer": "advertised_view",
            "implemented": "existing_or_manual",
            "description": "Same session_id and serial with different notification digest cannot be explained by temporal skew; collect notification refs and path evidence.",
            "command_hint": "# Run existing L2 notification refs collector for this PP/window.",
            "expected_output": "notification_refs evidence and path evidence.",
        })

    if anomaly_type == "A1_NOTIFICATION_FETCH_FAILURE":
        actions.append({
            "action_id": "inspect_fetch_failure_context",
            "priority": "high",
            "layer": "advertised_view",
            "implemented": True,
            "description": "Inspect failed probe, failure_stage, error_class, HTTP status, and latency.",
            "command_hint": "cat advertised_view/advertised_view_summary.json | python -m json.tool",
            "expected_output": "Localize fetch failure to probe/network/repository path.",
        })

    return actions


def _object_actions(event: Dict[str, Any], signal: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomaly_type = event.get("anomaly_type")
    trig = signal.get("trigger_signals") or {}
    root_key = trig.get("root_key")
    actions = []

    actions.append({
        "action_id": "inspect_object_root_summary",
        "priority": "high",
        "layer": "object_view",
        "implemented": True,
        "description": "Inspect per-probe object root values and divergent root key.",
        "command_hint": "cat object_view/object_root_summary.json | python -m json.tool | sed -n '1,260p'",
        "expected_output": "Find which root key diverges and which probes differ.",
        "root_key": root_key,
    })

    actions.append({
        "action_id": "inspect_object_values_by_probe",
        "priority": "high",
        "layer": "object_view",
        "implemented": True,
        "description": "Print values_by_probe for this object-layer anomaly.",
        "command_hint": "python - <<'PY'\nimport json, os\np=os.path.join(os.environ['WORKSPACE'],'object_view/object_root_summary.json')\no=json.load(open(p))\nprint(json.dumps(o.get('trigger_signals',{}).get('values_by_probe',{}), indent=2, ensure_ascii=False))\nPY",
        "expected_output": "Pairwise visible root differences.",
        "root_key": root_key,
    })

    if anomaly_type == "O1_OBJECT_ROOT_DIVERGENCE":
        actions.append({
            "action_id": "run_object_diff_index",
            "priority": "high",
            "layer": "object_view",
            "implemented": "planned_m18_m19",
            "description": "Run all-object URI/hash diff to identify concrete differing objects.",
            "command_hint": "# M18/M19: python scripts/p3/m19/run_object_diff_index.py --workspace \"$WORKSPACE\"",
            "expected_output": "manual_results/object_diff_index.jsonl",
        })

    if anomaly_type == "O2_MFT_ROOT_DIVERGENCE":
        actions.append({
            "action_id": "run_mft_version_skew_check",
            "priority": "high",
            "layer": "object_view",
            "implemented": "planned_m19",
            "description": "Check manifestNumber, thisUpdate, nextUpdate, and fileList differences to separate normal version skew from real object inconsistency.",
            "command_hint": "# M19: run MFT frozen semantic diff for differing MFT objects.",
            "expected_output": "manual_results/mft_semantic_diff.jsonl",
        })

    if anomaly_type == "O4_CER_ROOT_DIVERGENCE":
        actions.append({
            "action_id": "run_cer_resource_chain_check",
            "priority": "high",
            "layer": "object_view",
            "implemented": "partial",
            "description": "Check whether CER semantic root differs while resource root and chain index root are aligned.",
            "command_hint": "cat object_view/object_root_summary.json | python -m json.tool | grep -E 'cer_semantic_root|cer_chain_index_root|cer_resource_root' -n || true",
            "expected_output": "Decide whether CER diff is resource-impacting or low-impact semantic/context difference.",
        })

    if anomaly_type == "O5_CRL_ROOT_DIVERGENCE":
        actions.append({
            "action_id": "run_crl_semantic_drilldown",
            "priority": "high",
            "layer": "object_view",
            "implemented": "partial_or_planned_m19",
            "description": "Inspect CRL freshness, frozen hash, revoked set, and issuer/AKI root to decide whether it is freshness skew or impact-relevant revoked-set difference.",
            "command_hint": "cat object_view/object_root_summary.json | python -m json.tool | grep -E 'crl_freshness_root|crl_frozen_hash_root|crl_revoked_set_root|crl_issuer_aki_root' -n || true",
            "expected_output": "manual_results/crl_semantic_drilldown.json",
        })

    if anomaly_type == "O3_ROA_ROOT_DIVERGENCE":
        actions.append({
            "action_id": "run_roa_vrp_key_impact_check",
            "priority": "critical",
            "layer": "object_view",
            "implemented": "planned_m20",
            "description": "If roa_vrp_key_root diverges, map ROA semantic differences to candidate VRP entries.",
            "command_hint": "# M20: run object-to-validation-output impact mapping.",
            "expected_output": "manual_results/object_to_candidate_impact.jsonl",
        })

    return actions


def _validation_actions(event: Dict[str, Any], signal: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomaly_type = event.get("anomaly_type")
    actions = []

    actions.append({
        "action_id": "inspect_validation_output_summary",
        "priority": "high",
        "layer": "validation_output_view",
        "implemented": True,
        "description": "Inspect vrp_count, router_key_count, aspa_count, last_update_done, and source files.",
        "command_hint": "cat validation_output_view/output_summary.json | python -m json.tool | sed -n '1,260p'",
        "expected_output": "Determine whether output differences are count/root/config/cycle related.",
    })

    actions.append({
        "action_id": "inspect_validator_cycle_skew",
        "priority": "high",
        "layer": "validation_output_view",
        "implemented": True,
        "description": "Inspect validator last_update_done across probes before any E4 decision.",
        "command_hint": "cat temporal_context/context_freshness_assessment.json | python -m json.tool | grep -E 'validation_|validator_cycle|freshness_verdict' -n || true",
        "expected_output": "Confirm whether validator output diff is blocked by cycle skew.",
    })

    if anomaly_type in {"V1_VALIDATOR_OUTPUT_COUNT_DIVERGENCE", "V2_VALIDATOR_OUTPUT_ROOT_DIVERGENCE"}:
        actions.append({
            "action_id": "run_synchronized_vrp_export",
            "priority": "high",
            "layer": "validation_output_view",
            "implemented": "manual_or_planned_m21",
            "description": "Export full VRP only after validators have comparable last_update_done; then run canonical VRP diff.",
            "command_hint": "# M21: routinator vrps --format json --noupdate --output <file>; then canonicalize and diff.",
            "expected_output": "manual_results/vrp_diff_index.jsonl",
        })

    if anomaly_type == "V4_VALIDATOR_CYCLE_SKEW":
        actions.append({
            "action_id": "resample_after_validator_cycle",
            "priority": "high",
            "layer": "validation_output_view",
            "implemented": True,
            "description": "Wait one validator refresh interval or trigger synchronized export; do not confirm E4 at M17.",
            "command_hint": "cat temporal_context/resample_plan.json | python -m json.tool",
            "expected_output": "Comparable validator cycle context.",
        })

    if anomaly_type == "V5_VALIDATOR_CONFIG_DRIFT":
        actions.append({
            "action_id": "inspect_validator_config_drift",
            "priority": "high",
            "layer": "validation_output_view",
            "implemented": True,
            "description": "Compare validator version, config fingerprint, runtime fingerprint, TAL digest, and policy.",
            "command_hint": "cat validation_output_view/output_summary.json | python -m json.tool | grep -E 'version|fingerprint|tal|config' -n || true",
            "expected_output": "Block or downgrade E4 if validator context is not aligned.",
        })

    return actions


def build_actions(event: Dict[str, Any], signal: Dict[str, Any]) -> List[Dict[str, Any]]:
    layer = event.get("layer")
    actions = _base_actions(event)

    if layer == "advertised_view":
        actions.extend(_advertised_actions(event, signal))

    elif layer == "object_view":
        actions.extend(_object_actions(event, signal))

    elif layer == "validation_output_view":
        actions.extend(_validation_actions(event, signal))

    else:
        actions.append({
            "action_id": "inspect_cross_layer_context",
            "priority": "high",
            "layer": "cross_layer",
            "implemented": True,
            "description": "Inspect all layer contexts and temporal evidence.",
            "command_hint": "bash manual_evidence/manual_commands.sh",
            "expected_output": "Manual cross-layer context review.",
        })

    return actions


def render_next_steps(event: Dict[str, Any], actions: List[Dict[str, Any]], temporal_summary: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# M17-E Manual Evidence Locator")
    lines.append("")
    lines.append(f"- event_id: `{event.get('event_id')}`")
    lines.append(f"- layer: `{event.get('layer')}`")
    lines.append(f"- anomaly_type: `{event.get('anomaly_type')}`")
    lines.append(f"- severity: `{event.get('severity')}`")
    lines.append(f"- freshness_verdict: `{temporal_summary.get('freshness_verdict')}`")
    lines.append(f"- temporal_decision: `{(temporal_summary.get('temporal_decision') or {}).get('decision')}`")
    lines.append("")
    lines.append("## Recommended manual actions")
    lines.append("")

    for i, a in enumerate(actions, start=1):
        lines.append(f"### {i}. {a.get('action_id')}")
        lines.append("")
        lines.append(f"- priority: `{a.get('priority')}`")
        lines.append(f"- layer: `{a.get('layer')}`")
        lines.append(f"- implemented: `{a.get('implemented')}`")
        lines.append(f"- description: {a.get('description')}")
        lines.append(f"- expected_output: `{a.get('expected_output')}`")
        lines.append("")
        lines.append("Command hint:")
        lines.append("")
        lines.append("```bash")
        lines.append(str(a.get("command_hint") or "# no command"))
        lines.append("```")
        lines.append("")

    lines.append("## Manual results convention")
    lines.append("")
    lines.append("Put analyst-generated files under `manual_results/`, for example:")
    lines.append("")
    lines.append("- `manual_results/notes.md`")
    lines.append("- `manual_results/object_diff_index.jsonl`")
    lines.append("- `manual_results/semantic_diff_index.jsonl`")
    lines.append("- `manual_results/vrp_diff_index.jsonl`")
    lines.append("- `manual_results/manual_conclusion.json`")
    lines.append("")
    return "\n".join(lines)


def render_manual_results_readme(event: Dict[str, Any]) -> str:
    return f"""# Manual results for {event.get('event_id')}

This directory is reserved for analyst-generated evidence.

Recommended files:
- notes.md
- object_diff_index.jsonl
- semantic_diff_index.jsonl
- vrp_diff_index.jsonl
- manual_conclusion.json

Do not overwrite M17-generated files outside this directory unless you intentionally update the anomaly status.
"""


def render_notes_template(event: Dict[str, Any]) -> str:
    return f"""# Manual Analysis Notes

event_id: {event.get('event_id')}
layer: {event.get('layer')}
anomaly_type: {event.get('anomaly_type')}

## 1. What was observed?

TODO

## 2. Temporal / version skew assessment

TODO

## 3. Object-layer evidence

TODO

## 4. Validation-output evidence

TODO

## 5. Manual conclusion

Allowed examples:
- transient_temporal_skew
- object_layer_version_skew
- object_layer_real_diff
- validation_output_cycle_skew
- validator_config_drift
- e4_candidate_blocked
- e4_candidate_requires_m21
- insufficient_context

Conclusion:

TODO

## 6. Files attached under manual_results/

TODO
"""


def render_manual_commands(workspace: Path, event: Dict[str, Any], actions: List[Dict[str, Any]]) -> str:
    lines: List[str] = []

    lines.append("#!/usr/bin/env bash")
    lines.append("set -euo pipefail")
    lines.append("")
    lines.append("cd ~/s3_stage3_v3_code")
    lines.append("source ~/.bashrc || true")
    lines.append("")
    lines.append("if command -v conda >/dev/null 2>&1; then")
    lines.append("  eval \"$(conda shell.bash hook)\" || true")
    lines.append("  conda activate s3-radar || true")
    lines.append("elif [ -f \"$HOME/installers/ENTER/etc/profile.d/conda.sh\" ]; then")
    lines.append("  source \"$HOME/installers/ENTER/etc/profile.d/conda.sh\"")
    lines.append("  conda activate s3-radar || true")
    lines.append("fi")
    lines.append("")
    lines.append('export PYTHONNOUSERSITE=1')
    lines.append('export PYTHONPATH="$PWD:${PYTHONPATH:-}"')
    lines.append(f'export WORKSPACE="{workspace}"')
    lines.append("")
    lines.append('echo "========== M17-E MANUAL EVIDENCE LOCATOR =========="')
    lines.append('echo "WORKSPACE=$WORKSPACE"')
    lines.append("")
    lines.append('echo')
    lines.append('echo "========== EVENT =========="')
    lines.append('cat "$WORKSPACE/anomaly_event.json" | python -m json.tool | sed -n "1,220p"')
    lines.append("")
    lines.append('echo')
    lines.append('echo "========== TEMPORAL EVIDENCE SUMMARY =========="')
    lines.append('cat "$WORKSPACE/temporal_context/temporal_evidence_summary.json" | python -m json.tool | sed -n "1,260p"')
    lines.append("")
    lines.append('echo')
    lines.append('echo "========== CONTEXT FRESHNESS =========="')
    lines.append('cat "$WORKSPACE/temporal_context/context_freshness_assessment.json" | python -m json.tool | sed -n "1,260p"')
    lines.append("")
    lines.append('echo')
    lines.append('echo "========== LAYER CONTEXT =========="')
    lines.append('cat "$WORKSPACE/layer_context_summary.json" | python -m json.tool | sed -n "1,260p"')
    lines.append("")
    lines.append('echo')
    lines.append('echo "========== SCANNER SIGNAL =========="')
    lines.append('find "$WORKSPACE" -path "*/scanner_signal.json" -maxdepth 3 -type f -print -exec sh -c \'cat "$1" | python -m json.tool | sed -n "1,260p"\' sh {} \\;')
    lines.append("")
    lines.append('echo')
    lines.append('echo "========== ACTION CHECKLIST =========="')
    lines.append('cat "$WORKSPACE/manual_evidence/action_checklist.json" | python -m json.tool | sed -n "1,320p"')
    lines.append("")
    lines.append('echo')
    lines.append('echo "========== NEXT STEPS =========="')
    lines.append('sed -n "1,260p" "$WORKSPACE/manual_evidence/next_steps.md"')
    lines.append("")

    if event.get("layer") == "object_view":
        lines.append('echo')
        lines.append('echo "========== OBJECT ROOT SUMMARY =========="')
        lines.append('cat "$WORKSPACE/object_view/object_root_summary.json" | python -m json.tool | sed -n "1,320p"')
        lines.append("")
        lines.append('echo')
        lines.append('echo "========== OBJECT VALUES BY PROBE =========="')
        lines.append("python - <<'PY'")
        lines.append("import json, os")
        lines.append("p=os.path.join(os.environ['WORKSPACE'],'object_view/object_root_summary.json')")
        lines.append("o=json.load(open(p))")
        lines.append("print(json.dumps(o.get('trigger_signals',{}).get('values_by_probe',{}), indent=2, ensure_ascii=False))")
        lines.append("PY")
        lines.append("")

    if event.get("layer") == "validation_output_view":
        lines.append('echo')
        lines.append('echo "========== VALIDATION OUTPUT SUMMARY =========="')
        lines.append('cat "$WORKSPACE/validation_output_view/output_summary.json" | python -m json.tool | sed -n "1,320p"')
        lines.append("")
        lines.append('echo')
        lines.append('echo "========== VALIDATOR LAST_UPDATE_DONE =========="')
        lines.append("python - <<'PY'")
        lines.append("import json, os")
        lines.append("p=os.path.join(os.environ['WORKSPACE'],'validation_output_view/output_summary.json')")
        lines.append("o=json.load(open(p))")
        lines.append("sig=o.get('trigger_signals',{})")
        lines.append("print(json.dumps(sig.get('last_update_done',{}), indent=2, ensure_ascii=False))")
        lines.append("print('validator_cycle_skew_seconds =', sig.get('validator_cycle_skew_seconds'))")
        lines.append("PY")
        lines.append("")

    if event.get("layer") == "advertised_view":
        lines.append('echo')
        lines.append('echo "========== ADVERTISED VIEW LEVEL1 RECORDS =========="')
        lines.append('cat "$WORKSPACE/advertised_view/level1_records.jsonl" | sed -n "1,160p"')
        lines.append("")

    lines.append('echo')
    lines.append('echo "========== MANUAL RESULTS DIRECTORY =========="')
    lines.append('ls -lah "$WORKSPACE/manual_results"')
    lines.append("")
    lines.append('echo')
    lines.append('echo "Next: copy notes template if needed:"')
    lines.append('echo "cp $WORKSPACE/manual_results/notes_template.md $WORKSPACE/manual_results/notes.md"')

    return "\n".join(lines) + "\n"


def update_recommended_actions(workspace: Path, actions: List[Dict[str, Any]]) -> None:
    p = workspace / "recommended_manual_actions.json"
    obj = read_json(p)

    if not obj:
        obj = {
            "schema": "s3.m17.recommended_manual_actions.v1",
            "event_id": None,
            "actions": [],
        }

    existing = obj.get("actions") or []
    existing_ids = {x.get("action_id") for x in existing if isinstance(x, dict)}

    for a in actions:
        if a.get("action_id") not in existing_ids:
            existing.append(a)

    if "m17e_manual_evidence_locator" not in existing_ids:
        existing.append({
            "action_id": "m17e_manual_evidence_locator",
            "priority": "high",
            "layer": "manual_evidence",
            "implemented": True,
            "description": "Run manual_evidence/manual_commands.sh and follow manual_evidence/next_steps.md.",
            "command_hint": "bash manual_evidence/manual_commands.sh",
            "expected_output": "Analyst-readable evidence and optional manual_results/notes.md.",
        })

    obj["schema"] = "s3.m17.recommended_manual_actions.v2"
    obj["m17e_updated_at_utc"] = utc_now_iso()
    obj["actions"] = existing

    write_json(p, obj)


def append_commands_section(workspace: Path) -> None:
    p = workspace / "commands.sh"
    if not p.exists():
        return

    s = p.read_text(encoding="utf-8")
    marker = "========== STEP 5B: MANUAL EVIDENCE LOCATOR =========="
    if marker in s:
        return

    section = f"""

echo
echo "{marker}"
bash "$WORKSPACE/manual_evidence/manual_commands.sh"
"""

    p.write_text(s.rstrip() + section + "\n", encoding="utf-8")
    os.chmod(p, 0o755)


def enrich_workspace_manual_evidence(workspace: Path, *, repo_root: Path) -> Dict[str, Any]:
    workspace = Path(workspace)
    event = read_json(workspace / "anomaly_event.json")

    if not event:
        raise RuntimeError(f"anomaly_event.json missing or invalid: {workspace}")

    layer = event.get("layer")
    signal = load_scanner_signal(workspace, layer)

    temporal_summary = read_json(workspace / "temporal_context" / "temporal_evidence_summary.json")
    freshness = read_json(workspace / "temporal_context" / "context_freshness_assessment.json")

    actions = build_actions(event, signal)

    mdir = workspace / "manual_evidence"
    rdir = workspace / "manual_results"
    mdir.mkdir(parents=True, exist_ok=True)
    rdir.mkdir(parents=True, exist_ok=True)

    action_checklist = {
        "schema": "s3.m17e.action_checklist.v1",
        "generated_at_utc": utc_now_iso(),
        "event_id": event.get("event_id"),
        "layer": layer,
        "anomaly_type": event.get("anomaly_type"),
        "freshness_verdict": freshness.get("freshness_verdict"),
        "temporal_decision": (temporal_summary.get("temporal_decision") or {}).get("decision"),
        "actions": actions,
    }

    summary = {
        "schema": "s3.m17e.manual_evidence_locator_summary.v1",
        "generated_at_utc": utc_now_iso(),
        "event_id": event.get("event_id"),
        "workspace": str(workspace),
        "layer": layer,
        "anomaly_type": event.get("anomaly_type"),
        "action_count": len(actions),
        "high_priority_action_count": len([a for a in actions if a.get("priority") in {"high", "critical"}]),
        "freshness_verdict": freshness.get("freshness_verdict"),
        "temporal_decision": (temporal_summary.get("temporal_decision") or {}).get("decision"),
        "manual_commands": str(mdir / "manual_commands.sh"),
        "next_steps": str(mdir / "next_steps.md"),
        "action_checklist": str(mdir / "action_checklist.json"),
        "manual_results_dir": str(rdir),
    }

    write_json(mdir / "action_checklist.json", action_checklist)
    write_json(mdir / "manual_evidence_locator_summary.json", summary)
    write_text(mdir / "next_steps.md", render_next_steps(event, actions, temporal_summary))
    write_text(mdir / "manual_commands.sh", render_manual_commands(workspace, event, actions))
    os.chmod(mdir / "manual_commands.sh", 0o755)

    write_text(rdir / "README.md", render_manual_results_readme(event))
    write_text(rdir / "notes_template.md", render_notes_template(event))

    update_recommended_actions(workspace, actions)
    append_commands_section(workspace)

    return summary
