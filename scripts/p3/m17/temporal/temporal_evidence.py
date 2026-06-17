#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


TIME_TOKEN_RE = re.compile(r"20\d{6}T\d{6}Z")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    s = str(value).strip()
    if not s:
        return None

    if s.endswith("Z"):
        s2 = s[:-1] + "+00:00"
    else:
        s2 = s

    for fmt in [None, "%Y-%m-%d %H:%M:%S", "%Y%m%dT%H%M%SZ"]:
        try:
            if fmt is None:
                dt = datetime.fromisoformat(s2)
            else:
                dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            return dt.astimezone(timezone.utc)
        except Exception:
            pass

    return None


def dt_to_iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def seconds_between(a: Optional[datetime], b: Optional[datetime]) -> Optional[float]:
    if a is None or b is None:
        return None
    return abs((a - b).total_seconds())


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


def extract_time_tokens(text: str) -> List[datetime]:
    out: List[datetime] = []
    for token in TIME_TOKEN_RE.findall(text or ""):
        dt = parse_dt(token)
        if dt is not None:
            out.append(dt)
    return out


def latest_time_token(text: str) -> Optional[datetime]:
    dts = extract_time_tokens(text)
    if not dts:
        return None
    return max(dts)


def walk_values(obj: Any):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from walk_values(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_values(v)


def collect_source_paths(signal: Dict[str, Any]) -> List[str]:
    paths: List[str] = []

    for k, v in walk_values(signal):
        if k in {"source_file", "object_group_dir"} and isinstance(v, str):
            paths.append(v)

        if k == "summary_files" and isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    paths.append(item)

    dedup: List[str] = []
    seen = set()
    for p in paths:
        if p not in seen:
            seen.add(p)
            dedup.append(p)

    return dedup


def file_stat_rows(paths: List[str], repo_root: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    for raw in paths:
        p = Path(raw)
        if not p.is_absolute():
            p = repo_root / p

        exists = p.exists()
        mtime = None
        size = None

        if exists:
            try:
                st = p.stat()
                mtime = dt_to_iso(datetime.fromtimestamp(st.st_mtime, timezone.utc))
                size = st.st_size
            except Exception:
                pass

        rows.append({
            "path": raw,
            "abs_path": str(p),
            "exists": exists,
            "mtime_utc": mtime,
            "size_bytes": size,
        })

    return rows


def build_observation_timeline(
    *,
    event: Dict[str, Any],
    signal: Dict[str, Any],
    repo_root: Path,
) -> Dict[str, Any]:
    layer = event.get("layer")
    anomaly_type = event.get("anomaly_type")
    records: List[Dict[str, Any]] = []

    if layer == "advertised_view":
        for r in signal.get("context_rows") or []:
            records.append({
                "layer": "advertised_view",
                "probe_id": r.get("probe_id"),
                "pp_id": r.get("pp_id"),
                "observed_at_utc": r.get("observed_at_utc"),
                "session_id": r.get("session_id"),
                "serial": r.get("serial"),
                "notif_digest": r.get("notif_digest"),
                "fetch_status": r.get("fetch_status"),
                "source_file": r.get("source_file"),
            })

    if layer == "object_view":
        trig = signal.get("trigger_signals") or {}
        root_key = trig.get("root_key")
        values_by_probe = trig.get("values_by_probe") or {}
        object_group_dir = trig.get("object_group_dir")
        object_group_time = dt_to_iso(latest_time_token(str(object_group_dir)))

        for probe, root_value in sorted(values_by_probe.items()):
            records.append({
                "layer": "object_view",
                "probe_id": probe,
                "object_group_dir": object_group_dir,
                "object_group_time_utc": object_group_time,
                "root_key": root_key,
                "root_value": root_value,
                "anomaly_type": anomaly_type,
            })

        ctx = signal.get("context_summary") or {}
        per_probe = ((ctx.get("per_probe") or {}) if isinstance(ctx, dict) else {})
        for probe, info in sorted(per_probe.items()):
            for sf in info.get("summary_files") or []:
                p = Path(sf)
                if not p.is_absolute():
                    p = repo_root / p
                mtime = None
                if p.exists():
                    mtime = dt_to_iso(datetime.fromtimestamp(p.stat().st_mtime, timezone.utc))
                records.append({
                    "layer": "object_view_source_file",
                    "probe_id": probe,
                    "source_file": sf,
                    "source_file_mtime_utc": mtime,
                })

    if layer == "validation_output_view":
        trig = signal.get("trigger_signals") or {}
        latest_by_probe = (
            (signal.get("context_summary") or {}).get("latest_by_probe") or {}
        )

        for probe, info in sorted(latest_by_probe.items()):
            records.append({
                "layer": "validation_output_view",
                "probe_id": probe,
                "source_file": info.get("source_file"),
                "last_update_done": info.get("last_update_done"),
                "vrp_count": info.get("vrp_count"),
                "router_key_count": info.get("router_key_count"),
                "aspa_count": info.get("aspa_count"),
                "validator_version": info.get("validator_version") or info.get("routinator_version"),
            })

        for probe, t in sorted((trig.get("last_update_done") or {}).items()):
            if not any(r.get("probe_id") == probe and r.get("layer") == "validation_output_view" for r in records):
                records.append({
                    "layer": "validation_output_view",
                    "probe_id": probe,
                    "last_update_done": t,
                })

    return {
        "schema": "s3.m17.observation_timeline.v2",
        "generated_at_utc": utc_now_iso(),
        "event_id": event.get("event_id"),
        "layer": layer,
        "anomaly_type": anomaly_type,
        "record_count": len(records),
        "records": records,
    }


def build_context_freshness_assessment(
    *,
    event: Dict[str, Any],
    signal: Dict[str, Any],
    source_stats: List[Dict[str, Any]],
    repo_root: Path,
    max_context_age_seconds: int,
    max_cross_layer_delta_seconds: int,
) -> Dict[str, Any]:
    event_dt = parse_dt(event.get("created_at_utc"))
    layer = event.get("layer")
    trig = signal.get("trigger_signals") or {}

    file_mtimes = [
        parse_dt(x.get("mtime_utc"))
        for x in source_stats
        if x.get("mtime_utc")
    ]
    file_mtimes = [x for x in file_mtimes if x is not None]

    oldest_mtime = min(file_mtimes) if file_mtimes else None
    newest_mtime = max(file_mtimes) if file_mtimes else None

    oldest_age = seconds_between(event_dt, oldest_mtime)
    newest_age = seconds_between(event_dt, newest_mtime)
    file_span = seconds_between(oldest_mtime, newest_mtime)

    object_time = None
    validation_times: List[datetime] = []
    advertised_times: List[datetime] = []

    if layer == "object_view":
        object_group_dir = str((trig.get("object_group_dir") or ""))
        object_time = latest_time_token(object_group_dir)

    if layer == "validation_output_view":
        last_updates = trig.get("last_update_done") or {}
        for t in last_updates.values():
            dt = parse_dt(t)
            if dt:
                validation_times.append(dt)

        latest_by_probe = (signal.get("context_summary") or {}).get("latest_by_probe") or {}
        for info in latest_by_probe.values():
            dt = parse_dt(info.get("last_update_done"))
            if dt:
                validation_times.append(dt)

    if layer == "advertised_view":
        for r in signal.get("context_rows") or []:
            dt = parse_dt(r.get("observed_at_utc"))
            if dt:
                advertised_times.append(dt)

    validation_oldest = min(validation_times) if validation_times else None
    validation_newest = max(validation_times) if validation_times else None
    advertised_oldest = min(advertised_times) if advertised_times else None
    advertised_newest = max(advertised_times) if advertised_times else None

    validator_cycle_skew_seconds = seconds_between(validation_oldest, validation_newest)

    object_validation_delta_seconds = None
    if object_time and validation_newest:
        object_validation_delta_seconds = seconds_between(object_time, validation_newest)

    freshness_flags: List[str] = []

    if oldest_age is not None and oldest_age > max_context_age_seconds:
        freshness_flags.append("source_file_context_stale")

    if layer == "validation_output_view":
        validation_age = seconds_between(event_dt, validation_newest)
        if validation_age is not None and validation_age > max_context_age_seconds:
            freshness_flags.append("validation_output_context_stale")

    if object_validation_delta_seconds is not None and object_validation_delta_seconds > max_cross_layer_delta_seconds:
        freshness_flags.append("object_validation_context_misaligned")

    if not source_stats:
        freshness_flags.append("no_source_files_found")

    if freshness_flags:
        verdict = "context_not_strong_for_cross_layer_attribution"
    else:
        verdict = "context_acceptable_for_manual_evidence"

    return {
        "schema": "s3.m17.context_freshness_assessment.v1",
        "generated_at_utc": utc_now_iso(),
        "event_id": event.get("event_id"),
        "layer": layer,
        "event_created_at_utc": event.get("created_at_utc"),
        "max_context_age_seconds": max_context_age_seconds,
        "max_cross_layer_delta_seconds": max_cross_layer_delta_seconds,
        "source_file_count": len(source_stats),
        "oldest_source_file_mtime_utc": dt_to_iso(oldest_mtime),
        "newest_source_file_mtime_utc": dt_to_iso(newest_mtime),
        "oldest_source_file_age_seconds": oldest_age,
        "newest_source_file_age_seconds": newest_age,
        "source_file_time_span_seconds": file_span,
        "advertised_oldest_observed_at_utc": dt_to_iso(advertised_oldest),
        "advertised_newest_observed_at_utc": dt_to_iso(advertised_newest),
        "object_context_time_utc": dt_to_iso(object_time),
        "validation_oldest_last_update_done": dt_to_iso(validation_oldest),
        "validation_newest_last_update_done": dt_to_iso(validation_newest),
        "validator_cycle_skew_seconds": validator_cycle_skew_seconds,
        "object_validation_delta_seconds": object_validation_delta_seconds,
        "freshness_flags": freshness_flags,
        "freshness_verdict": verdict,
        "source_files": source_stats,
    }


def build_temporal_decision(
    *,
    event: Dict[str, Any],
    signal: Dict[str, Any],
    freshness: Dict[str, Any],
) -> Dict[str, Any]:
    tc = event.get("temporal_context") or {}
    layer = event.get("layer")
    anomaly_type = event.get("anomaly_type")
    temporal_class = tc.get("temporal_skew_class") or signal.get("temporal_skew_class") or "not_assessed"

    freshness_verdict = freshness.get("freshness_verdict")
    flags = freshness.get("freshness_flags") or []

    e4_allowed = False
    decision = "MANUAL_ATTRIBUTION_READY"
    confidence = "medium"
    reason: List[str] = []

    if freshness_verdict == "context_not_strong_for_cross_layer_attribution":
        decision = "TEMPORAL_OR_CONTEXT_WEAKNESS_REQUIRES_MANUAL_CHECK"
        confidence = "medium"
        reason.append("Context freshness is not strong enough for cross-layer attribution.")
        reason.extend(flags)

    if temporal_class in {
        "normal_rrdp_version_skew_likely",
        "crl_freshness_skew_possible",
        "validator_cycle_skew_likely",
        "manifest_version_skew_possible",
    }:
        decision = "TEMPORAL_SKEW_CANDIDATE"
        confidence = "medium-high"
        reason.append(f"Temporal classifier marked the event as {temporal_class}.")

    if temporal_class in {
        "crl_frozen_hash_diff_requires_semantic_check",
        "crl_revoked_set_diff_requires_impact_check",
        "object_root_divergent_requires_diff",
        "object_semantic_root_divergent_requires_diff",
        "cer_semantic_or_resource_diff_requires_check",
    }:
        decision = "OBJECT_DIFF_REQUIRES_MANUAL_OR_M19_CHECK"
        confidence = "medium-high"
        reason.append(f"Object-layer classifier marked the event as {temporal_class}.")

    if layer == "validation_output_view":
        e4_allowed = False
        reason.append("Validation-output anomaly cannot confirm E4 at M17; object alignment, validator cycle, config, and fetch context must be verified.")

    if temporal_class == "not_temporal_skew":
        decision = "CONFIRMED_ANOMALY_REQUIRES_MANUAL_ATTRIBUTION"
        confidence = "medium-high"
        reason.append("Temporal skew does not explain this anomaly.")

    return {
        "schema": "s3.m17.temporal_decision.v1",
        "generated_at_utc": utc_now_iso(),
        "event_id": event.get("event_id"),
        "layer": layer,
        "anomaly_type": anomaly_type,
        "temporal_skew_class": temporal_class,
        "freshness_verdict": freshness_verdict,
        "decision": decision,
        "confidence": confidence,
        "e4_confirmation_allowed": e4_allowed,
        "reason": reason,
    }


def build_resample_plan(
    *,
    event: Dict[str, Any],
    decision: Dict[str, Any],
    freshness: Dict[str, Any],
    resample_after_seconds: int,
) -> Dict[str, Any]:
    layer = event.get("layer")
    decision_name = decision.get("decision")
    temporal_class = decision.get("temporal_skew_class")

    target_layers = [layer]
    if layer == "validation_output_view":
        target_layers = ["validation_output_view", "object_view"]
    elif layer == "object_view":
        target_layers = ["object_view", "validation_output_view"]
    elif layer == "advertised_view":
        target_layers = ["advertised_view", "object_view"]

    enabled = decision_name in {
        "TEMPORAL_SKEW_CANDIDATE",
        "TEMPORAL_OR_CONTEXT_WEAKNESS_REQUIRES_MANUAL_CHECK",
        "OBJECT_DIFF_REQUIRES_MANUAL_OR_M19_CHECK",
    }

    return {
        "schema": "s3.m17.resample_plan.v2",
        "generated_at_utc": utc_now_iso(),
        "event_id": event.get("event_id"),
        "enabled": enabled,
        "resample_after_seconds": resample_after_seconds,
        "max_resample_attempts": 2,
        "target_layers": target_layers,
        "temporal_skew_class": temporal_class,
        "freshness_verdict": freshness.get("freshness_verdict"),
        "confirmation_rule": "same anomaly persists across two consecutive windows or semantic/impact diff confirms non-temporal cause",
        "downgrade_rule": "serials, object roots, or validator outputs converge in the next comparable window",
        "manual_next_steps": [
            "Inspect temporal_context/temporal_decision_explanation.md",
            "Inspect temporal_context/context_freshness_assessment.json",
            "If object_view anomaly persists, run M18/M19 object diff and frozen semantic diff",
            "If validation_output_view anomaly persists, run synchronized VRP export before E4 gate",
        ],
    }


def render_markdown(
    *,
    event: Dict[str, Any],
    decision: Dict[str, Any],
    freshness: Dict[str, Any],
    timeline: Dict[str, Any],
) -> str:
    lines: List[str] = []

    lines.append("# M17 Temporal Decision Explanation")
    lines.append("")
    lines.append(f"- event_id: `{event.get('event_id')}`")
    lines.append(f"- layer: `{event.get('layer')}`")
    lines.append(f"- anomaly_type: `{event.get('anomaly_type')}`")
    lines.append(f"- severity: `{event.get('severity')}`")
    lines.append(f"- temporal_skew_class: `{decision.get('temporal_skew_class')}`")
    lines.append(f"- decision: `{decision.get('decision')}`")
    lines.append(f"- confidence: `{decision.get('confidence')}`")
    lines.append(f"- e4_confirmation_allowed: `{decision.get('e4_confirmation_allowed')}`")
    lines.append("")
    lines.append("## Context freshness")
    lines.append("")
    lines.append(f"- freshness_verdict: `{freshness.get('freshness_verdict')}`")
    lines.append(f"- freshness_flags: `{freshness.get('freshness_flags')}`")
    lines.append(f"- source_file_count: `{freshness.get('source_file_count')}`")
    lines.append(f"- oldest_source_file_age_seconds: `{freshness.get('oldest_source_file_age_seconds')}`")
    lines.append(f"- validator_cycle_skew_seconds: `{freshness.get('validator_cycle_skew_seconds')}`")
    lines.append(f"- object_validation_delta_seconds: `{freshness.get('object_validation_delta_seconds')}`")
    lines.append("")
    lines.append("## Reason")
    lines.append("")
    for r in decision.get("reason") or []:
        lines.append(f"- {r}")
    lines.append("")
    lines.append("## Observation timeline")
    lines.append("")
    lines.append(f"- record_count: `{timeline.get('record_count')}`")
    lines.append("")
    lines.append("## Manual next steps")
    lines.append("")
    if event.get("layer") == "object_view":
        lines.append("1. Inspect object_view/object_root_summary.json.")
        lines.append("2. If root divergence persists, run M18/M19 object diff and frozen semantic diff.")
        lines.append("3. If ROA/CRL/CER impact is suspected, defer final output attribution to M20.")
    elif event.get("layer") == "validation_output_view":
        lines.append("1. Inspect validation_output_view/output_summary.json.")
        lines.append("2. Do synchronized VRP export only after validator cycles are comparable.")
        lines.append("3. Do not confirm E4 at M17.")
    elif event.get("layer") == "advertised_view":
        lines.append("1. Inspect advertised_view/level1_records.jsonl.")
        lines.append("2. Re-sample the same PP after one polling interval.")
        lines.append("3. If same session/serial different digest persists, run L2 notification refs.")
    else:
        lines.append("1. Inspect all layer summaries.")
        lines.append("2. Attach manual findings under manual_results/.")

    lines.append("")
    return "\n".join(lines) + "\n"


def append_commands_section(workspace: Path) -> None:
    p = workspace / "commands.sh"
    if not p.exists():
        return

    s = p.read_text(encoding="utf-8")
    marker = "========== STEP 2B: TEMPORAL EVIDENCE WORKSPACE =========="
    if marker in s:
        return

    section = f"""

echo
echo "{marker}"
cat "$WORKSPACE/temporal_context/temporal_evidence_summary.json" \\
  | python -m json.tool \\
  | sed -n '1,260p'

echo
echo "========== STEP 2C: CONTEXT FRESHNESS =========="
cat "$WORKSPACE/temporal_context/context_freshness_assessment.json" \\
  | python -m json.tool \\
  | sed -n '1,260p'

echo
echo "========== STEP 2D: TEMPORAL DECISION EXPLANATION =========="
sed -n '1,260p' "$WORKSPACE/temporal_context/temporal_decision_explanation.md"
"""

    p.write_text(s.rstrip() + section + "\n", encoding="utf-8")
    os.chmod(p, 0o755)


def enrich_workspace_temporal_evidence(
    workspace: Path,
    *,
    repo_root: Path,
    max_context_age_seconds: int = 86400,
    max_cross_layer_delta_seconds: int = 3600,
    resample_after_seconds: int = 300,
) -> Dict[str, Any]:
    workspace = Path(workspace)

    event = read_json(workspace / "anomaly_event.json")
    signal_obj = read_json(workspace / event.get("layer", "") / "scanner_signal.json")
    signal = signal_obj.get("signal") or {}

    if not signal:
        signal_obj = read_json(workspace / "object_view" / "scanner_signal.json")
        signal = signal_obj.get("signal") or {}

    source_paths = collect_source_paths(signal)
    source_stats = file_stat_rows(source_paths, repo_root)

    timeline = build_observation_timeline(
        event=event,
        signal=signal,
        repo_root=repo_root,
    )

    freshness = build_context_freshness_assessment(
        event=event,
        signal=signal,
        source_stats=source_stats,
        repo_root=repo_root,
        max_context_age_seconds=max_context_age_seconds,
        max_cross_layer_delta_seconds=max_cross_layer_delta_seconds,
    )

    decision = build_temporal_decision(
        event=event,
        signal=signal,
        freshness=freshness,
    )

    resample_plan = build_resample_plan(
        event=event,
        decision=decision,
        freshness=freshness,
        resample_after_seconds=resample_after_seconds,
    )

    tdir = workspace / "temporal_context"
    tdir.mkdir(parents=True, exist_ok=True)

    write_json(tdir / "observation_timeline.json", timeline)
    write_json(tdir / "context_freshness_assessment.json", freshness)
    write_json(tdir / "resample_plan.json", resample_plan)
    write_json(tdir / "temporal_evidence_summary.json", {
        "schema": "s3.m17.temporal_evidence_summary.v1",
        "generated_at_utc": utc_now_iso(),
        "event_id": event.get("event_id"),
        "layer": event.get("layer"),
        "anomaly_type": event.get("anomaly_type"),
        "temporal_decision": decision,
        "freshness_verdict": freshness.get("freshness_verdict"),
        "timeline_record_count": timeline.get("record_count"),
        "source_file_count": freshness.get("source_file_count"),
        "resample_enabled": resample_plan.get("enabled"),
    })

    write_text(
        tdir / "temporal_decision_explanation.md",
        render_markdown(
            event=event,
            decision=decision,
            freshness=freshness,
            timeline=timeline,
        ),
    )

    version_skew = read_json(tdir / "version_skew_assessment.json")
    version_skew["generated_at_utc"] = utc_now_iso()
    version_skew["context_freshness_assessment"] = {
        "freshness_verdict": freshness.get("freshness_verdict"),
        "freshness_flags": freshness.get("freshness_flags"),
        "source_file_count": freshness.get("source_file_count"),
        "oldest_source_file_age_seconds": freshness.get("oldest_source_file_age_seconds"),
        "validator_cycle_skew_seconds": freshness.get("validator_cycle_skew_seconds"),
        "object_validation_delta_seconds": freshness.get("object_validation_delta_seconds"),
    }
    version_skew["temporal_decision"] = decision
    write_json(tdir / "version_skew_assessment.json", version_skew)

    append_commands_section(workspace)

    return {
        "event_id": event.get("event_id"),
        "workspace": str(workspace),
        "layer": event.get("layer"),
        "anomaly_type": event.get("anomaly_type"),
        "temporal_skew_class": decision.get("temporal_skew_class"),
        "decision": decision.get("decision"),
        "freshness_verdict": freshness.get("freshness_verdict"),
        "source_file_count": freshness.get("source_file_count"),
        "timeline_record_count": timeline.get("record_count"),
    }
