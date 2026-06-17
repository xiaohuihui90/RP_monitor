#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.p3.m17.io_utils import read_json, write_json, write_text
from scripts.p3.m17.time_utils import utc_compact, utc_now_iso
from scripts.p3.m17.workspace import build_workspace
from scripts.p3.m17.scanners.advertised_view_scanner import scan_advertised_view
from scripts.p3.m17.scanners.object_view_scanner import scan_object_view
from scripts.p3.m17.scanners.validation_output_scanner import scan_validation_output
from scripts.p3.m17.scanners.common import write_jsonl
from scripts.p3.m17.temporal.temporal_skew_classifier import refine_signal
from scripts.p3.m17.temporal.temporal_evidence import enrich_workspace_temporal_evidence
from scripts.p3.m17.actions.manual_evidence_locator import enrich_workspace_manual_evidence
from scripts.p3.m17.registry_state import find_existing_workspace_for_signal, update_existing_workspace_occurrence


def safe_load(path: Path) -> Dict[str, Any]:
    try:
        return read_json(path)
    except Exception:
        return {}


def safe_dump(path: Path, obj: Dict[str, Any]) -> None:
    write_json(path, obj)


def layer_dir_name(layer: str) -> str:
    if layer == "advertised_view":
        return "advertised_view"
    if layer == "object_view":
        return "object_view"
    if layer == "validation_output_view":
        return "validation_output_view"
    return "cross_layer"


def update_workspace_with_signal(workspace: Path, signal: Dict[str, Any]) -> None:
    layer = signal.get("layer")
    ldir = workspace / layer_dir_name(layer)
    ldir.mkdir(parents=True, exist_ok=True)

    write_json(ldir / "scanner_signal.json", {
        "schema": "s3.m17.scanner_signal.v1",
        "created_at_utc": utc_now_iso(),
        "signal": signal,
    })

    if layer == "advertised_view":
        rows = signal.get("context_rows") or []
        write_jsonl(ldir / "level1_records.jsonl", rows)
        write_json(ldir / "advertised_view_summary.json", {
            "schema": "s3.m17.advertised_view_summary.v1",
            "pp_id": signal.get("pp_id"),
            "anomaly_type": signal.get("anomaly_type"),
            "trigger_signals": signal.get("trigger_signals"),
            "record_count": len(rows),
        })

    if layer == "object_view":
        ctx = signal.get("context_summary") or {}
        write_json(ldir / "object_root_summary.json", {
            "schema": "s3.m17.object_root_summary.v1",
            "anomaly_type": signal.get("anomaly_type"),
            "trigger_signals": signal.get("trigger_signals"),
            "context_summary": ctx,
        })

    if layer == "validation_output_view":
        ctx = signal.get("context_summary") or {}
        write_json(ldir / "output_summary.json", {
            "schema": "s3.m17.validation_output_summary.v1",
            "anomaly_type": signal.get("anomaly_type"),
            "trigger_signals": signal.get("trigger_signals"),
            "context_summary": ctx,
        })

    event_path = workspace / "anomaly_event.json"
    event = safe_load(event_path)
    tc = event.get("temporal_context") or {}
    tc["temporal_skew_class"] = signal.get("temporal_skew_class", tc.get("temporal_skew_class"))
    tc["requires_resample"] = bool(signal.get("requires_resample", tc.get("requires_resample", False)))
    tc["e4_confirmation_allowed"] = False

    trig = signal.get("trigger_signals") or {}
    if "observed_at_utc" in trig:
        tc["probe_observation_times"] = trig.get("observed_at_utc") or {}
    if "max_probe_time_skew_seconds" in trig:
        tc["max_probe_time_skew_seconds"] = trig.get("max_probe_time_skew_seconds")
    if "sessions" in trig or "serials" in trig or "digests" in trig:
        tc["rrdp_versions"] = {
            "sessions": trig.get("sessions"),
            "serials": trig.get("serials"),
            "digests": trig.get("digests"),
        }
    if "last_update_done" in trig:
        tc["validator_last_update_done"] = trig.get("last_update_done") or {}
    if "validator_cycle_skew_seconds" in trig:
        tc["validator_cycle_skew_seconds"] = trig.get("validator_cycle_skew_seconds")

    event["temporal_context"] = tc
    event["trigger_signals"] = signal.get("trigger_signals") or {}
    event["current_status"] = "MANUAL_ATTRIBUTION_READY"
    safe_dump(event_path, event)

    layer_context_path = workspace / "layer_context_summary.json"
    layer_ctx = safe_load(layer_context_path)

    layer_ctx["skew_assessment"] = {
        "overall_temporal_skew_class": signal.get("temporal_skew_class"),
        "requires_resample": bool(signal.get("requires_resample", False)),
        "e4_confirmation_allowed": False,
    }

    if layer == "advertised_view":
        layer_ctx["advertised_view"] = {
            "available": True,
            "status": signal.get("anomaly_type"),
            "session_id_aligned": None,
            "serial_aligned": None,
            "notif_digest_aligned": None,
            "fetch_success_ratio": None,
            "context_age_seconds": None,
        }

    if layer == "object_view":
        layer_ctx["object_view"] = {
            "available": True,
            "status": signal.get("anomaly_type"),
            "object_context_stale": signal.get("temporal_skew_class") == "context_stale",
            "all_object_root_aligned": False,
            "type_roots": {},
        }

    if layer == "validation_output_view":
        trig = signal.get("trigger_signals") or {}
        layer_ctx["validation_output_view"] = {
            "available": True,
            "status": signal.get("anomaly_type"),
            "vrp_count_aligned": False if "count_diff" in trig else None,
            "vrp_root_aligned": False if "root_diff" in trig else None,
            "validator_cycle_skew_seconds": trig.get("validator_cycle_skew_seconds"),
            "validator_config_aligned": False if "config_diff" in trig else None,
        }

    safe_dump(layer_context_path, layer_ctx)

    related_path = workspace / "related_files.json"
    related = safe_load(related_path)
    related.setdefault(layer_dir_name(layer), {})
    related[layer_dir_name(layer)]["scanner_signal"] = str(ldir / "scanner_signal.json")
    if layer == "advertised_view":
        related[layer_dir_name(layer)]["level1_records"] = str(ldir / "level1_records.jsonl")
        related[layer_dir_name(layer)]["advertised_view_summary"] = str(ldir / "advertised_view_summary.json")
    if layer == "object_view":
        related[layer_dir_name(layer)]["object_root_summary"] = str(ldir / "object_root_summary.json")
    if layer == "validation_output_view":
        related[layer_dir_name(layer)]["output_summary"] = str(ldir / "output_summary.json")
    safe_dump(related_path, related)

    assessment_path = workspace / "temporal_context" / "version_skew_assessment.json"
    assessment = safe_load(assessment_path)
    assessment["overall_temporal_skew_class"] = signal.get("temporal_skew_class")
    assessment["requires_resample"] = bool(signal.get("requires_resample", False))
    assessment.setdefault("assessment", {})
    assessment["assessment"][f"{layer}_skew"] = {
        "class": signal.get("temporal_skew_class"),
        "reason": f"Detected by M17-B {layer} scanner for {signal.get('anomaly_type')}.",
        "confidence": "medium",
    }
    safe_dump(assessment_path, assessment)


def create_workspace_from_signal(
    *,
    out_root: Path,
    signal: Dict[str, Any],
    event_index: int,
) -> Dict[str, Any]:
    existing_workspace = find_existing_workspace_for_signal(out_root, signal)

    if existing_workspace is not None:
        event = update_existing_workspace_occurrence(
            out_root=out_root,
            workspace=existing_workspace,
            signal=signal,
        )

        update_workspace_with_signal(existing_workspace, signal)

        try:
            enrich_workspace_temporal_evidence(
                existing_workspace,
                repo_root=Path(".").resolve(),
                max_context_age_seconds=86400,
                max_cross_layer_delta_seconds=3600,
                resample_after_seconds=300,
            )
        except Exception as e:
            marker = existing_workspace / "temporal_context" / "temporal_evidence_error.txt"
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text(repr(e) + "\n", encoding="utf-8")

        try:
            enrich_workspace_manual_evidence(
                existing_workspace,
                repo_root=Path(".").resolve(),
            )
        except Exception as e:
            marker = existing_workspace / "manual_evidence" / "manual_evidence_error.txt"
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text(repr(e) + "\n", encoding="utf-8")

        return {
            "event_id": event.get("event_id"),
            "workspace": str(existing_workspace),
            "layer": signal.get("layer"),
            "anomaly_type": signal.get("anomaly_type"),
            "severity": signal.get("severity"),
            "temporal_skew_class": signal.get("temporal_skew_class"),
            "dedup_hit": True,
            "occurrence_count": event.get("occurrence_count"),
        }

    event_id = (
        f"anom_{utc_compact()}_"
        f"{signal.get('layer')}_"
        f"{signal.get('anomaly_type')}_"
        f"{event_index:04d}"
    ).replace("/", "_")

    result = build_workspace(
        out_root=out_root,
        event_id=event_id,
        layer=signal.get("layer"),
        anomaly_type=signal.get("anomaly_type"),
        severity=signal.get("severity", "warning"),
        snapshot_group_id=signal.get("snapshot_group_id"),
        object_export_id=signal.get("object_export_id"),
        pp_id=signal.get("pp_id"),
        repo_host=signal.get("repo_host"),
        probes=signal.get("probes"),
        validators=signal.get("validators"),
        trigger_signals=signal.get("trigger_signals") or {},
        temporal_skew_class=signal.get("temporal_skew_class", "not_assessed"),
        requires_resample=bool(signal.get("requires_resample", False)),
        window_seconds=300,
    )

    workspace = Path(result["workspace"])
    update_workspace_with_signal(workspace, signal)

    try:
        enrich_workspace_temporal_evidence(
            workspace,
            repo_root=Path(".").resolve(),
            max_context_age_seconds=86400,
            max_cross_layer_delta_seconds=3600,
            resample_after_seconds=300,
        )
    except Exception as e:
        marker = workspace / "temporal_context" / "temporal_evidence_error.txt"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(repr(e) + "\n", encoding="utf-8")

    try:
        enrich_workspace_manual_evidence(
            workspace,
            repo_root=Path(".").resolve(),
        )
    except Exception as e:
        marker = workspace / "manual_evidence" / "manual_evidence_error.txt"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(repr(e) + "\n", encoding="utf-8")

    return {
        "event_id": result["event"]["event_id"],
        "workspace": result["workspace"],
        "layer": signal.get("layer"),
        "anomaly_type": signal.get("anomaly_type"),
        "severity": signal.get("severity"),
        "temporal_skew_class": signal.get("temporal_skew_class"),
        "dedup_hit": False,
        "occurrence_count": 1,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan multi-layer S3 anomalies and build M17 workspaces.")
    ap.add_argument("--collector-root", required=True)
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--run-dir", default=None)
    ap.add_argument("--window-seconds", type=int, default=300)
    ap.add_argument("--strong-cycle-skew-seconds", type=int, default=120)
    ap.add_argument("--max-object-context-age-seconds", type=int, default=86400)
    ap.add_argument("--object-group-dir", default=None)
    ap.add_argument("--validator", default="routinator")
    ap.add_argument("--scan-advertised-view", action="store_true")
    ap.add_argument("--scan-object-view", action="store_true")
    ap.add_argument("--scan-validation-output", action="store_true")
    ap.add_argument("--enable-temporal-skew-classifier", action="store_true")
    ap.add_argument("--max-events", type=int, default=50)
    ap.add_argument("--dry-run", action="store_true")

    args = ap.parse_args()

    collector_root = Path(args.collector_root)
    out_root = Path(args.out_root)

    if not (args.scan_advertised_view or args.scan_object_view or args.scan_validation_output):
        args.scan_advertised_view = True
        args.scan_object_view = True
        args.scan_validation_output = True

    scanner_results: Dict[str, Any] = {}
    signals: List[Dict[str, Any]] = []

    if args.scan_advertised_view:
        res = scan_advertised_view(
            collector_root=collector_root,
            window_seconds=args.window_seconds,
        )
        scanner_results["advertised_view"] = {
            k: v for k, v in res.items()
            if k != "signals"
        }
        signals.extend(res.get("signals", []))

    if args.scan_object_view:
        res = scan_object_view(
            collector_root=collector_root,
            object_group_dir=args.object_group_dir,
            max_context_age_seconds=args.max_object_context_age_seconds,
        )
        scanner_results["object_view"] = {
            k: v for k, v in res.items()
            if k != "signals"
        }
        signals.extend(res.get("signals", []))

    if args.scan_validation_output:
        res = scan_validation_output(
            collector_root=collector_root,
            validator=args.validator,
            strong_cycle_skew_seconds=args.strong_cycle_skew_seconds,
        )
        scanner_results["validation_output_view"] = {
            k: v for k, v in res.items()
            if k != "signals"
        }
        signals.extend(res.get("signals", []))

    if args.enable_temporal_skew_classifier:
        signals = [
            refine_signal(
                sig,
                window_seconds=args.window_seconds,
                strong_cycle_skew_seconds=args.strong_cycle_skew_seconds,
            )
            for sig in signals
        ]

    signals = signals[: args.max_events]

    events: List[Dict[str, Any]] = []
    if not args.dry_run:
        for idx, sig in enumerate(signals, start=1):
            try:
                events.append(create_workspace_from_signal(
                    out_root=out_root,
                    signal=sig,
                    event_index=idx,
                ))
            except Exception as e:
                events.append({
                    "event_id": None,
                    "workspace": None,
                    "layer": sig.get("layer"),
                    "anomaly_type": sig.get("anomaly_type"),
                    "error": repr(e),
                })

    summary = {
        "schema": "s3.m17b.multilayer_scan_summary.v1",
        "created_at_utc": utc_compact(),
        "collector_root": str(collector_root),
        "out_root": str(out_root),
        "scanner_results": scanner_results,
        "raw_signal_count": len(signals),
        "created_event_count": len([e for e in events if e.get("event_id")]),
        "dedup_hit_count": len([e for e in events if e.get("dedup_hit") is True]),
        "new_workspace_count": len([e for e in events if e.get("event_id") and e.get("dedup_hit") is False]),
        "events": events,
        "dry_run": args.dry_run,
    }

    if args.run_dir:
        run_dir = Path(args.run_dir)
        (run_dir / "outputs").mkdir(parents=True, exist_ok=True)
        write_json(run_dir / "outputs" / "M17B_multilayer_scan_summary.json", summary)

    print("M17B_MULTILAYER_SCAN=DONE")
    print(f"collector_root = {collector_root}")
    print(f"out_root = {out_root}")
    print(f"raw_signal_count = {summary['raw_signal_count']}")
    print(f"created_event_count = {summary['created_event_count']}")
    print(f"dedup_hit_count = {summary.get('dedup_hit_count')}")
    print(f"new_workspace_count = {summary.get('new_workspace_count')}")
    print("scanner_results:")
    print(json.dumps(scanner_results, ensure_ascii=False, indent=2))
    print("events:")
    print(json.dumps(events, ensure_ascii=False, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
