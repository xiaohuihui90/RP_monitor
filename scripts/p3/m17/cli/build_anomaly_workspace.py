#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.p3.m17.workspace import build_workspace


def parse_csv(value: str | None, default: list[str]) -> list[str]:
    if value is None or not value.strip():
        return default
    return [x.strip() for x in value.split(",") if x.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description="Build an M17 anomaly evidence workspace.")
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--event-id", default=None)
    ap.add_argument("--layer", required=True, choices=["advertised_view", "object_view", "validation_output_view", "cross_layer"])
    ap.add_argument("--anomaly-type", required=True)
    ap.add_argument("--severity", default="warning", choices=["info", "warning", "high", "critical"])
    ap.add_argument("--snapshot-group-id", default=None)
    ap.add_argument("--object-export-id", default=None)
    ap.add_argument("--pp-id", default=None)
    ap.add_argument("--repo-host", default=None)
    ap.add_argument("--probes", default="probe-cd,probe-bj,probe-sg")
    ap.add_argument("--validators", default="routinator")
    ap.add_argument("--window-seconds", type=int, default=300)
    ap.add_argument("--temporal-skew-class", default="not_assessed")
    ap.add_argument("--requires-resample", action="store_true")
    ap.add_argument("--trigger-signals-json", default=None)

    args = ap.parse_args()

    trigger_signals = {}
    if args.trigger_signals_json:
        trigger_signals = json.loads(args.trigger_signals_json)

    result = build_workspace(
        out_root=Path(args.out_root),
        event_id=args.event_id,
        layer=args.layer,
        anomaly_type=args.anomaly_type,
        severity=args.severity,
        snapshot_group_id=args.snapshot_group_id,
        object_export_id=args.object_export_id,
        pp_id=args.pp_id,
        repo_host=args.repo_host,
        probes=parse_csv(args.probes, ["probe-cd", "probe-bj", "probe-sg"]),
        validators=parse_csv(args.validators, ["routinator"]),
        trigger_signals=trigger_signals,
        temporal_skew_class=args.temporal_skew_class,
        requires_resample=args.requires_resample,
        window_seconds=args.window_seconds,
    )

    print("M17_BUILD_ANOMALY_WORKSPACE=DONE")
    print(f"event_id = {result['event']['event_id']}")
    print(f"workspace = {result['workspace']}")
    print(f"registry_path = {result['registry_path']}")
    print(f"anomaly_event = {result['paths']['anomaly_event']}")
    print(f"commands_sh = {result['paths']['commands_sh']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
