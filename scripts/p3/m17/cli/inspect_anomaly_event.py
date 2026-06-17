#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def print_json(title: str, obj) -> None:
    print()
    print(f"========== {title} ==========")
    if obj is None:
        print("MISSING")
    else:
        print(json.dumps(obj, ensure_ascii=False, indent=2))


def main() -> int:
    ap = argparse.ArgumentParser(description="Inspect an M17 anomaly workspace.")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--show-all", action="store_true")
    args = ap.parse_args()

    ws = Path(args.workspace)
    event = load_json(ws / "anomaly_event.json")
    layer = load_json(ws / "layer_context_summary.json")
    related = load_json(ws / "related_files.json")
    actions = load_json(ws / "recommended_manual_actions.json")
    skew = load_json(ws / "temporal_context/version_skew_assessment.json")

    if event is None:
        print("M17_INSPECT_ANOMALY=FAIL")
        print(f"workspace = {ws}")
        print("reason = anomaly_event.json missing")
        return 2

    print("M17_INSPECT_ANOMALY=OK")
    print(f"event_id = {event.get('event_id')}")
    print(f"layer = {event.get('layer')}")
    print(f"anomaly_type = {event.get('anomaly_type')}")
    print(f"severity = {event.get('severity')}")
    print(f"status = {event.get('current_status')}")
    print(f"temporal_skew_class = {(event.get('temporal_context') or {}).get('temporal_skew_class')}")
    print(f"requires_resample = {(event.get('temporal_context') or {}).get('requires_resample')}")
    print(f"e4_confirmation_allowed = {event.get('e4_confirmation_allowed')}")
    print(f"workspace = {ws}")

    print_json("TEMPORAL SKEW ASSESSMENT", skew)

    if args.show_all:
        print_json("ANOMALY EVENT", event)
        print_json("LAYER CONTEXT", layer)
        print_json("RELATED FILES", related)
        print_json("RECOMMENDED ACTIONS", actions)

    init_path = ws / "initial_decision.txt"
    print()
    print("========== INITIAL DECISION ==========")
    if init_path.exists():
        print(init_path.read_text(encoding="utf-8"))
    else:
        print("MISSING")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
