#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

from scripts.p3.m17.temporal.temporal_evidence import enrich_workspace_temporal_evidence


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def discover_workspaces(root: Path, limit: int) -> List[Path]:
    items = sorted(
        [p for p in root.iterdir() if p.is_dir() and p.name.startswith("anom_")],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return items[:limit]


def workspaces_from_summary(path: Path) -> List[Path]:
    obj = load_json(path)
    out = []
    for e in obj.get("created_events") or obj.get("events") or []:
        ws = e.get("workspace")
        if ws:
            out.append(Path(ws))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Enrich M17 workspaces with temporal evidence files.")
    ap.add_argument("--workspace", default=None)
    ap.add_argument("--root", default=None)
    ap.add_argument("--summary-json", default=None)
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--out", default=None)
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--max-context-age-seconds", type=int, default=86400)
    ap.add_argument("--max-cross-layer-delta-seconds", type=int, default=3600)
    ap.add_argument("--resample-after-seconds", type=int, default=300)

    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()

    workspaces: List[Path] = []

    if args.workspace:
        workspaces.append(Path(args.workspace))

    if args.summary_json:
        workspaces.extend(workspaces_from_summary(Path(args.summary_json)))

    if args.root:
        workspaces.extend(discover_workspaces(Path(args.root), args.limit))

    dedup = []
    seen = set()
    for ws in workspaces:
        ws = ws.resolve()
        if ws in seen:
            continue
        seen.add(ws)
        if (ws / "anomaly_event.json").exists():
            dedup.append(ws)

    reports = []
    errors = []

    for ws in dedup:
        try:
            reports.append(enrich_workspace_temporal_evidence(
                ws,
                repo_root=repo_root,
                max_context_age_seconds=args.max_context_age_seconds,
                max_cross_layer_delta_seconds=args.max_cross_layer_delta_seconds,
                resample_after_seconds=args.resample_after_seconds,
            ))
        except Exception as e:
            errors.append({
                "workspace": str(ws),
                "error": repr(e),
            })

    out = {
        "schema": "s3.m17d.enrich_temporal_evidence_summary.v1",
        "workspace_count": len(dedup),
        "enriched_count": len(reports),
        "error_count": len(errors),
        "reports": reports,
        "errors": errors,
    }

    if args.out:
        p = Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("M17D_ENRICH_TEMPORAL_EVIDENCE=DONE")
    print(f"workspace_count = {out['workspace_count']}")
    print(f"enriched_count = {out['enriched_count']}")
    print(f"error_count = {out['error_count']}")
    print(json.dumps(out, ensure_ascii=False, indent=2))

    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
