#!/usr/bin/env python3
"""
Path helpers for M24.5 run directories.
"""

from __future__ import annotations

from pathlib import Path


def probe_run_dir(
    project_dir: str | Path,
    probe_id: str,
    window_id: str,
) -> Path:
    return (
        Path(project_dir)
        / "data"
        / "probe"
        / "m245_three_layer_baseline"
        / "history"
        / f"m245_probe_{probe_id}_{window_id}"
    )


def collector_window_dir(
    project_dir: str | Path,
    window_id: str,
) -> Path:
    return (
        Path(project_dir)
        / "data"
        / "p3_collector"
        / "m245_three_layer_baseline"
        / "history"
        / f"m245_window_{window_id}"
    )


def ensure_standard_dirs(run_dir: str | Path) -> dict:
    base = Path(run_dir)
    dirs = {
        "base": base,
        "inputs": base / "inputs",
        "indexes": base / "indexes",
        "outputs": base / "outputs",
        "checks": base / "checks",
        "full": base / "full",
    }
    for p in dirs.values():
        p.mkdir(parents=True, exist_ok=True)
    return dirs
