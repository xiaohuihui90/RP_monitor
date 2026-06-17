from __future__ import annotations

from pathlib import Path


def scan_window_dirs(history_root: Path) -> list[Path]:
    if not history_root.exists():
        return []

    return sorted(
        p for p in history_root.glob("m245_window_*")
        if p.is_dir()
    )


def window_id_from_dir(window_dir: Path) -> str:
    name = window_dir.name
    if name.startswith("m245_window_"):
        return name.removeprefix("m245_window_")
    return name
