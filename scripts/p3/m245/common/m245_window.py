#!/usr/bin/env python3
"""
M24.5 window helpers.

This module defines a stable 10-minute observation window ID.
Example:
  win_20260520T020000Z_10m
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta


DEFAULT_WINDOW_SIZE_SEC = 600


@dataclass(frozen=True)
class M245Window:
    window_id: str
    window_start_utc: str
    window_end_utc: str
    window_size_sec: int


def _floor_datetime(dt: datetime, window_size_sec: int = DEFAULT_WINDOW_SIZE_SEC) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)

    epoch = int(dt.timestamp())
    floored = epoch - (epoch % window_size_sec)
    return datetime.fromtimestamp(floored, tz=timezone.utc)


def format_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_window(
    now: datetime | None = None,
    window_size_sec: int = DEFAULT_WINDOW_SIZE_SEC,
) -> M245Window:
    if now is None:
        now = datetime.now(timezone.utc)

    start = _floor_datetime(now, window_size_sec)
    end = start + timedelta(seconds=window_size_sec)

    if window_size_sec == 600:
        suffix = "10m"
    else:
        suffix = f"{window_size_sec}s"

    compact_start = start.strftime("%Y%m%dT%H%M%SZ")
    window_id = f"win_{compact_start}_{suffix}"

    return M245Window(
        window_id=window_id,
        window_start_utc=format_utc(start),
        window_end_utc=format_utc(end),
        window_size_sec=window_size_sec,
    )


def parse_window_id(window_id: str) -> dict:
    # Minimal parser for validation and DB-ready metadata.
    # Expected: win_YYYYMMDDTHHMMSSZ_10m
    parts = window_id.split("_")
    if len(parts) < 3 or parts[0] != "win":
        raise ValueError(f"invalid M24.5 window_id: {window_id}")

    dt = datetime.strptime(parts[1], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)

    suffix = parts[2]
    if suffix == "10m":
        size = 600
    elif suffix.endswith("s") and suffix[:-1].isdigit():
        size = int(suffix[:-1])
    else:
        raise ValueError(f"unsupported window suffix: {suffix}")

    return {
        "window_id": window_id,
        "window_start_utc": format_utc(dt),
        "window_end_utc": format_utc(dt + timedelta(seconds=size)),
        "window_size_sec": size,
    }


if __name__ == "__main__":
    w = make_window()
    print(w)
