from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone, timedelta


def parse_utc(s: str) -> datetime:
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def fmt_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def floor_time(dt: datetime, window_size_sec: int) -> datetime:
    ts = int(dt.timestamp())
    floored = ts - (ts % window_size_sec)
    return datetime.fromtimestamp(floored, tz=timezone.utc)


def build_window(now: datetime, mode: str, window_size_sec: int, lag_sec: int) -> dict:
    if mode == "previous-completed":
        target = now - timedelta(seconds=lag_sec)
    elif mode == "current":
        target = now
    else:
        raise ValueError(f"unsupported mode: {mode}")

    start = floor_time(target, window_size_sec)
    end = start + timedelta(seconds=window_size_sec)

    window_id = start.strftime("win_%Y%m%dT%H%M%SZ_10m")

    return {
        "schema": "s3.m245.window_id.v1",
        "mode": mode,
        "now_utc": fmt_utc(now),
        "target_utc": fmt_utc(target),
        "window_id": window_id,
        "window_start_utc": fmt_utc(start),
        "window_end_utc": fmt_utc(end),
        "window_size_sec": window_size_sec,
        "lag_sec": lag_sec,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="previous-completed", choices=["previous-completed", "current"])
    ap.add_argument("--window-size-sec", type=int, default=600)
    ap.add_argument("--lag-sec", type=int, default=600)
    ap.add_argument("--now-utc", default="")
    ap.add_argument("--format", default="json", choices=["json", "shell", "window-id"])
    args = ap.parse_args()

    now = parse_utc(args.now_utc) if args.now_utc else datetime.now(timezone.utc)
    obj = build_window(
        now=now,
        mode=args.mode,
        window_size_sec=args.window_size_sec,
        lag_sec=args.lag_sec,
    )

    if args.format == "json":
        print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))
    elif args.format == "shell":
        print(f'export M245_SHARED_WINDOW_ID="{obj["window_id"]}"')
        print(f'export M245_WINDOW_START_UTC="{obj["window_start_utc"]}"')
        print(f'export M245_WINDOW_END_UTC="{obj["window_end_utc"]}"')
        print(f'export M245_WINDOW_SIZE_SEC="{obj["window_size_sec"]}"')
        print(f'export M245_WINDOW_MODE="{obj["mode"]}"')
    elif args.format == "window-id":
        print(obj["window_id"])


if __name__ == "__main__":
    main()
