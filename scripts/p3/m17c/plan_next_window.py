#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_window_id(window_size_sec: int, safety_lag_windows: int) -> str:
    now = datetime.now(timezone.utc)
    ts = int(now.timestamp())
    current_window_start = ts - (ts % window_size_sec)
    target_window_start = current_window_start - safety_lag_windows * window_size_sec
    dt = datetime.fromtimestamp(target_window_start, tz=timezone.utc)
    return "win_" + dt.strftime("%Y%m%dT%H%M%SZ") + "_10m"


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def append_jsonl(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")


def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--m17c-root", default="data/p3_collector/m17_continuous_lite")
    ap.add_argument("--collector-url", default="http://47.108.137.128:28117/upload")
    ap.add_argument("--raw-sidecar-url", default="http://47.108.137.128:28116/upload")
    ap.add_argument("--window-size-sec", type=int, default=600)
    ap.add_argument("--safety-lag-windows", type=int, default=2)
    ap.add_argument("--force-window-id", default="")
    args = ap.parse_args()

    root = Path(args.m17c_root)
    state_dir = root / "state"
    queue_dir = root / "queues"
    history_dir = root / "history"

    for d in [state_dir, queue_dir, history_dir, root / "reports", root / "logs"]:
        d.mkdir(parents=True, exist_ok=True)

    window_id = args.force_window_id.strip() or make_window_id(
        window_size_sec=args.window_size_sec,
        safety_lag_windows=args.safety_lag_windows,
    )

    run_id = "m17c_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = history_dir / run_id
    (run_dir / "checks").mkdir(parents=True, exist_ok=True)
    (run_dir / "outputs").mkdir(parents=True, exist_ok=True)
    (run_dir / "logs").mkdir(parents=True, exist_ok=True)

    completed = read_jsonl(queue_dir / "completed_windows.jsonl")
    failed = read_jsonl(queue_dir / "failed_windows.jsonl")
    pending = read_jsonl(queue_dir / "pending_windows.jsonl")

    seen = {
        r.get("window_id")
        for r in completed + failed + pending
        if isinstance(r, dict)
    }

    duplicate = window_id in seen

    record = {
        "schema": "s3.m17c.planned_window.v1",
        "created_at_utc": utc_now(),
        "run_id": run_id,
        "window_id": window_id,
        "collector_url": args.collector_url,
        "raw_sidecar_url": args.raw_sidecar_url,
        "window_size_sec": args.window_size_sec,
        "safety_lag_windows": args.safety_lag_windows,
        "duplicate_window": duplicate,
        "run_dir": str(run_dir),
        "status": "planned_duplicate" if duplicate else "planned",
    }

    append_jsonl(queue_dir / "pending_windows.jsonl", record)

    env_path = state_dir / "current_m17c_run.env"
    env_path.write_text(
        "\n".join([
            f'export M17C_RUN_ID="{run_id}"',
            f'export M17C_TARGET_WINDOW_ID="{window_id}"',
            f'export M17C_COLLECTOR_URL="{args.collector_url}"',
            f'export M17C_RAW_SIDECAR_URL="{args.raw_sidecar_url}"',
            f'export M17C_ROOT="{args.m17c_root}"',
            f'export M17C_RUN_DIR="{run_dir}"',
            "",
        ]),
        encoding="utf-8",
    )

    write_json(run_dir / "outputs" / "planned_window.json", record)

    txt = [
        "M17C_PLAN_NEXT_WINDOW=PASS",
        f"created_at_utc = {record['created_at_utc']}",
        f"run_id = {run_id}",
        f"window_id = {window_id}",
        f"collector_url = {args.collector_url}",
        f"raw_sidecar_url = {args.raw_sidecar_url}",
        f"duplicate_window = {duplicate}",
        f"run_dir = {run_dir}",
        f"env_path = {env_path}",
        "next_batch = S2_PROBE_CD_RUN_PROBE_M17C_ONCE",
    ]

    (run_dir / "checks" / "M17C_S1_plan_next_window.txt").write_text(
        "\n".join(txt) + "\n",
        encoding="utf-8",
    )

    print("\n".join(txt))


if __name__ == "__main__":
    main()
