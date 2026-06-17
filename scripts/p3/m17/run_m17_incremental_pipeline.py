#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_SELECTED_WINDOWS = "data/p3_collector/m245_three_layer_baseline/m17_vrp_entry_diff_inputs/selected_windows.json"
DEFAULT_OUT_ROOT = "data/p3_collector/m17_vrp_entry_diff"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path, default=None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return default


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def first_existing(*vals: str | None, default: str) -> str:
    for v in vals:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return default


def load_selected_windows(path: Path) -> list[dict[str, Any]]:
    obj = read_json(path)
    if not isinstance(obj, dict):
        raise RuntimeError(f"selected_windows is not an object: {path}")
    wins = obj.get("selected_windows", [])
    if not isinstance(wins, list):
        raise RuntimeError(f"selected_windows field is not a list: {path}")
    return [x for x in wins if isinstance(x, dict)]


def pick_target_windows(selected: list[dict[str, Any]], target_window_id: str | None) -> list[dict[str, Any]]:
    if not target_window_id:
        return selected
    picked = [x for x in selected if x.get("window_id") == target_window_id]
    if not picked:
        raise RuntimeError(f"target_window_not_found_in_selected_windows: {target_window_id}")
    return picked


def find_plan_json(plan_dir: str | None, explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit)
        if p.exists():
            return p

    if plan_dir:
        d = Path(plan_dir)
        candidates = [
            d / "m17_incremental_plan.json",
            d / "outputs" / "m17_incremental_plan.json",
        ]
        candidates.extend(sorted(d.glob("**/m17_incremental_plan.json")))
        for p in candidates:
            if p.exists():
                return p

    return None


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Compatibility wrapper for M17 incremental pipeline. "
                    "Supports current run_m17c_hourly_incremental_once.sh --plan-dir/--run-dir interface."
    )

    # 当前 wrapper 传入的参数
    ap.add_argument("--plan-dir", default="")
    ap.add_argument("--run-dir", default="")
    ap.add_argument("--force-current-window", action="store_true")
    ap.add_argument("--repair-missing-windows", action="store_true")
    ap.add_argument("--verbose", action="store_true")

    # 直接调用时可用的参数
    ap.add_argument("--selected-windows", default="")
    ap.add_argument("--out-root", default="")
    ap.add_argument("--target-window-id", default="")
    ap.add_argument("--plan-json", default="")
    ap.add_argument("--run-id", default="")
    ap.add_argument("--plan-out-dir", default="")

    # 兼容可能出现的旧参数
    ap.add_argument("--selected-windows-path", default="")
    ap.add_argument("--m17-out-root", default="")
    ap.add_argument("--out-dir", default="")
    ap.add_argument("--history-root", default="")
    ap.add_argument("--incremental-plan-json", default="")

    args, unknown = ap.parse_known_args()

    plan_path = find_plan_json(args.plan_dir or args.plan_out_dir, args.plan_json or args.incremental_plan_json)
    plan = read_json(plan_path, {}) if plan_path else {}
    if not isinstance(plan, dict):
        plan = {}

    selected_windows_from_plan = (
        plan.get("selected_windows_path")
        or plan.get("selected_windows")
        or plan.get("selected_windows_json")
        or ""
    )

    target_from_plan = (
        plan.get("target_window_id")
        or plan.get("target")
        or ""
    )

    out_root_from_plan = (
        plan.get("out_root")
        or plan.get("m17_out_root")
        or ""
    )

    selected_path = Path(first_existing(
        args.selected_windows,
        args.selected_windows_path,
        selected_windows_from_plan,
        default=DEFAULT_SELECTED_WINDOWS,
    ))

    out_root = Path(first_existing(
        args.out_root,
        args.m17_out_root,
        args.history_root,
        out_root_from_plan,
        default=DEFAULT_OUT_ROOT,
    ))

    target_window_id = first_existing(
        args.target_window_id,
        target_from_plan,
        default="",
    )

    selected = load_selected_windows(selected_path)
    filtered = pick_target_windows(selected, target_window_id or None)

    tmp_dir = Path(tempfile.mkdtemp(prefix="m17_incremental_selected_"))
    tmp_selected = tmp_dir / "selected_windows.json"

    write_json(tmp_selected, {
        "schema": "s3.m17.incremental_selected_windows.compat.v3",
        "generated_at_utc": utc_now(),
        "source_selected_windows": str(selected_path),
        "plan_json": str(plan_path) if plan_path else None,
        "target_window_id": target_window_id,
        "run_id": args.run_id,
        "run_dir": args.run_dir,
        "selected_window_count": len(filtered),
        "selected_windows": filtered,
        "unknown_args": unknown,
    })

    cmd = [
        sys.executable,
        "-m",
        "scripts.p3.m17.run_m17_vrp_entry_diff",
        "--selected-windows",
        str(tmp_selected),
        "--out-root",
        str(out_root),
        "--step",
        "all",
    ]

    print("M17_INCREMENTAL_PIPELINE_COMPAT=START")
    print(f"generated_at_utc = {utc_now()}")
    print(f"target_window_id = {target_window_id}")
    print(f"run_id = {args.run_id}")
    print(f"run_dir = {args.run_dir}")
    print(f"plan_dir = {args.plan_dir}")
    print(f"plan_json = {plan_path}")
    print(f"source_selected_windows = {selected_path}")
    print(f"filtered_selected_windows = {tmp_selected}")
    print(f"filtered_window_count = {len(filtered)}")
    print(f"out_root = {out_root}")
    print(f"unknown_args = {unknown}")
    print("command = " + " ".join(cmd))

    proc = subprocess.run(cmd, text=True)

    status = "PASS" if proc.returncode == 0 else "FAIL"

    # wrapper line 222 expects this check under plan dir if available
    if args.plan_dir:
        check_path = Path(args.plan_dir) / "M17_INCREMENTAL_I2_PIPELINE_CHECK.txt"
        lines = [
            f"M17_INCREMENTAL_I2_PIPELINE={status}",
            f"generated_at_utc = {utc_now()}",
            f"target_window_id = {target_window_id}",
            f"returncode = {proc.returncode}",
            f"plan_json = {plan_path}",
            f"filtered_selected_windows = {tmp_selected}",
            f"out_root = {out_root}",
        ]
        check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"M17_INCREMENTAL_PIPELINE_COMPAT={status}")
    print(f"returncode = {proc.returncode}")

    raise SystemExit(proc.returncode)


if __name__ == "__main__":
    main()
