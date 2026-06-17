#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def file_nonempty(path: Path) -> bool:
    return path.exists() and path.is_file() and path.stat().st_size > 0


def text_contains(path: Path, needle: str) -> bool:
    if not path.exists() or not path.is_file():
        return False
    try:
        return needle in path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False


def output_dir_for_window(out_root: Path, window_id: str) -> Path:
    return out_root / "history" / f"m17_window_{window_id}" / "outputs"


def check_window_completion(out_root: Path, window_id: str) -> dict[str, Any]:
    out_dir = output_dir_for_window(out_root, window_id)

    canonical_manifest = out_dir / "canonical_vrp_manifest.json"
    pairwise_summary = out_dir / "pairwise_diff_summary.json"
    diff_records = out_dir / "vrp_entry_diff_records.jsonl"
    diff_summary = out_dir / "vrp_entry_diff_summary.json"
    lifetime_seed = out_dir / "m18_lifetime_seed_records.jsonl"
    acceptance = out_dir / "M17_ACCEPTANCE.txt"

    checks = {
        "canonical_complete": file_nonempty(canonical_manifest),
        "pairwise_complete": file_nonempty(pairwise_summary) and file_nonempty(diff_records),
        "aggregator_complete": file_nonempty(diff_summary),
        "lifetime_seed_complete": file_nonempty(lifetime_seed),
        "acceptance_pass": file_nonempty(acceptance) and text_contains(acceptance, "M17_ACCEPTANCE=PASS"),
    }

    complete = all(checks.values())

    missing = [k for k, v in checks.items() if not v]

    return {
        "window_id": window_id,
        "out_dir": str(out_dir),
        "complete": complete,
        "missing_checks": missing,
        "checks": checks,
        "files": {
            "canonical_vrp_manifest": str(canonical_manifest),
            "pairwise_diff_summary": str(pairwise_summary),
            "vrp_entry_diff_records": str(diff_records),
            "vrp_entry_diff_summary": str(diff_summary),
            "m18_lifetime_seed_records": str(lifetime_seed),
            "M17_ACCEPTANCE": str(acceptance),
        },
        "file_sizes": {
            "canonical_vrp_manifest": canonical_manifest.stat().st_size if canonical_manifest.exists() else 0,
            "pairwise_diff_summary": pairwise_summary.stat().st_size if pairwise_summary.exists() else 0,
            "vrp_entry_diff_records": diff_records.stat().st_size if diff_records.exists() else 0,
            "vrp_entry_diff_summary": diff_summary.stat().st_size if diff_summary.exists() else 0,
            "m18_lifetime_seed_records": lifetime_seed.stat().st_size if lifetime_seed.exists() else 0,
            "M17_ACCEPTANCE": acceptance.stat().st_size if acceptance.exists() else 0,
        },
    }


def step_plan_for_window(
    *,
    window_id: str,
    target_window_id: str,
    completion: dict[str, Any],
    force_current_window: bool,
    repair_missing_windows: bool,
) -> dict[str, str]:
    is_target = window_id == target_window_id

    if is_target and force_current_window:
        return {
            "canonical_vrp_normalizer": "run",
            "pairwise_vrp_diff": "run",
            "aggregator": "run",
            "lifetime_seed": "run",
            "acceptance": "run",
        }

    if completion["complete"]:
        return {
            "canonical_vrp_normalizer": "skip",
            "pairwise_vrp_diff": "skip",
            "aggregator": "skip",
            "lifetime_seed": "skip",
            "acceptance": "skip",
        }

    if not repair_missing_windows:
        return {
            "canonical_vrp_normalizer": "skip_incomplete_no_repair",
            "pairwise_vrp_diff": "skip_incomplete_no_repair",
            "aggregator": "skip_incomplete_no_repair",
            "lifetime_seed": "skip_incomplete_no_repair",
            "acceptance": "skip_incomplete_no_repair",
        }

    checks = completion["checks"]

    # 简化修复策略：从第一个缺失阶段开始向后补跑。
    if not checks["canonical_complete"]:
        return {
            "canonical_vrp_normalizer": "run",
            "pairwise_vrp_diff": "run",
            "aggregator": "run",
            "lifetime_seed": "run",
            "acceptance": "run",
        }

    if not checks["pairwise_complete"]:
        return {
            "canonical_vrp_normalizer": "skip",
            "pairwise_vrp_diff": "run",
            "aggregator": "run",
            "lifetime_seed": "run",
            "acceptance": "run",
        }

    if not checks["aggregator_complete"]:
        return {
            "canonical_vrp_normalizer": "skip",
            "pairwise_vrp_diff": "skip",
            "aggregator": "run",
            "lifetime_seed": "run",
            "acceptance": "run",
        }

    if not checks["lifetime_seed_complete"]:
        return {
            "canonical_vrp_normalizer": "skip",
            "pairwise_vrp_diff": "skip",
            "aggregator": "skip",
            "lifetime_seed": "run",
            "acceptance": "run",
        }

    if not checks["acceptance_pass"]:
        return {
            "canonical_vrp_normalizer": "skip",
            "pairwise_vrp_diff": "skip",
            "aggregator": "skip",
            "lifetime_seed": "skip",
            "acceptance": "run",
        }

    return {
        "canonical_vrp_normalizer": "skip",
        "pairwise_vrp_diff": "skip",
        "aggregator": "skip",
        "lifetime_seed": "skip",
        "acceptance": "skip",
    }


def classify_window_action(steps: dict[str, str]) -> str:
    vals = set(steps.values())
    if vals == {"skip"}:
        return "skip"
    if any(v == "run" for v in vals):
        return "run"
    if any(v == "skip_incomplete_no_repair" for v in vals):
        return "blocked_incomplete_no_repair"
    return "unknown"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selected-windows", required=True)
    ap.add_argument("--out-root", default="data/p3_collector/m17_vrp_entry_diff")
    ap.add_argument("--target-window-id", required=True)
    ap.add_argument("--plan-out-dir", required=True)
    ap.add_argument("--force-current-window", action="store_true")
    ap.add_argument("--repair-missing-windows", action="store_true")
    args = ap.parse_args()

    selected_path = Path(args.selected_windows)
    out_root = Path(args.out_root)
    plan_out_dir = Path(args.plan_out_dir)
    plan_out_dir.mkdir(parents=True, exist_ok=True)

    selected = read_json(selected_path)
    windows = selected.get("selected_windows", [])

    target_found = any(w.get("window_id") == args.target_window_id for w in windows)

    window_records = []
    run_windows = []
    skip_windows = []
    repair_windows = []
    blocked_windows = []

    for w in windows:
        wid = w.get("window_id")
        if not wid:
            continue

        completion = check_window_completion(out_root, wid)
        steps = step_plan_for_window(
            window_id=wid,
            target_window_id=args.target_window_id,
            completion=completion,
            force_current_window=args.force_current_window,
            repair_missing_windows=args.repair_missing_windows,
        )

        action = classify_window_action(steps)
        reason = []

        if wid == args.target_window_id:
            reason.append("target_window")
            if args.force_current_window:
                reason.append("force_current_window")

        if action == "skip":
            reason.append("completed_history_window")
            skip_windows.append(wid)
        elif action == "run":
            if wid != args.target_window_id and not completion["complete"]:
                reason.append("repair_missing_window")
                repair_windows.append(wid)
            else:
                run_windows.append(wid)
        elif action == "blocked_incomplete_no_repair":
            reason.append("incomplete_but_repair_disabled")
            blocked_windows.append(wid)

        window_records.append({
            "window_id": wid,
            "action": action,
            "reason": reason,
            "steps": steps,
            "completion": completion,
            "selected_window_record": w,
        })

    status = "PASS"
    blockers = []

    if not target_found:
        status = "FAIL_TARGET_NOT_SELECTED"
        blockers.append("target_window_not_found_in_selected_windows")

    if blocked_windows:
        status = "FAIL_BLOCKED_INCOMPLETE_WINDOWS"
        blockers.append("incomplete_windows_found_but_repair_disabled")

    plan = {
        "schema": "s3.m17.incremental_plan.v1",
        "generated_at_utc": utc_now(),
        "status": status,
        "mode": "incremental",
        "selected_windows_path": str(selected_path),
        "out_root": str(out_root),
        "target_window_id": args.target_window_id,
        "target_found": target_found,
        "force_current_window": args.force_current_window,
        "repair_missing_windows": args.repair_missing_windows,
        "window_count": len(window_records),
        "run_windows": run_windows,
        "skip_windows": skip_windows,
        "repair_windows": repair_windows,
        "blocked_windows": blocked_windows,
        "blockers": blockers,
        "summary": {
            "run_window_count": len(run_windows),
            "skip_window_count": len(skip_windows),
            "repair_window_count": len(repair_windows),
            "blocked_window_count": len(blocked_windows),
        },
        "windows": window_records,
    }

    write_json(plan_out_dir / "m17_incremental_plan.json", plan)

    md = []
    md.append("# M17 Incremental Plan")
    md.append("")
    md.append(f"generated_at_utc: `{plan['generated_at_utc']}`")
    md.append(f"status: `{status}`")
    md.append(f"target_window_id: `{args.target_window_id}`")
    md.append("")
    md.append("## Summary")
    md.append("")
    for k, v in plan["summary"].items():
        md.append(f"- {k}: `{v}`")
    md.append("")
    md.append("## Windows")
    md.append("")
    for r in window_records:
        md.append(f"- `{r['window_id']}` action=`{r['action']}` reason=`{','.join(r['reason'])}`")
    md.append("")
    (plan_out_dir / "m17_incremental_plan.md").write_text("\n".join(md), encoding="utf-8")

    txt = [
        f"M17_INCREMENTAL_PLAN={status}",
        f"generated_at_utc = {plan['generated_at_utc']}",
        f"target_window_id = {args.target_window_id}",
        f"target_found = {target_found}",
        f"window_count = {len(window_records)}",
        f"run_window_count = {len(run_windows)}",
        f"skip_window_count = {len(skip_windows)}",
        f"repair_window_count = {len(repair_windows)}",
        f"blocked_window_count = {len(blocked_windows)}",
        f"force_current_window = {args.force_current_window}",
        f"repair_missing_windows = {args.repair_missing_windows}",
        f"blockers = {blockers}",
        f"plan_json = {plan_out_dir / 'm17_incremental_plan.json'}",
        f"plan_md = {plan_out_dir / 'm17_incremental_plan.md'}",
    ]

    (plan_out_dir / "M17_INCREMENTAL_PLAN_CHECK.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")
    print("\n".join(txt))

    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
