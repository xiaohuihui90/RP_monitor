from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from scripts.p3.m245.continuous.window_inbox_resolver import resolve_window


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def discover_window_ids(project_dir: Path) -> list[str]:
    inbox_root = project_dir / "data/p3_collector/m245_three_layer_baseline/inbox"
    if not inbox_root.exists():
        return []
    return sorted([p.name for p in inbox_root.iterdir() if p.is_dir() and p.name.startswith("win_")])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--allow-rerun", action="store_true")
    ap.add_argument("--window-id", default="")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    state_dir = project_dir / "data/p3_collector/m245_three_layer_baseline/state"
    finalized_path = state_dir / "finalized_windows.jsonl"
    scheduler_log_path = state_dir / "scheduler_runs.jsonl"

    already_finalized = {
        r.get("window_id")
        for r in read_jsonl(finalized_path)
        if r.get("status") == "PASS"
    }

    if args.window_id:
        window_ids = [args.window_id]
    else:
        window_ids = discover_window_ids(project_dir)

    scheduler_records = []
    hard_fail = []

    for window_id in window_ids:
        record = {
            "schema": "s3.m245.g3c.scheduler_window_record.v1",
            "created_at_utc": utc_now(),
            "window_id": window_id,
            "action": None,
            "status": None,
            "reason": None,
            "finalizer_dir": None,
            "collector_run_dir": None,
        }

        if window_id in already_finalized and not args.allow_rerun:
            record["action"] = "skip"
            record["status"] = "SKIP"
            record["reason"] = "already_finalized"
            scheduler_records.append(record)
            continue

        resolved = resolve_window(project_dir, window_id)

        if not resolved.get("ready_for_finalizer"):
            record["action"] = "skip"
            record["status"] = "NOT_READY"
            record["reason"] = ",".join(resolved.get("hard_fail", []))
            scheduler_records.append(record)
            continue

        finalizer_dir = out_dir / f"finalizer_{window_id}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        finalizer_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable,
            "-m",
            "scripts.p3.m245.continuous.window_auto_finalizer",
            "--project-dir",
            str(project_dir),
            "--window-id",
            window_id,
            "--out-dir",
            str(finalizer_dir),
        ]

        proc = subprocess.run(
            cmd,
            cwd=str(project_dir),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        stdout_path = finalizer_dir / "scheduler_finalizer.stdout"
        stderr_path = finalizer_dir / "scheduler_finalizer.stderr"
        stdout_path.write_text(proc.stdout, encoding="utf-8")
        stderr_path.write_text(proc.stderr, encoding="utf-8")

        collector_run_dir = None
        for line in proc.stdout.splitlines():
            if line.startswith("M245_G3B_COLLECTOR_RUN_DIR="):
                collector_run_dir = line.split("=", 1)[1].strip()

        if proc.returncode == 0 and "M245_G3B_STATUS=PASS" in proc.stdout:
            record["action"] = "finalize"
            record["status"] = "PASS"
            record["reason"] = "finalizer_pass"
            record["finalizer_dir"] = str(finalizer_dir)
            record["collector_run_dir"] = collector_run_dir

            append_jsonl(finalized_path, {
                "schema": "s3.m245.finalized_window.v1",
                "created_at_utc": utc_now(),
                "window_id": window_id,
                "status": "PASS",
                "finalizer_dir": str(finalizer_dir),
                "collector_run_dir": collector_run_dir,
            })
        else:
            record["action"] = "finalize"
            record["status"] = "FAIL"
            record["reason"] = f"returncode={proc.returncode}"
            record["finalizer_dir"] = str(finalizer_dir)
            record["collector_run_dir"] = collector_run_dir
            hard_fail.append(f"{window_id}:finalizer_failed")

        scheduler_records.append(record)

    for r in scheduler_records:
        append_jsonl(scheduler_log_path, r)

    status = "PASS" if not hard_fail else "FAIL"

    summary = {
        "schema": "s3.m245.g3c.scheduler_summary.v1",
        "status": status,
        "created_at_utc": utc_now(),
        "window_count": len(window_ids),
        "records": scheduler_records,
        "hard_fail": hard_fail,
    }

    summary_path = out_dir / "M245_G3C_scheduler_summary.json"
    check_path = out_dir / "M245_G3C_scheduler_check.txt"

    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    by_status = {}
    for r in scheduler_records:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1

    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"M245_G3C_SCHEDULER={status}\n\n")
        f.write(f"created_at_utc = {summary['created_at_utc']}\n")
        f.write(f"window_count = {summary['window_count']}\n")
        f.write(f"by_status = {by_status}\n")
        f.write(f"hard_fail = {hard_fail}\n")
        for r in scheduler_records:
            f.write(f"\n[{r['window_id']}]\n")
            f.write(f"action = {r['action']}\n")
            f.write(f"status = {r['status']}\n")
            f.write(f"reason = {r['reason']}\n")
            f.write(f"collector_run_dir = {r['collector_run_dir']}\n")
            f.write(f"finalizer_dir = {r['finalizer_dir']}\n")

    print(f"M245_G3C_CHECK={check_path}")
    print(f"M245_G3C_STATUS={status}")


if __name__ == "__main__":
    main()
