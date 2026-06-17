from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--update-existing-summaries", action="store_true")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    history_root = project_dir / "data/p3_collector/m245_three_layer_baseline/history"
    hard_fail: list[str] = []
    records: list[dict[str, Any]] = []

    if not history_root.exists():
        hard_fail.append(f"history_root_missing:{history_root}")

    run_dirs = []
    if history_root.exists():
        run_dirs = sorted(
            history_root.glob("m245_window_win_*"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )

    candidate_count = 0
    processed_count = 0
    skipped_count = 0

    env = os.environ.copy()
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = f"{project_dir}:{env.get('PYTHONPATH', '')}"

    for run_dir in run_dirs[: args.limit]:
        window_id = run_dir.name.replace("m245_window_", "", 1)
        outputs = run_dir / "outputs"

        loop_summary = outputs / "THREE_LAYER_BASELINE_LOOP_SUMMARY.json"
        matrix = outputs / "M245_three_layer_status_matrix.json"
        m25_summary = outputs / "M25_basic_attribution_summary.json"
        mapping_context = outputs / "M245_layer_mapping_context.json"

        if not loop_summary.exists() or not matrix.exists() or not m25_summary.exists():
            skipped_count += 1
            records.append({
                "window_id": window_id,
                "action": "skip",
                "reason": "required_outputs_missing",
                "run_dir": str(run_dir),
            })
            continue

        if mapping_context.exists() and not args.force:
            skipped_count += 1
            records.append({
                "window_id": window_id,
                "action": "skip",
                "reason": "mapping_context_exists",
                "run_dir": str(run_dir),
            })
            continue

        candidate_count += 1

        item_out_dir = out_dir / f"mapping_{window_id}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        item_out_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable,
            "-m",
            "scripts.p3.m245.collector.layer_mapping_context_builder",
            "--project-dir",
            str(project_dir),
            "--collector-run-dir",
            str(run_dir),
            "--window-id",
            window_id,
            "--out-dir",
            str(item_out_dir),
            "--update-existing-summaries",
        ]

        proc = subprocess.run(
            cmd,
            cwd=str(project_dir),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        (item_out_dir / "builder.stdout").write_text(proc.stdout, encoding="utf-8")
        (item_out_dir / "builder.stderr").write_text(proc.stderr, encoding="utf-8")

        ok = proc.returncode == 0 and mapping_context.exists()

        if ok:
            processed_count += 1
            action = "processed"
            reason = "mapping_context_created"
        else:
            action = "fail"
            reason = f"builder_rc_{proc.returncode}"
            hard_fail.append(f"{window_id}:{reason}")

        records.append({
            "window_id": window_id,
            "action": action,
            "reason": reason,
            "run_dir": str(run_dir),
            "mapping_context": str(mapping_context),
            "builder_out_dir": str(item_out_dir),
            "returncode": proc.returncode,
        })

    status = "PASS" if not hard_fail else "FAIL"

    summary = {
        "schema": "s3.m245.h3b.layer_mapping_backfill_once.v1",
        "status": status,
        "created_at_utc": utc_now(),
        "history_root": str(history_root),
        "candidate_count": candidate_count,
        "processed_count": processed_count,
        "skipped_count": skipped_count,
        "records": records,
        "hard_fail": hard_fail,
    }

    write_json(out_dir / "H3B_mapping_context_backfill_once_summary.json", summary)

    check_path = out_dir / "H3B_MAPPING_CONTEXT_BACKFILL_ONCE_CHECK.txt"
    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"H3B_MAPPING_CONTEXT_BACKFILL_ONCE={status}\n\n")
        f.write(f"created_at_utc = {summary['created_at_utc']}\n")
        f.write(f"candidate_count = {candidate_count}\n")
        f.write(f"processed_count = {processed_count}\n")
        f.write(f"skipped_count = {skipped_count}\n")
        f.write(f"hard_fail = {hard_fail}\n")
        for r in records[:20]:
            f.write(f"\n[{r['window_id']}]\n")
            f.write(f"action = {r['action']}\n")
            f.write(f"reason = {r['reason']}\n")
            f.write(f"mapping_context = {r.get('mapping_context')}\n")

    print(f"H3B_BACKFILL_CHECK={check_path}")
    print(f"H3B_BACKFILL_STATUS={status}")
    print(f"H3B_BACKFILL_PROCESSED={processed_count}")


if __name__ == "__main__":
    main()
