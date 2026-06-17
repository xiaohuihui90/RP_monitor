#!/usr/bin/env python3
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
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_text_head(path: Path, limit: int = 4000) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")[:limit]


def run_step(
    *,
    name: str,
    cmd: list[str],
    project_dir: Path,
    log_dir: Path,
    env: dict[str, str],
) -> dict[str, Any]:
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = log_dir / f"{name}.stdout"
    stderr_path = log_dir / f"{name}.stderr"

    started = utc_now()
    with stdout_path.open("w", encoding="utf-8") as out, stderr_path.open("w", encoding="utf-8") as err:
        proc = subprocess.run(
            cmd,
            cwd=str(project_dir),
            env=env,
            stdout=out,
            stderr=err,
            text=True,
        )

    finished = utc_now()
    status = "PASS" if proc.returncode == 0 else "FAIL"

    return {
        "step": name,
        "status": status,
        "returncode": proc.returncode,
        "started_at_utc": started,
        "finished_at_utc": finished,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stdout_head": read_text_head(stdout_path),
        "stderr_head": read_text_head(stderr_path),
        "cmd": cmd,
    }


def must_continue(step_record: dict[str, Any]) -> None:
    if step_record["status"] != "PASS":
        print(f"STEP_FAILED={step_record['step']}")
        print(f"stdout={step_record['stdout_path']}")
        print(f"stderr={step_record['stderr_path']}")
        print(step_record.get("stderr_head", ""))
        raise SystemExit(1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--run-id", default="")
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--m17c-root", default="data/p3_collector/m17_continuous_lite")
    ap.add_argument("--m245-history-root", default="data/p3_collector/m245_three_layer_baseline/history")
    ap.add_argument("--m17-root", default="data/p3_collector/m17_vrp_entry_diff/history")
    ap.add_argument("--m17-out-root", default="data/p3_collector/m17_vrp_entry_diff")
    ap.add_argument("--selected-windows", default="data/p3_collector/m245_three_layer_baseline/m17_vrp_entry_diff_inputs/selected_windows.json")
    ap.add_argument("--report-dir", default="data/p3_collector/m17_continuous_lite/reports")
    ap.add_argument("--skip-finalizer", action="store_true")
    ap.add_argument("--skip-raw-import", action="store_true")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    window_id = args.window_id
    run_id = args.run_id or os.environ.get("M17C_RUN_ID") or f"m17c_manual_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    m17c_root = project_dir / args.m17c_root
    run_dir = m17c_root / "history" / run_id
    check_dir = run_dir / "checks"
    output_dir = run_dir / "outputs"
    log_dir = run_dir / "logs"

    check_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONPATH"] = f"{project_dir}:{env.get('PYTHONPATH', '')}"

    steps: list[dict[str, Any]] = []

    def run(name: str, cmd: list[str], required: bool = True) -> None:
        print(f"===== STEP {name} =====", flush=True)
        rec = run_step(name=name, cmd=cmd, project_dir=project_dir, log_dir=log_dir, env=env)
        steps.append(rec)
        print(f"{name}={rec['status']} returncode={rec['returncode']}", flush=True)
        if required:
            must_continue(rec)

    # 1. resolver
    run(
        "01_window_inbox_resolver",
        [
            sys.executable,
            "-m",
            "scripts.p3.m245.continuous.window_inbox_resolver",
            "--project-dir",
            str(project_dir),
            "--window-id",
            window_id,
            "--out-dir",
            str(output_dir / f"resolve_{window_id}"),
        ],
    )

    # 2. finalizer
    if not args.skip_finalizer:
        run(
            "02_window_auto_finalizer",
            [
                sys.executable,
                "-m",
                "scripts.p3.m245.continuous.window_auto_finalizer",
                "--project-dir",
                str(project_dir),
                "--window-id",
                window_id,
                "--out-dir",
                str(output_dir / f"finalizer_{window_id}"),
            ],
        )

    # 3. raw VRP sidecar import
    if not args.skip_raw_import:
        run(
            "03_raw_vrp_sidecar_import",
            [
                sys.executable,
                "scripts/p3/import_raw_vrp_sidecar_to_history.py",
                "--incoming-dir",
                f"data/p3_collector/m245_three_layer_baseline/raw_vrp_sidecar_incoming/{window_id}",
                "--history-root",
                "data/p3_collector/m245_three_layer_baseline/history",
                "--pending-root",
                "data/p3_collector/m245_three_layer_baseline/raw_vrp_sidecar_pending",
                "--work-dir",
                "data/p3_collector/m245_three_layer_baseline/raw_vrp_sidecar_import_work",
                "--out-dir",
                str(output_dir / f"import_{window_id}"),
            ],
        )

    # 4. P0 post-check
    p0_modules = [
        "scripts.p3.run_p0_h7_overlay",
        "scripts.p3.run_p0_raw_vrp_retention_check",
        "scripts.p3.run_p0_validator_metadata_check",
        "scripts.p3.run_p0_window_stats",
        "scripts.p3.run_p0_basic_evidence_pack",
        "scripts.p3.run_p0_semantic_guardrail",
        "scripts.p3.run_p0_select_m17_candidates",
    ]

    for i, mod in enumerate(p0_modules, start=4):
        run(f"{i:02d}_{mod.split('.')[-1]}", [sys.executable, "-m", mod])

    # 5. M17 entry diff steps
    m17_steps = [
        "canonical_vrp_normalizer",
        "pairwise_vrp_diff",
        "aggregator",
        "lifetime_seed",
        "acceptance",
    ]

    for i, step in enumerate(m17_steps, start=11):
        run(
            f"{i:02d}_m17_{step}",
            [
                sys.executable,
                "-m",
                "scripts.p3.m17.run_m17_vrp_entry_diff",
                "--selected-windows",
                args.selected_windows,
                "--out-root",
                args.m17_out_root,
                "--step",
                step,
            ],
        )

    m17_window_dir = Path(args.m17_out_root) / "history" / f"m17_window_{window_id}"
    m17_outputs = m17_window_dir / "outputs"

    # 6. quality annotation
    run(
        "16_m17_quality_annotation",
        [
            sys.executable,
            "-m",
            "scripts.p3.m17.run_m17_quality_annotation",
            "--window-id",
            window_id,
            "--m17-root",
            str(Path(args.m17_out_root) / "history"),
            "--m245-root",
            args.m245_history_root,
        ],
    )

    # 7. result digest
    run(
        "17_m17_result_digest",
        [
            sys.executable,
            "-m",
            "scripts.p3.m17.run_m17_result_digest",
            "--m17-window-dir",
            str(m17_window_dir),
            "--out-dir",
            f"data/p3_collector/m17_vrp_entry_diff/reports/{window_id}",
            "--top-n",
            "30",
        ],
    )

    # 8. validator cycle
    run(
        "18_validator_cycle_record",
        [
            sys.executable,
            "-m",
            "scripts.p3.m17.run_m17_validator_cycle_record",
            "--window-id",
            window_id,
            "--m245-history-root",
            args.m245_history_root,
            "--m17-root",
            str(Path(args.m17_out_root) / "history"),
        ],
    )

    # 9. effective input summary
    run(
        "19_validator_effective_input_summary",
        [
            sys.executable,
            "-m",
            "scripts.p3.m17.run_m17_effective_input_summary",
            "--window-id",
            window_id,
            "--m245-history-root",
            args.m245_history_root,
            "--m17-root",
            str(Path(args.m17_out_root) / "history"),
        ],
    )

    # 10. report refresh
    run(
        "20_m17c_window_report",
        [
            sys.executable,
            "-m",
            "scripts.p3.m17c.run_m17c_window_report",
            "--m17-root",
            str(Path(args.m17_out_root) / "history"),
            "--report-dir",
            args.report_dir,
        ],
    )

    status = "PASS" if all(s["status"] == "PASS" for s in steps) else "FAIL"

    summary = {
        "schema": "s3.m17c.collector_pipeline_summary.v1",
        "generated_at_utc": utc_now(),
        "run_id": run_id,
        "window_id": window_id,
        "status": status,
        "manual_szrz_used": False,
        "step_count": len(steps),
        "steps": {s["step"]: s["status"] for s in steps},
        "step_records": steps,
        "outputs": {
            "run_dir": str(run_dir),
            "m245_window_dir": f"data/p3_collector/m245_three_layer_baseline/history/m245_window_{window_id}",
            "m17_window_dir": str(m17_window_dir),
            "m17_acceptance": str(m17_outputs / "M17_ACCEPTANCE.txt"),
            "m17_quality_annotation": str(m17_outputs / "M17_quality_annotation.txt"),
            "validator_cycle_record_check": str(m17_outputs / "M17_validator_cycle_record_check.txt"),
            "validator_effective_input_summary_check": str(m17_outputs / "M17_validator_effective_input_summary_check.txt"),
            "m17c_window_report": "data/p3_collector/m17_continuous_lite/reports/M17C_window_report_check.txt",
            "m18_input_manifest": "data/p3_collector/m17_continuous_lite/reports/M17C_m18_input_manifest.json",
        },
        "semantic_boundary": {
            "mapping_strength": "weak",
            "strong_causal_claim_allowed": False,
            "accepted_object_set_available": False,
        },
    }

    summary_path = output_dir / "M17C_collector_pipeline_summary.json"
    write_json(summary_path, summary)

    txt = [
        f"M17C_COLLECTOR_PIPELINE={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"run_id = {run_id}",
        f"window_id = {window_id}",
        f"manual_szrz_used = false",
        f"step_count = {len(steps)}",
        f"summary_path = {summary_path}",
        "",
        "steps:",
    ]
    for s in steps:
        txt.append(f"  {s['step']} = {s['status']}")

    txt.append("")
    txt.append("next_stage = NEXT_SCHEDULED_WINDOW_OR_M18_PRECHECK")

    check_path = check_dir / "M17C_collector_pipeline_check.txt"
    check_path.write_text("\n".join(txt) + "\n", encoding="utf-8")

    print("\n".join(txt))

    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
