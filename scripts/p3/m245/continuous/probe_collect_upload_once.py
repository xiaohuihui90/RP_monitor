from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_stdout_value(text: str, key: str) -> str:
    prefix = key + "="
    for line in text.splitlines():
        if line.startswith(prefix):
            return line.split("=", 1)[1].strip()
    return ""


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--collector-url", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--window-id", default="")
    ap.add_argument("--window-mode", default="previous-completed")
    ap.add_argument("--timeout-sec", type=int, default=20)
    ap.add_argument("--vrp-timeout-sec", type=int, default=2400)
    ap.add_argument("--validator-update-mode", default="noupdate")
    ap.add_argument("--vrp-count-low-threshold", type=int, default=500000)
    ap.add_argument("--window-quality", default="late")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = f"{project_dir}:{env.get('PYTHONPATH', '')}"

    hard_fail = []

    if args.window_id:
        window_id = args.window_id
    else:
        cmd_window = [
            sys.executable,
            "-m",
            "scripts.p3.m245.continuous.m245_window_id",
            "--mode",
            args.window_mode,
            "--format",
            "window-id",
        ]
        win_proc = subprocess.run(
            cmd_window,
            cwd=str(project_dir),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if win_proc.returncode != 0:
            raise SystemExit(
                "WINDOW_ID_FAILED\n"
                + f"STDOUT={win_proc.stdout}\n"
                + f"STDERR={win_proc.stderr}\n"
            )
        window_id = win_proc.stdout.strip()

    probe_stdout_path = out_dir / f"probe_window_runner_{args.probe_id}_{window_id}.stdout"
    probe_stderr_path = out_dir / f"probe_window_runner_{args.probe_id}_{window_id}.stderr"

    cmd_probe = [
        sys.executable,
        "-m",
        "scripts.p3.m245.probe.probe_window_runner",
        "--probe-id",
        args.probe_id,
        "--project-dir",
        str(project_dir),
        "--timeout-sec",
        str(args.timeout_sec),
        "--vrp-timeout-sec",
        str(args.vrp_timeout_sec),
        "--window-id",
        window_id,
        "--run-mode",
        "scheduled",
        "--window-quality",
        args.window_quality,
        "--validator-update-mode",
        args.validator_update_mode,
        "--vrp-count-low-threshold",
        str(args.vrp_count_low_threshold),
    ]

    probe_proc = subprocess.run(
        cmd_probe,
        cwd=str(project_dir),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    probe_stdout_path.write_text(probe_proc.stdout, encoding="utf-8")
    probe_stderr_path.write_text(probe_proc.stderr, encoding="utf-8")

    run_dir_str = parse_stdout_value(probe_proc.stdout, "M245_PROBE_WINDOW_RUN_DIR")
    probe_status = parse_stdout_value(probe_proc.stdout, "M245_PROBE_WINDOW_STATUS")

    if probe_proc.returncode != 0:
        hard_fail.append(f"probe_runner_returncode_{probe_proc.returncode}")
    if not run_dir_str:
        hard_fail.append("probe_run_dir_missing_from_stdout")
    if probe_status != "PASS":
        hard_fail.append(f"probe_status_{probe_status or 'UNKNOWN'}")

    upload_result = {}
    upload_stdout_path = out_dir / f"upload_{args.probe_id}_{window_id}.stdout"
    upload_stderr_path = out_dir / f"upload_{args.probe_id}_{window_id}.stderr"

    if not hard_fail:
        run_dir = Path(run_dir_str)
        upload_tmp = out_dir / "upload_tmp"
        upload_tmp.mkdir(parents=True, exist_ok=True)

        cmd_upload = [
            sys.executable,
            "-m",
            "scripts.p3.m245.continuous.probe_result_uploader",
            "--project-dir",
            str(project_dir),
            "--run-dir",
            str(run_dir),
            "--probe-id",
            args.probe_id,
            "--window-id",
            window_id,
            "--collector-url",
            args.collector_url,
            "--token",
            args.token,
            "--out-dir",
            str(upload_tmp),
            "--stdout",
            str(probe_stdout_path),
        ]

        upload_proc = subprocess.run(
            cmd_upload,
            cwd=str(project_dir),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        upload_stdout_path.write_text(upload_proc.stdout, encoding="utf-8")
        upload_stderr_path.write_text(upload_proc.stderr, encoding="utf-8")

        if upload_proc.returncode != 0:
            hard_fail.append(f"upload_returncode_{upload_proc.returncode}")

        upload_json = upload_tmp / f"upload_result_{args.probe_id}_{window_id}.json"
        if upload_json.exists():
            upload_result = read_json(upload_json)
        else:
            hard_fail.append("upload_result_json_missing")

        if upload_result and upload_result.get("status") != "PASS":
            hard_fail.append(f"upload_status_{upload_result.get('status')}")

    status = "PASS" if not hard_fail else "FAIL"

    summary = {
        "schema": "s3.m245.h1.probe_collect_upload_once.v1",
        "status": status,
        "created_at_utc": utc_now(),
        "probe_id": args.probe_id,
        "window_id": window_id,
        "project_dir": str(project_dir),
        "out_dir": str(out_dir),
        "probe_runner_returncode": probe_proc.returncode,
        "probe_status": probe_status,
        "probe_run_dir": run_dir_str,
        "collector_url": args.collector_url,
        "upload_status": upload_result.get("status") if upload_result else None,
        "upload_receipt_status": upload_result.get("receipt", {}).get("status") if upload_result else None,
        "upload_extract_status": upload_result.get("receipt", {}).get("extract_status") if upload_result else None,
        "hard_fail": hard_fail,
    }

    summary_path = out_dir / f"H1_probe_collect_upload_once_summary_{args.probe_id}_{window_id}.json"
    check_path = out_dir / f"H1_probe_collect_upload_once_check_{args.probe_id}_{window_id}.txt"

    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"H1_PROBE_COLLECT_UPLOAD_ONCE={status}\n\n")
        f.write(f"created_at_utc = {summary['created_at_utc']}\n")
        f.write(f"probe_id = {args.probe_id}\n")
        f.write(f"window_id = {window_id}\n")
        f.write(f"probe_status = {probe_status}\n")
        f.write(f"probe_run_dir = {run_dir_str}\n")
        f.write(f"upload_status = {summary['upload_status']}\n")
        f.write(f"upload_receipt_status = {summary['upload_receipt_status']}\n")
        f.write(f"upload_extract_status = {summary['upload_extract_status']}\n")
        f.write(f"hard_fail = {hard_fail}\n")

    print(f"H1_CHECK={check_path}")
    print(f"H1_SUMMARY={summary_path}")
    print(f"H1_STATUS={status}")
    print(f"H1_WINDOW_ID={window_id}")
    print(f"H1_PROBE_RUN_DIR={run_dir_str}")


if __name__ == "__main__":
    main()
