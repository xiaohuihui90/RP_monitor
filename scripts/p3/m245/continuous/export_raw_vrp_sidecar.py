#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def infer_previous_completed_window(window_size_sec: int = 600) -> str:
    now = datetime.now(timezone.utc)
    ts = int(now.timestamp())

    # previous completed 10-minute window
    current_window_start = ts - (ts % window_size_sec)
    previous_window_start = current_window_start - window_size_sec

    dt = datetime.fromtimestamp(previous_window_start, tz=timezone.utc)
    return "win_" + dt.strftime("%Y%m%dT%H%M%SZ") + "_10m"


def detect_routinator_version(binary: str) -> str | None:
    try:
        p = subprocess.run(
            [binary, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        out = (p.stdout or p.stderr or "").strip()
        return out.splitlines()[0] if out else None
    except Exception:
        return None


def run_export(
    binary: str,
    fmt: str,
    out_path: Path,
    extra_args: list[str],
    timeout_sec: int,
) -> dict[str, Any]:
    cmd = [binary, "vrps", "--format", fmt, "--noupdate", *extra_args]

    out_path.parent.mkdir(parents=True, exist_ok=True)

    started = utc_now()
    with out_path.open("w", encoding="utf-8") as f:
        proc = subprocess.run(
            cmd,
            stdout=f,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout_sec,
        )
    finished = utc_now()

    stderr_text = proc.stderr or ""

    return {
        "command": cmd,
        "started_at_utc": started,
        "finished_at_utc": finished,
        "exit_code": proc.returncode,
        "stderr_excerpt": "\n".join(stderr_text.splitlines()[:80]),
        "output_path": str(out_path),
        "output_size_bytes": out_path.stat().st_size if out_path.exists() else 0,
        "output_sha256": sha256_file(out_path),
    }


def quick_count_json_vrps(path: Path) -> tuple[int | None, str]:
    """
    Best-effort count. Avoid heavy processing if format is unexpected.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None, "json_parse_failed"

    if isinstance(data, list):
        return len(data), "top_level_list"

    if isinstance(data, dict):
        for key in ["roas", "vrps", "validated_roa_payloads", "validated_roas"]:
            val = data.get(key)
            if isinstance(val, list):
                return len(val), f"dict_key:{key}"

        return None, "dict_without_known_vrp_array"

    return None, f"unsupported_json_type:{type(data).__name__}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-id", default=os.environ.get("PROBE_ID", "probe-cd"))
    parser.add_argument("--window-id", default="")
    parser.add_argument("--out-root", default="data/probe/m245_three_layer_baseline/raw_vrp_sidecar")
    parser.add_argument("--routinator-bin", default=os.environ.get("ROUTINATOR_BIN", "routinator"))
    parser.add_argument("--format", default="json", choices=["json", "jsonext"])
    parser.add_argument("--timeout-sec", type=int, default=900)
    parser.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        help="extra args passed after --noupdate, repeatable",
    )
    args = parser.parse_args()

    if not shutil.which(args.routinator_bin):
        print(f"ERROR: routinator binary not found: {args.routinator_bin}", file=sys.stderr)
        sys.exit(2)

    window_id = args.window_id or infer_previous_completed_window()
    out_dir = Path(args.out_root) / window_id / args.probe_id

    # Keep filename stable and simple.
    raw_path = out_dir / f"{args.probe_id}_{window_id}_raw_vrp.{args.format}"

    version = detect_routinator_version(args.routinator_bin)

    export_result = run_export(
        binary=args.routinator_bin,
        fmt=args.format,
        out_path=raw_path,
        extra_args=list(args.extra_arg),
        timeout_sec=args.timeout_sec,
    )

    vrp_count_guess, count_method = quick_count_json_vrps(raw_path) if export_result["exit_code"] == 0 else (None, "export_failed")

    status = "PASS" if export_result["exit_code"] == 0 and export_result["output_size_bytes"] > 0 else "FAIL"

    manifest = {
        "schema": "s3.m245.raw_vrp_sidecar_manifest.v1",
        "generated_at_utc": utc_now(),
        "status": status,
        "probe_id": args.probe_id,
        "window_id": window_id,
        "out_dir": str(out_dir),
        "validator": "routinator",
        "validator_version": version,
        "update_mode": "noupdate",
        "format": args.format,
        "raw_vrp_path": str(raw_path),
        "raw_vrp_sha256": export_result["output_sha256"],
        "raw_vrp_size_bytes": export_result["output_size_bytes"],
        "vrp_count_guess": vrp_count_guess,
        "vrp_count_guess_method": count_method,
        "export_result": export_result,
        "strong_attribution_allowed": False,
        "note": "Raw VRP sidecar export for M17 entry-level diff; not used for strong causal attribution.",
    }

    write_json(out_dir / "raw_vrp_export_manifest.json", manifest)

    txt = [
        f"P0_RAW_VRP_SIDECAR={status}",
        f"generated_at_utc = {manifest['generated_at_utc']}",
        f"probe_id = {args.probe_id}",
        f"window_id = {window_id}",
        f"validator_version = {version}",
        f"format = {args.format}",
        f"raw_vrp_path = {raw_path}",
        f"raw_vrp_size_bytes = {export_result['output_size_bytes']}",
        f"vrp_count_guess = {vrp_count_guess}",
        f"exit_code = {export_result['exit_code']}",
    ]

    (out_dir / "raw_vrp_export_check.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")
    print("\n".join(txt))

    if status != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    main()
