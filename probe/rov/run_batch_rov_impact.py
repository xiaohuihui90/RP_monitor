#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_BATCH_SUMMARY = "s3.probe.rov.p10d_batch_summary.v1"
ACCEPTANCE_FILE = "checks/P10D_BATCH_ROV_IMPACT_ACCEPTANCE.txt"
WINDOW_SUMMARY_FIELDS = [
    "batch_id",
    "window_id",
    "p8_run_dir",
    "p10c_run_dir",
    "p10a_run_dir",
    "p10b_run_dir",
    "collector",
    "selected_rib_time_utc",
    "rib_time_delta_sec",
    "p10c_status",
    "p10a_status",
    "p10b_status",
    "route_count",
    "transition_event_count",
    "affected_prefix_count",
    "affected_origin_as_count",
    "usable_window",
    "normal_impact_analysis_executed",
    "exclusion_reasons",
]
TRANSITION_MATRIX_FIELDS = [
    "batch_id",
    "window_id",
    "collector",
    "p10a_run_dir",
    "probe_a",
    "probe_b",
    "state_a",
    "state_b",
    "route_count",
    "unique_prefix_count",
    "unique_origin_as_count",
]
PREFIX_FIELDS = [
    "batch_id",
    "collector",
    "p10a_run_dir",
    "window_id",
    "prefix",
    "origin_asn",
    "transition_types",
    "probe_pairs",
    "collector_count",
    "first_seen_utc",
    "last_seen_utc",
]
ORIGIN_FIELDS = [
    "batch_id",
    "collector",
    "p10a_run_dir",
    "window_id",
    "origin_asn",
    "affected_prefix_count",
    "transition_types",
    "probe_pairs",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"expected true or false, got {value}")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def resolve_path(value: str, root: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()


def fsync_parent(path: Path) -> None:
    if os.name == "nt":
        return
    fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    try:
        with tmp.open("wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        fsync_parent(path)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def atomic_write_json(path: Path, obj: Any) -> None:
    atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def csv_text(fieldnames: list[str], rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({name: row.get(name, "") for name in fieldnames})
    return buf.getvalue()


def parse_key_value_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    parsed: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip().lstrip("\ufeff")] = value.strip()
    return parsed


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def parse_window_start(window_id: str) -> datetime | None:
    match = re.fullmatch(r"win_(\d{8}T\d{6}Z)_1h", str(window_id or "").strip())
    if not match:
        return None
    text = match.group(1)
    try:
        return datetime.strptime(text, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def str_is_true(value: Any) -> bool:
    return str(value).strip().lower() == "true"


def p8_window_is_eligible(parsed: dict[str, str], min_p8_skew_ok: bool) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    status = parsed.get("P8_CROSS_PROBE_PIPELINE") or parsed.get("P8_CROSS_PROBE_OBSERVATION") or parsed.get("P2_CROSS_PROBE_DIFF")
    if status != "PASS":
        reasons.append("P8_NOT_PASS")
    if min_p8_skew_ok:
        if parsed.get("window_quality") != "OK":
            reasons.append("WINDOW_QUALITY_NOT_OK")
        if parsed.get("all_validator_healthy") is not None and not str_is_true(parsed.get("all_validator_healthy")):
            reasons.append("VALIDATOR_NOT_HEALTHY")
        if parsed.get("capture_time_skew_within_threshold") is not None and not str_is_true(parsed.get("capture_time_skew_within_threshold")):
            reasons.append("CAPTURE_SKEW_NOT_WITHIN_THRESHOLD")
    return not reasons, reasons


def scan_p8_runs(p8_root: Path, min_p8_skew_ok: bool) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for acceptance_path in sorted(p8_root.rglob("checks/P8_CROSS_PROBE_PIPELINE_ACCEPTANCE.txt")):
        run_dir = acceptance_path.parents[1]
        parsed = parse_key_value_file(acceptance_path)
        window_id = parsed.get("window_id") or ""
        window_start = parse_window_start(window_id)
        eligible, reasons = p8_window_is_eligible(parsed, min_p8_skew_ok)
        runs.append({
            "p8_run_dir": run_dir,
            "acceptance_path": acceptance_path,
            "acceptance": parsed,
            "window_id": window_id,
            "window_start": window_start,
            "eligible": eligible and window_start is not None,
            "selection_reasons": reasons if window_start is not None else reasons + ["WINDOW_ID_PARSE_FAILED"],
        })
    runs.sort(key=lambda item: (item["window_start"] or datetime.min.replace(tzinfo=timezone.utc), str(item["p8_run_dir"])))
    return runs


def filter_windows(
    runs: list[dict[str, Any]],
    latest_n: int | None,
    start_window_id: str | None,
    end_window_id: str | None,
) -> list[dict[str, Any]]:
    start_dt = parse_window_start(start_window_id) if start_window_id else None
    end_dt = parse_window_start(end_window_id) if end_window_id else None
    selected = []
    for item in runs:
        if not item["eligible"]:
            continue
        window_start = item["window_start"]
        if start_dt is not None and window_start < start_dt:
            continue
        if end_dt is not None and window_start > end_dt:
            continue
        selected.append(item)
    if latest_n is not None:
        selected = selected[-latest_n:]
    return selected


def sanitize_run_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.=-]+", "_", value or "unknown")


def default_batch_id() -> str:
    return "p10d_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def run_command(cmd: list[str], cwd: Path) -> dict[str, Any]:
    started = utc_now()
    proc = subprocess.run(cmd, cwd=str(cwd), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return {
        "command": cmd,
        "exit_code": proc.returncode,
        "started_at_utc": started,
        "finished_at_utc": utc_now(),
        "stdout_tail": (proc.stdout or "")[-4000:],
        "stderr_tail": (proc.stderr or "")[-4000:],
    }


def p10c_command(root: Path, args: argparse.Namespace, p8_run_dir: Path, p10c_run_dir: Path) -> list[str]:
    bash = shutil.which("bash")
    wrapper = root / "scripts" / "runtime" / "run_p10c_time_aligned_rov_once.sh"
    cmd = [bash, str(wrapper)] if bash else [sys.executable, "-m", "probe.rov.select_bgp_rib_for_window"]
    cmd += [
        "--p8-run-dir",
        str(p8_run_dir),
        "--collector",
        args.collector,
        "--source",
        args.source,
        "--rib-time-policy",
        args.rib_time_policy,
        "--download",
        str(bool(args.download)).lower(),
        "--bgpdump-bin",
        args.bgpdump_bin,
        "--out-dir",
        str(p10c_run_dir),
    ]
    if args.max_routes is not None:
        cmd += ["--max-routes", str(args.max_routes)]
    return cmd


def read_csv_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return [dict(row) for row in csv.DictReader(f)]


def append_transition_events_sample(source_path: Path, target_f: Any, remaining: int) -> int:
    if remaining <= 0 or not source_path.is_file():
        return 0
    written = 0
    with source_path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            if written >= remaining:
                break
            if not line.strip():
                continue
            target_f.write(line if line.endswith("\n") else line + "\n")
            written += 1
    return written


def collect_window_result(batch_id: str, collector: str, p8_run_dir: Path, p10c_run_dir: Path, command_result: dict[str, Any] | None) -> dict[str, Any]:
    p10c_acceptance = parse_key_value_file(p10c_run_dir / "checks" / "P10C_TIME_ALIGNED_ROV_ACCEPTANCE.txt")
    p10c_summary = load_json(p10c_run_dir / "p10c_summary.json")
    p10a_run_dir = Path(str(p10c_summary.get("p10a_run_dir") or p10c_acceptance.get("p10a_run_dir") or ""))
    p10b_run_dir = Path(str(p10c_summary.get("p10b_run_dir") or p10c_acceptance.get("p10b_run_dir") or ""))
    p10a_acceptance = parse_key_value_file(p10a_run_dir / "checks" / "P10_ROV_IMPACT_ACCEPTANCE.txt") if str(p10a_run_dir) else {}
    p10b_acceptance = parse_key_value_file(p10b_run_dir / "checks" / "P10_BGP_ROUTE_TABLE_ACCEPTANCE.txt") if str(p10b_run_dir) else {}
    p10a_summary = load_json(p10a_run_dir / "rov_impact_summary.json") if str(p10a_run_dir) else {}

    quality = p10a_summary.get("quality") if isinstance(p10a_summary.get("quality"), dict) else {}
    exclusion_reasons = quality.get("exclusion_reasons", p10a_summary.get("exclusion_reasons", []))
    if isinstance(exclusion_reasons, list):
        exclusion_text = "|".join(str(item) for item in exclusion_reasons)
    else:
        exclusion_text = str(exclusion_reasons or "")

    row = {
        "batch_id": batch_id,
        "window_id": p10c_summary.get("window_id") or p10c_acceptance.get("window_id") or "",
        "p8_run_dir": str(p8_run_dir),
        "p10c_run_dir": str(p10c_run_dir),
        "p10a_run_dir": str(p10a_run_dir) if str(p10a_run_dir) != "." else "",
        "p10b_run_dir": str(p10b_run_dir) if str(p10b_run_dir) != "." else "",
        "collector": collector,
        "selected_rib_time_utc": p10c_summary.get("selected_rib_time_utc") or p10c_acceptance.get("selected_rib_time_utc") or "",
        "rib_time_delta_sec": p10c_summary.get("rib_time_delta_sec", p10c_acceptance.get("rib_time_delta_sec", "")),
        "p10c_status": p10c_acceptance.get("P10C_TIME_ALIGNED_ROV") or p10c_summary.get("status") or "",
        "p10a_status": p10a_acceptance.get("P10_ROV_IMPACT") or p10c_summary.get("p10a_acceptance_status") or "",
        "p10b_status": p10b_acceptance.get("P10_BGP_ROUTE_TABLE") or p10c_summary.get("p10b_acceptance_status") or "",
        "route_count": p10a_acceptance.get("route_count") or p10a_summary.get("route_count", 0),
        "transition_event_count": p10a_acceptance.get("transition_event_count") or p10a_summary.get("transition_event_count", 0),
        "affected_prefix_count": p10a_acceptance.get("affected_prefix_count") or p10a_summary.get("affected_prefix_count", 0),
        "affected_origin_as_count": p10a_acceptance.get("affected_origin_as_count") or p10a_summary.get("affected_origin_as_count", 0),
        "usable_window": p10a_acceptance.get("usable_window") or str(p10a_summary.get("usable_window", "")).lower(),
        "normal_impact_analysis_executed": p10a_acceptance.get("normal_impact_analysis_executed") or str(p10a_summary.get("normal_impact_analysis_executed", "")).lower(),
        "exclusion_reasons": exclusion_text,
        "_p10a_run_dir_path": p10a_run_dir if str(p10a_run_dir) and str(p10a_run_dir) != "." else None,
        "_command_result": command_result or {},
    }
    return row


def int_value(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def write_acceptance(out_dir: Path, status: str, summary: dict[str, Any], checks: dict[str, bool]) -> None:
    lines = [
        f"P10D_BATCH_ROV_IMPACT={status}",
        f"batch_id={summary.get('batch_id', '')}",
        f"window_count_selected={summary.get('window_count_selected', 0)}",
        f"window_count_succeeded={summary.get('window_count_succeeded', 0)}",
        f"window_count_failed={summary.get('window_count_failed', 0)}",
        f"total_transition_event_count={summary.get('total_transition_event_count', 0)}",
        f"unique_affected_prefix_count={summary.get('unique_affected_prefix_count', 0)}",
        f"unique_affected_origin_as_count={summary.get('unique_affected_origin_as_count', 0)}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={str(value).lower()}" for key, value in checks.items())
    atomic_write_text(out_dir / ACCEPTANCE_FILE, "\n".join(lines) + "\n")


def run_batch(args: argparse.Namespace) -> int:
    root = repo_root()
    started_at = utc_now()
    batch_id = args.batch_id or default_batch_id()
    out_dir = resolve_path(args.out_dir, root)
    out_dir.mkdir(parents=True, exist_ok=True)
    p8_root = resolve_path(args.p8_root, root)
    all_runs = scan_p8_runs(p8_root, bool(args.min_p8_skew_ok))
    selected = filter_windows(all_runs, args.latest_n, args.start_window_id, args.end_window_id)

    window_rows: list[dict[str, Any]] = []
    transition_rows: list[dict[str, Any]] = []
    prefix_rows: list[dict[str, Any]] = []
    origin_rows: list[dict[str, Any]] = []
    command_results: list[dict[str, Any]] = []
    invoked_or_existing_count = 0
    invoked_count = 0
    failed_runtime_count = 0
    sample_remaining = int(args.transition_event_sample_limit)
    sample_path = out_dir / "p10d_transition_event_sample.jsonl"
    sample_tmp = sample_path.with_name(f"{sample_path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    sample_path.parent.mkdir(parents=True, exist_ok=True)

    with sample_tmp.open("w", encoding="utf-8", newline="\n") as sample_f:
        for item in selected:
            window_id = item["window_id"]
            p10c_run_dir = out_dir / "p10c_runs" / f"{sanitize_run_part(window_id)}_{sanitize_run_part(args.collector)}"
            p10c_acceptance_path = p10c_run_dir / "checks" / "P10C_TIME_ALIGNED_ROV_ACCEPTANCE.txt"
            command_result: dict[str, Any] | None = None
            if args.skip_existing and p10c_acceptance_path.is_file():
                invoked_or_existing_count += 1
            else:
                invoked_count += 1
                invoked_or_existing_count += 1
                cmd = p10c_command(root, args, item["p8_run_dir"], p10c_run_dir)
                command_result = run_command(cmd, root)
                command_results.append({
                    "window_id": window_id,
                    "p8_run_dir": str(item["p8_run_dir"]),
                    "p10c_run_dir": str(p10c_run_dir),
                    "result": command_result,
                })
                if command_result.get("exit_code") not in (0,):
                    failed_runtime_count += 1
                    if not args.continue_on_error:
                        row = collect_window_result(batch_id, args.collector, item["p8_run_dir"], p10c_run_dir, command_result)
                        window_rows.append(row)
                        break

            row = collect_window_result(batch_id, args.collector, item["p8_run_dir"], p10c_run_dir, command_result)
            window_rows.append(row)
            p10a_run_dir = row.get("_p10a_run_dir_path")
            if isinstance(p10a_run_dir, Path):
                for raw in read_csv_rows(p10a_run_dir / "transition_matrix.csv"):
                    merged = {"batch_id": batch_id, "window_id": row["window_id"], "collector": args.collector, "p10a_run_dir": str(p10a_run_dir)}
                    merged.update(raw)
                    transition_rows.append(merged)
                for raw in read_csv_rows(p10a_run_dir / "affected_prefix_summary.csv"):
                    merged = {"batch_id": batch_id, "collector": args.collector, "p10a_run_dir": str(p10a_run_dir)}
                    merged.update(raw)
                    prefix_rows.append(merged)
                for raw in read_csv_rows(p10a_run_dir / "affected_origin_as_summary.csv"):
                    merged = {"batch_id": batch_id, "collector": args.collector, "p10a_run_dir": str(p10a_run_dir)}
                    merged.update(raw)
                    origin_rows.append(merged)
                written = append_transition_events_sample(p10a_run_dir / "validation_transition_events.jsonl", sample_f, sample_remaining)
                sample_remaining -= written
    with sample_tmp.open("rb+") as f:
        f.flush()
        os.fsync(f.fileno())
    os.replace(sample_tmp, sample_path)
    fsync_parent(sample_path)

    public_window_rows = [{k: v for k, v in row.items() if not k.startswith("_")} for row in window_rows]
    atomic_write_text(out_dir / "p10d_window_summary.csv", csv_text(WINDOW_SUMMARY_FIELDS, public_window_rows))
    atomic_write_text(out_dir / "p10d_transition_matrix_merged.csv", csv_text(TRANSITION_MATRIX_FIELDS, transition_rows))
    atomic_write_text(out_dir / "p10d_affected_prefix_merged.csv", csv_text(PREFIX_FIELDS, prefix_rows))
    atomic_write_text(out_dir / "p10d_affected_origin_as_merged.csv", csv_text(ORIGIN_FIELDS, origin_rows))

    transition_dist: Counter[str] = Counter()
    for row in transition_rows:
        transition = f"{row.get('state_a', '')}->{row.get('state_b', '')}"
        transition_dist[transition] += int_value(row.get("route_count"))

    prefix_counter: Counter[str] = Counter()
    affected_prefixes: set[str] = set()
    for row in prefix_rows:
        prefix = str(row.get("prefix") or "")
        if prefix:
            affected_prefixes.add(prefix)
            prefix_counter[prefix] += 1

    origin_counter: Counter[str] = Counter()
    affected_origins: set[str] = set()
    for row in origin_rows:
        origin = str(row.get("origin_asn") or "")
        if origin:
            affected_origins.add(origin)
            origin_counter[origin] += int_value(row.get("affected_prefix_count")) or 1

    window_count_succeeded = sum(1 for row in window_rows if row.get("p10c_status") == "PASS" and row.get("p10a_status") == "PASS")
    window_count_pass_with_exclusions = sum(
        1
        for row in window_rows
        if row.get("p10c_status") == "PASS_WITH_EXCLUSIONS" or row.get("p10a_status") in {"PASS_WITH_EXCLUSIONS", "SKIPPED"}
    )
    window_count_failed = sum(1 for row in window_rows if row.get("p10c_status") in {"", "FAIL"} or row.get("p10a_status") == "FAIL")
    total_route_count = sum(int_value(row.get("route_count")) for row in window_rows)
    total_transition_event_count = sum(int_value(row.get("transition_event_count")) for row in window_rows)

    checks = {
        "p8_pass_windows_found": len(selected) > 0,
        "p10c_invoked": invoked_or_existing_count > 0,
        "window_summary_written": (out_dir / "p10d_window_summary.csv").is_file(),
        "transition_matrix_merged_written": (out_dir / "p10d_transition_matrix_merged.csv").is_file(),
        "affected_prefix_merged_written": (out_dir / "p10d_affected_prefix_merged.csv").is_file(),
        "affected_origin_as_merged_written": (out_dir / "p10d_affected_origin_as_merged.csv").is_file(),
        "batch_summary_json_ok": False,
        "no_strong_root_cause_claim": True,
        "continue_on_error_respected": bool(args.continue_on_error) or failed_runtime_count == 0,
    }
    if not checks["p8_pass_windows_found"] or not checks["p10c_invoked"]:
        status = "FAIL"
    elif window_count_succeeded > 0 and window_count_failed == 0 and window_count_pass_with_exclusions == 0:
        status = "PASS"
    elif window_count_succeeded + window_count_pass_with_exclusions > 0:
        status = "PASS_WITH_EXCLUSIONS"
    else:
        status = "FAIL"

    summary = {
        "schema": SCHEMA_BATCH_SUMMARY,
        "batch_id": batch_id,
        "status": status,
        "window_count_requested": args.latest_n if args.latest_n is not None else len(selected),
        "window_count_scanned": len(all_runs),
        "window_count_selected": len(selected),
        "window_count_succeeded": window_count_succeeded,
        "window_count_pass_with_exclusions": window_count_pass_with_exclusions,
        "window_count_failed": window_count_failed,
        "total_route_count": total_route_count,
        "total_transition_event_count": total_transition_event_count,
        "unique_affected_prefix_count": len(affected_prefixes),
        "unique_affected_origin_as_count": len(affected_origins),
        "transition_type_distribution": dict(sorted(transition_dist.items())),
        "top_affected_origin_as": [{"origin_asn": key, "score": value} for key, value in origin_counter.most_common(20)],
        "top_affected_prefixes": [{"prefix": key, "score": value} for key, value in prefix_counter.most_common(20)],
        "collector": args.collector,
        "source": args.source,
        "rib_time_policy": args.rib_time_policy,
        "max_routes": args.max_routes,
        "download": bool(args.download),
        "skip_existing": bool(args.skip_existing),
        "continue_on_error": bool(args.continue_on_error),
        "upload_minio": bool(args.upload_minio),
        "out_dir": str(out_dir),
        "command_results": command_results,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
    }
    atomic_write_json(out_dir / "p10d_batch_summary.json", summary)
    checks["batch_summary_json_ok"] = (out_dir / "p10d_batch_summary.json").is_file()
    if status == "FAIL" and not all(
        checks[key]
        for key in (
            "window_summary_written",
            "transition_matrix_merged_written",
            "affected_prefix_merged_written",
            "affected_origin_as_merged_written",
            "batch_summary_json_ok",
        )
    ):
        status = "FAIL"
        summary["status"] = status
        atomic_write_json(out_dir / "p10d_batch_summary.json", summary)
    write_acceptance(out_dir, status, summary, checks)
    return 0 if status in {"PASS", "PASS_WITH_EXCLUSIONS"} else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="P10-D batch ROV impact runner over multiple P8 PASS windows.")
    parser.add_argument("--p8-root", default="data/probe/cross_probe_pipeline")
    parser.add_argument("--latest-n", type=int)
    parser.add_argument("--start-window-id")
    parser.add_argument("--end-window-id")
    parser.add_argument("--collector", default="routeviews2")
    parser.add_argument("--source", choices=["routeviews", "ris"], default="routeviews")
    parser.add_argument("--rib-time-policy", choices=["nearest_leq", "nearest", "nearest_geq"], default="nearest_leq")
    parser.add_argument("--download", type=parse_bool, default=True)
    parser.add_argument("--bgpdump-bin", default="bgpdump")
    parser.add_argument("--max-routes", type=int)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--continue-on-error", type=parse_bool, default=True)
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--min-p8-skew-ok", type=parse_bool, default=True)
    parser.add_argument("--upload-minio", type=parse_bool, default=False)
    parser.add_argument("--transition-event-sample-limit", type=int, default=10000)
    parser.add_argument("--batch-id")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run_batch(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
