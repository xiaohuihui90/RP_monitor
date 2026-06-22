#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


SCHEMA_SUMMARY = "s3.probe.live_msal_cron_health_summary.v1"
ACCEPTANCE_NAME = "E3_CRON_HEALTH"
DEFAULT_CYCLE_ROOT = "data/probe/e2e_msal_cycles"
DEFAULT_CRON_LOG = "logs/probe_cd_live_msal_cycle_cron.log"
E2_ACCEPTANCE_RELATIVE_PATH = Path("checks") / "E2_LIVE_MSAL_CYCLE_ACCEPTANCE.txt"
HEALTH_ACCEPTANCE_RELATIVE_PATH = Path("checks") / "E3_CRON_HEALTH_ACCEPTANCE.txt"
RUN_DIR_PATTERNS = ("hourly_*", "e2_cycle_*", "cycle_*")
CRITICAL_LOG_RE = re.compile(r"\b(ERROR|Traceback|Killed|OOM|timeout)\b|out of memory", re.IGNORECASE)
WARNING_LOG_RE = re.compile(r"\b(WARN|WARNING)\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class CycleDir:
    name: str
    path: Path
    mtime_ns: int


def utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


def utc_now() -> str:
    return utc_now_dt().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def parse_iso_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_time_token(text: str) -> datetime | None:
    match = re.search(r"(\d{8}T\d{6})(\d{1,6})?Z", text)
    if match:
        base = match.group(1)
        frac = (match.group(2) or "").ljust(6, "0")
        try:
            return datetime.strptime(base + frac + "Z", "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    match = re.search(r"(\d{4})[-_]?(\d{2})[-_]?(\d{2})[T_ -]?(\d{2})[-_]?(\d{2})(?:[-_]?(\d{2}))?", text)
    if match:
        year, month, day, hour, minute, second = match.groups()
        try:
            return datetime(
                int(year),
                int(month),
                int(day),
                int(hour),
                int(minute),
                int(second or "0"),
                tzinfo=timezone.utc,
            )
        except ValueError:
            return None
    return None


def cycle_sort_key(cycle: CycleDir) -> tuple[int, str, int, str]:
    token_dt = parse_time_token(cycle.name)
    if token_dt is not None:
        return (1, token_dt.isoformat(), cycle.mtime_ns, cycle.name)
    return (0, "", cycle.mtime_ns, cycle.name)


def resolve_probe_cycle_root(cycle_root: Path, probe_id: str) -> Path:
    root = cycle_root.resolve()
    if (root / probe_id).is_dir():
        return root / probe_id
    if root.name == probe_id:
        return root
    return root / probe_id


def list_cycle_dirs(cycle_root: Path, probe_id: str) -> list[CycleDir]:
    probe_root = resolve_probe_cycle_root(cycle_root, probe_id)
    if not probe_root.is_dir():
        return []

    found: dict[Path, CycleDir] = {}
    for pattern in RUN_DIR_PATTERNS:
        for path in probe_root.glob(pattern):
            if not path.is_dir():
                continue
            resolved = path.resolve()
            stat = resolved.stat()
            found[resolved] = CycleDir(name=resolved.name, path=resolved, mtime_ns=stat.st_mtime_ns)
    cycles = list(found.values())
    cycles.sort(key=cycle_sort_key)
    return cycles


def load_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8-sig") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise RuntimeError(f"expected JSON object at {path}")
    return obj


def parse_key_value_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    parsed: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip().lstrip("\ufeff")] = value.strip()
    return parsed


def as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def bool_false(value: Any) -> bool:
    if value is False:
        return True
    if isinstance(value, str):
        return value.strip().lower() == "false"
    return False


def format_value(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return str(value)


def cycle_observed_at(cycle: CycleDir, summary: dict[str, Any]) -> datetime:
    for key in ("finished_at_utc", "started_at_utc"):
        dt = parse_iso_datetime(summary.get(key))
        if dt is not None:
            return dt
    for key in ("new_snapshot_id", "curr_snapshot_id", "prev_snapshot_id"):
        value = summary.get(key)
        if value:
            dt = parse_time_token(str(value))
            if dt is not None:
                return dt
    dt = parse_time_token(cycle.name)
    if dt is not None:
        return dt
    return datetime.fromtimestamp(cycle.mtime_ns / 1_000_000_000, tz=timezone.utc)


def extract_cycle_row(cycle: CycleDir) -> dict[str, Any]:
    acceptance_path = cycle.path / E2_ACCEPTANCE_RELATIVE_PATH
    summary_path = cycle.path / "cycle_summary.json"
    acceptance = parse_key_value_file(acceptance_path)
    summary = load_json_object(summary_path)
    e1_summary = summary.get("e1_summary") if isinstance(summary.get("e1_summary"), dict) else {}
    diff_summary = e1_summary.get("diff") if isinstance(e1_summary.get("diff"), dict) else {}
    msal_summary = e1_summary.get("msal") if isinstance(e1_summary.get("msal"), dict) else {}

    event_count = as_int(diff_summary.get("event_count"))
    if event_count is None:
        event_count = as_int(acceptance.get("event_count"))
    msal_output_record_count = as_int(msal_summary.get("output_record_count"))
    if msal_output_record_count is None:
        msal_output_record_count = as_int(acceptance.get("msal_output_record_count"))

    acceptance_status = acceptance.get("E2_LIVE_MSAL_CYCLE")
    summary_status = summary.get("status")
    status = "PASS" if acceptance_status == "PASS" and summary_status == "PASS" else "FAIL"
    duration_sec = as_float(summary.get("duration_sec"))
    causal_claim_allowed_count = as_int(msal_summary.get("causal_claim_allowed_count"))
    if causal_claim_allowed_count is None:
        causal_claim_allowed_count = as_int(acceptance.get("causal_claim_allowed_count"))
    root_cause_confirmed = summary.get("root_cause_confirmed")
    if root_cause_confirmed is None:
        root_cause_confirmed = msal_summary.get("root_cause_confirmed")
    if root_cause_confirmed is None and "root_cause_confirmed" in acceptance:
        root_cause_confirmed = acceptance.get("root_cause_confirmed")

    reasons: list[str] = []
    if not acceptance_path.exists():
        reasons.append("missing_acceptance")
    if not summary_path.exists() or not summary:
        reasons.append("missing_cycle_summary")
    if acceptance_status == "FAIL" or summary_status == "FAIL" or status == "FAIL":
        reasons.append("cycle_not_pass")
    if causal_claim_allowed_count not in (None, 0):
        reasons.append("causal_claim_allowed_nonzero")
    if root_cause_confirmed is not None and not bool_false(root_cause_confirmed):
        reasons.append("root_cause_confirmed_not_false")
    if status == "PASS" and event_count != msal_output_record_count:
        reasons.append("pass_event_msal_output_mismatch")

    observed_at = cycle_observed_at(cycle, summary)
    return {
        "run_name": cycle.name,
        "cycle_dir": str(cycle.path),
        "acceptance_path": str(acceptance_path),
        "cycle_summary_path": str(summary_path),
        "observed_at_utc": iso_z(observed_at),
        "observed_at_epoch": observed_at.timestamp(),
        "acceptance_status": acceptance_status,
        "summary_status": summary_status,
        "status": status,
        "missing_acceptance": not acceptance_path.exists(),
        "missing_cycle_summary": not summary_path.exists() or not summary,
        "duration_sec": duration_sec,
        "event_count": event_count,
        "msal_output_record_count": msal_output_record_count,
        "causal_claim_allowed_count": causal_claim_allowed_count,
        "root_cause_confirmed": root_cause_confirmed,
        "reasons": sorted(set(reasons)),
    }


def tail_text(path: Path, max_bytes: int = 2_000_000) -> str | None:
    if not path.exists():
        return None
    size = path.stat().st_size
    with path.open("rb") as f:
        if size > max_bytes:
            f.seek(size - max_bytes)
        data = f.read()
    return data.decode("utf-8", errors="replace")


def matching_lines(text: str | None, pattern: re.Pattern[str], limit: int = 20) -> list[str]:
    if text is None:
        return []
    matches: list[str] = []
    for line in text.splitlines():
        line = line.lstrip("\ufeff")
        if pattern.search(line):
            matches.append(line[-1000:])
            if len(matches) >= limit:
                break
    return matches


def existing_path_for_disk(paths: list[Path]) -> Path:
    for path in paths:
        current = path.resolve()
        while not current.exists() and current.parent != current:
            current = current.parent
        if current.exists():
            return current
    return Path.cwd()


def disk_check(paths: list[Path], min_free_gb: float) -> dict[str, Any]:
    path = existing_path_for_disk(paths)
    usage = shutil.disk_usage(path)
    free_gb = usage.free / (1024 ** 3)
    total_gb = usage.total / (1024 ** 3)
    used_gb = usage.used / (1024 ** 3)
    return {
        "path": str(path),
        "free_gb": round(free_gb, 3),
        "used_gb": round(used_gb, 3),
        "total_gb": round(total_gb, 3),
        "min_free_gb": float(min_free_gb),
        "ok": free_gb >= float(min_free_gb),
    }


def detect_missing_run_windows(rows: list[dict[str, Any]], cutoff: datetime, now: datetime, expected_interval_min: int) -> list[dict[str, Any]]:
    interval = timedelta(minutes=expected_interval_min)
    tolerance = timedelta(minutes=max(5.0, min(15.0, expected_interval_min * 0.25)))
    points = sorted(
        datetime.fromtimestamp(float(row["observed_at_epoch"]), tz=timezone.utc)
        for row in rows
        if row.get("observed_at_epoch") is not None
    )
    missing: list[dict[str, Any]] = []
    if not points:
        expected = max(1, math.ceil((now - cutoff).total_seconds() / interval.total_seconds()))
        missing.append({"from": iso_z(cutoff), "to": iso_z(now), "expected_missing_count": expected, "reason": "no_cycles_in_lookback"})
        return missing

    anchors = [cutoff, *points, now]
    for prev, curr in zip(anchors, anchors[1:]):
        gap = curr - prev
        if gap <= interval + tolerance:
            continue
        expected_missing = max(1, math.floor((gap - tolerance).total_seconds() / interval.total_seconds()))
        missing.append({
            "from": iso_z(prev),
            "to": iso_z(curr),
            "gap_min": round(gap.total_seconds() / 60, 3),
            "expected_missing_count": expected_missing,
        })
    return missing


def detect_event_spikes(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = [as_int(row.get("event_count")) for row in rows]
    numeric_counts = [count for count in counts if count is not None]
    positive_counts = [count for count in numeric_counts if count > 0]
    if len(positive_counts) < 3:
        return {"spike": False, "median_event_count": statistics.median(positive_counts) if positive_counts else None, "spike_runs": []}
    median_count = statistics.median(positive_counts)
    threshold = median_count * 10
    spike_runs = [
        {
            "run_name": row.get("run_name"),
            "cycle_dir": row.get("cycle_dir"),
            "observed_at_utc": row.get("observed_at_utc"),
            "event_count": row.get("event_count"),
            "threshold": threshold,
        }
        for row in rows
        if as_int(row.get("event_count")) is not None and as_int(row.get("event_count")) > threshold
    ]
    return {
        "spike": bool(spike_runs),
        "median_event_count": median_count,
        "threshold": threshold,
        "spike_runs": spike_runs,
    }


def build_status(fail_reasons: list[str], warn_reasons: list[str]) -> str:
    if fail_reasons:
        return "FAIL"
    if warn_reasons:
        return "WARN"
    return "PASS"


def acceptance_text(summary: dict[str, Any]) -> str:
    checks = summary.get("acceptance_checks", {})
    fields = [
        (ACCEPTANCE_NAME, summary.get("status")),
        ("probe_id", summary.get("probe_id")),
        ("cycle_root", summary.get("cycle_root")),
        ("cron_log", summary.get("cron_log", {}).get("path") if isinstance(summary.get("cron_log"), dict) else None),
        ("lookback_hours", summary.get("lookback_hours")),
        ("expected_interval_min", summary.get("expected_interval_min")),
        ("run_count", summary.get("run_count")),
        ("missing_run_window_count", summary.get("missing_run_window_count")),
        ("latest_cycle_status", summary.get("latest_cycle", {}).get("status") if isinstance(summary.get("latest_cycle"), dict) else None),
        ("missing_acceptance_count", summary.get("missing_acceptance_count")),
        ("e2_fail_count", summary.get("e2_fail_count")),
        ("critical_log_match_count", summary.get("cron_log", {}).get("critical_match_count") if isinstance(summary.get("cron_log"), dict) else None),
        ("disk_free_gb", summary.get("disk", {}).get("free_gb") if isinstance(summary.get("disk"), dict) else None),
        ("disk_min_free_gb", summary.get("disk", {}).get("min_free_gb") if isinstance(summary.get("disk"), dict) else None),
        ("event_spike", summary.get("event_spike", {}).get("spike") if isinstance(summary.get("event_spike"), dict) else None),
    ]
    lines = [f"{name}={format_value(value)}" for name, value in fields]
    lines.extend(["", "[checks]"])
    for key in sorted(checks):
        lines.append(f"{key}={format_value(checks[key])}")
    if summary.get("fail_reasons"):
        lines.extend(["", "[fail_reasons]"])
        lines.extend(str(item) for item in summary.get("fail_reasons", []))
    if summary.get("warn_reasons"):
        lines.extend(["", "[warn_reasons]"])
        lines.extend(str(item) for item in summary.get("warn_reasons", []))
    return "\n".join(lines) + "\n"


def report_text(summary: dict[str, Any]) -> str:
    latest = summary.get("latest_cycle") if isinstance(summary.get("latest_cycle"), dict) else {}
    lines = [
        f"Live MSAL cron health: {summary.get('status')}",
        f"probe_id: {summary.get('probe_id')}",
        f"lookback: {summary.get('lookback_hours')}h, expected interval: {summary.get('expected_interval_min')} min",
        f"runs in lookback: {summary.get('run_count')}",
        f"latest cycle: {latest.get('run_name')} {latest.get('status')} at {latest.get('observed_at_utc')}",
        f"missing run windows: {summary.get('missing_run_window_count')}",
        f"missing acceptance: {summary.get('missing_acceptance_count')}",
        f"E2 FAIL count: {summary.get('e2_fail_count')}",
        f"disk free: {summary.get('disk', {}).get('free_gb')} GB / min {summary.get('disk', {}).get('min_free_gb')} GB",
        f"critical log matches: {summary.get('cron_log', {}).get('critical_match_count')}",
        f"warning log matches: {summary.get('cron_log', {}).get('warning_match_count')}",
    ]
    if summary.get("fail_reasons"):
        lines.extend(["", "FAIL reasons:"])
        lines.extend(f"- {item}" for item in summary.get("fail_reasons", []))
    if summary.get("warn_reasons"):
        lines.extend(["", "WARN reasons:"])
        lines.extend(f"- {item}" for item in summary.get("warn_reasons", []))
    return "\n".join(lines) + "\n"


def compact_cycle(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_name": row.get("run_name"),
        "cycle_dir": row.get("cycle_dir"),
        "observed_at_utc": row.get("observed_at_utc"),
        "status": row.get("status"),
        "event_count": row.get("event_count"),
        "msal_output_record_count": row.get("msal_output_record_count"),
        "duration_sec": row.get("duration_sec"),
        "reasons": row.get("reasons"),
    }


def build_health_summary(args: argparse.Namespace) -> dict[str, Any]:
    started_at_utc = utc_now()
    started = time.monotonic()
    now = utc_now_dt()
    cutoff = now - timedelta(hours=float(args.lookback_hours))
    cycle_root = Path(args.cycle_root).resolve()
    probe_cycle_root = resolve_probe_cycle_root(cycle_root, args.probe_id)
    cron_log_path = Path(args.cron_log).resolve()
    out_dir = Path(args.out_dir).resolve()

    cycles = list_cycle_dirs(cycle_root, args.probe_id)
    rows_all = [extract_cycle_row(cycle) for cycle in cycles]
    rows_lookback = [
        row
        for row in rows_all
        if row.get("observed_at_epoch") is not None and float(row["observed_at_epoch"]) >= cutoff.timestamp()
    ]
    rows_lookback.sort(key=lambda row: float(row.get("observed_at_epoch") or 0))
    latest_cycle = rows_all[-1] if rows_all else None
    latest_cycle_status = latest_cycle.get("status") if latest_cycle else None

    missing_windows = detect_missing_run_windows(rows_lookback, cutoff, now, int(args.expected_interval_min))
    missing_acceptance_rows = [row for row in rows_lookback if row.get("missing_acceptance")]
    e2_fail_rows = [row for row in rows_lookback if row.get("status") == "FAIL"]
    timeout_sec = int(args.expected_interval_min) * 60
    timeout_rows = [row for row in rows_lookback if (as_float(row.get("duration_sec")) or 0) > timeout_sec]

    log_text = tail_text(cron_log_path)
    critical_log_lines = matching_lines(log_text, CRITICAL_LOG_RE)
    warning_log_lines = matching_lines(log_text, WARNING_LOG_RE)
    log_missing = log_text is None
    disk = disk_check([probe_cycle_root, cycle_root, out_dir], float(args.min_free_gb))
    event_spike = detect_event_spikes(rows_lookback)

    fail_reasons: list[str] = []
    warn_reasons: list[str] = []
    if missing_windows:
        fail_reasons.append("missing_cycle_run_window")
    if latest_cycle_status != "PASS":
        fail_reasons.append("latest_cycle_not_pass")
    if missing_acceptance_rows:
        fail_reasons.append("missing_e2_acceptance")
    if e2_fail_rows:
        fail_reasons.append("e2_cycle_fail")
    if critical_log_lines:
        fail_reasons.append("critical_cron_log_match")
    if not disk["ok"]:
        fail_reasons.append("disk_free_below_threshold")
    if timeout_rows:
        fail_reasons.append("cycle_duration_timeout")
    if event_spike.get("spike"):
        warn_reasons.append("event_count_spike")
    if warning_log_lines and not critical_log_lines:
        warn_reasons.append("cron_log_warning_match")
    if log_missing:
        warn_reasons.append("cron_log_missing")

    checks = {
        "run_count_gt_zero": len(rows_lookback) > 0,
        "no_missing_run_windows": not missing_windows,
        "latest_cycle_pass": latest_cycle_status == "PASS",
        "missing_acceptance_count_zero": not missing_acceptance_rows,
        "e2_fail_count_zero": not e2_fail_rows,
        "critical_log_match_count_zero": not critical_log_lines,
        "disk_free_gb_ok": bool(disk["ok"]),
        "cycle_duration_timeout_count_zero": not timeout_rows,
    }
    if not checks["run_count_gt_zero"] and "missing_cycle_run_window" not in fail_reasons:
        fail_reasons.append("no_cycles_in_lookback")

    status = build_status(fail_reasons, warn_reasons)
    return {
        "schema": SCHEMA_SUMMARY,
        "status": status,
        "probe_id": args.probe_id,
        "cycle_root": str(cycle_root),
        "probe_cycle_root": str(probe_cycle_root),
        "out_dir": str(out_dir),
        "lookback_hours": float(args.lookback_hours),
        "expected_interval_min": int(args.expected_interval_min),
        "min_free_gb": float(args.min_free_gb),
        "lookback_started_at_utc": iso_z(cutoff),
        "checked_at_utc": iso_z(now),
        "run_count": len(rows_lookback),
        "all_run_count": len(rows_all),
        "latest_cycle": compact_cycle(latest_cycle) if latest_cycle else None,
        "missing_run_window_count": len(missing_windows),
        "missing_run_windows": missing_windows,
        "missing_acceptance_count": len(missing_acceptance_rows),
        "missing_acceptance_runs": [compact_cycle(row) for row in missing_acceptance_rows],
        "e2_fail_count": len(e2_fail_rows),
        "e2_fail_runs": [compact_cycle(row) for row in e2_fail_rows],
        "timeout_count": len(timeout_rows),
        "timeout_runs": [compact_cycle(row) for row in timeout_rows],
        "event_spike": event_spike,
        "cron_log": {
            "path": str(cron_log_path),
            "exists": cron_log_path.exists(),
            "critical_match_count": len(critical_log_lines),
            "critical_matches": critical_log_lines,
            "warning_match_count": len(warning_log_lines),
            "warning_matches": warning_log_lines,
        },
        "disk": disk,
        "acceptance_checks": checks,
        "fail_reasons": sorted(set(fail_reasons)),
        "warn_reasons": sorted(set(warn_reasons)),
        "recent_cycles": [compact_cycle(row) for row in rows_lookback],
        "started_at_utc": started_at_utc,
        "finished_at_utc": utc_now(),
        "duration_sec": round(time.monotonic() - started, 6),
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = Path(args.out_dir).resolve()
    summary = build_health_summary(args)
    summary_path = out_dir / "health_summary.json"
    report_path = out_dir / "health_report.txt"
    latest_summary_path = out_dir / "latest_health_summary.json"
    acceptance_path = out_dir / HEALTH_ACCEPTANCE_RELATIVE_PATH
    summary["outputs"] = {
        "health_summary": str(summary_path),
        "health_report": str(report_path),
        "latest_health_summary": str(latest_summary_path),
        "acceptance": str(acceptance_path),
    }

    atomic_write_json(summary_path, summary)
    atomic_write_json(latest_summary_path, summary)
    atomic_write_text(report_path, report_text(summary))
    atomic_write_text(acceptance_path, acceptance_text(summary))
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check live MSAL cron health for missing runs, failures, logs, disk, and event spikes.")
    parser.add_argument("--probe-id", default="probe-cd")
    parser.add_argument("--cycle-root", default=DEFAULT_CYCLE_ROOT)
    parser.add_argument("--cron-log", default=DEFAULT_CRON_LOG)
    parser.add_argument("--lookback-hours", type=float, default=24)
    parser.add_argument("--expected-interval-min", type=int, default=60)
    parser.add_argument("--min-free-gb", type=float, default=10)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = run(args)
    return 0 if summary.get("status") in {"PASS", "WARN"} else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        raise SystemExit(1)