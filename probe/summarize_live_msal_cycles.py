#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_SUMMARY = "s3.probe.live_msal_cycle_rollup_summary.v1"
ACCEPTANCE_NAME = "E3_LIVE_MSAL_24H_SUMMARY"
DEFAULT_CYCLE_ROOT = "data/probe/e2e_msal_cycles"
E2_ACCEPTANCE_RELATIVE_PATH = Path("checks") / "E2_LIVE_MSAL_CYCLE_ACCEPTANCE.txt"
E3_ACCEPTANCE_RELATIVE_PATH = Path("checks") / "E3_LIVE_MSAL_24H_SUMMARY_ACCEPTANCE.txt"
RUN_DIR_PATTERNS = ("hourly_*", "e2_cycle_*", "cycle_*")


@dataclass(frozen=True, slots=True)
class CycleDir:
    name: str
    path: Path
    mtime_ns: int


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def publish_existing_atomically(tmp_path: Path, final_path: Path) -> None:
    final_path.parent.mkdir(parents=True, exist_ok=True)
    with tmp_path.open("rb+") as f:
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, final_path)
    fsync_parent(final_path)


def parse_time_token(text: str) -> str | None:
    match = re.search(r"(\d{8}T\d{6}(?:\d{1,6})?Z)", text)
    if match:
        return match.group(1)
    match = re.search(r"(\d{4}[-_]?\d{2}[-_]?\d{2}[T_ -]?\d{2}[-_]?\d{2}(?:[-_]?\d{2})?)", text)
    if match:
        return re.sub(r"[^0-9T]", "", match.group(1))
    return None


def cycle_sort_key(cycle: CycleDir) -> tuple[int, str, int, str]:
    token = parse_time_token(cycle.name)
    if token is not None:
        return (1, token, cycle.mtime_ns, cycle.name)
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


def as_bool_false(value: Any) -> bool:
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


def add_distribution(target: dict[str, int], source: Any) -> None:
    if not isinstance(source, dict):
        return
    for key, value in source.items():
        count = as_int(value)
        if count is None:
            continue
        text_key = str(key)
        target[text_key] = target.get(text_key, 0) + count


def get_nested(obj: dict[str, Any], path: list[str]) -> Any:
    current: Any = obj
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


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

    causal_claim_allowed_count = as_int(msal_summary.get("causal_claim_allowed_count"))
    if causal_claim_allowed_count is None:
        causal_claim_allowed_count = as_int(acceptance.get("causal_claim_allowed_count"))
    if causal_claim_allowed_count is None:
        causal_claim_allowed_count = 0 if status == "PASS" else None

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
    if acceptance_status != "PASS":
        reasons.append("acceptance_not_pass")
    if summary_status != "PASS":
        reasons.append("summary_not_pass")
    if causal_claim_allowed_count != 0:
        reasons.append("causal_claim_allowed_nonzero")
    if not as_bool_false(root_cause_confirmed):
        reasons.append("root_cause_confirmed_not_false")
    if status == "PASS" and event_count != msal_output_record_count:
        reasons.append("pass_event_msal_output_mismatch")

    return {
        "run_name": cycle.name,
        "cycle_dir": str(cycle.path),
        "acceptance_path": str(acceptance_path),
        "cycle_summary_path": str(summary_path),
        "acceptance_status": acceptance_status,
        "summary_status": summary_status,
        "status": status,
        "missing_acceptance": not acceptance_path.exists(),
        "missing_cycle_summary": not summary_path.exists() or not summary,
        "started_at_utc": summary.get("started_at_utc"),
        "finished_at_utc": summary.get("finished_at_utc"),
        "duration_sec": as_float(summary.get("duration_sec")),
        "event_count": event_count,
        "msal_output_record_count": msal_output_record_count,
        "added_count": as_int(diff_summary.get("added_count")),
        "removed_count": as_int(diff_summary.get("removed_count")),
        "changed_count": as_int(diff_summary.get("changed_count")),
        "evidence_level_distribution": msal_summary.get("evidence_level_distribution") if isinstance(msal_summary.get("evidence_level_distribution"), dict) else {},
        "tal_distribution": msal_summary.get("by_tal") if isinstance(msal_summary.get("by_tal"), dict) else {},
        "causal_claim_allowed_count": causal_claim_allowed_count,
        "root_cause_confirmed": root_cause_confirmed,
        "reasons": reasons,
    }


def compact_run(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_name": row.get("run_name"),
        "cycle_dir": row.get("cycle_dir"),
        "started_at_utc": row.get("started_at_utc"),
        "finished_at_utc": row.get("finished_at_utc"),
        "status": row.get("status"),
    }


def sum_int(rows: list[dict[str, Any]], key: str) -> int:
    total = 0
    for row in rows:
        value = as_int(row.get(key))
        if value is not None:
            total += value
    return total


def build_acceptance_checks(summary: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, bool]:
    pass_rows = [row for row in rows if row.get("status") == "PASS"]
    pass_output_mismatches = [
        row
        for row in pass_rows
        if as_int(row.get("event_count")) != as_int(row.get("msal_output_record_count"))
    ]
    return {
        "run_count_gt_zero": summary.get("run_count", 0) > 0,
        "pass_count_eq_run_count": summary.get("pass_count") == summary.get("run_count"),
        "missing_acceptance_count_zero": summary.get("missing_acceptance_count") == 0,
        "causal_claim_allowed_count_always_zero": summary.get("causal_claim_allowed_nonzero_run_count") == 0,
        "root_cause_confirmed_always_false": summary.get("root_cause_confirmed_true_run_count") == 0,
        "pass_run_msal_output_record_count_matches_event_count": len(pass_output_mismatches) == 0,
    }


def acceptance_text(status: str, checks: dict[str, bool], summary: dict[str, Any]) -> str:
    fields = [
        (ACCEPTANCE_NAME, status),
        ("probe_id", summary.get("probe_id")),
        ("cycle_root", summary.get("cycle_root")),
        ("out_dir", summary.get("out_dir")),
        ("run_count", summary.get("run_count")),
        ("pass_count", summary.get("pass_count")),
        ("fail_count", summary.get("fail_count")),
        ("missing_acceptance_count", summary.get("missing_acceptance_count")),
        ("total_event_count", summary.get("total_event_count")),
        ("total_msal_output_record_count", summary.get("total_msal_output_record_count")),
        ("causal_claim_allowed_nonzero_run_count", summary.get("causal_claim_allowed_nonzero_run_count")),
        ("root_cause_confirmed_true_run_count", summary.get("root_cause_confirmed_true_run_count")),
        ("disk_latest_available", summary.get("disk_latest_available")),
    ]
    lines = [f"{name}={format_value(value)}" for name, value in fields]
    lines.extend(["", "[checks]"])
    for name in sorted(checks):
        lines.append(f"{name}={format_value(checks[name])}")
    return "\n".join(lines) + "\n"


def write_summary_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "run_name",
        "cycle_dir",
        "status",
        "acceptance_status",
        "summary_status",
        "missing_acceptance",
        "missing_cycle_summary",
        "started_at_utc",
        "finished_at_utc",
        "duration_sec",
        "event_count",
        "msal_output_record_count",
        "added_count",
        "removed_count",
        "changed_count",
        "causal_claim_allowed_count",
        "root_cause_confirmed",
        "reasons",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    try:
        with tmp.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({name: format_value(row.get(name)) for name in fieldnames})
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


def write_failed_runs(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as f:
            for row in rows:
                if row.get("status") == "PASS" and not row.get("reasons"):
                    continue
                f.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
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


def build_summary(args: argparse.Namespace) -> dict[str, Any]:
    started_at_utc = utc_now()
    started = time.monotonic()
    cycle_root = Path(args.cycle_root).resolve()
    probe_cycle_root = resolve_probe_cycle_root(cycle_root, args.probe_id)
    out_dir = Path(args.out_dir).resolve()

    all_cycles = list_cycle_dirs(cycle_root, args.probe_id)
    limit = max(0, int(args.limit))
    selected_cycles = all_cycles[-limit:] if limit else []
    rows = [extract_cycle_row(cycle) for cycle in selected_cycles]

    evidence_distribution: dict[str, int] = {}
    tal_distribution: dict[str, int] = {}
    for row in rows:
        add_distribution(evidence_distribution, row.get("evidence_level_distribution"))
        add_distribution(tal_distribution, row.get("tal_distribution"))

    durations = [value for value in (as_float(row.get("duration_sec")) for row in rows) if value is not None]
    pass_count = sum(1 for row in rows if row.get("status") == "PASS")
    missing_acceptance_count = sum(1 for row in rows if row.get("missing_acceptance"))
    causal_nonzero_count = sum(1 for row in rows if row.get("causal_claim_allowed_count") != 0)
    root_cause_true_count = sum(1 for row in rows if not as_bool_false(row.get("root_cause_confirmed")))
    latest_row = rows[-1] if rows else None

    summary = {
        "schema": SCHEMA_SUMMARY,
        "probe_id": args.probe_id,
        "cycle_root": str(cycle_root),
        "probe_cycle_root": str(probe_cycle_root),
        "out_dir": str(out_dir),
        "limit": limit,
        "available_run_count": len(all_cycles),
        "run_count": len(rows),
        "pass_count": pass_count,
        "fail_count": len(rows) - pass_count,
        "missing_acceptance_count": missing_acceptance_count,
        "first_run": compact_run(rows[0]) if rows else None,
        "last_run": compact_run(rows[-1]) if rows else None,
        "total_event_count": sum_int(rows, "event_count"),
        "total_msal_output_record_count": sum_int(rows, "msal_output_record_count"),
        "added_count_sum": sum_int(rows, "added_count"),
        "removed_count_sum": sum_int(rows, "removed_count"),
        "changed_count_sum": sum_int(rows, "changed_count"),
        "evidence_level_distribution": evidence_distribution,
        "tal_distribution": tal_distribution,
        "max_duration_sec": round(max(durations), 6) if durations else None,
        "avg_duration_sec": round(sum(durations) / len(durations), 6) if durations else None,
        "disk_latest_available": bool(
            latest_row
            and Path(str(latest_row.get("cycle_summary_path"))).exists()
            and Path(str(latest_row.get("acceptance_path"))).exists()
        ),
        "causal_claim_allowed_nonzero_run_count": causal_nonzero_count,
        "root_cause_confirmed_true_run_count": root_cause_true_count,
        "selected_runs": [compact_run(row) for row in rows],
        "started_at_utc": started_at_utc,
        "finished_at_utc": utc_now(),
        "duration_sec": round(time.monotonic() - started, 6),
    }
    checks = build_acceptance_checks(summary, rows)
    status = "PASS" if all(checks.values()) else "FAIL"
    summary["status"] = status
    summary["acceptance_checks"] = checks
    return summary | {"_rows": rows}


def run(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = Path(args.out_dir).resolve()
    summary_with_rows = build_summary(args)
    rows = summary_with_rows.pop("_rows")

    summary_path = out_dir / "summary.json"
    csv_path = out_dir / "summary.csv"
    failed_runs_path = out_dir / "failed_runs.jsonl"
    latest_summary_path = out_dir / "latest_e3_summary.json"
    acceptance_path = out_dir / E3_ACCEPTANCE_RELATIVE_PATH

    summary_with_rows["outputs"] = {
        "summary": str(summary_path),
        "summary_csv": str(csv_path),
        "failed_runs": str(failed_runs_path),
        "latest_e3_summary": str(latest_summary_path),
        "acceptance": str(acceptance_path),
    }

    atomic_write_json(summary_path, summary_with_rows)
    atomic_write_json(latest_summary_path, summary_with_rows)
    write_summary_csv(csv_path, rows)
    write_failed_runs(failed_runs_path, rows)
    atomic_write_text(
        acceptance_path,
        acceptance_text(str(summary_with_rows.get("status")), summary_with_rows.get("acceptance_checks", {}), summary_with_rows),
    )
    print(json.dumps(summary_with_rows, ensure_ascii=False, indent=2, sort_keys=True))
    return summary_with_rows


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize recent live MSAL E2 cycle runs.")
    parser.add_argument("--probe-id", default="probe-cd")
    parser.add_argument("--cycle-root", default=DEFAULT_CYCLE_ROOT)
    parser.add_argument("--limit", type=int, default=24)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else None)
    summary = run(args)
    return 0 if summary.get("status") == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        raise SystemExit(1)