#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_SUMMARY = "s3.probe.live_vrp_msal_once_summary.v1"
ACCEPTANCE_NAME = "E1_LIVE_VRP_MSAL_ONCE"
RUNNER_ACCEPTANCE_NAME = "E1_LIVE_VRP_MSAL_RUNNER"
RUNNER_ACCEPTANCE_RELATIVE_PATH = Path("checks") / "E1_LIVE_VRP_MSAL_RUNNER_ACCEPTANCE.txt"
DEFAULT_SNAPSHOT_ROOT = "data/probe/live_vrp_snapshots"

EVIDENCE_INDEX_ARGS = [
    "source_pp_coverage",
    "l2_object_index",
    "manifest_filelist_index",
    "hash_evidence_index",
    "candidate_evidence_table",
]


@dataclass(frozen=True, slots=True)
class SnapshotCandidate:
    snapshot_id: str
    normalized_path: Path
    mtime_ns: int


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


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


def script_repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_probe_snapshot_base(snapshot_root: Path, probe_id: str) -> Path:
    root = snapshot_root.resolve()
    if (root / "history").is_dir():
        return root
    if root.name == probe_id:
        return root
    return root / probe_id


def parse_snapshot_time_token(snapshot_id: str) -> str | None:
    match = re.search(r"(\d{8}T\d{6}(?:\d{1,6})?Z)", snapshot_id)
    if not match:
        return None
    return match.group(1)


def snapshot_sort_key(candidate: SnapshotCandidate) -> tuple[int, str, int, str]:
    token = parse_snapshot_time_token(candidate.snapshot_id)
    if token is not None:
        return (1, token, candidate.mtime_ns, candidate.snapshot_id)
    return (0, "", candidate.mtime_ns, candidate.snapshot_id)


def find_recent_snapshots(snapshot_root: Path, probe_id: str) -> tuple[SnapshotCandidate, SnapshotCandidate]:
    probe_base = resolve_probe_snapshot_base(snapshot_root, probe_id)
    history_dir = probe_base / "history"
    if not history_dir.is_dir():
        raise RuntimeError(f"snapshot history directory not found: {history_dir}")

    candidates: list[SnapshotCandidate] = []
    for normalized_path in history_dir.glob("*/normalized_vrp.jsonl"):
        if not normalized_path.is_file():
            continue
        stat = normalized_path.stat()
        candidates.append(
            SnapshotCandidate(
                snapshot_id=normalized_path.parent.name,
                normalized_path=normalized_path.resolve(),
                mtime_ns=stat.st_mtime_ns,
            )
        )

    candidates.sort(key=snapshot_sort_key)
    if len(candidates) < 2:
        raise RuntimeError(f"need at least two normalized_vrp.jsonl snapshots under {history_dir}; found {len(candidates)}")
    return candidates[-2], candidates[-1]


def infer_snapshot_id_from_normalized(path: Path) -> str:
    return path.resolve().parent.name


def load_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8-sig") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise RuntimeError(f"expected JSON object at {path}")
    return obj


def append_optional_path_arg(command: list[str], arg_name: str, value: str | None) -> None:
    if value:
        command.extend([f"--{arg_name.replace('_', '-')}", str(Path(value).resolve())])


def run_step(name: str, command: list[str], cwd: Path) -> dict[str, Any]:
    started_at_utc = utc_now()
    started = time.monotonic()
    print(f"[{started_at_utc}] {name}: starting", file=sys.stderr, flush=True)
    print(subprocess.list2cmdline(command), file=sys.stderr, flush=True)
    error = None
    return_code: int | None
    try:
        proc = subprocess.run(command, cwd=str(cwd), check=False)
        return_code = int(proc.returncode)
    except Exception as exc:
        error = repr(exc)
        return_code = None
    finished_at_utc = utc_now()
    result = {
        "name": name,
        "command": command,
        "cwd": str(cwd),
        "return_code": return_code,
        "ok": return_code == 0,
        "error": error,
        "started_at_utc": started_at_utc,
        "finished_at_utc": finished_at_utc,
        "duration_sec": round(time.monotonic() - started, 6),
    }
    status = "ok" if result["ok"] else "failed"
    print(f"[{finished_at_utc}] {name}: {status} return_code={return_code}", file=sys.stderr, flush=True)
    return result


def make_run_id(prev_snapshot_id: str, curr_snapshot_id: str) -> str:
    return f"run_{prev_snapshot_id}__{curr_snapshot_id}_{utc_compact()}"


def resolve_run_dir(args: argparse.Namespace, prev_snapshot_id: str, curr_snapshot_id: str) -> Path:
    if args.out_dir:
        return Path(args.out_dir).resolve()
    probe_base = resolve_probe_snapshot_base(Path(args.snapshot_root), args.probe_id)
    return (probe_base / "msal_runs" / make_run_id(prev_snapshot_id, curr_snapshot_id)).resolve()


def build_diff_command(args: argparse.Namespace, repo_root: Path, prev_path: Path, curr_path: Path, diff_dir: Path) -> list[str]:
    return [
        args.python_bin,
        str(repo_root / "probe" / "diff_live_vrp_snapshots.py"),
        "--prev-normalized",
        str(prev_path),
        "--curr-normalized",
        str(curr_path),
        "--probe-id",
        args.probe_id,
        "--out-dir",
        str(diff_dir),
    ]


def build_msal_command(args: argparse.Namespace, repo_root: Path, diff_events: Path, msal_dir: Path) -> list[str]:
    command = [
        args.python_bin,
        str(repo_root / "probe" / "msal_minimal_attribution.py"),
        "--diff-events",
        str(diff_events),
        "--probe-id",
        args.probe_id,
        "--out-dir",
        str(msal_dir),
    ]
    if args.allow_empty_events:
        command.append("--allow-empty-events")
    if args.dump_index_stats:
        command.append("--dump-index-stats")
    for arg_name in EVIDENCE_INDEX_ARGS:
        append_optional_path_arg(command, arg_name, getattr(args, arg_name))
    return command


def truthy_zero(value: Any) -> bool:
    return value == 0


def build_acceptance_checks(
    diff_step: dict[str, Any] | None,
    msal_step: dict[str, Any] | None,
    diff_summary: dict[str, Any],
    msal_summary: dict[str, Any],
    diff_events_path: Path,
    msal_records_path: Path,
) -> dict[str, bool]:
    diff_event_count = diff_summary.get("event_count")
    msal_input_event_count = msal_summary.get("input_event_count")
    checks = {
        "diff_exit_zero": bool(diff_step and diff_step.get("return_code") == 0),
        "msal_exit_zero": bool(msal_step and msal_step.get("return_code") == 0),
        "diff_events_exists": diff_events_path.exists() and diff_events_path.is_file(),
        "diff_summary_exists": bool(diff_summary),
        "msal_records_exists": msal_records_path.exists() and msal_records_path.is_file(),
        "msal_summary_exists": bool(msal_summary),
        "msal_input_event_count_matches_diff": diff_event_count is not None and msal_input_event_count == diff_event_count,
        "causal_claim_allowed_count_zero": truthy_zero(msal_summary.get("causal_claim_allowed_count")),
        "root_cause_confirmed_false": True,
        "l2_time_series_not_evaluated": True,
        "control_plane_impact_not_evaluated": True,
    }
    return checks


def acceptance_text(status: str, checks: dict[str, bool], summary: dict[str, Any]) -> str:
    lines = [
        f"{ACCEPTANCE_NAME}={status}",
        f"probe_id={summary.get('probe_id')}",
        f"run_id={summary.get('run_id')}",
        f"prev_snapshot_id={summary.get('prev_snapshot_id')}",
        f"curr_snapshot_id={summary.get('curr_snapshot_id')}",
        f"diff_event_count={summary.get('diff', {}).get('event_count')}",
        f"msal_input_event_count={summary.get('msal', {}).get('input_event_count')}",
        f"causal_claim_allowed_count={summary.get('msal', {}).get('causal_claim_allowed_count')}",
        "root_cause_confirmed=false",
        "l2_time_series_evaluated=false",
        "control_plane_impact_evaluated=false",
        "",
        "[checks]",
    ]
    for name in sorted(checks):
        lines.append(f"{name}={str(checks[name]).lower()}")
    return "\n".join(lines) + "\n"


def as_int(value: Any) -> int | None:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def format_check_value(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return str(value)


def build_runner_acceptance_checks(diff_summary: dict[str, Any], msal_summary: dict[str, Any]) -> dict[str, bool]:
    prev_count = as_int(diff_summary.get("prev_count"))
    curr_count = as_int(diff_summary.get("curr_count"))
    return {
        "diff_summary_json": bool(diff_summary),
        "msal_summary_json": bool(msal_summary),
        "diff_prev_count_gt_zero": prev_count is not None and prev_count > 0,
        "diff_curr_count_gt_zero": curr_count is not None and curr_count > 0,
        "msal_status_pass": msal_summary.get("status") == "PASS",
        "msal_missing_indexes_empty": msal_summary.get("missing_input_indexes") == [],
        "msal_causal_claim_allowed_zero": msal_summary.get("causal_claim_allowed_count") == 0,
        "msal_root_cause_false": msal_summary.get("root_cause_confirmed") is False,
    }


def runner_acceptance_text(status: str, checks: dict[str, bool], summary: dict[str, Any]) -> str:
    diff_summary = summary.get("diff", {})
    msal_summary = summary.get("msal", {})
    fields = [
        (RUNNER_ACCEPTANCE_NAME, status),
        ("run_dir", summary.get("run_dir")),
        ("prev_snapshot_id", summary.get("prev_snapshot_id")),
        ("curr_snapshot_id", summary.get("curr_snapshot_id")),
        ("prev_count", diff_summary.get("prev_count")),
        ("curr_count", diff_summary.get("curr_count")),
        ("event_count", diff_summary.get("event_count")),
        ("msal_input_event_count", msal_summary.get("input_event_count")),
        ("msal_output_record_count", msal_summary.get("output_record_count")),
        ("loaded_index_counts", msal_summary.get("loaded_index_counts")),
        ("missing_input_indexes", msal_summary.get("missing_input_indexes")),
        ("causal_claim_allowed_count", msal_summary.get("causal_claim_allowed_count")),
        ("root_cause_confirmed", summary.get("root_cause_confirmed")),
    ]
    lines = [f"{name}={format_check_value(value)}" for name, value in fields]
    lines.extend(["", "[checks]"])
    for name in [
        "diff_summary_json",
        "msal_summary_json",
        "diff_prev_count_gt_zero",
        "diff_curr_count_gt_zero",
        "msal_status_pass",
        "msal_missing_indexes_empty",
        "msal_causal_claim_allowed_zero",
        "msal_root_cause_false",
    ]:
        lines.append(f"{name}={format_check_value(checks.get(name, False))}")
    return "\n".join(lines) + "\n"


def collect_index_paths(args: argparse.Namespace) -> dict[str, str | None]:
    return {arg_name: (str(Path(getattr(args, arg_name)).resolve()) if getattr(args, arg_name) else None) for arg_name in EVIDENCE_INDEX_ARGS}


def resolve_input_snapshots(args: argparse.Namespace) -> tuple[str, Path, str, Path]:
    if args.prev_normalized or args.curr_normalized:
        if not args.prev_normalized or not args.curr_normalized:
            raise RuntimeError("--prev-normalized and --curr-normalized must be provided together")
        prev_path = Path(args.prev_normalized).resolve()
        curr_path = Path(args.curr_normalized).resolve()
        if not prev_path.is_file():
            raise RuntimeError(f"prev normalized file not found: {prev_path}")
        if not curr_path.is_file():
            raise RuntimeError(f"curr normalized file not found: {curr_path}")
        return infer_snapshot_id_from_normalized(prev_path), prev_path, infer_snapshot_id_from_normalized(curr_path), curr_path

    prev, curr = find_recent_snapshots(Path(args.snapshot_root), args.probe_id)
    return prev.snapshot_id, prev.normalized_path, curr.snapshot_id, curr.normalized_path


def run_once(args: argparse.Namespace) -> dict[str, Any]:
    started_at_utc = utc_now()
    started = time.monotonic()
    repo_root = script_repo_root()
    prev_snapshot_id, prev_path, curr_snapshot_id, curr_path = resolve_input_snapshots(args)
    run_dir = resolve_run_dir(args, prev_snapshot_id, curr_snapshot_id)
    diff_dir = run_dir / "diff"
    msal_dir = run_dir / "msal"
    run_dir.mkdir(parents=True, exist_ok=True)

    diff_events_path = diff_dir / "events.jsonl"
    diff_summary_path = diff_dir / "summary.json"
    msal_records_path = msal_dir / "attribution_records.jsonl"
    msal_summary_path = msal_dir / "summary.json"
    run_summary_path = run_dir / "run_summary.json"
    acceptance_path = run_dir / "acceptance_check.txt"
    runner_acceptance_path = repo_root / RUNNER_ACCEPTANCE_RELATIVE_PATH

    diff_command = build_diff_command(args, repo_root, prev_path, curr_path, diff_dir)
    msal_command = build_msal_command(args, repo_root, diff_events_path, msal_dir)

    diff_step = run_step("diff_live_vrp_snapshots", diff_command, repo_root)
    msal_step: dict[str, Any] | None = None
    if diff_step.get("return_code") == 0:
        msal_step = run_step("msal_minimal_attribution", msal_command, repo_root)

    diff_summary = load_json_object(diff_summary_path)
    msal_summary = load_json_object(msal_summary_path)
    checks = build_acceptance_checks(diff_step, msal_step, diff_summary, msal_summary, diff_events_path, msal_records_path)
    runner_checks = build_runner_acceptance_checks(diff_summary, msal_summary)
    status = "PASS" if all(checks.values()) else "FAIL"
    runner_status = "PASS" if all(runner_checks.values()) else "FAIL"
    finished_at_utc = utc_now()

    summary: dict[str, Any] = {
        "schema": SCHEMA_SUMMARY,
        "status": status,
        "probe_id": args.probe_id,
        "run_id": run_dir.name,
        "run_dir": str(run_dir),
        "prev_snapshot_id": prev_snapshot_id,
        "curr_snapshot_id": curr_snapshot_id,
        "prev_normalized": str(prev_path),
        "curr_normalized": str(curr_path),
        "diff_dir": str(diff_dir),
        "msal_dir": str(msal_dir),
        "diff_events": str(diff_events_path),
        "attribution_records": str(msal_records_path),
        "run_summary_file": str(run_summary_path),
        "acceptance_check_file": str(acceptance_path),
        "runner_acceptance_file": str(runner_acceptance_path),
        "allow_empty_events": bool(args.allow_empty_events),
        "dump_index_stats": bool(args.dump_index_stats),
        "evidence_index_paths": collect_index_paths(args),
        "steps": {
            "diff": diff_step,
            "msal": msal_step,
        },
        "diff": diff_summary,
        "msal": msal_summary,
        "acceptance_checks": checks,
        "runner_acceptance_status": runner_status,
        "runner_acceptance_checks": runner_checks,
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
        "l2_time_series_evaluated": False,
        "control_plane_impact_evaluated": False,
        "data_logs_committed": False,
        "started_at_utc": started_at_utc,
        "finished_at_utc": finished_at_utc,
        "duration_sec": round(time.monotonic() - started, 6),
    }

    atomic_write_json(run_summary_path, summary)
    atomic_write_text(acceptance_path, acceptance_text(status, checks, summary))
    atomic_write_text(runner_acceptance_path, runner_acceptance_text(runner_status, runner_checks, summary))
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return summary


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one live VRP diff plus MSAL minimal attribution pass.")
    parser.add_argument("--probe-id", default=os.environ.get("PROBE_ID", "probe-cd"))
    parser.add_argument("--snapshot-root", default=DEFAULT_SNAPSHOT_ROOT)
    parser.add_argument("--out-dir", help="Run output directory. Defaults under <snapshot-root>/<probe-id>/msal_runs/.")
    parser.add_argument("--prev-normalized", help="Optional previous normalized_vrp.jsonl override.")
    parser.add_argument("--curr-normalized", help="Optional current normalized_vrp.jsonl override.")
    parser.add_argument("--source-pp-coverage")
    parser.add_argument("--l2-object-index")
    parser.add_argument("--manifest-filelist-index")
    parser.add_argument("--hash-evidence-index")
    parser.add_argument("--candidate-evidence-table")
    parser.add_argument("--allow-empty-events", action="store_true")
    parser.add_argument("--dump-index-stats", action="store_true")
    parser.add_argument("--python-bin", default=sys.executable)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    summary = run_once(args)
    return 0 if summary.get("status") == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
