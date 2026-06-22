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


SCHEMA_SUMMARY = "s3.probe.live_msal_cycle_summary.v1"
CYCLE_ACCEPTANCE_NAME = "E2_LIVE_MSAL_CYCLE"
CYCLE_ACCEPTANCE_RELATIVE_PATH = Path("checks") / "E2_LIVE_MSAL_CYCLE_ACCEPTANCE.txt"
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


def list_normalized_snapshots(snapshot_root: Path, probe_id: str) -> list[SnapshotCandidate]:
    probe_base = resolve_probe_snapshot_base(snapshot_root, probe_id)
    history_dir = probe_base / "history"
    if not history_dir.is_dir():
        return []

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
    return candidates


def find_recent_snapshots(snapshot_root: Path, probe_id: str) -> tuple[SnapshotCandidate, SnapshotCandidate] | None:
    candidates = list_normalized_snapshots(snapshot_root, probe_id)
    if len(candidates) < 2:
        return None
    return candidates[-2], candidates[-1]


def load_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8-sig") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise RuntimeError(f"expected JSON object at {path}")
    return obj


def read_text_or_none(path: Path) -> str | None:
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    return text or None


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


def resolve_cycle_dir(args: argparse.Namespace) -> Path:
    if args.out_dir:
        return Path(args.out_dir).resolve()
    probe_base = resolve_probe_snapshot_base(Path(args.snapshot_root), args.probe_id)
    return (probe_base / "msal_cycles" / f"cycle_{utc_compact()}").resolve()


def build_export_command(args: argparse.Namespace, repo_root: Path) -> list[str]:
    command = [
        args.python_bin,
        str(repo_root / "probe" / "export_routinator_live_snapshot.py"),
        "--probe-id",
        args.probe_id,
        "--out-root",
        str(Path(args.snapshot_root).resolve()),
        "--capture-mode",
        "command",
        "--routinator-bin",
        args.routinator_bin,
        "--command-format",
        args.command_format,
        "--command-timeout-sec",
        str(args.command_timeout_sec),
        "--no-retry-command-with-update",
    ]
    for extra_arg in args.command_extra_arg or []:
        command.extend(["--command-extra-arg", extra_arg])
    return command


def build_e1_command(args: argparse.Namespace, repo_root: Path, e1_out_dir: Path) -> list[str]:
    command = [
        args.python_bin,
        str(repo_root / "probe" / "run_live_vrp_msal_once.py"),
        "--probe-id",
        args.probe_id,
        "--snapshot-root",
        str(Path(args.snapshot_root).resolve()),
        "--out-dir",
        str(e1_out_dir),
        "--python-bin",
        args.python_bin,
    ]
    if args.allow_empty_events:
        command.append("--allow-empty-events")
    if args.dump_index_stats:
        command.append("--dump-index-stats")
    for arg_name in EVIDENCE_INDEX_ARGS:
        append_optional_path_arg(command, arg_name, getattr(args, arg_name))
    return command


def collect_index_paths(args: argparse.Namespace) -> dict[str, str | None]:
    return {arg_name: (str(Path(getattr(args, arg_name)).resolve()) if getattr(args, arg_name) else None) for arg_name in EVIDENCE_INDEX_ARGS}


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


def read_e1_runner_acceptance(repo_root: Path) -> dict[str, str]:
    path = repo_root / "checks" / "E1_LIVE_VRP_MSAL_RUNNER_ACCEPTANCE.txt"
    if not path.exists():
        return {}
    parsed: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def build_cycle_acceptance_checks(summary: dict[str, Any]) -> dict[str, bool]:
    export_metadata = summary.get("export_metadata", {})
    e1_summary = summary.get("e1_summary", {})
    diff_summary = e1_summary.get("diff", {}) if isinstance(e1_summary, dict) else {}
    msal_summary = e1_summary.get("msal", {}) if isinstance(e1_summary, dict) else {}
    e1_runner_acceptance = summary.get("e1_runner_acceptance", {})
    export_step = summary.get("export_step") or {}
    e1_step = summary.get("e1_step") or {}
    return {
        "export_exit_zero": export_step.get("return_code") == 0,
        "export_metadata_json": bool(export_metadata),
        "export_snapshot_id_present": bool(summary.get("new_snapshot_id")),
        "export_normalized_vrp_exists": bool(summary.get("new_normalized_vrp_exists")),
        "recent_two_snapshots_found": bool(summary.get("prev_snapshot_id") and summary.get("curr_snapshot_id")),
        "e1_exit_zero": e1_step.get("return_code") == 0,
        "e1_run_summary_json": bool(e1_summary),
        "e1_status_pass": e1_summary.get("status") == "PASS",
        "e1_runner_acceptance_pass": e1_runner_acceptance.get("E1_LIVE_VRP_MSAL_RUNNER") == "PASS",
        "diff_prev_count_gt_zero": (as_int(diff_summary.get("prev_count")) or 0) > 0,
        "diff_curr_count_gt_zero": (as_int(diff_summary.get("curr_count")) or 0) > 0,
        "msal_status_pass": msal_summary.get("status") == "PASS",
        "msal_causal_claim_allowed_zero": msal_summary.get("causal_claim_allowed_count") == 0,
        "msal_root_cause_false": msal_summary.get("root_cause_confirmed") is False,
        "l2_time_series_not_evaluated": summary.get("l2_time_series_evaluated") is False,
        "control_plane_impact_not_evaluated": summary.get("control_plane_impact_evaluated") is False,
        "data_logs_not_committed": summary.get("data_logs_committed") is False,
    }


def cycle_acceptance_text(status: str, checks: dict[str, bool], summary: dict[str, Any]) -> str:
    e1_summary = summary.get("e1_summary", {})
    diff_summary = e1_summary.get("diff", {}) if isinstance(e1_summary, dict) else {}
    msal_summary = e1_summary.get("msal", {}) if isinstance(e1_summary, dict) else {}
    fields = [
        (CYCLE_ACCEPTANCE_NAME, status),
        ("cycle_dir", summary.get("cycle_dir")),
        ("cycle_summary", summary.get("cycle_summary_file")),
        ("new_snapshot_id", summary.get("new_snapshot_id")),
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
        ("l2_time_series_evaluated", summary.get("l2_time_series_evaluated")),
        ("control_plane_impact_evaluated", summary.get("control_plane_impact_evaluated")),
    ]
    lines = [f"{name}={format_check_value(value)}" for name, value in fields]
    lines.extend(["", "[checks]"])
    for name in sorted(checks):
        lines.append(f"{name}={format_check_value(checks[name])}")
    return "\n".join(lines) + "\n"


def run_cycle(args: argparse.Namespace) -> dict[str, Any]:
    started_at_utc = utc_now()
    started = time.monotonic()
    repo_root = script_repo_root()
    snapshot_root = Path(args.snapshot_root).resolve()
    probe_base = resolve_probe_snapshot_base(snapshot_root, args.probe_id)
    cycle_dir = resolve_cycle_dir(args)
    e1_out_dir = cycle_dir / "e1_run"
    cycle_summary_path = cycle_dir / "cycle_summary.json"
    acceptance_path = cycle_dir / CYCLE_ACCEPTANCE_RELATIVE_PATH
    cycle_dir.mkdir(parents=True, exist_ok=True)

    before_snapshots = list_normalized_snapshots(snapshot_root, args.probe_id)
    export_command = build_export_command(args, repo_root)
    export_step = run_step("export_routinator_live_snapshot", export_command, repo_root)

    latest_snapshot_path = probe_base / "latest_snapshot_id.txt"
    latest_metadata_path = probe_base / "latest_metadata.json"
    new_snapshot_id = read_text_or_none(latest_snapshot_path)
    export_metadata = load_json_object(latest_metadata_path)
    if not new_snapshot_id and export_metadata:
        new_snapshot_id = str(export_metadata.get("snapshot_id") or "") or None

    new_normalized_path = probe_base / "history" / str(new_snapshot_id) / "normalized_vrp.jsonl" if new_snapshot_id else None
    recent_pair = find_recent_snapshots(snapshot_root, args.probe_id)
    prev_snapshot_id = recent_pair[0].snapshot_id if recent_pair else None
    curr_snapshot_id = recent_pair[1].snapshot_id if recent_pair else None

    e1_step: dict[str, Any] | None = None
    if export_step.get("return_code") == 0 and recent_pair is not None:
        e1_command = build_e1_command(args, repo_root, e1_out_dir)
        e1_step = run_step("run_live_vrp_msal_once", e1_command, repo_root)

    e1_summary = load_json_object(e1_out_dir / "run_summary.json")
    e1_runner_acceptance = read_e1_runner_acceptance(repo_root)
    finished_at_utc = utc_now()

    summary: dict[str, Any] = {
        "schema": SCHEMA_SUMMARY,
        "probe_id": args.probe_id,
        "cycle_dir": str(cycle_dir),
        "cycle_summary_file": str(cycle_summary_path),
        "acceptance_check_file": str(acceptance_path),
        "snapshot_root": str(snapshot_root),
        "new_snapshot_id": new_snapshot_id,
        "new_normalized_vrp": str(new_normalized_path) if new_normalized_path else None,
        "new_normalized_vrp_exists": bool(new_normalized_path and new_normalized_path.exists() and new_normalized_path.stat().st_size > 0),
        "before_snapshot_count": len(before_snapshots),
        "after_snapshot_count": len(list_normalized_snapshots(snapshot_root, args.probe_id)),
        "prev_snapshot_id": prev_snapshot_id,
        "curr_snapshot_id": curr_snapshot_id,
        "capture_mode": "command",
        "command_no_update_mode": True,
        "command_allow_update_enabled": False,
        "command_retry_with_update_enabled": False,
        "allow_empty_events": bool(args.allow_empty_events),
        "dump_index_stats": bool(args.dump_index_stats),
        "evidence_index_paths": collect_index_paths(args),
        "export_step": export_step,
        "export_metadata": export_metadata,
        "e1_step": e1_step,
        "e1_summary": e1_summary,
        "e1_runner_acceptance": e1_runner_acceptance,
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
        "l2_time_series_evaluated": False,
        "control_plane_impact_evaluated": False,
        "data_logs_committed": False,
        "started_at_utc": started_at_utc,
        "finished_at_utc": finished_at_utc,
        "duration_sec": round(time.monotonic() - started, 6),
    }

    checks = build_cycle_acceptance_checks(summary)
    status = "PASS" if all(checks.values()) else "FAIL"
    summary["status"] = status
    summary["acceptance_checks"] = checks

    atomic_write_json(cycle_summary_path, summary)
    atomic_write_text(acceptance_path, cycle_acceptance_text(status, checks, summary))
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return summary


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one probe-cd live Routinator snapshot plus VRP diff/MSAL attribution cycle.")
    parser.add_argument("--probe-id", default=os.environ.get("PROBE_ID", "probe-cd"))
    parser.add_argument("--snapshot-root", default=DEFAULT_SNAPSHOT_ROOT)
    parser.add_argument("--out-dir", help="Cycle output directory. Defaults under <snapshot-root>/<probe-id>/msal_cycles/.")
    parser.add_argument("--routinator-bin", default=os.environ.get("ROUTINATOR_BIN", "routinator"))
    parser.add_argument("--command-format", choices=["json", "jsonext"], default="json")
    parser.add_argument("--command-timeout-sec", type=int, default=900)
    parser.add_argument("--command-extra-arg", action="append", default=[])
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
    summary = run_cycle(args)
    return 0 if summary.get("status") == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)