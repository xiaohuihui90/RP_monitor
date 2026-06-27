#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_SUMMARY = "s3.probe.cross_probe_observation_run_summary.v1"
ACCEPTANCE_NAME = "P5_CROSS_PROBE_OBSERVATION"
DEFAULT_LOCAL_SNAPSHOT_ROOT = "data/probe/live_vrp_snapshots"
DEFAULT_REMOTE_SNAPSHOT_ROOT = "data/probe/remote_snapshots"
DEFAULT_MINIO_BUCKET = "rpki-probe-artifacts"
DEFAULT_MINIO_PREFIX = "rp-monitor"
LATEST_METADATA = "latest_metadata.json"
LATEST_NORMALIZED = "latest_normalized_vrp.jsonl"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iso_z(dt: datetime | None) -> str | None:
    if dt is None:
        return None
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


def load_json_object(path: Path) -> tuple[dict[str, Any], str | None]:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            return {}, f"expected JSON object at {path}"
        return obj, None
    except Exception as exc:
        return {}, str(exc)


def parse_assignment(value: str, option_name: str) -> tuple[str, str]:
    if "=" not in value:
        raise ValueError(f"{option_name} must be probe_id=value, got: {value}")
    probe_id, rhs = value.split("=", 1)
    probe_id = probe_id.strip()
    rhs = rhs.strip()
    if not probe_id or not rhs:
        raise ValueError(f"{option_name} must be probe_id=value, got: {value}")
    return probe_id, rhs


def parse_assignments(values: list[str], option_name: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        probe_id, rhs = parse_assignment(value, option_name)
        if probe_id in parsed:
            raise ValueError(f"duplicate {option_name} for probe_id={probe_id}")
        parsed[probe_id] = rhs
    return parsed


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def latest_paths(probe_dir: Path) -> dict[str, Path]:
    return {
        "metadata": probe_dir / LATEST_METADATA,
        "normalized": probe_dir / LATEST_NORMALIZED,
    }


def file_nonempty(path: Path) -> bool:
    return path.is_file() and path.stat().st_size > 0


def run_command(command: list[str], cwd: Path) -> dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.run(command, cwd=str(cwd), text=True, capture_output=True)
        return {
            "command": command,
            "exit_code": proc.returncode,
            "stdout_tail": proc.stdout[-4000:],
            "stderr_tail": proc.stderr[-4000:],
            "duration_sec": round(time.monotonic() - started, 6),
        }
    except FileNotFoundError as exc:
        return {
            "command": command,
            "exit_code": 127,
            "stdout_tail": "",
            "stderr_tail": str(exc),
            "duration_sec": round(time.monotonic() - started, 6),
        }


def pull_remote_probe(
    probe_id: str,
    remote_root: str,
    local_dir: Path,
    rsync_bin: str,
    ssh_command: str | None,
    cwd: Path,
) -> dict[str, Any]:
    local_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for filename in (LATEST_METADATA, LATEST_NORMALIZED):
        source = f"{remote_root.rstrip('/')}/{filename}"
        command = [rsync_bin, "-avz"]
        if ssh_command:
            command.extend(["-e", ssh_command])
        command.extend([source, str(local_dir / filename)])
        results.append(run_command(command, cwd))
    return {
        "probe_id": probe_id,
        "remote_root": remote_root,
        "local_dir": str(local_dir),
        "files": [LATEST_METADATA, LATEST_NORMALIZED],
        "results": results,
        "exit_zero": all(result.get("exit_code") == 0 for result in results),
    }


def snapshot_record(probe_id: str, probe_dir: Path, role: str) -> dict[str, Any]:
    paths = latest_paths(probe_dir)
    metadata_ok = file_nonempty(paths["metadata"])
    normalized_ok = file_nonempty(paths["normalized"])
    metadata: dict[str, Any] = {}
    metadata_error = None
    if metadata_ok:
        metadata, metadata_error = load_json_object(paths["metadata"])
    capture_time = parse_iso_datetime(metadata.get("capture_time_utc"))
    if capture_time is None and isinstance(metadata.get("raw_metadata"), dict):
        capture_time = parse_iso_datetime(metadata["raw_metadata"].get("generatedTime"))
    validator_health = metadata.get("validator_health")
    return {
        "probe_id": probe_id,
        "role": role,
        "probe_dir": str(probe_dir),
        "metadata_path": str(paths["metadata"]),
        "normalized_path": str(paths["normalized"]),
        "metadata_exists": metadata_ok,
        "normalized_exists": normalized_ok,
        "metadata_json_ok": metadata_ok and metadata_error is None,
        "metadata_error": metadata_error,
        "capture_time_utc": iso_z(capture_time),
        "capture_time_epoch": capture_time.timestamp() if capture_time else None,
        "validator_health": validator_health,
        "validator_healthy": validator_health in {"healthy", "degraded"},
        "vrp_count": metadata.get("vrp_count"),
        "normalized_vrp_count": metadata.get("normalized_vrp_count"),
        "snapshot_id": metadata.get("snapshot_id"),
    }


def capture_time_skew(records: dict[str, dict[str, Any]]) -> int | None:
    epochs = [record.get("capture_time_epoch") for record in records.values()]
    numeric = [float(epoch) for epoch in epochs if epoch is not None]
    if not numeric:
        return None
    return int(max(numeric) - min(numeric))


def parse_acceptance(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    parsed: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip().lstrip("\ufeff")] = value.strip()
    return parsed


def bool_text(value: Any) -> str:
    return "true" if bool(value) else "false"


def build_acceptance(summary: dict[str, Any]) -> tuple[str, dict[str, bool]]:
    checks = summary.get("acceptance_checks") if isinstance(summary.get("acceptance_checks"), dict) else {}
    status = "PASS" if all(checks.values()) else "FAIL"
    lines = [
        f"{ACCEPTANCE_NAME}={status}",
        f"out_dir={summary.get('out_dir')}",
        f"probe_ids={','.join(summary.get('probe_ids', []))}",
        f"capture_time_skew_sec={summary.get('capture_time_skew_sec')}",
        f"max_skew_sec={summary.get('max_skew_sec')}",
        f"allow_skew_up_to_sec={summary.get('allow_skew_up_to_sec') or ''}",
        f"window_quality_warning={bool_text(summary.get('window_quality_warning'))}",
        f"p2_run_dir={summary.get('outputs', {}).get('p2_run_dir') if isinstance(summary.get('outputs'), dict) else ''}",
        f"p3_run_dir={summary.get('outputs', {}).get('p3_run_dir') if isinstance(summary.get('outputs'), dict) else ''}",
        f"p4_run_dir={summary.get('outputs', {}).get('p4_run_dir') if isinstance(summary.get('outputs'), dict) else ''}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={bool_text(value)}" for key, value in checks.items())
    return "\n".join(lines) + "\n", checks


def p2_args(python_bin: str, root: Path, records: dict[str, dict[str, Any]], out_dir: Path, window_size_sec: int, max_skew_sec: int) -> list[str]:
    command = [
        python_bin,
        str(root / "probe" / "diff_cross_probe_vrp_snapshots.py"),
        "--window-size-sec",
        str(window_size_sec),
        "--max-skew-sec",
        str(max_skew_sec),
        "--out-dir",
        str(out_dir),
    ]
    for probe_id in sorted(records):
        command.extend(["--snapshot", f"{probe_id}={records[probe_id]['normalized_path']}"])
        command.extend(["--metadata", f"{probe_id}={records[probe_id]['metadata_path']}"])
    return command


def run_p3_args(python_bin: str, root: Path, p2_dir: Path, out_dir: Path, min_consecutive: int, max_skew_sec: int) -> list[str]:
    return [
        python_bin,
        str(root / "probe" / "analyze_cross_probe_persistence.py"),
        "--p2-run-dir",
        str(p2_dir),
        "--min-consecutive",
        str(min_consecutive),
        "--max-skew-sec",
        str(max_skew_sec),
        "--out-dir",
        str(out_dir),
    ]


def run_p4_args(
    python_bin: str,
    root: Path,
    p2_dir: Path,
    p3_dir: Path | None,
    out_dir: Path,
    minio_bucket: str,
    minio_prefix: str,
) -> list[str]:
    command = [
        python_bin,
        str(root / "probe" / "build_cross_probe_artifact_manifest.py"),
        "--p2-run-dir",
        str(p2_dir),
        "--out-dir",
        str(out_dir),
        "--minio-bucket",
        minio_bucket,
        "--minio-prefix",
        minio_prefix,
    ]
    if p3_dir is not None:
        command.extend(["--p3-run-dir", str(p3_dir)])
    return command


def summarize_p2(p2_dir: Path) -> dict[str, Any]:
    summary, error = load_json_object(p2_dir / "cross_probe_summary.json")
    acceptance = parse_acceptance(p2_dir / "checks" / "P2_CROSS_PROBE_DIFF_ACCEPTANCE.txt")
    return {
        "summary": summary,
        "summary_error": error,
        "acceptance": acceptance,
        "acceptance_pass": acceptance.get("P2_CROSS_PROBE_DIFF") == "PASS",
    }


def summarize_p3(p3_dir: Path | None) -> dict[str, Any] | None:
    if p3_dir is None:
        return None
    summary, error = load_json_object(p3_dir / "summary.json")
    acceptance = parse_acceptance(p3_dir / "checks" / "P3_CROSS_WINDOW_PERSISTENCE_ACCEPTANCE.txt")
    return {
        "summary": summary,
        "summary_error": error,
        "acceptance": acceptance,
        "acceptance_pass": acceptance.get("P3_CROSS_WINDOW_PERSISTENCE") == "PASS",
    }


def summarize_p4(p4_dir: Path | None) -> dict[str, Any] | None:
    if p4_dir is None:
        return None
    manifest, error = load_json_object(p4_dir / "artifact_manifest.json")
    acceptance = parse_acceptance(p4_dir / "checks" / "P4_CROSS_PROBE_ARTIFACT_MANIFEST_ACCEPTANCE.txt")
    return {
        "manifest": manifest,
        "manifest_error": error,
        "acceptance": acceptance,
        "acceptance_pass": acceptance.get("P4_CROSS_PROBE_ARTIFACT_MANIFEST") == "PASS",
    }


def observation_allowed(skew_sec: int | None, max_skew_sec: int, allow_skew_up_to_sec: int | None) -> tuple[bool, int, bool]:
    if skew_sec is None:
        return False, max_skew_sec, False
    if skew_sec <= max_skew_sec:
        return True, max_skew_sec, False
    if allow_skew_up_to_sec is not None and skew_sec <= allow_skew_up_to_sec:
        return True, allow_skew_up_to_sec, True
    return False, max_skew_sec, False


def run_observation(args: argparse.Namespace) -> dict[str, Any]:
    started_at_utc = utc_now()
    started = time.monotonic()
    root = repo_root()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    python_bin = args.python_bin or sys.executable

    remote_probes = parse_assignments(args.remote_probe or [], "--remote-probe")
    remote_local_dirs = parse_assignments(args.remote_probe_local_dir or [], "--remote-probe-local-dir")

    remote_pull_status: list[dict[str, Any]] = []
    remote_snapshot_root = Path(args.remote_snapshot_root).resolve()
    for probe_id, remote_root in remote_probes.items():
        local_dir = remote_snapshot_root / probe_id
        remote_pull_status.append(
            pull_remote_probe(
                probe_id=probe_id,
                remote_root=remote_root,
                local_dir=local_dir,
                rsync_bin=args.rsync_bin,
                ssh_command=args.ssh_command,
                cwd=root,
            )
        )
        remote_local_dirs.setdefault(probe_id, str(local_dir))

    records: dict[str, dict[str, Any]] = {}
    local_dir = Path(args.local_snapshot_root).resolve() / args.probe_id_local
    records[args.probe_id_local] = snapshot_record(args.probe_id_local, local_dir, "local")
    for probe_id, local_path in remote_local_dirs.items():
        records[probe_id] = snapshot_record(probe_id, Path(local_path).resolve(), "remote_local")

    skew_sec = capture_time_skew(records)
    can_run_p2, effective_max_skew, warning = observation_allowed(skew_sec, int(args.max_skew_sec), args.allow_skew_up_to_sec)

    p2_dir = out_dir / "p2_cross_probe"
    p3_dir = out_dir / "p3_persistence" if args.run_p3 else None
    p4_dir = out_dir / "p4_artifact_manifest" if args.run_p4 else None
    command_results: dict[str, Any] = {}

    snapshots_ok = all(record["metadata_exists"] and record["normalized_exists"] for record in records.values())
    metadata_ok = all(record["metadata_json_ok"] for record in records.values())
    enough_probes = len(records) >= 2
    if can_run_p2 and snapshots_ok and metadata_ok and enough_probes:
        p2_command = p2_args(python_bin, root, records, p2_dir, int(args.window_size_sec), effective_max_skew)
        command_results["p2"] = run_command(p2_command, root)
    else:
        command_results["p2"] = {
            "skipped": True,
            "reason": "skew_or_input_check_failed",
            "can_run_p2": can_run_p2,
            "snapshots_ok": snapshots_ok,
            "metadata_ok": metadata_ok,
            "enough_probes": enough_probes,
        }

    p2_info = summarize_p2(p2_dir) if (p2_dir / "cross_probe_summary.json").exists() else {
        "summary": {},
        "summary_error": "p2_not_run_or_summary_missing",
        "acceptance": {},
        "acceptance_pass": False,
    }

    if args.run_p3 and command_results.get("p2", {}).get("exit_code") == 0:
        assert p3_dir is not None
        command_results["p3"] = run_command(
            run_p3_args(python_bin, root, p2_dir, p3_dir, int(args.p3_min_consecutive), effective_max_skew),
            root,
        )
    elif args.run_p3:
        command_results["p3"] = {"skipped": True, "reason": "p2_not_successful"}

    p3_info = summarize_p3(p3_dir) if p3_dir and (p3_dir / "summary.json").exists() else None

    if args.run_p4 and command_results.get("p2", {}).get("exit_code") == 0:
        assert p4_dir is not None
        command_results["p4"] = run_command(
            run_p4_args(
                python_bin,
                root,
                p2_dir,
                p3_dir if p3_info is not None else None,
                p4_dir,
                args.minio_bucket,
                args.minio_prefix,
            ),
            root,
        )
    elif args.run_p4:
        command_results["p4"] = {"skipped": True, "reason": "p2_not_successful"}

    p4_info = summarize_p4(p4_dir) if p4_dir and (p4_dir / "artifact_manifest.json").exists() else None
    p2_summary = p2_info.get("summary") if isinstance(p2_info, dict) else {}
    p3_summary = p3_info.get("summary") if isinstance(p3_info, dict) and isinstance(p3_info.get("summary"), dict) else {}

    causal_claim_allowed_count = int(p2_summary.get("causal_claim_allowed_count") or 0)
    if p3_summary:
        causal_claim_allowed_count += int(p3_summary.get("causal_claim_allowed_count") or 0)
    root_cause_confirmed = bool(p2_summary.get("root_cause_confirmed") is True or p3_summary.get("root_cause_confirmed") is True)

    checks = {
        "local_snapshot_exists": records[args.probe_id_local]["metadata_exists"] and records[args.probe_id_local]["normalized_exists"],
        "remote_snapshot_exists": all(
            record["metadata_exists"] and record["normalized_exists"]
            for probe_id, record in records.items()
            if probe_id != args.probe_id_local
        ),
        "metadata_json_ok": metadata_ok,
        "all_validator_healthy": all(record.get("validator_healthy") for record in records.values()),
        "capture_time_skew_within_threshold": skew_sec is not None and skew_sec <= effective_max_skew,
        "p2_exit_zero": command_results.get("p2", {}).get("exit_code") == 0,
        "p2_window_quality_ok": p2_summary.get("window_quality") == "OK",
        "p2_acceptance_pass": bool(p2_info.get("acceptance_pass")),
        "causal_claim_allowed_zero": causal_claim_allowed_count == 0,
        "root_cause_confirmed_false": root_cause_confirmed is False,
    }

    summary = {
        "schema": SCHEMA_SUMMARY,
        "status": "PASS" if all(checks.values()) else "FAIL",
        "out_dir": str(out_dir),
        "probe_id_local": args.probe_id_local,
        "probe_ids": sorted(records),
        "window_size_sec": int(args.window_size_sec),
        "max_skew_sec": int(args.max_skew_sec),
        "allow_skew_up_to_sec": args.allow_skew_up_to_sec,
        "effective_p2_max_skew_sec": effective_max_skew,
        "window_quality_warning": warning,
        "capture_time_skew_sec": skew_sec,
        "capture_time_by_probe": {probe_id: record.get("capture_time_utc") for probe_id, record in records.items()},
        "validator_health_by_probe": {probe_id: record.get("validator_health") for probe_id, record in records.items()},
        "snapshot_paths": {
            probe_id: {
                "metadata": record.get("metadata_path"),
                "normalized": record.get("normalized_path"),
            }
            for probe_id, record in records.items()
        },
        "snapshot_records": records,
        "remote_pull_status": remote_pull_status,
        "commands": command_results,
        "p2": p2_info,
        "p3": p3_info,
        "p4": p4_info,
        "causal_claim_allowed_count": causal_claim_allowed_count,
        "root_cause_confirmed": root_cause_confirmed,
        "acceptance_checks": checks,
        "outputs": {
            "run_summary": str(out_dir / "run_summary.json"),
            "acceptance": str(out_dir / "checks" / "P5_CROSS_PROBE_OBSERVATION_ACCEPTANCE.txt"),
            "p2_run_dir": str(p2_dir),
            "p3_run_dir": str(p3_dir) if p3_dir else None,
            "p4_run_dir": str(p4_dir) if p4_dir else None,
        },
        "started_at_utc": started_at_utc,
        "finished_at_utc": utc_now(),
        "duration_sec": round(time.monotonic() - started, 6),
    }
    acceptance, _ = build_acceptance(summary)
    atomic_write_json(out_dir / "run_summary.json", summary)
    atomic_write_text(out_dir / "checks" / "P5_CROSS_PROBE_OBSERVATION_ACCEPTANCE.txt", acceptance)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return summary


def self_test_record(probe_id: str, capture_time: str, rows: list[dict[str, Any]], root: Path) -> Path:
    probe_dir = root / probe_id
    probe_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "schema": "s3.probe.routinator_live_snapshot_metadata.v1",
        "snapshot_id": f"self_{probe_id}_{capture_time.replace(':', '').replace('-', '')}",
        "probe_id": probe_id,
        "capture_time_utc": capture_time,
        "validator_health": "healthy",
        "vrp_count": len(rows),
        "normalized_vrp_count": len(rows),
        "raw_metadata": {"generatedTime": capture_time},
    }
    atomic_write_json(probe_dir / LATEST_METADATA, metadata)
    atomic_write_text(
        probe_dir / LATEST_NORMALIZED,
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
    )
    return probe_dir


def run_self_test(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).resolve()
    input_root = out_dir / "self_test_inputs"
    local_root = input_root / "live_vrp_snapshots"
    remote_root = input_root / "remote_snapshots"
    common = {"tal": "apnic", "asn": 64500, "prefix": "203.0.113.0/24", "max_length": 24, "source_uri": "rsync://repo/common.roa"}
    missing = {"tal": "apnic", "asn": 64501, "prefix": "198.51.100.0/24", "max_length": 24, "source_uri": "rsync://repo/missing.roa"}
    source_a = {"tal": "ripe", "asn": 64502, "prefix": "192.0.2.0/24", "max_length": 24, "source_uri": "rsync://repo/a.roa"}
    source_b = {"tal": "ripe", "asn": 64502, "prefix": "192.0.2.0/24", "max_length": 24, "source_uri": "rsync://repo/b.roa"}
    self_test_record("probe-cd", "2026-06-25T00:00:00Z", [common, missing, source_a], local_root)
    self_test_record("probe-sg", "2026-06-25T00:01:00Z", [common, source_b], remote_root)
    self_test_record("probe-k02", "2026-06-25T00:02:00Z", [common, missing, source_a], remote_root)

    test_args = argparse.Namespace(
        probe_id_local="probe-cd",
        remote_probe=[],
        remote_probe_local_dir=[
            f"probe-sg={remote_root / 'probe-sg'}",
            f"probe-k02={remote_root / 'probe-k02'}",
        ],
        out_dir=str(out_dir),
        window_size_sec=args.window_size_sec,
        max_skew_sec=args.max_skew_sec,
        allow_skew_up_to_sec=args.allow_skew_up_to_sec,
        run_p3=True,
        run_p4=True,
        p3_min_consecutive=args.p3_min_consecutive,
        python_bin=args.python_bin or sys.executable,
        ssh_command=args.ssh_command,
        rsync_bin=args.rsync_bin,
        local_snapshot_root=str(local_root),
        remote_snapshot_root=str(remote_root),
        minio_bucket=args.minio_bucket,
        minio_prefix=args.minio_prefix,
        self_test=False,
    )
    summary = run_observation(test_args)
    checks = summary.get("acceptance_checks") if isinstance(summary.get("acceptance_checks"), dict) else {}
    self_checks = {
        "p5_pass": summary.get("status") == "PASS",
        "p2_exit_zero": checks.get("p2_exit_zero") is True,
        "p2_acceptance_pass": checks.get("p2_acceptance_pass") is True,
        "p3_ran": isinstance(summary.get("p3"), dict),
        "p4_ran": isinstance(summary.get("p4"), dict),
        "causal_false": checks.get("causal_claim_allowed_zero") is True and checks.get("root_cause_confirmed_false") is True,
    }
    if not all(self_checks.values()):
        print(json.dumps({"self_test_checks": self_checks, "summary": summary}, ensure_ascii=False, indent=2, sort_keys=True), file=sys.stderr)
        return 1
    print("[P5 self-test] PASS " + json.dumps(self_checks, sort_keys=True), file=sys.stderr)
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one CD2 cross-probe observation by gathering latest snapshots and invoking P2/P3/P4.")
    parser.add_argument("--probe-id-local", default="probe-cd")
    parser.add_argument("--remote-probe", action="append", default=[], help="Remote pull spec: probe_id=user@host:/path/to/live_vrp_snapshots/probe_id. Repeatable.")
    parser.add_argument("--remote-probe-local-dir", action="append", default=[], help="Already-synced remote probe dir: probe_id=data/probe/remote_snapshots/probe_id. Repeatable.")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--window-size-sec", type=int, default=3600)
    parser.add_argument("--max-skew-sec", type=int, default=600)
    parser.add_argument("--allow-skew-up-to-sec", type=int)
    parser.add_argument("--run-p3", action="store_true")
    parser.add_argument("--run-p4", action="store_true")
    parser.add_argument("--p3-min-consecutive", type=int, default=2)
    parser.add_argument("--python-bin", default=sys.executable)
    parser.add_argument("--ssh-command", help="Optional ssh command passed to rsync with -e. No private key is hardcoded by this script.")
    parser.add_argument("--rsync-bin", default="rsync")
    parser.add_argument("--local-snapshot-root", default=DEFAULT_LOCAL_SNAPSHOT_ROOT)
    parser.add_argument("--remote-snapshot-root", default=DEFAULT_REMOTE_SNAPSHOT_ROOT)
    parser.add_argument("--minio-bucket", default=DEFAULT_MINIO_BUCKET)
    parser.add_argument("--minio-prefix", default=DEFAULT_MINIO_PREFIX)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.window_size_sec <= 0:
        parser.error("--window-size-sec must be > 0")
    if args.max_skew_sec < 0:
        parser.error("--max-skew-sec must be >= 0")
    if args.allow_skew_up_to_sec is not None and args.allow_skew_up_to_sec < args.max_skew_sec:
        parser.error("--allow-skew-up-to-sec must be >= --max-skew-sec when provided")
    if args.p3_min_consecutive <= 0:
        parser.error("--p3-min-consecutive must be > 0")
    if not args.self_test and not args.remote_probe and not args.remote_probe_local_dir:
        parser.error("provide --remote-probe and/or --remote-probe-local-dir, or use --self-test")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test(args)
    summary = run_observation(args)
    return 0 if summary.get("status") == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
