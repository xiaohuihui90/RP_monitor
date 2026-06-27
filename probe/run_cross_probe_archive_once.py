#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_SUMMARY = "s3.probe.cross_probe_archive_pipeline_summary.v1"
ACCEPTANCE_NAME = "P8_CROSS_PROBE_PIPELINE"
LATEST_METADATA = "latest_metadata.json"
LATEST_NORMALIZED = "latest_normalized_vrp.jsonl"
DEFAULT_OUT_ROOT = "data/probe/cross_probe_pipeline"
DEFAULT_MINIO_BUCKET = "rpki-probe-artifacts"
DEFAULT_MINIO_PREFIX = "rp-monitor"


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


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def parse_probe_ids(value: str) -> list[str]:
    probe_ids = [item.strip() for item in value.split(",") if item.strip()]
    if not probe_ids:
        raise ValueError("--probe-id-list must contain at least one probe id")
    seen: set[str] = set()
    duplicates: list[str] = []
    for probe_id in probe_ids:
        if probe_id in seen:
            duplicates.append(probe_id)
        seen.add(probe_id)
    if duplicates:
        raise ValueError(f"duplicate probe ids in --probe-id-list: {','.join(sorted(set(duplicates)))}")
    return probe_ids


def parse_assignment(value: str, option_name: str) -> tuple[str, str]:
    if "=" not in value:
        raise ValueError(f"{option_name} must be probe_id=path, got: {value}")
    probe_id, rhs = value.split("=", 1)
    probe_id = probe_id.strip()
    rhs = rhs.strip()
    if not probe_id or not rhs:
        raise ValueError(f"{option_name} must be probe_id=path, got: {value}")
    return probe_id, rhs


def parse_assignments(values: list[str], option_name: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        probe_id, rhs = parse_assignment(value, option_name)
        if probe_id in parsed:
            raise ValueError(f"duplicate {option_name} for probe_id={probe_id}")
        parsed[probe_id] = rhs
    return parsed


def resolve_path(path_text: str, root: Path) -> Path:
    path = Path(path_text)
    if path.is_absolute():
        return path
    return (root / path).resolve()


def is_windows_drive_path(path_text: str) -> bool:
    return len(path_text) >= 3 and path_text[1] == ":" and path_text[2] in {"\\", "/"}


def is_remote_path(path_text: str) -> bool:
    text = path_text.strip()
    if not text or is_windows_drive_path(text):
        return False
    if "://" in text:
        return False
    if ":" not in text:
        return False
    left, right = text.split(":", 1)
    return bool(left.strip()) and bool(right.strip()) and "/" in right.replace("\\", "/")


def remote_source_for_assignment(path_text: str, filename: str) -> str:
    text = path_text.strip()
    tail = text.rstrip("/").replace("\\", "/").split("/")[-1]
    if tail == filename or tail.endswith(".json") or tail.endswith(".jsonl"):
        return text
    return text.rstrip("/") + "/" + filename


def default_probe_base_dirs(root: Path, probe_id: str) -> list[Path]:
    return [
        root / "data" / "probe" / "live_vrp_snapshots" / probe_id,
        root / "data" / "probe" / "remote_snapshots" / probe_id,
    ]


def resolve_probe_file(
    probe_id: str,
    assignments: dict[str, str],
    root: Path,
    filename: str,
) -> tuple[Path, str]:
    assigned = assignments.get(probe_id)
    if assigned:
        if is_remote_path(assigned):
            raise ValueError("remote assignments must be materialized before resolve_probe_file")
        path = resolve_path(assigned, root)
        if path.is_dir():
            return (path / filename).resolve(), "assigned_directory"
        return path.resolve(), "assigned_file"
    for base_dir in default_probe_base_dirs(root, probe_id):
        candidate = base_dir / filename
        if candidate.exists():
            return candidate.resolve(), f"default:{base_dir.relative_to(root).as_posix()}"
    return (default_probe_base_dirs(root, probe_id)[0] / filename).resolve(), "default_missing"


def file_nonempty(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def load_json_object(path: Path) -> tuple[dict[str, Any], str | None]:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            return {}, f"expected JSON object at {path}"
        return obj, None
    except Exception as exc:
        return {}, str(exc)


def parse_iso_datetime(value: Any) -> datetime | None:
    if value is None:
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


def iso_z(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def snapshot_record(
    probe_id: str,
    normalized_path: Path,
    metadata_path: Path,
    normalized_source: str,
    metadata_source: str,
) -> dict[str, Any]:
    metadata_exists = file_nonempty(metadata_path)
    normalized_exists = file_nonempty(normalized_path)
    metadata: dict[str, Any] = {}
    metadata_error = None
    if metadata_exists:
        metadata, metadata_error = load_json_object(metadata_path)
    capture_time = parse_iso_datetime(metadata.get("capture_time_utc"))
    if capture_time is None and isinstance(metadata.get("raw_metadata"), dict):
        capture_time = parse_iso_datetime(metadata["raw_metadata"].get("generatedTime"))
    validator_health = metadata.get("validator_health")
    return {
        "probe_id": probe_id,
        "normalized_path": str(normalized_path),
        "metadata_path": str(metadata_path),
        "normalized_source": normalized_source,
        "metadata_source": metadata_source,
        "normalized_exists": normalized_exists,
        "metadata_exists": metadata_exists,
        "metadata_json_ok": metadata_exists and metadata_error is None,
        "metadata_error": metadata_error,
        "capture_time_utc": iso_z(capture_time),
        "capture_time_epoch": capture_time.timestamp() if capture_time else None,
        "validator_health": validator_health,
        "validator_healthy": validator_health in {"healthy", "degraded"},
        "snapshot_id": metadata.get("snapshot_id"),
        "vrp_count": metadata.get("vrp_count"),
        "normalized_vrp_count": metadata.get("normalized_vrp_count"),
    }


def capture_time_skew(records: dict[str, dict[str, Any]]) -> int | None:
    epochs = [record.get("capture_time_epoch") for record in records.values()]
    numeric = [float(epoch) for epoch in epochs if epoch is not None]
    if len(numeric) < 2:
        return None
    return int(max(numeric) - min(numeric))


def run_command(command: list[str], cwd: Path) -> dict[str, Any]:
    started = time.monotonic()
    print("[P8] running:", " ".join(command), file=sys.stderr)
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


def materialize_remote_file(
    remote_source: str,
    local_target: Path,
    rsync_bin: str,
    ssh_command: str | None,
    cwd: Path,
) -> dict[str, Any]:
    local_target.parent.mkdir(parents=True, exist_ok=True)
    command = [rsync_bin, "-avz"]
    if ssh_command:
        command.extend(["-e", ssh_command])
    command.extend([remote_source, str(local_target)])
    return run_command(command, cwd)


def materialize_probe_file(
    probe_id: str,
    assignments: dict[str, str],
    root: Path,
    filename: str,
    run_dir: Path,
    rsync_bin: str,
    ssh_command: str | None,
) -> tuple[Path, str, dict[str, Any] | None]:
    assigned = assignments.get(probe_id)
    if assigned and is_remote_path(assigned):
        local_target = (run_dir / "input_snapshots" / probe_id / filename).resolve()
        remote_source = remote_source_for_assignment(assigned, filename)
        result = materialize_remote_file(remote_source, local_target, rsync_bin, ssh_command, root)
        return local_target, f"remote_rsync:{remote_source}", result
    local_path, source = resolve_probe_file(probe_id, assignments, root, filename)
    return local_path, source, None


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


def first_acceptance_value(parsed: dict[str, str], name: str) -> str:
    return parsed.get(name, "")


def load_json_if_exists(path: Path) -> tuple[dict[str, Any], str | None]:
    if not path.is_file():
        return {}, "missing"
    return load_json_object(path)


def is_truthy_text(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "pass", "ok"}


def bool_text(value: Any) -> str:
    return "true" if bool(value) else "false"


def p2_command(
    python_bin: str,
    root: Path,
    records: dict[str, dict[str, Any]],
    out_dir: Path,
    window_size_sec: int,
    max_skew_sec: int,
) -> list[str]:
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


def p3_command(
    python_bin: str,
    root: Path,
    p2_dir: Path,
    out_dir: Path,
    min_consecutive: int,
    max_skew_sec: int,
) -> list[str]:
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


def p4_command(
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


def p6_command(
    python_bin: str,
    root: Path,
    manifest_path: Path,
    out_dir: Path,
    mode: str,
    minio_endpoint: str | None,
    minio_bucket: str,
    compress_jsonl: bool,
) -> list[str]:
    p6_mode = "dry-run" if mode == "dry-run" else "upload"
    command = [
        python_bin,
        str(root / "probe" / "archive_cross_probe_artifacts.py"),
        "--artifact-manifest",
        str(manifest_path),
        "--out-dir",
        str(out_dir),
        "--mode",
        p6_mode,
        "--minio-bucket",
        minio_bucket,
    ]
    if minio_endpoint:
        command.extend(["--minio-endpoint", minio_endpoint])
    if compress_jsonl:
        command.append("--compress-jsonl")
        command.extend(["--compression-format", "gz"])
    return command


def p7_command(
    python_bin: str,
    root: Path,
    archive_report: Path,
    out_dir: Path,
    mc_bin: str,
    sample_download: int,
) -> list[str]:
    return [
        python_bin,
        str(root / "probe" / "verify_minio_cross_probe_archive.py"),
        "--archive-report",
        str(archive_report),
        "--out-dir",
        str(out_dir),
        "--mc-bin",
        mc_bin,
        "--sample-download",
        str(sample_download),
    ]


def no_normalized_vrp_in_manifest(manifest: dict[str, Any]) -> bool:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return False
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        artifact_type = str(artifact.get("artifact_type") or "").lower()
        local_path = str(artifact.get("local_path") or "").replace("\\", "/").lower()
        relative_path = str(artifact.get("relative_path") or "").replace("\\", "/").lower()
        if artifact_type == "normalized_vrp":
            return False
        if "normalized_vrp.jsonl" in local_path or "latest_normalized_vrp.jsonl" in local_path:
            return False
        if "normalized_vrp.jsonl" in relative_path or "latest_normalized_vrp.jsonl" in relative_path:
            return False
    return True


def p6_no_normalized_upload(report: dict[str, Any]) -> bool:
    disallowed = report.get("disallowed_normalized_vrp_count")
    if isinstance(disallowed, int):
        return disallowed == 0
    plan_summary = report.get("plan_summary")
    if isinstance(plan_summary, dict):
        value = plan_summary.get("disallowed_normalized_vrp_count")
        if isinstance(value, int):
            return value == 0
    artifacts = report.get("artifacts")
    if isinstance(artifacts, list):
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                continue
            status = str(artifact.get("upload_status") or "").lower()
            if status not in {"uploaded", "planned", "dry_run"}:
                continue
            path_text = f"{artifact.get('local_path', '')} {artifact.get('relative_path', '')}".lower()
            if "normalized_vrp.jsonl" in path_text or "latest_normalized_vrp.jsonl" in path_text:
                return False
    return True


def root_cause_confirmed_false(*objects: dict[str, Any]) -> bool:
    for obj in objects:
        if not obj:
            continue
        if obj.get("root_cause_confirmed") is True:
            return False
        if str(obj.get("root_cause_confirmed")).strip().lower() == "true":
            return False
    return True


def causal_claim_allowed_zero(*objects: dict[str, Any]) -> bool:
    for obj in objects:
        if not obj:
            continue
        value = obj.get("causal_claim_allowed_count")
        if value is None:
            if obj.get("causal_claim_allowed") is True:
                return False
            continue
        try:
            if int(value) != 0:
                return False
        except (TypeError, ValueError):
            if str(value).strip() not in {"", "0", "0.0", "false", "False"}:
                return False
    return True


def build_acceptance(summary: dict[str, Any]) -> str:
    checks = summary.get("acceptance_checks") if isinstance(summary.get("acceptance_checks"), dict) else {}
    status = "PASS" if checks and all(bool(value) for value in checks.values()) else "FAIL"
    outputs = summary.get("outputs") if isinstance(summary.get("outputs"), dict) else {}
    lines = [
        f"{ACCEPTANCE_NAME}={status}",
        f"run_dir={summary.get('run_dir', '')}",
        f"mode={summary.get('mode', '')}",
        f"probe_ids={','.join(summary.get('probe_ids', []))}",
        f"window_id={summary.get('window_id') or ''}",
        f"window_quality={summary.get('window_quality') or ''}",
        f"capture_time_skew_sec={summary.get('capture_time_skew_sec')}",
        f"max_skew_sec={summary.get('max_skew_sec')}",
        f"p2_run_dir={outputs.get('p2_run_dir', '')}",
        f"p3_run_dir={outputs.get('p3_run_dir', '')}",
        f"p4_run_dir={outputs.get('p4_run_dir', '')}",
        f"p6_run_dir={outputs.get('p6_run_dir', '')}",
        f"p7_run_dir={outputs.get('p7_run_dir', '')}",
        f"artifact_count={summary.get('artifact_count', 0)}",
        f"archive_mode_effective={summary.get('archive_mode_effective', '')}",
        f"upload_attempted={bool_text(summary.get('upload_attempted'))}",
        f"causal_claim_allowed_count={summary.get('causal_claim_allowed_count', 0)}",
        f"root_cause_confirmed={bool_text(summary.get('root_cause_confirmed'))}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={bool_text(value)}" for key, value in checks.items())
    return "\n".join(lines) + "\n"


def run_pipeline(args: argparse.Namespace) -> int:
    root = repo_root()
    started_at = utc_now()
    started_monotonic = time.monotonic()
    probe_ids = parse_probe_ids(args.probe_id_list)
    snapshot_assignments = parse_assignments(args.snapshot, "--snapshot")
    metadata_assignments = parse_assignments(args.metadata, "--metadata")

    run_id = f"cross_probe_archive_{utc_now().replace('-', '').replace(':', '').replace('Z', 'Z')}"
    out_root = resolve_path(args.out_root, root)
    run_dir = out_root / run_id
    p2_dir = run_dir / "p2"
    p3_dir = run_dir / "p3"
    p4_dir = run_dir / "p4"
    p6_dir = run_dir / "p6"
    p7_dir = run_dir / "p7"
    checks_dir = run_dir / "checks"
    for path in (p2_dir, p4_dir, p6_dir, checks_dir):
        path.mkdir(parents=True, exist_ok=True)

    records: dict[str, dict[str, Any]] = {}
    remote_pull_results: list[dict[str, Any]] = []
    for probe_id in probe_ids:
        normalized_path, normalized_source, normalized_pull = materialize_probe_file(
            probe_id,
            snapshot_assignments,
            root,
            LATEST_NORMALIZED,
            run_dir,
            args.rsync_bin,
            args.ssh_command,
        )
        metadata_path, metadata_source, metadata_pull = materialize_probe_file(
            probe_id,
            metadata_assignments,
            root,
            LATEST_METADATA,
            run_dir,
            args.rsync_bin,
            args.ssh_command,
        )
        for label, result in (("snapshot", normalized_pull), ("metadata", metadata_pull)):
            if result is not None:
                remote_pull_results.append({"probe_id": probe_id, "kind": label, **result})
        records[probe_id] = snapshot_record(probe_id, normalized_path, metadata_path, normalized_source, metadata_source)

    skew_sec = capture_time_skew(records)
    commands: dict[str, dict[str, Any]] = {}

    p2_result = run_command(
        p2_command(args.python_bin, root, records, p2_dir, args.window_size_sec, args.max_skew_sec),
        root,
    )
    commands["p2"] = p2_result
    p2_summary, p2_summary_error = load_json_if_exists(p2_dir / "cross_probe_summary.json")
    p2_acceptance = parse_acceptance(p2_dir / "checks" / "P2_CROSS_PROBE_DIFF_ACCEPTANCE.txt")
    p2_window_quality_ok = p2_summary.get("window_quality") == "OK"

    p3_result: dict[str, Any] | None = None
    p3_summary: dict[str, Any] = {}
    p3_summary_error: str | None = "not_run"
    p3_acceptance: dict[str, str] = {}
    p3_ran = False
    if p2_result.get("exit_code") == 0 and p2_window_quality_ok:
        p3_dir.mkdir(parents=True, exist_ok=True)
        p3_result = run_command(
            p3_command(args.python_bin, root, p2_dir, p3_dir, args.min_consecutive, args.max_skew_sec),
            root,
        )
        commands["p3"] = p3_result
        p3_ran = True
        p3_summary, p3_summary_error = load_json_if_exists(p3_dir / "summary.json")
        p3_acceptance = parse_acceptance(p3_dir / "checks" / "P3_CROSS_WINDOW_PERSISTENCE_ACCEPTANCE.txt")

    p4_result: dict[str, Any] | None = None
    p4_manifest: dict[str, Any] = {}
    p4_manifest_error: str | None = "not_run"
    p4_acceptance: dict[str, str] = {}
    p4_p3_dir = p3_dir if p3_ran and (p3_dir / "summary.json").is_file() else None
    if p2_summary:
        p4_result = run_command(
            p4_command(args.python_bin, root, p2_dir, p4_p3_dir, p4_dir, args.minio_bucket, args.minio_prefix),
            root,
        )
        commands["p4"] = p4_result
        p4_manifest, p4_manifest_error = load_json_if_exists(p4_dir / "artifact_manifest.json")
        p4_acceptance = parse_acceptance(p4_dir / "checks" / "P4_CROSS_PROBE_ARTIFACT_MANIFEST_ACCEPTANCE.txt")

    p6_result: dict[str, Any] | None = None
    p6_report: dict[str, Any] = {}
    p6_report_error: str | None = "not_run"
    p6_acceptance: dict[str, str] = {}
    artifact_manifest_path = p4_dir / "artifact_manifest.json"
    if artifact_manifest_path.is_file():
        p6_result = run_command(
            p6_command(
                args.python_bin,
                root,
                artifact_manifest_path,
                p6_dir,
                args.mode,
                args.minio_endpoint,
                args.minio_bucket,
                args.compress_jsonl,
            ),
            root,
        )
        commands["p6"] = p6_result
        p6_report, p6_report_error = load_json_if_exists(p6_dir / "archive_report.json")
        p6_acceptance = parse_acceptance(p6_dir / "checks" / "P6_MINIO_ARCHIVE_ACCEPTANCE.txt")

    p7_result: dict[str, Any] | None = None
    p7_report: dict[str, Any] = {}
    p7_report_error: str | None = "not_run"
    p7_acceptance: dict[str, str] = {}
    p7_required = args.mode in {"upload", "verify"}
    archive_report_path = p6_dir / "archive_report.json"
    if p7_required and archive_report_path.is_file():
        p7_dir.mkdir(parents=True, exist_ok=True)
        p7_result = run_command(
            p7_command(args.python_bin, root, archive_report_path, p7_dir, args.mc_bin, args.sample_download),
            root,
        )
        commands["p7"] = p7_result
        p7_report, p7_report_error = load_json_if_exists(p7_dir / "verify_report.json")
        p7_acceptance = parse_acceptance(p7_dir / "checks" / "P7_MINIO_ARCHIVE_VERIFY_ACCEPTANCE.txt")

    p4_artifacts = p4_manifest.get("artifacts") if isinstance(p4_manifest.get("artifacts"), list) else []
    archive_mode_effective = "dry-run" if args.mode == "dry-run" else "upload"
    p2_acceptance_pass = first_acceptance_value(p2_acceptance, "P2_CROSS_PROBE_DIFF") == "PASS"
    p3_acceptance_pass = (not p3_ran) or first_acceptance_value(p3_acceptance, "P3_CROSS_WINDOW_PERSISTENCE") == "PASS"
    p4_acceptance_pass = first_acceptance_value(p4_acceptance, "P4_CROSS_PROBE_ARTIFACT_MANIFEST") == "PASS"
    p6_acceptance_pass = first_acceptance_value(p6_acceptance, "P6_MINIO_ARCHIVE") == "PASS"
    p7_acceptance_pass = (not p7_required) or first_acceptance_value(p7_acceptance, "P7_MINIO_ARCHIVE_VERIFY") == "PASS"
    p3_requirement_ok = (not p2_window_quality_ok) or p3_ran
    no_normalized_upload = no_normalized_vrp_in_manifest(p4_manifest) and p6_no_normalized_upload(p6_report)
    causal_ok = causal_claim_allowed_zero(p2_summary, p3_summary, p6_report, p7_report)
    root_ok = root_cause_confirmed_false(p2_summary, p3_summary, p6_report, p7_report)

    checks = {
        "probe_id_count_gt_one": len(probe_ids) >= 2,
        "all_snapshots_exist": all(record.get("normalized_exists") for record in records.values()),
        "all_metadata_exist": all(record.get("metadata_exists") for record in records.values()),
        "remote_inputs_materialized": all(result.get("exit_code") == 0 for result in remote_pull_results),
        "metadata_json_ok": all(record.get("metadata_json_ok") for record in records.values()),
        "all_validator_healthy": all(record.get("validator_healthy") for record in records.values()),
        "capture_time_skew_within_threshold": skew_sec is not None and skew_sec <= args.max_skew_sec,
        "p2_exit_zero": p2_result.get("exit_code") == 0,
        "p2_summary_json_ok": bool(p2_summary) and p2_summary_error is None,
        "p2_window_quality_ok": p2_window_quality_ok,
        "p2_acceptance_pass": p2_acceptance_pass,
        "p3_ran_if_p2_ok": p3_requirement_ok,
        "p3_acceptance_pass_or_not_required": p3_acceptance_pass,
        "p4_exit_zero": p4_result is not None and p4_result.get("exit_code") == 0,
        "p4_acceptance_pass": p4_acceptance_pass,
        "p6_exit_zero": p6_result is not None and p6_result.get("exit_code") == 0,
        "p6_acceptance_pass": p6_acceptance_pass,
        "p7_acceptance_pass_or_not_required": p7_acceptance_pass,
        "no_normalized_vrp_upload": no_normalized_upload,
        "causal_claim_allowed_zero": causal_ok,
        "root_cause_confirmed_false": root_ok,
    }

    summary = {
        "schema": SCHEMA_SUMMARY,
        "run_id": run_id,
        "run_dir": str(run_dir),
        "status": "PASS" if all(checks.values()) else "FAIL",
        "mode": args.mode,
        "archive_mode_effective": archive_mode_effective,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "duration_sec": round(time.monotonic() - started_monotonic, 6),
        "probe_ids": probe_ids,
        "probe_records": records,
        "remote_pull_results": remote_pull_results,
        "capture_time_by_probe": {probe_id: record.get("capture_time_utc") for probe_id, record in records.items()},
        "capture_time_skew_sec": skew_sec,
        "max_skew_sec": args.max_skew_sec,
        "window_size_sec": args.window_size_sec,
        "min_consecutive": args.min_consecutive,
        "window_id": p2_summary.get("window_id"),
        "window_quality": p2_summary.get("window_quality"),
        "p2_candidate_event_count": p2_summary.get("candidate_event_count"),
        "p2_event_count": p2_summary.get("event_count"),
        "p3_persistent_event_count": p3_summary.get("persistent_event_count"),
        "p3_semantic_divergence_count": p3_summary.get("semantic_divergence_count"),
        "artifact_count": len(p4_artifacts),
        "upload_attempted": archive_mode_effective == "upload",
        "p6_upload_success_count": p6_report.get("upload_success_count"),
        "p6_upload_failed_count": p6_report.get("upload_failed_count"),
        "p7_stat_failed_count": p7_report.get("stat_failed_count"),
        "p7_size_mismatch_count": p7_report.get("size_mismatch_count"),
        "p7_sample_sha256_mismatch_count": p7_report.get("sample_sha256_mismatch_count"),
        "causal_claim_allowed_count": 0 if causal_ok else "nonzero",
        "root_cause_confirmed": not root_ok,
        "minio_endpoint": args.minio_endpoint or "",
        "minio_bucket": args.minio_bucket,
        "minio_prefix": args.minio_prefix,
        "outputs": {
            "p2_run_dir": str(p2_dir),
            "p3_run_dir": str(p3_dir) if p3_ran else "",
            "p4_run_dir": str(p4_dir) if p4_result else "",
            "p6_run_dir": str(p6_dir) if p6_result else "",
            "p7_run_dir": str(p7_dir) if p7_result else "",
            "pipeline_summary_json": str(run_dir / "pipeline_summary.json"),
            "acceptance_check_file": str(checks_dir / "P8_CROSS_PROBE_PIPELINE_ACCEPTANCE.txt"),
        },
        "stage_summary_errors": {
            "p2_summary": p2_summary_error,
            "p3_summary": p3_summary_error,
            "p4_manifest": p4_manifest_error,
            "p6_report": p6_report_error,
            "p7_report": p7_report_error,
        },
        "acceptance": {
            "p2": p2_acceptance,
            "p3": p3_acceptance,
            "p4": p4_acceptance,
            "p6": p6_acceptance,
            "p7": p7_acceptance,
        },
        "commands": commands,
        "acceptance_checks": checks,
    }
    atomic_write_json(run_dir / "pipeline_summary.json", summary)
    atomic_write_text(checks_dir / "P8_CROSS_PROBE_PIPELINE_ACCEPTANCE.txt", build_acceptance(summary))
    print(str(run_dir), file=sys.stderr)
    return 0 if summary["status"] == "PASS" else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one cross-probe observation archive pipeline: P2 diff, optional P3 persistence, P4 manifest, P6 archive, optional P7 verify.",
    )
    parser.add_argument("--probe-id-list", default="probe-cd,probe-sg,probe-k02", help="Comma-separated probe ids.")
    parser.add_argument("--snapshot", action="append", default=[], help="Probe snapshot assignment: probe_id=path/to/latest_normalized_vrp.jsonl or probe_id=dir. Repeatable.")
    parser.add_argument("--metadata", action="append", default=[], help="Probe metadata assignment: probe_id=path/to/latest_metadata.json or probe_id=dir. Repeatable.")
    parser.add_argument("--out-root", default=DEFAULT_OUT_ROOT)
    parser.add_argument("--minio-endpoint", default=os.environ.get("MINIO_ENDPOINT", ""))
    parser.add_argument("--minio-bucket", default=os.environ.get("MINIO_BUCKET", DEFAULT_MINIO_BUCKET))
    parser.add_argument("--minio-prefix", default=os.environ.get("MINIO_PREFIX", DEFAULT_MINIO_PREFIX))
    parser.add_argument("--max-skew-sec", type=int, default=600)
    parser.add_argument("--window-size-sec", type=int, default=3600)
    parser.add_argument("--min-consecutive", type=int, default=2)
    parser.add_argument("--mode", choices=["dry-run", "upload", "verify"], default="dry-run")
    parser.add_argument("--python-bin", default=sys.executable)
    parser.add_argument("--rsync-bin", default=os.environ.get("RSYNC_BIN", "rsync"), help="rsync binary for rsync-style remote assignments.")
    parser.add_argument("--ssh-command", help="Optional ssh command passed to rsync -e for remote assignments.")
    parser.add_argument("--mc-bin", default="mc", help="MinIO mc CLI path for P7 verification.")
    parser.add_argument("--sample-download", type=int, default=0, help="P7 restore sample count for upload/verify mode.")
    parser.add_argument("--compress-jsonl", action="store_true", help="Pass --compress-jsonl to P6 archive tool.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run_pipeline(args)
    except ValueError as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        return 130
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
