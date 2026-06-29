#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_MANIFEST = "s3.probe.snapshot_checkpoint_manifest.v2"
SCHEMA_REPORT = "s3.probe.snapshot_checkpoint_archive_report.v2"
DEFAULT_SNAPSHOT_ROOT = "data/probe/live_vrp_snapshots"
DEFAULT_MINIO_PREFIX = "rp-monitor"
LATEST_METADATA = "latest_metadata.json"
LATEST_NORMALIZED = "latest_normalized_vrp.jsonl"


def utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


def utc_now() -> str:
    return utc_now_dt().replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def resolve_path(value: str, root: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()


def resolve_probe_dir(snapshot_root: Path, probe_id: str) -> Path:
    if (snapshot_root / LATEST_METADATA).is_file() or (snapshot_root / LATEST_NORMALIZED).is_file():
        return snapshot_root
    if snapshot_root.name == probe_id:
        return snapshot_root
    return snapshot_root / probe_id


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


def load_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def gzip_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(f"{dst.name}.tmp.{os.getpid()}.{time.time_ns()}")
    try:
        with src.open("rb") as fin, tmp.open("wb") as raw_out, gzip.GzipFile(fileobj=raw_out, mode="wb", compresslevel=6, mtime=0) as fout:
            shutil.copyfileobj(fin, fout, length=1024 * 1024)
        os.replace(tmp, dst)
        fsync_parent(dst)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def minio_key(prefix: str, probe_id: str, capture_time: datetime | None, filename: str) -> str:
    date_text = capture_time.date().isoformat() if capture_time is not None else utc_now_dt().date().isoformat()
    base = "/".join(part for part in prefix.strip("/").split("/") if part)
    suffix = f"snapshot_checkpoints/probe_id={probe_id}/date={date_text}/{filename}"
    return f"{base}/{suffix}" if base else suffix


def run_command(command: list[str]) -> dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.run(command, text=True, capture_output=True)
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


def upload_and_stat(local_path: Path, key: str, alias: str, bucket: str, mc_bin: str) -> tuple[dict[str, Any], dict[str, Any]]:
    target = f"{alias}/{bucket}/{key}"
    upload = {"local_path": str(local_path), "object_key": key, "target": target, **run_command([mc_bin, "cp", str(local_path), target])}
    if upload.get("exit_code") == 0:
        stat = {"local_path": str(local_path), "object_key": key, "target": target, **run_command([mc_bin, "stat", target])}
    else:
        stat = {
            "local_path": str(local_path),
            "object_key": key,
            "target": target,
            "command": [mc_bin, "stat", target],
            "exit_code": 99,
            "stdout_tail": "",
            "stderr_tail": "skipped because upload failed",
            "duration_sec": 0,
        }
    return upload, stat


def bool_text(value: Any) -> str:
    return "true" if bool(value) else "false"


def write_acceptance(out_dir: Path, report: dict[str, Any]) -> None:
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
    status = str(report.get("status") or ("PASS" if checks and all(bool(value) for value in checks.values()) else "FAIL"))
    lines = [
        f"P9_SNAPSHOT_CHECKPOINT={status}",
        f"probe_id={report.get('probe_id', '')}",
        f"probe_dir={report.get('probe_dir', '')}",
        f"skip_reason={report.get('skip_reason', '')}",
        f"checkpoint_enabled={bool_text(report.get('checkpoint_enabled'))}",
        f"upload_requested={bool_text(report.get('upload_requested'))}",
        f"allow_large_snapshot_upload={bool_text(report.get('allow_large_snapshot_upload'))}",
        f"large_snapshot_upload_attempted={bool_text(report.get('large_snapshot_upload_attempted'))}",
        f"upload_success_count={report.get('upload_success_count', 0)}",
        f"stat_failed_count={report.get('stat_failed_count', 0)}",
        f"checkpoint_manifest_json={out_dir / 'checkpoint_manifest.json'}",
        f"checkpoint_archive_report_json={out_dir / 'checkpoint_archive_report.json'}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={bool_text(value)}" for key, value in checks.items())
    atomic_write_text(out_dir / "checks" / "P9_SNAPSHOT_CHECKPOINT_ACCEPTANCE.txt", "\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and optionally upload an explicit latest_normalized_vrp snapshot checkpoint.")
    parser.add_argument("--probe-id", required=True)
    parser.add_argument("--snapshot-root", default=DEFAULT_SNAPSHOT_ROOT)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--checkpoint", action="store_true", help="Enable processing latest_normalized_vrp.jsonl. Default is off.")
    parser.add_argument("--gzip", action="store_true", help="Compress latest_normalized_vrp.jsonl before checkpoint upload.")
    parser.add_argument("--upload-minio", action="store_true")
    parser.add_argument("--allow-large-snapshot-upload", action="store_true")
    parser.add_argument("--mc-bin", default="mc")
    parser.add_argument("--minio-alias", default=os.environ.get("MINIO_ALIAS", ""))
    parser.add_argument("--minio-bucket", default=os.environ.get("MINIO_BUCKET", ""))
    parser.add_argument("--minio-prefix", default=os.environ.get("MINIO_PREFIX", DEFAULT_MINIO_PREFIX))
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = repo_root()
    snapshot_root = resolve_path(args.snapshot_root, root)
    out_dir = resolve_path(args.out_dir, root)
    files_dir = out_dir / "files"
    out_dir.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()

    probe_dir = resolve_probe_dir(snapshot_root, args.probe_id)
    metadata_path = probe_dir / LATEST_METADATA
    normalized_path = probe_dir / LATEST_NORMALIZED
    metadata = load_json_object(metadata_path)
    capture_time = parse_iso_datetime(metadata.get("capture_time_utc"))
    if capture_time is None and isinstance(metadata.get("raw_metadata"), dict):
        capture_time = parse_iso_datetime(metadata["raw_metadata"].get("generatedTime"))
    snapshot_id = str(metadata.get("snapshot_id") or "latest")

    missing_inputs: list[str] = []
    if args.checkpoint and not metadata_path.is_file():
        missing_inputs.append(str(metadata_path))
    if args.checkpoint and not normalized_path.is_file():
        missing_inputs.append(str(normalized_path))

    checkpoint_artifact: dict[str, Any] | None = None
    metadata_artifact: dict[str, Any] | None = None
    errors: list[str] = []
    if args.checkpoint and not missing_inputs:
        if not normalized_path.is_file():
            errors.append(f"missing latest normalized VRP: {normalized_path}")
        else:
            checkpoint_path = files_dir / (LATEST_NORMALIZED + ".gz" if args.gzip else LATEST_NORMALIZED)
            if args.gzip:
                gzip_copy(normalized_path, checkpoint_path)
                compression = "gz"
            else:
                checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(normalized_path, checkpoint_path)
                compression = ""
            checkpoint_artifact = {
                "artifact_type": "latest_normalized_vrp_checkpoint",
                "probe_id": args.probe_id,
                "snapshot_id": snapshot_id,
                "capture_time_utc": iso_z(capture_time),
                "source_path": str(normalized_path),
                "local_path": str(checkpoint_path),
                "filename": checkpoint_path.name,
                "compression": compression,
                "size_bytes": normalized_path.stat().st_size,
                "sha256": sha256_file(normalized_path),
                "archive_size_bytes": checkpoint_path.stat().st_size,
                "archive_sha256": sha256_file(checkpoint_path),
                "suggested_minio_key": minio_key(args.minio_prefix, args.probe_id, capture_time, checkpoint_path.name),
            }
        if metadata_path.is_file():
            metadata_copy = files_dir / LATEST_METADATA
            metadata_copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(metadata_path, metadata_copy)
            metadata_artifact = {
                "artifact_type": "latest_metadata_checkpoint",
                "probe_id": args.probe_id,
                "snapshot_id": snapshot_id,
                "capture_time_utc": iso_z(capture_time),
                "source_path": str(metadata_path),
                "local_path": str(metadata_copy),
                "filename": metadata_copy.name,
                "compression": "",
                "size_bytes": metadata_copy.stat().st_size,
                "sha256": sha256_file(metadata_copy),
                "archive_size_bytes": metadata_copy.stat().st_size,
                "archive_sha256": sha256_file(metadata_copy),
                "suggested_minio_key": minio_key(args.minio_prefix, args.probe_id, capture_time, metadata_copy.name),
            }
    artifacts = [artifact for artifact in (checkpoint_artifact, metadata_artifact) if artifact is not None]

    manifest = {
        "schema": SCHEMA_MANIFEST,
        "status": "SKIPPED" if missing_inputs else "PENDING",
        "probe_id": args.probe_id,
        "snapshot_root": str(snapshot_root),
        "probe_dir": str(probe_dir),
        "snapshot_id": snapshot_id,
        "capture_time_utc": iso_z(capture_time),
        "checkpoint_enabled": args.checkpoint,
        "gzip_enabled": args.gzip,
        "latest_normalized_vrp": str(normalized_path),
        "latest_metadata": str(metadata_path),
        "sha256": checkpoint_artifact.get("sha256") if checkpoint_artifact else "",
        "size_bytes": checkpoint_artifact.get("size_bytes") if checkpoint_artifact else 0,
        "archive_sha256": checkpoint_artifact.get("archive_sha256") if checkpoint_artifact else "",
        "archive_size_bytes": checkpoint_artifact.get("archive_size_bytes") if checkpoint_artifact else 0,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "missing_inputs": missing_inputs,
        "skipped": bool(missing_inputs),
        "skip_reason": "missing_checkpoint_inputs" if missing_inputs else "",
        "minio_alias": args.minio_alias,
        "minio_bucket": args.minio_bucket,
        "minio_prefix": args.minio_prefix,
        "errors": errors,
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
        "created_at_utc": started_at,
    }
    manifest_path = out_dir / "checkpoint_manifest.json"
    atomic_write_json(manifest_path, manifest)

    upload_results: list[dict[str, Any]] = []
    stat_results: list[dict[str, Any]] = []
    upload_preflight_error = ""
    large_snapshot_upload_attempted = False
    large_snapshot_upload_blocked = False
    if args.upload_minio and not missing_inputs:
        if not args.minio_alias or not args.minio_bucket:
            upload_preflight_error = "MINIO_ALIAS and MINIO_BUCKET are required for --upload-minio"
        elif not args.checkpoint:
            upload_preflight_error = "--checkpoint is required before snapshot checkpoint upload"
        elif checkpoint_artifact is None:
            upload_preflight_error = "no checkpoint artifact available for upload"
        elif not args.allow_large_snapshot_upload:
            large_snapshot_upload_blocked = True
            upload_preflight_error = "--allow-large-snapshot-upload is required to upload latest_normalized_vrp checkpoint"
        else:
            for artifact in artifacts:
                local_path = Path(str(artifact["local_path"]))
                key = str(artifact["suggested_minio_key"])
                if artifact.get("artifact_type") == "latest_normalized_vrp_checkpoint":
                    large_snapshot_upload_attempted = True
                upload, stat = upload_and_stat(local_path, key, args.minio_alias, args.minio_bucket, args.mc_bin)
                upload_results.append(upload)
                stat_results.append(stat)

    upload_success_count = sum(1 for item in upload_results if item.get("exit_code") == 0)
    upload_failed_count = (1 if upload_preflight_error else 0) + sum(1 for item in upload_results if item.get("exit_code") != 0)
    stat_success_count = sum(1 for item in stat_results if item.get("exit_code") == 0)
    stat_failed_count = (1 if upload_preflight_error else 0) + sum(1 for item in stat_results if item.get("exit_code") != 0)
    skipped = bool(missing_inputs)
    checks = {
        "manifest_json_ok": True,
        "missing_inputs_empty": not missing_inputs,
        "checkpoint_off_is_noop": args.checkpoint or not artifacts,
        "checkpoint_artifact_exists_if_enabled": (not args.checkpoint) or checkpoint_artifact is not None,
        "upload_success_if_requested": (not args.upload_minio) or (upload_success_count == len(artifacts) and upload_failed_count == 0),
        "minio_stat_ok_if_uploaded": (not args.upload_minio) or (stat_success_count == len(artifacts) and stat_failed_count == 0),
        "no_large_snapshot_upload_without_explicit_allow": (not large_snapshot_upload_attempted) or args.allow_large_snapshot_upload,
    }
    if skipped:
        checks["checkpoint_artifact_exists_if_enabled"] = False
        checks["upload_success_if_requested"] = True
        checks["minio_stat_ok_if_uploaded"] = True
    status = "SKIPPED" if skipped else ("PASS" if all(checks.values()) else "FAIL")
    manifest["status"] = status
    atomic_write_json(manifest_path, manifest)
    report = {
        "schema": SCHEMA_REPORT,
        "status": status,
        "probe_id": args.probe_id,
        "snapshot_root": str(snapshot_root),
        "probe_dir": str(probe_dir),
        "snapshot_id": snapshot_id,
        "capture_time_utc": iso_z(capture_time),
        "skipped": skipped,
        "skip_reason": "missing_checkpoint_inputs" if skipped else "",
        "missing_inputs": missing_inputs,
        "checkpoint_enabled": args.checkpoint,
        "gzip_enabled": args.gzip,
        "upload_requested": args.upload_minio,
        "allow_large_snapshot_upload": args.allow_large_snapshot_upload,
        "large_snapshot_upload_attempted": large_snapshot_upload_attempted,
        "large_snapshot_upload_blocked": large_snapshot_upload_blocked,
        "upload_preflight_error": upload_preflight_error,
        "artifact_count": len(artifacts),
        "upload_success_count": upload_success_count,
        "upload_failed_count": upload_failed_count,
        "stat_success_count": stat_success_count,
        "stat_failed_count": stat_failed_count,
        "upload_results": upload_results,
        "stat_results": stat_results,
        "manifest_path": str(manifest_path),
        "minio_alias": args.minio_alias,
        "minio_bucket": args.minio_bucket,
        "minio_prefix": args.minio_prefix,
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "checks": checks,
    }
    atomic_write_json(out_dir / "checkpoint_archive_report.json", report)
    write_acceptance(out_dir, report)
    return 0 if status in {"PASS", "SKIPPED"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
