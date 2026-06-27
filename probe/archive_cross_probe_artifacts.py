#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_PLAN = "s3.probe.cross_probe_minio_archive_plan.v1"
SCHEMA_REPORT = "s3.probe.cross_probe_minio_archive_report.v1"
OUTPUT_PLAN = "archive_plan.json"
OUTPUT_REPORT = "archive_report.json"
OUTPUT_ACCEPTANCE = "P6_MINIO_ARCHIVE_ACCEPTANCE.txt"
DEFAULT_ACCESS_KEY_ENV = "MINIO_ACCESS_KEY"
DEFAULT_SECRET_KEY_ENV = "MINIO_SECRET_KEY"
DEFAULT_ALIAS = "rp-monitor-p6"


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


def load_json_object(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise RuntimeError(f"expected JSON object at {path}")
    return obj


def as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def normalize_sha256(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if text.startswith("sha256:"):
        return text
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return "sha256:" + text
    return text


def resolve_local_path(raw_path: Any, manifest_path: Path) -> Path:
    text = str(raw_path or "").strip()
    if not text:
        return Path("")
    path = Path(text)
    if path.is_absolute():
        return path
    return (manifest_path.parent / path).resolve()


def is_normalized_vrp_path(value: Any) -> bool:
    text = str(value or "").replace("\\", "/").lower()
    return "normalized_vrp.jsonl" in text or "latest_normalized_vrp.jsonl" in text


def is_disallowed_normalized_artifact(artifact: dict[str, Any]) -> bool:
    artifact_type = str(artifact.get("artifact_type") or "").lower()
    path_like = " ".join(
        str(artifact.get(key) or "")
        for key in ("local_path", "relative_path", "suggested_minio_key")
    )
    if not is_normalized_vrp_path(path_like):
        return False
    return "normalized_vrp" in artifact_type or artifact_type in {"normalized", "latest_normalized"}


def safe_path_part(value: Any, fallback: str) -> str:
    text = str(value or "").strip() or fallback
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    return text.strip("._-") or fallback


def manifest_bucket(manifest: dict[str, Any], args: argparse.Namespace) -> str:
    if args.minio_bucket:
        return args.minio_bucket
    minio = manifest.get("minio") if isinstance(manifest.get("minio"), dict) else {}
    return str(minio.get("bucket") or "")


def minio_key(artifact: dict[str, Any], manifest: dict[str, Any]) -> str:
    suggested = str(artifact.get("suggested_minio_key") or "").replace("\\", "/").strip("/")
    if suggested:
        return suggested
    minio = manifest.get("minio") if isinstance(manifest.get("minio"), dict) else {}
    prefix = str(minio.get("prefix") or "").strip("/")
    relative_path = str(artifact.get("relative_path") or "").replace("\\", "/").strip("/")
    return "/".join(part for part in (prefix, relative_path) if part)


def verify_artifact(artifact: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    local_path = resolve_local_path(artifact.get("local_path"), manifest_path)
    expected_size = as_int(artifact.get("size_bytes"))
    expected_sha256 = normalize_sha256(artifact.get("sha256"))
    result: dict[str, Any] = {
        "local_path": str(local_path) if str(local_path) else "",
        "expected_size_bytes": expected_size,
        "expected_sha256": expected_sha256,
        "exists": False,
        "actual_size_bytes": None,
        "actual_sha256": "",
        "size_match": False,
        "sha256_match": False,
        "verified": False,
        "errors": [],
    }
    errors: list[str] = []
    if not str(local_path) or not local_path.is_file():
        errors.append("local_path_missing")
        result["errors"] = errors
        return result
    actual_size = local_path.stat().st_size
    actual_sha256 = sha256_file(local_path)
    size_match = expected_size == actual_size
    sha256_match = expected_sha256 == actual_sha256
    if not size_match:
        errors.append("size_mismatch")
    if not expected_sha256:
        errors.append("expected_sha256_missing")
    elif not sha256_match:
        errors.append("sha256_mismatch")
    result.update(
        {
            "exists": True,
            "actual_size_bytes": actual_size,
            "actual_sha256": actual_sha256,
            "size_match": size_match,
            "sha256_match": sha256_match,
            "verified": size_match and sha256_match,
            "errors": errors,
        }
    )
    return result


def compression_needed(artifact: dict[str, Any], args: argparse.Namespace) -> bool:
    if not args.compress_jsonl:
        return False
    relative_path = str(artifact.get("relative_path") or artifact.get("local_path") or "").lower()
    return relative_path.endswith(".jsonl") and not relative_path.endswith(".jsonl.gz")


def compressed_path(out_dir: Path, index: int, artifact: dict[str, Any], sha256_value: str) -> Path:
    digest = sha256_value.removeprefix("sha256:")[:16] or f"{index:06d}"
    name = safe_path_part(Path(str(artifact.get("relative_path") or artifact.get("local_path") or "artifact")).name, "artifact")
    return out_dir / "staging" / f"{index:06d}_{digest}_{name}.gz"


def gzip_compress(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f"{target.name}.tmp.{os.getpid()}.{time.time_ns()}")
    try:
        with source.open("rb") as src, tmp.open("wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=6) as gz:
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    gz.write(chunk)
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(tmp, target)
        fsync_parent(target)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def build_plan(args: argparse.Namespace, manifest: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    bucket = manifest_bucket(manifest, args)
    planned: list[dict[str, Any]] = []
    for index, artifact in enumerate(artifacts, 1):
        if not isinstance(artifact, dict):
            artifact = {"raw_artifact": artifact}
        validation = verify_artifact(artifact, manifest_path)
        disallowed_normalized = is_disallowed_normalized_artifact(artifact)
        compress = compression_needed(artifact, args)
        key = minio_key(artifact, manifest)
        if compress and not key.endswith(".gz"):
            key = key + ".gz"
        archive_local_path = validation["local_path"]
        archive_size = validation["actual_size_bytes"]
        archive_sha256 = validation["actual_sha256"]
        if compress:
            archive_local_path = ""
            archive_size = None
            archive_sha256 = ""
        upload_status = "dry_run_planned" if args.mode == "dry-run" else "pending"
        upload_error = ""
        if disallowed_normalized:
            upload_status = "skipped_disallowed_normalized_vrp"
            upload_error = "normalized_vrp artifact_type is not uploaded by default"
        elif not validation["verified"]:
            upload_status = "skipped_validation_failed"
            upload_error = ",".join(validation["errors"])
        planned.append(
            {
                "artifact_index": index,
                "artifact_type": artifact.get("artifact_type"),
                "relative_path": artifact.get("relative_path"),
                "source_local_path": validation["local_path"],
                "source_size_bytes": validation["actual_size_bytes"],
                "source_sha256": validation["actual_sha256"],
                "validation": validation,
                "verified": validation["verified"],
                "disallowed_normalized_vrp": disallowed_normalized,
                "compression": {
                    "enabled": compress,
                    "format": args.compression_format if compress else None,
                    "materialized": False,
                },
                "archive_local_path": archive_local_path,
                "archive_size_bytes": archive_size,
                "archive_sha256": archive_sha256,
                "minio_bucket": bucket,
                "minio_key": key,
                "mc_target": f"{DEFAULT_ALIAS}/{bucket}/{key}" if bucket and key else "",
                "upload_status": upload_status,
                "upload_error": upload_error,
                "mc_stat": None,
            }
        )
    return {
        "schema": SCHEMA_PLAN,
        "generated_at_utc": utc_now(),
        "mode": args.mode,
        "artifact_manifest": str(manifest_path),
        "compression": {
            "compress_jsonl": bool(args.compress_jsonl),
            "compression_format": args.compression_format,
        },
        "minio": {
            "endpoint": args.minio_endpoint,
            "bucket": bucket,
            "alias": DEFAULT_ALIAS,
        },
        "artifact_count": len(planned),
        "artifacts": planned,
    }


def run_command(command: list[str]) -> dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.run(command, text=True, capture_output=True)
        return {
            "command": command,
            "exit_code": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-4000:],
            "duration_sec": round(time.monotonic() - started, 6),
        }
    except FileNotFoundError as exc:
        return {
            "command": command,
            "exit_code": 127,
            "stdout": "",
            "stderr": str(exc),
            "duration_sec": round(time.monotonic() - started, 6),
        }


def parse_mc_stat(stdout: str) -> dict[str, Any]:
    text = stdout.strip()
    if not text:
        return {}
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return {
                "raw": obj,
                "size": obj.get("size") or obj.get("Size"),
                "etag": obj.get("etag") or obj.get("ETag"),
                "metadata": obj.get("metadata") or obj.get("Metadata"),
            }
    except json.JSONDecodeError:
        pass
    return {"raw_text": text[-4000:]}


def ensure_mc_available() -> str:
    mc_path = shutil.which("mc")
    if not mc_path:
        raise RuntimeError("upload mode requires MinIO mc CLI, but 'mc' was not found in PATH")
    return mc_path


def materialize_archive(item: dict[str, Any], args: argparse.Namespace, out_dir: Path) -> None:
    compression = item.get("compression") if isinstance(item.get("compression"), dict) else {}
    if not compression.get("enabled"):
        return
    source = Path(str(item.get("source_local_path") or ""))
    target = compressed_path(out_dir, int(item["artifact_index"]), {"relative_path": item.get("relative_path")}, str(item.get("source_sha256") or ""))
    gzip_compress(source, target)
    item["archive_local_path"] = str(target)
    item["archive_size_bytes"] = target.stat().st_size
    item["archive_sha256"] = sha256_file(target)
    compression["materialized"] = True
    item["compression"] = compression


def perform_uploads(args: argparse.Namespace, plan: dict[str, Any], out_dir: Path) -> str:
    if args.mode != "upload":
        return ""
    try:
        mc_path = ensure_mc_available()
    except RuntimeError as exc:
        error = str(exc)
        for item in plan["artifacts"]:
            if item.get("upload_status") == "pending":
                item["upload_status"] = "upload_failed"
                item["upload_error"] = error
        return error

    endpoint = args.minio_endpoint
    bucket = str((plan.get("minio") or {}).get("bucket") or "")
    access_key = os.environ.get(args.access_key_env)
    secret_key = os.environ.get(args.secret_key_env)
    setup_error = ""
    if not endpoint:
        setup_error = "--minio-endpoint is required in upload mode"
    elif not bucket:
        setup_error = "MinIO bucket is required in upload mode"
    elif not access_key:
        setup_error = f"missing access key env var: {args.access_key_env}"
    elif not secret_key:
        setup_error = f"missing secret key env var: {args.secret_key_env}"
    if setup_error:
        for item in plan["artifacts"]:
            if item.get("upload_status") == "pending":
                item["upload_status"] = "upload_failed"
                item["upload_error"] = setup_error
        return setup_error

    alias_result = run_command([mc_path, "alias", "set", DEFAULT_ALIAS, endpoint, access_key, secret_key])
    plan["mc_alias_set"] = alias_result
    if alias_result["exit_code"] != 0:
        setup_error = "mc alias set failed: " + (alias_result.get("stderr") or alias_result.get("stdout") or "")
        for item in plan["artifacts"]:
            if item.get("upload_status") == "pending":
                item["upload_status"] = "upload_failed"
                item["upload_error"] = setup_error
        return setup_error

    for item in plan["artifacts"]:
        if item.get("upload_status") != "pending":
            continue
        try:
            materialize_archive(item, args, out_dir)
            source = Path(str(item.get("archive_local_path") or ""))
            if not source.is_file():
                item["upload_status"] = "upload_failed"
                item["upload_error"] = "archive_local_path_missing"
                continue
            target = str(item.get("mc_target") or "")
            cp_result = run_command([mc_path, "cp", str(source), target])
            item["mc_cp"] = cp_result
            if cp_result["exit_code"] != 0:
                item["upload_status"] = "upload_failed"
                item["upload_error"] = "mc cp failed: " + (cp_result.get("stderr") or cp_result.get("stdout") or "")
                continue
            stat_result = run_command([mc_path, "stat", "--json", target])
            item["mc_stat_command"] = stat_result
            item["mc_stat"] = parse_mc_stat(stat_result.get("stdout") or "") if stat_result["exit_code"] == 0 else {
                "error": stat_result.get("stderr") or stat_result.get("stdout") or "mc stat failed"
            }
            item["upload_status"] = "uploaded"
            item["upload_error"] = ""
        except Exception as exc:
            item["upload_status"] = "upload_failed"
            item["upload_error"] = str(exc)
    return ""


def json_file_ok(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            json.load(f)
        return True
    except Exception:
        return False


def build_report(plan: dict[str, Any], report_path: Path, upload_setup_error: str, started_at: str) -> dict[str, Any]:
    artifacts = plan.get("artifacts") if isinstance(plan.get("artifacts"), list) else []
    artifact_count = len(artifacts)
    verified_count = sum(1 for item in artifacts if item.get("verified"))
    disallowed_normalized_count = sum(1 for item in artifacts if item.get("disallowed_normalized_vrp"))
    upload_attempted = plan.get("mode") == "upload"
    upload_success_count = sum(1 for item in artifacts if item.get("upload_status") == "uploaded")
    upload_failed_count = sum(1 for item in artifacts if item.get("upload_status") == "upload_failed")
    skipped_count = sum(1 for item in artifacts if str(item.get("upload_status") or "").startswith("skipped_"))
    total_input_bytes = sum(as_int(item.get("source_size_bytes")) or 0 for item in artifacts)
    total_archive_bytes = sum(
        as_int(item.get("archive_size_bytes")) if as_int(item.get("archive_size_bytes")) is not None else (as_int(item.get("source_size_bytes")) or 0)
        for item in artifacts
        if item.get("verified") and not item.get("disallowed_normalized_vrp")
    )
    minio = plan.get("minio") if isinstance(plan.get("minio"), dict) else {}
    finished_at = utc_now()
    checks = {
        "artifact_count_gt_zero": artifact_count > 0,
        "all_artifacts_verified": verified_count == artifact_count and artifact_count > 0,
        "no_normalized_vrp_by_default": disallowed_normalized_count == 0,
        "upload_failed_count_zero": upload_failed_count == 0,
        "archive_report_json_ok": json_file_ok(report_path) if report_path.exists() else True,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    return {
        "schema": SCHEMA_REPORT,
        "status": status,
        "mode": plan.get("mode"),
        "artifact_manifest": plan.get("artifact_manifest"),
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "artifact_count": artifact_count,
        "verified_artifact_count": verified_count,
        "disallowed_normalized_vrp_count": disallowed_normalized_count,
        "skipped_artifact_count": skipped_count,
        "upload_attempted": upload_attempted,
        "upload_setup_error": upload_setup_error,
        "upload_success_count": upload_success_count,
        "upload_failed_count": upload_failed_count,
        "total_input_bytes": total_input_bytes,
        "total_archive_bytes": total_archive_bytes,
        "minio_endpoint": minio.get("endpoint") or "",
        "minio_bucket": minio.get("bucket") or "",
        "checks": checks,
    }


def acceptance_text(report: dict[str, Any]) -> str:
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
    lines = [
        f"P6_MINIO_ARCHIVE={report.get('status')}",
        f"artifact_count={report.get('artifact_count')}",
        f"verified_artifact_count={report.get('verified_artifact_count')}",
        f"disallowed_normalized_vrp_count={report.get('disallowed_normalized_vrp_count')}",
        f"upload_attempted={bool_text(bool(report.get('upload_attempted')))}",
        f"upload_success_count={report.get('upload_success_count')}",
        f"upload_failed_count={report.get('upload_failed_count')}",
        f"total_input_bytes={report.get('total_input_bytes')}",
        f"total_archive_bytes={report.get('total_archive_bytes')}",
        f"minio_endpoint={report.get('minio_endpoint') or ''}",
        f"minio_bucket={report.get('minio_bucket') or ''}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={bool_text(bool(value))}" for key, value in checks.items())
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> dict[str, Any]:
    started_at = utc_now()
    out_dir = Path(args.out_dir).resolve()
    manifest_path = Path(args.artifact_manifest).resolve()
    plan_path = out_dir / OUTPUT_PLAN
    report_path = out_dir / OUTPUT_REPORT
    acceptance_path = out_dir / "checks" / OUTPUT_ACCEPTANCE

    manifest = load_json_object(manifest_path)
    plan = build_plan(args, manifest, manifest_path)
    upload_setup_error = perform_uploads(args, plan, out_dir)

    atomic_write_json(plan_path, plan)
    report = build_report(plan, report_path, upload_setup_error, started_at)
    atomic_write_json(report_path, report)
    report["checks"]["archive_report_json_ok"] = json_file_ok(report_path)
    report["status"] = "PASS" if all(report["checks"].values()) else "FAIL"
    atomic_write_json(report_path, report)
    atomic_write_text(acceptance_path, acceptance_text(report))
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Dry-run or upload P4 cross-probe artifacts to MinIO using the mc CLI.")
    parser.add_argument("--artifact-manifest", required=True, help="P4 artifact_manifest.json.")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--mode", choices=["dry-run", "upload"], default="dry-run")
    parser.add_argument("--minio-endpoint", help="MinIO endpoint URL. Required for upload mode.")
    parser.add_argument("--minio-bucket", help="Override bucket from manifest.")
    parser.add_argument("--access-key-env", default=DEFAULT_ACCESS_KEY_ENV)
    parser.add_argument("--secret-key-env", default=DEFAULT_SECRET_KEY_ENV)
    parser.add_argument("--compress-jsonl", action="store_true")
    parser.add_argument("--compression-format", choices=["gz"], default="gz")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = run(args)
    return 0 if report.get("status") == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
