#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_PLAN = "s3.probe.live_msal_cycle_archive_plan.v1"
SCHEMA_REPORT = "s3.probe.live_msal_cycle_archive_report.v1"
SCHEMA_DB_INDEX = "s3.probe.live_msal_cycle_archive_index_preview.v1"
OUTPUT_PLAN = "archive_plan.json"
OUTPUT_REPORT = "archive_report.json"
OUTPUT_DB_INDEX = "db_rows_archive_index.json"
OUTPUT_ACCEPTANCE = "E5_ARTIFACT_ARCHIVE_ACCEPTANCE.txt"


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


def atomic_write_json(path: Path, obj: Any) -> None:
    data = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    atomic_write_bytes(path, data.encode("utf-8"))


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


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


def safe_key_part(value: Any, fallback: str) -> str:
    text = str(value or "").strip() or fallback
    text = text.replace("\\", "/").strip("/")
    text = re.sub(r"[^A-Za-z0-9._=:/-]+", "_", text)
    return text or fallback


def safe_filename_part(value: str, fallback: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())[:80].strip("._-")
    return text or fallback


def resolve_local_path(raw_path: Any, manifest_path: Path) -> Path:
    path_text = str(raw_path or "").strip()
    if not path_text:
        return Path("")
    path = Path(path_text)
    if path.is_absolute():
        return path
    return (manifest_path.parent / path).resolve()


def build_minio_run_prefix(minio_prefix: str, probe_id: str, run_id: str) -> str:
    base_parts = [part for part in minio_prefix.strip("/").split("/") if part]
    probe_segment = f"probe_id={probe_id}"
    run_segment = f"run_id={run_id}"
    if base_parts and base_parts[-1] == run_segment:
        return "/".join(base_parts)
    if base_parts and base_parts[-1] == probe_segment:
        return "/".join([*base_parts, run_segment])
    return "/".join([*base_parts, probe_segment, run_segment])


def minio_key_for_artifact(artifact: dict[str, Any], args: argparse.Namespace, manifest: dict[str, Any]) -> str:
    relative_path = str(artifact.get("relative_path") or "").replace("\\", "/").strip("/")
    metadata = manifest.get("cycle_metadata") if isinstance(manifest.get("cycle_metadata"), dict) else {}
    if args.minio_prefix:
        probe_id = safe_key_part(metadata.get("probe_id"), "unknown_probe")
        run_id = safe_key_part(metadata.get("run_id"), "unknown_run")
        return f"{build_minio_run_prefix(args.minio_prefix, probe_id, run_id)}/{relative_path}"

    suggested = str(artifact.get("suggested_minio_key") or "").replace("\\", "/").strip("/")
    if suggested:
        return suggested

    minio = manifest.get("minio") if isinstance(manifest.get("minio"), dict) else {}
    prefix = str(minio.get("prefix") or "").strip("/")
    probe_id = safe_key_part(metadata.get("probe_id"), "unknown_probe")
    run_id = safe_key_part(metadata.get("run_id"), "unknown_run")
    return f"{build_minio_run_prefix(prefix, probe_id, run_id)}/{relative_path}"


def compression_needed(artifact: dict[str, Any], args: argparse.Namespace) -> bool:
    relative_path = str(artifact.get("relative_path") or "").lower()
    if relative_path.endswith((".gz", ".zst")):
        return False
    if args.compress_jsonl and relative_path.endswith(".jsonl"):
        return True
    if args.compress_json and relative_path.endswith(".json"):
        return True
    return False


def compression_suffix(args: argparse.Namespace) -> str:
    return ".zst" if args.compression_format == "zst" else ".gz"


def archive_key_with_compression(base_key: str, args: argparse.Namespace, should_compress: bool) -> str:
    if not should_compress:
        return base_key
    suffix = compression_suffix(args)
    if base_key.endswith(suffix):
        return base_key
    return base_key + suffix


def compressed_output_path(out_dir: Path, index: int, artifact: dict[str, Any], source_sha256: str, args: argparse.Namespace) -> Path:
    digest = source_sha256.removeprefix("sha256:")[:16] or f"{index:06d}"
    basename = safe_filename_part(Path(str(artifact.get("relative_path") or "artifact")).name, "artifact")
    return out_dir / "compressed" / f"{index:06d}_{digest}_{basename}{compression_suffix(args)}"


def gzip_compress_file(source: Path, target: Path) -> None:
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


def zstd_compress_file(source: Path, target: Path) -> None:
    try:
        import zstandard as zstd  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("zstd compression requires the optional 'zstandard' Python package") from exc

    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f"{target.name}.tmp.{os.getpid()}.{time.time_ns()}")
    try:
        compressor = zstd.ZstdCompressor(level=3)
        with source.open("rb") as src, tmp.open("wb") as raw:
            compressor.copy_stream(src, raw)
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


def compress_file(source: Path, target: Path, args: argparse.Namespace) -> None:
    if args.compression_format == "zst":
        zstd_compress_file(source, target)
    else:
        gzip_compress_file(source, target)


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
        "validation_errors": [],
    }

    errors: list[str] = []
    if not str(local_path) or not local_path.is_file():
        errors.append("missing_local_path")
        result["validation_errors"] = errors
        return result

    actual_size = local_path.stat().st_size
    actual_sha256 = sha256_file(local_path)
    size_match = expected_size == actual_size
    sha256_match = expected_sha256 == actual_sha256
    if not size_match:
        errors.append("size_mismatch")
    if not expected_sha256:
        errors.append("missing_expected_sha256")
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
            "validation_errors": errors,
        }
    )
    return result


def build_upload_plan(args: argparse.Namespace, manifest: dict[str, Any], manifest_path: Path) -> dict[str, Any]:
    out_dir = Path(args.out_dir).resolve()
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    minio = manifest.get("minio") if isinstance(manifest.get("minio"), dict) else {}
    bucket = args.minio_bucket or str(minio.get("bucket") or "")
    prefix = args.minio_prefix if args.minio_prefix is not None else str(minio.get("prefix") or "")
    planned_artifacts: list[dict[str, Any]] = []

    for index, artifact_obj in enumerate(artifacts, start=1):
        if not isinstance(artifact_obj, dict):
            artifact_obj = {"raw_artifact": artifact_obj}
        validation = verify_artifact(artifact_obj, manifest_path)
        should_compress = compression_needed(artifact_obj, args)
        base_key = minio_key_for_artifact(artifact_obj, args, manifest)
        archive_key = archive_key_with_compression(base_key, args, should_compress)
        archive_local_path = validation["local_path"]
        archive_size_bytes = validation["actual_size_bytes"] if validation["verified"] and not should_compress else None
        archive_sha256 = validation["actual_sha256"] if validation["verified"] and not should_compress else ""
        archive_size_basis = "actual_source_file"
        materialized_compression = False
        compression_error = ""

        if should_compress:
            archive_size_basis = "not_materialized_dry_run"
            archive_local_path = ""
            if args.mode == "upload" and validation["verified"]:
                try:
                    target = compressed_output_path(out_dir, index, artifact_obj, validation["actual_sha256"], args)
                    compress_file(Path(validation["local_path"]), target, args)
                    archive_local_path = str(target)
                    archive_size_bytes = target.stat().st_size
                    archive_sha256 = sha256_file(target)
                    archive_size_basis = "actual_compressed_file"
                    materialized_compression = True
                except Exception as exc:
                    compression_error = str(exc)

        upload_status = "dry_run_planned" if args.mode == "dry-run" else "pending"
        if not validation["verified"]:
            upload_status = "skipped_validation_failed"
        elif compression_error:
            upload_status = "compression_failed"

        estimated_archive_size = archive_size_bytes
        if estimated_archive_size is None and validation["actual_size_bytes"] is not None:
            estimated_archive_size = validation["actual_size_bytes"]

        planned_artifacts.append(
            {
                "artifact_index": index,
                "artifact_type": artifact_obj.get("artifact_type"),
                "relative_path": artifact_obj.get("relative_path"),
                "source_local_path": validation["local_path"],
                "source_size_bytes": validation["actual_size_bytes"],
                "source_sha256": validation["actual_sha256"],
                "expected_size_bytes": validation["expected_size_bytes"],
                "expected_sha256": validation["expected_sha256"],
                "validation": validation,
                "verified": validation["verified"],
                "compression": {
                    "enabled": should_compress,
                    "format": args.compression_format if should_compress else None,
                    "materialized": materialized_compression,
                    "error": compression_error,
                },
                "archive_local_path": archive_local_path,
                "archive_size_bytes": archive_size_bytes,
                "archive_size_basis": archive_size_basis,
                "archive_sha256": archive_sha256,
                "estimated_archive_size_bytes": estimated_archive_size,
                "minio_bucket": bucket,
                "minio_key": archive_key,
                "upload_status": upload_status,
                "upload_error": compression_error,
            }
        )

    return {
        "schema": SCHEMA_PLAN,
        "generated_at_utc": utc_now(),
        "mode": args.mode,
        "artifact_manifest": str(manifest_path),
        "compression": {
            "compress_jsonl": bool(args.compress_jsonl),
            "compress_json": bool(args.compress_json),
            "format": args.compression_format,
            "dry_run_materializes_compressed_files": False,
        },
        "minio": {
            "endpoint": args.minio_endpoint,
            "bucket": bucket,
            "prefix": prefix.strip("/"),
        },
        "artifact_count": len(planned_artifacts),
        "artifacts": planned_artifacts,
    }


def make_s3_client(args: argparse.Namespace) -> Any:
    access_key = os.environ.get(args.access_key_env)
    secret_key = os.environ.get(args.secret_key_env)
    if not args.minio_endpoint:
        raise RuntimeError("--minio-endpoint is required in upload mode")
    if not access_key:
        raise RuntimeError(f"missing access key env var: {args.access_key_env}")
    if not secret_key:
        raise RuntimeError(f"missing secret key env var: {args.secret_key_env}")
    try:
        import boto3  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("upload mode requires boto3 to be installed") from exc

    return boto3.client(
        "s3",
        endpoint_url=args.minio_endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-east-1",
    )


def perform_uploads(args: argparse.Namespace, plan: dict[str, Any]) -> str:
    if args.mode != "upload":
        return ""
    bucket = str((plan.get("minio") or {}).get("bucket") or "")
    if not bucket:
        setup_error = "missing MinIO bucket"
        for item in plan["artifacts"]:
            if item.get("upload_status") == "pending":
                item["upload_status"] = "upload_failed"
                item["upload_error"] = setup_error
        return setup_error

    try:
        client = make_s3_client(args)
    except Exception as exc:
        setup_error = str(exc)
        for item in plan["artifacts"]:
            if item.get("upload_status") == "pending":
                item["upload_status"] = "upload_failed"
                item["upload_error"] = setup_error
        return setup_error

    for item in plan["artifacts"]:
        if item.get("upload_status") != "pending":
            continue
        archive_local_path = Path(str(item.get("archive_local_path") or ""))
        if not archive_local_path.is_file():
            item["upload_status"] = "upload_failed"
            item["upload_error"] = "archive_local_path_missing"
            continue
        extra_args = {
            "Metadata": {
                "source-sha256": str(item.get("source_sha256") or "").replace("sha256:", ""),
                "archive-sha256": str(item.get("archive_sha256") or "").replace("sha256:", ""),
                "artifact-type": str(item.get("artifact_type") or ""),
            }
        }
        try:
            client.upload_file(str(archive_local_path), bucket, str(item["minio_key"]), ExtraArgs=extra_args)
            item["upload_status"] = "uploaded"
            item["upload_error"] = ""
        except Exception as exc:
            item["upload_status"] = "upload_failed"
            item["upload_error"] = str(exc)
    return ""


def summarize(plan: dict[str, Any], started_at: str, finished_at: str, upload_setup_error: str = "") -> dict[str, Any]:
    artifacts = plan.get("artifacts") if isinstance(plan.get("artifacts"), list) else []
    artifact_count = len(artifacts)
    verified_count = sum(1 for item in artifacts if item.get("verified"))
    missing_count = sum(1 for item in artifacts if not (item.get("validation") or {}).get("exists"))
    size_mismatch_count = sum(1 for item in artifacts if (item.get("validation") or {}).get("exists") and not (item.get("validation") or {}).get("size_match"))
    sha256_mismatch_count = sum(1 for item in artifacts if (item.get("validation") or {}).get("exists") and not (item.get("validation") or {}).get("sha256_match"))
    compression_failed_count = sum(1 for item in artifacts if item.get("upload_status") == "compression_failed")
    upload_success_count = sum(1 for item in artifacts if item.get("upload_status") == "uploaded")
    upload_failed_count = sum(1 for item in artifacts if item.get("upload_status") == "upload_failed")
    upload_attempted = plan.get("mode") == "upload"
    total_input_bytes = sum(as_int(item.get("source_size_bytes")) or 0 for item in artifacts)
    total_archive_bytes = sum(
        as_int(item.get("archive_size_bytes")) if as_int(item.get("archive_size_bytes")) is not None else (as_int(item.get("estimated_archive_size_bytes")) or 0)
        for item in artifacts
        if item.get("verified")
    )
    minio = plan.get("minio") if isinstance(plan.get("minio"), dict) else {}

    checks = {
        "artifact_count_gt_zero": artifact_count > 0,
        "all_artifacts_verified": verified_count == artifact_count and artifact_count > 0,
        "missing_artifact_count_zero": missing_count == 0,
        "size_mismatch_count_zero": size_mismatch_count == 0,
        "sha256_mismatch_count_zero": sha256_mismatch_count == 0,
        "compression_failed_count_zero": compression_failed_count == 0,
        "upload_failed_count_zero": upload_failed_count == 0,
        "upload_count_valid": (not upload_attempted and upload_success_count == 0) or (upload_success_count == verified_count and upload_failed_count == 0),
    }
    status = "PASS" if all(checks.values()) else "FAIL"

    try:
        duration_sec = max(0.0, datetime.fromisoformat(finished_at.replace("Z", "+00:00")).timestamp() - datetime.fromisoformat(started_at.replace("Z", "+00:00")).timestamp())
    except Exception:
        duration_sec = None

    return {
        "schema": SCHEMA_REPORT,
        "status": status,
        "mode": plan.get("mode"),
        "artifact_manifest": plan.get("artifact_manifest"),
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "duration_sec": duration_sec,
        "artifact_count": artifact_count,
        "verified_artifact_count": verified_count,
        "missing_artifact_count": missing_count,
        "size_mismatch_count": size_mismatch_count,
        "sha256_mismatch_count": sha256_mismatch_count,
        "compression_failed_count": compression_failed_count,
        "upload_attempted": upload_attempted,
        "upload_setup_error": upload_setup_error,
        "upload_success_count": upload_success_count,
        "upload_failed_count": upload_failed_count,
        "total_input_bytes": total_input_bytes,
        "total_archive_bytes": total_archive_bytes,
        "minio_bucket": minio.get("bucket") or "",
        "minio_prefix": minio.get("prefix") or "",
        "checks": checks,
    }


def build_db_rows_archive_index(plan: dict[str, Any], report: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    metadata = manifest.get("cycle_metadata") if isinstance(manifest.get("cycle_metadata"), dict) else {}
    rows = []
    for item in plan.get("artifacts", []):
        rows.append(
            {
                "table": "live_msal_cycle_archive_index",
                "probe_id": metadata.get("probe_id"),
                "run_id": metadata.get("run_id"),
                "snapshot_id": metadata.get("snapshot_id"),
                "artifact_type": item.get("artifact_type"),
                "relative_path": item.get("relative_path"),
                "source_local_path": item.get("source_local_path"),
                "source_size_bytes": item.get("source_size_bytes"),
                "source_sha256": item.get("source_sha256"),
                "archive_size_bytes": item.get("archive_size_bytes"),
                "archive_sha256": item.get("archive_sha256"),
                "compression_format": (item.get("compression") or {}).get("format"),
                "compression_enabled": (item.get("compression") or {}).get("enabled"),
                "minio_bucket": item.get("minio_bucket"),
                "minio_key": item.get("minio_key"),
                "verified": item.get("verified"),
                "upload_status": item.get("upload_status"),
                "upload_error": item.get("upload_error"),
            }
        )
    return {
        "schema": SCHEMA_DB_INDEX,
        "generated_at_utc": utc_now(),
        "note": "Preview only: this script does not connect to a database.",
        "archive_status": report.get("status"),
        "tables": {
            "live_msal_cycle_archive_index": rows,
        },
    }


def build_acceptance_text(report: dict[str, Any]) -> str:
    status = report.get("status") or "FAIL"
    lines = [
        f"E5_ARTIFACT_ARCHIVE={status}",
        f"artifact_count={report.get('artifact_count')}",
        f"verified_artifact_count={report.get('verified_artifact_count')}",
        f"missing_artifact_count={report.get('missing_artifact_count')}",
        f"sha256_mismatch_count={report.get('sha256_mismatch_count')}",
        f"upload_attempted={bool_text(bool(report.get('upload_attempted')))}",
        f"upload_success_count={report.get('upload_success_count')}",
        f"upload_failed_count={report.get('upload_failed_count')}",
        f"total_input_bytes={report.get('total_input_bytes')}",
        f"total_archive_bytes={report.get('total_archive_bytes')}",
        f"minio_bucket={report.get('minio_bucket') or ''}",
        f"minio_prefix={report.get('minio_prefix') or ''}",
        "",
        "[checks]",
    ]
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
    lines.extend(f"{key}={bool_text(bool(value))}" for key, value in checks.items())
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> dict[str, Any]:
    started_at = utc_now()
    manifest_path = Path(args.artifact_manifest).resolve()
    out_dir = Path(args.out_dir).resolve()
    plan_path = out_dir / OUTPUT_PLAN
    report_path = out_dir / OUTPUT_REPORT
    db_index_path = out_dir / OUTPUT_DB_INDEX
    acceptance_path = out_dir / "checks" / OUTPUT_ACCEPTANCE

    manifest = load_json_object(manifest_path)
    plan = build_upload_plan(args, manifest, manifest_path)
    upload_setup_error = perform_uploads(args, plan)
    finished_at = utc_now()
    report = summarize(plan, started_at, finished_at, upload_setup_error)
    db_index = build_db_rows_archive_index(plan, report, manifest)

    atomic_write_json(plan_path, plan)
    atomic_write_json(report_path, report)
    atomic_write_json(db_index_path, db_index)
    atomic_write_text(acceptance_path, build_acceptance_text(report))
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build or execute a MinIO archive upload plan from an E4 artifact_manifest.json.")
    parser.add_argument("--artifact-manifest", required=True, help="Path to E4 artifact_manifest.json.")
    parser.add_argument("--out-dir", required=True, help="Output directory for E5 archive plan, report, DB index preview, and acceptance check.")
    parser.add_argument("--mode", choices=["dry-run", "upload"], default="dry-run", help="dry-run only writes a plan; upload sends verified artifacts to MinIO.")
    parser.add_argument("--compress-jsonl", action="store_true", help="Archive .jsonl artifacts as compressed objects.")
    parser.add_argument("--compress-json", action="store_true", help="Archive .json artifacts as compressed objects.")
    parser.add_argument("--compression-format", choices=["gz", "zst"], default="gz", help="Compression format used when compression flags match an artifact.")
    parser.add_argument("--minio-endpoint", help="MinIO/S3 endpoint URL. Required only in upload mode.")
    parser.add_argument("--minio-bucket", help="Override bucket from artifact_manifest.json.")
    parser.add_argument("--minio-prefix", help="Override object key prefix; probe_id/run_id are appended when absent.")
    parser.add_argument("--access-key-env", default="MINIO_ACCESS_KEY", help="Environment variable name containing the MinIO access key.")
    parser.add_argument("--secret-key-env", default="MINIO_SECRET_KEY", help="Environment variable name containing the MinIO secret key.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = run(args)
    return 0 if report.get("status") == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        raise SystemExit(1)