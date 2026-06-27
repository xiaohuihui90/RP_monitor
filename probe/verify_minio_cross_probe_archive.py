#!/usr/bin/env python3
from __future__ import annotations

import argparse
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


SCHEMA_VERIFY_REPORT = "s3.probe.cross_probe_minio_archive_verify_report.v1"
SCHEMA_RESTORED_SAMPLE = "s3.probe.cross_probe_minio_archive_restored_sample.v1"
OUTPUT_VERIFY_REPORT = "verify_report.json"
OUTPUT_RESTORED_SAMPLES = "restored_samples.jsonl"
OUTPUT_ACCEPTANCE = "P7_MINIO_ARCHIVE_VERIFY_ACCEPTANCE.txt"


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


def load_json_object(path: Path) -> tuple[dict[str, Any], str | None]:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            return {}, f"expected JSON object at {path}"
        return obj, None
    except Exception as exc:
        return {}, str(exc)


def json_file_ok(path: Path) -> bool:
    obj, error = load_json_object(path)
    return error is None and isinstance(obj, dict)


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


def is_normalized_vrp_path(value: Any) -> bool:
    text = str(value or "").replace("\\", "/").lower()
    return "normalized_vrp.jsonl" in text or "latest_normalized_vrp.jsonl" in text


def safe_filename(value: Any, fallback: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    text = text.rsplit("/", 1)[-1]
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    return text.strip("._-") or fallback


def ensure_mc(mc_bin: str) -> tuple[str, str | None]:
    requested = str(mc_bin or "mc")
    requested_path = Path(requested)
    if requested_path.is_absolute() or os.sep in requested or (os.altsep and os.altsep in requested):
        if requested_path.is_file():
            return str(requested_path), None
        return "", f"MinIO mc CLI not found: {requested}"

    candidates = [requested]
    if requested == "mc":
        candidates.extend(["mc.exe", "mc.cmd", "mc.bat"])
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path, None
    return "", "MinIO mc CLI not found in PATH"


def run_command(command: list[str]) -> dict[str, Any]:
    started = time.monotonic()
    try:
        proc = subprocess.run(command, text=True, capture_output=True)
        return {
            "command": command,
            "exit_code": proc.returncode,
            "stdout": proc.stdout[-8000:],
            "stderr": proc.stderr[-8000:],
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
    except json.JSONDecodeError:
        return {"raw_text": text[-4000:]}
    if not isinstance(obj, dict):
        return {"raw": obj}
    return {
        "raw": obj,
        "size": obj.get("size") or obj.get("Size") or obj.get("length"),
        "etag": obj.get("etag") or obj.get("ETag"),
        "metadata": obj.get("metadata") or obj.get("Metadata") or {},
        "key": obj.get("key") or obj.get("Key") or obj.get("name"),
        "last_modified": obj.get("lastModified") or obj.get("LastModified"),
    }


def uploaded_artifacts(plan: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = plan.get("artifacts") if isinstance(plan.get("artifacts"), list) else []
    return [item for item in artifacts if isinstance(item, dict) and item.get("upload_status") == "uploaded"]


def expected_object_size(item: dict[str, Any]) -> int | None:
    for key in ("archive_size_bytes", "source_size_bytes"):
        value = as_int(item.get(key))
        if value is not None:
            return value
    return None


def expected_object_sha256(item: dict[str, Any]) -> str:
    return normalize_sha256(item.get("archive_sha256") or item.get("source_sha256"))


def mc_target(item: dict[str, Any]) -> str:
    target = str(item.get("mc_target") or "").strip()
    if target:
        return target
    bucket = str(item.get("minio_bucket") or "").strip("/")
    key = str(item.get("minio_key") or "").strip("/")
    if not bucket or not key:
        return ""
    return f"rp-monitor-p6/{bucket}/{key}"


def verify_stat(item: dict[str, Any], mc_path: str, mc_missing_error: str | None) -> dict[str, Any]:
    target = mc_target(item)
    expected_size = expected_object_size(item)
    result: dict[str, Any] = {
        "artifact_index": item.get("artifact_index"),
        "artifact_type": item.get("artifact_type"),
        "relative_path": item.get("relative_path"),
        "minio_bucket": item.get("minio_bucket"),
        "minio_key": item.get("minio_key"),
        "mc_target": target,
        "expected_size_bytes": expected_size,
        "expected_sha256": expected_object_sha256(item),
        "stat_ok": False,
        "stat_size_bytes": None,
        "size_match": False,
        "etag": None,
        "metadata": {},
        "stat_error": "",
        "mc_stat": None,
    }
    if mc_missing_error:
        result["stat_error"] = mc_missing_error
        return result
    if not target:
        result["stat_error"] = "missing mc target"
        return result
    command = [mc_path, "stat", "--json", target]
    stat = run_command(command)
    result["mc_stat"] = stat
    if stat["exit_code"] != 0:
        result["stat_error"] = stat.get("stderr") or stat.get("stdout") or "mc stat failed"
        return result
    parsed = parse_mc_stat(stat.get("stdout") or "")
    stat_size = as_int(parsed.get("size"))
    result.update(
        {
            "stat_ok": True,
            "stat_size_bytes": stat_size,
            "size_match": stat_size is not None and expected_size is not None and stat_size == expected_size,
            "etag": parsed.get("etag"),
            "metadata": parsed.get("metadata") if isinstance(parsed.get("metadata"), dict) else {},
            "parsed_stat": parsed,
        }
    )
    if expected_size is None:
        result["stat_error"] = "missing expected size"
    elif stat_size != expected_size:
        result["stat_error"] = f"size mismatch: stat={stat_size} expected={expected_size}"
    return result


def sample_candidates(items: list[dict[str, Any]], include_normalized: bool) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for item in items:
        path_like = " ".join(
            str(item.get(key) or "")
            for key in ("relative_path", "source_local_path", "minio_key")
        )
        if not include_normalized and is_normalized_vrp_path(path_like):
            continue
        candidates.append(item)
    return candidates


def download_sample(
    item: dict[str, Any],
    sample_index: int,
    mc_path: str,
    mc_missing_error: str | None,
    restore_dir: Path,
) -> dict[str, Any]:
    target = mc_target(item)
    expected_sha256 = expected_object_sha256(item)
    dest_name = f"{sample_index:03d}_{safe_filename(item.get('relative_path') or item.get('minio_key'), 'artifact')}"
    if str(item.get("minio_key") or "").endswith(".gz") and not dest_name.endswith(".gz"):
        dest_name += ".gz"
    dest_path = restore_dir / dest_name
    result: dict[str, Any] = {
        "schema": SCHEMA_RESTORED_SAMPLE,
        "sample_index": sample_index,
        "artifact_index": item.get("artifact_index"),
        "artifact_type": item.get("artifact_type"),
        "relative_path": item.get("relative_path"),
        "minio_key": item.get("minio_key"),
        "mc_target": target,
        "download_path": str(dest_path),
        "expected_sha256": expected_sha256,
        "download_ok": False,
        "actual_sha256": "",
        "sha256_match": False,
        "error": "",
    }
    if mc_missing_error:
        result["error"] = mc_missing_error
        return result
    if not target:
        result["error"] = "missing mc target"
        return result
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    command = [mc_path, "cp", target, str(dest_path)]
    cp = run_command(command)
    result["mc_cp"] = cp
    if cp["exit_code"] != 0:
        result["error"] = cp.get("stderr") or cp.get("stdout") or "mc cp failed"
        return result
    if not dest_path.is_file():
        result["error"] = "download file missing after mc cp"
        return result
    actual = sha256_file(dest_path)
    result.update(
        {
            "download_ok": True,
            "actual_size_bytes": dest_path.stat().st_size,
            "actual_sha256": actual,
            "sha256_match": bool(expected_sha256) and actual == expected_sha256,
        }
    )
    if not result["sha256_match"]:
        result["error"] = "sha256 mismatch"
    return result


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    text = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in rows)
    atomic_write_text(path, text)


def acceptance_text(report: dict[str, Any]) -> str:
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
    lines = [
        f"P7_MINIO_ARCHIVE_VERIFY={report.get('status')}",
        f"archive_report={report.get('archive_report')}",
        f"archive_plan={report.get('archive_plan')}",
        f"uploaded_object_count={report.get('uploaded_object_count')}",
        f"stat_failed_count={report.get('stat_failed_count')}",
        f"size_mismatch_count={report.get('size_mismatch_count')}",
        f"sample_download_requested={report.get('sample_download_requested')}",
        f"sample_download_count={report.get('sample_download_count')}",
        f"sample_sha256_mismatch_count={report.get('sample_sha256_mismatch_count')}",
        f"causal_claim_allowed={bool_text(bool(report.get('causal_claim_allowed')))}",
        f"root_cause_confirmed={bool_text(bool(report.get('root_cause_confirmed')))}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={bool_text(bool(value))}" for key, value in checks.items())
    return "\n".join(lines) + "\n"


def run(args: argparse.Namespace) -> dict[str, Any]:
    started_at = utc_now()
    archive_report_path = Path(args.archive_report).resolve()
    out_dir = Path(args.out_dir).resolve()
    verify_report_path = out_dir / OUTPUT_VERIFY_REPORT
    samples_path = out_dir / OUTPUT_RESTORED_SAMPLES
    acceptance_path = out_dir / "checks" / OUTPUT_ACCEPTANCE
    plan_path = Path(args.archive_plan).resolve() if args.archive_plan else archive_report_path.parent / "archive_plan.json"

    archive_report, archive_report_error = load_json_object(archive_report_path)
    plan, plan_error = load_json_object(plan_path)
    uploaded = uploaded_artifacts(plan)
    mc_path, mc_error = ensure_mc(args.mc_bin)

    stat_results = [verify_stat(item, mc_path, mc_error) for item in uploaded]
    sample_items = sample_candidates(uploaded, bool(args.include_normalized_vrp_samples))[: max(0, int(args.sample_download))]
    restore_dir = out_dir / "restore_sample"
    restored_samples = [
        download_sample(item, index, mc_path, mc_error, restore_dir)
        for index, item in enumerate(sample_items, 1)
    ]

    stat_failed_count = sum(1 for item in stat_results if not item.get("stat_ok"))
    size_mismatch_count = sum(1 for item in stat_results if item.get("stat_ok") and not item.get("size_match"))
    sample_sha256_mismatch_count = sum(1 for item in restored_samples if not item.get("sha256_match"))
    checks = {
        "archive_report_json_ok": archive_report_error is None,
        "archive_plan_json_ok": plan_error is None,
        "uploaded_object_count_gt_zero": len(uploaded) > 0,
        "stat_failed_count_zero": stat_failed_count == 0,
        "size_mismatch_count_zero": size_mismatch_count == 0,
        "sample_sha256_mismatch_count_zero": sample_sha256_mismatch_count == 0,
        "causal_claim_allowed_false": True,
        "root_cause_confirmed_false": True,
    }
    report = {
        "schema": SCHEMA_VERIFY_REPORT,
        "status": "PASS" if all(checks.values()) else "FAIL",
        "archive_report": str(archive_report_path),
        "archive_report_json_ok": archive_report_error is None,
        "archive_report_error": archive_report_error,
        "archive_plan": str(plan_path),
        "archive_plan_json_ok": plan_error is None,
        "archive_plan_error": plan_error,
        "archive_status": archive_report.get("status") if isinstance(archive_report, dict) else None,
        "mc_path": mc_path,
        "mc_error": mc_error,
        "uploaded_object_count": len(uploaded),
        "stat_checked_count": len(stat_results),
        "stat_failed_count": stat_failed_count,
        "size_mismatch_count": size_mismatch_count,
        "sample_download_requested": int(args.sample_download),
        "sample_download_count": len(restored_samples),
        "sample_sha256_mismatch_count": sample_sha256_mismatch_count,
        "normalized_vrp_samples_included": bool(args.include_normalized_vrp_samples),
        "stat_results": stat_results,
        "restored_samples_file": str(samples_path),
        "checks": checks,
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
    }
    atomic_write_json(verify_report_path, report)
    write_jsonl(samples_path, restored_samples)
    report["checks"]["archive_report_json_ok"] = json_file_ok(archive_report_path)
    report["outputs"] = {
        "verify_report": str(verify_report_path),
        "restored_samples": str(samples_path),
        "acceptance": str(acceptance_path),
    }
    report["status"] = "PASS" if all(report["checks"].values()) else "FAIL"
    atomic_write_json(verify_report_path, report)
    atomic_write_text(acceptance_path, acceptance_text(report))
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify MinIO cross-probe archive objects from a P6 archive_report.json using mc CLI.")
    parser.add_argument("--archive-report", required=True, help="P6 archive_report.json.")
    parser.add_argument("--archive-plan", help="Optional archive_plan.json. Defaults to archive_report sibling.")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--mc-bin", default="mc", help="MinIO mc CLI path or command name. Default: mc.")
    parser.add_argument("--sample-download", type=int, default=0, metavar="N", help="Download N uploaded objects into out-dir/restore_sample and verify sha256.")
    parser.add_argument("--include-normalized-vrp-samples", action="store_true", help="Allow normalized_vrp objects to be sampled. Default: false.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.sample_download < 0:
        print("ERROR: --sample-download must be >= 0", file=sys.stderr)
        return 2
    report = run(args)
    return 0 if report.get("status") == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
