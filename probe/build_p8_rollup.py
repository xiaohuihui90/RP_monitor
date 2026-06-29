#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO


SCHEMA_RECORD = "s3.probe.p8_rollup_record.v1"
SCHEMA_SUMMARY = "s3.probe.p8_rollup_summary.v1"
DEFAULT_P8_ROOT = "data/probe/cross_probe_pipeline"
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


def open_tmp_jsonl(path: Path) -> tuple[Path, TextIO]:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    return tmp, tmp.open("w", encoding="utf-8", newline="\n")


def publish_existing_atomically(tmp_path: Path, final_path: Path) -> None:
    final_path.parent.mkdir(parents=True, exist_ok=True)
    with tmp_path.open("rb+") as f:
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, final_path)
    fsync_parent(final_path)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_path(value: str, root: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()


def load_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


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


def as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


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


def run_sort_time(run_dir: Path, summary: dict[str, Any]) -> float:
    for key in ("finished_at_utc", "started_at_utc"):
        dt = parse_iso_datetime(summary.get(key))
        if dt is not None:
            return dt.timestamp()
    try:
        return run_dir.stat().st_mtime
    except OSError:
        return 0.0


def discover_p8_run_dirs(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    candidates: list[Path] = []
    for item in root.iterdir():
        if not item.is_dir():
            continue
        if (item / "pipeline_summary.json").is_file() or (item / "checks" / "P8_CROSS_PROBE_PIPELINE_ACCEPTANCE.txt").is_file():
            candidates.append(item)
    return candidates


def p8_record(run_dir: Path) -> dict[str, Any]:
    p8_summary = load_json_object(run_dir / "pipeline_summary.json")
    p6_report = load_json_object(run_dir / "p6" / "archive_report.json")
    p7_report = load_json_object(run_dir / "p7" / "verify_report.json")
    p8_acceptance = parse_acceptance(run_dir / "checks" / "P8_CROSS_PROBE_PIPELINE_ACCEPTANCE.txt")
    p6_acceptance = parse_acceptance(run_dir / "p6" / "checks" / "P6_MINIO_ARCHIVE_ACCEPTANCE.txt")
    p7_acceptance = parse_acceptance(run_dir / "p7" / "checks" / "P7_MINIO_ARCHIVE_VERIFY_ACCEPTANCE.txt")

    p8_status = p8_acceptance.get("P8_CROSS_PROBE_PIPELINE") or str(p8_summary.get("status") or "MISSING")
    p6_status = p6_acceptance.get("P6_MINIO_ARCHIVE") or str(p6_report.get("status") or "MISSING")
    p7_status = p7_acceptance.get("P7_MINIO_ARCHIVE_VERIFY") or str(p7_report.get("status") or "MISSING")
    window_quality = str(p8_summary.get("window_quality") or p8_acceptance.get("window_quality") or "")
    all_pass = p8_status == "PASS" and p6_status == "PASS" and p7_status == "PASS"

    return {
        "schema": SCHEMA_RECORD,
        "run_id": str(p8_summary.get("run_id") or run_dir.name),
        "run_dir": str(run_dir),
        "started_at_utc": p8_summary.get("started_at_utc"),
        "finished_at_utc": p8_summary.get("finished_at_utc"),
        "sort_timestamp": run_sort_time(run_dir, p8_summary),
        "mode": p8_summary.get("mode") or p8_acceptance.get("mode"),
        "window_id": p8_summary.get("window_id") or p8_acceptance.get("window_id"),
        "window_quality": window_quality,
        "p8_status": p8_status,
        "p6_status": p6_status,
        "p7_status": p7_status,
        "p8_p6_p7_all_pass": all_pass,
        "p8_event_count": as_int(p8_summary.get("p2_event_count")),
        "p8_candidate_event_count": as_int(p8_summary.get("p2_candidate_event_count")),
        "artifact_count": as_int(p8_summary.get("artifact_count")),
        "p6_upload_success_count": as_int(p6_report.get("upload_success_count")),
        "p6_upload_failed_count": as_int(p6_report.get("upload_failed_count")),
        "p7_uploaded_object_count": as_int(p7_report.get("uploaded_object_count")),
        "p7_stat_failed_count": as_int(p7_report.get("stat_failed_count")),
        "p7_size_mismatch_count": as_int(p7_report.get("size_mismatch_count")),
        "causal_claim_allowed_count": as_int(p8_summary.get("causal_claim_allowed_count")) or 0,
        "root_cause_confirmed": bool(p8_summary.get("root_cause_confirmed")),
    }


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


def minio_key(prefix: str, rollup_id: str, filename: str) -> str:
    base = "/".join(part for part in prefix.strip("/").split("/") if part)
    suffix = f"rollups/{rollup_id}/{filename}"
    return f"{base}/{suffix}" if base else suffix


def upload_and_stat(paths: list[Path], rollup_id: str, minio_alias: str, bucket: str, prefix: str, mc_bin: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    uploads: list[dict[str, Any]] = []
    stats: list[dict[str, Any]] = []
    for path in paths:
        key = minio_key(prefix, rollup_id, path.name)
        target = f"{minio_alias}/{bucket}/{key}"
        cp_result = run_command([mc_bin, "cp", str(path), target])
        uploads.append({"local_path": str(path), "object_key": key, "target": target, **cp_result})
        stat_result = run_command([mc_bin, "stat", target]) if cp_result.get("exit_code") == 0 else {
            "command": [mc_bin, "stat", target],
            "exit_code": 99,
            "stdout_tail": "",
            "stderr_tail": "skipped because upload failed",
            "duration_sec": 0,
        }
        stats.append({"local_path": str(path), "object_key": key, "target": target, **stat_result})
    return uploads, stats


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a small rollup of P8/P6/P7 cross-probe pipeline runs.")
    parser.add_argument("--p8-root", default=DEFAULT_P8_ROOT)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--limit", type=int, default=0, help="Newest N P8 runs to include. 0 means all.")
    parser.add_argument("--upload-minio", action="store_true")
    parser.add_argument("--mc-bin", default="mc")
    parser.add_argument("--minio-alias", default=os.environ.get("MINIO_ALIAS", ""))
    parser.add_argument("--minio-bucket", default=os.environ.get("MINIO_BUCKET", ""))
    parser.add_argument("--minio-prefix", default=os.environ.get("MINIO_PREFIX", DEFAULT_MINIO_PREFIX))
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = repo_root()
    p8_root = resolve_path(args.p8_root, root)
    out_dir = resolve_path(args.out_dir, root)
    out_dir.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    rollup_id = "p8_rollup_" + started_at.replace("-", "").replace(":", "").replace("Z", "Z")

    records = [p8_record(path) for path in discover_p8_run_dirs(p8_root)]
    records.sort(key=lambda item: (float(item.get("sort_timestamp") or 0), str(item.get("run_id"))), reverse=True)
    if args.limit and args.limit > 0:
        records = records[: args.limit]

    rollup_jsonl = out_dir / "p8_rollup.jsonl"
    tmp_path, f = open_tmp_jsonl(rollup_jsonl)
    try:
        with f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        publish_existing_atomically(tmp_path, rollup_jsonl)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise

    status_dist = Counter(str(record.get("p8_status")) for record in records)
    window_quality_dist = Counter(str(record.get("window_quality") or "UNKNOWN") for record in records)
    p6_dist = Counter(str(record.get("p6_status")) for record in records)
    p7_dist = Counter(str(record.get("p7_status")) for record in records)
    upload_results: list[dict[str, Any]] = []
    stat_results: list[dict[str, Any]] = []
    upload_preflight_error = ""

    summary_path = out_dir / "p8_rollup_summary.json"
    summary = {
        "schema": SCHEMA_SUMMARY,
        "rollup_id": rollup_id,
        "p8_root": str(p8_root),
        "out_dir": str(out_dir),
        "run_count": len(records),
        "p8_status_distribution": dict(status_dist),
        "p6_status_distribution": dict(p6_dist),
        "p7_status_distribution": dict(p7_dist),
        "window_quality_distribution": dict(window_quality_dist),
        "all_pass_count": sum(1 for record in records if record.get("p8_p6_p7_all_pass")),
        "window_incomplete_count": sum(1 for record in records if record.get("window_quality") == "WINDOW_INCOMPLETE"),
        "upload_requested": bool(args.upload_minio),
        "minio_alias": args.minio_alias,
        "minio_bucket": args.minio_bucket,
        "minio_prefix": args.minio_prefix,
        "upload_success_count": 0,
        "upload_failed_count": 0,
        "stat_success_count": 0,
        "stat_failed_count": 0,
        "rollup_uploaded": False,
        "minio_stat_ok": False,
        "started_at_utc": started_at,
        "finished_at_utc": None,
        "outputs": {
            "p8_rollup_jsonl": str(rollup_jsonl),
            "p8_rollup_summary_json": str(summary_path),
        },
    }
    atomic_write_json(summary_path, summary)

    if args.upload_minio:
        if not args.minio_alias or not args.minio_bucket:
            upload_preflight_error = "MINIO_ALIAS and MINIO_BUCKET are required for --upload-minio"
        else:
            upload_results, stat_results = upload_and_stat([rollup_jsonl, summary_path], rollup_id, args.minio_alias, args.minio_bucket, args.minio_prefix, args.mc_bin)

    summary["upload_preflight_error"] = upload_preflight_error
    summary["upload_results"] = upload_results
    summary["stat_results"] = stat_results
    summary["upload_success_count"] = sum(1 for item in upload_results if item.get("exit_code") == 0)
    summary["upload_failed_count"] = (2 if upload_preflight_error else 0) + sum(1 for item in upload_results if item.get("exit_code") != 0)
    summary["stat_success_count"] = sum(1 for item in stat_results if item.get("exit_code") == 0)
    summary["stat_failed_count"] = (2 if upload_preflight_error else 0) + sum(1 for item in stat_results if item.get("exit_code") != 0)
    summary["rollup_uploaded"] = (not args.upload_minio) or (summary["upload_success_count"] == 2 and summary["upload_failed_count"] == 0)
    summary["minio_stat_ok"] = (not args.upload_minio) or (summary["stat_success_count"] == 2 and summary["stat_failed_count"] == 0)
    summary["finished_at_utc"] = utc_now()
    atomic_write_json(summary_path, summary)

    if args.upload_minio and (not summary["rollup_uploaded"] or not summary["minio_stat_ok"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
