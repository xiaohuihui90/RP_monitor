#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_REPORT = "s3.probe.runtime_retention_report.v1"
ACCEPTANCE_NAME = "P9_RUNTIME_RETENTION"
DEFAULT_P8_ROOT = "data/probe/cross_probe_pipeline"
DEFAULT_SNAPSHOT_ROOT = "data/probe/live_vrp_snapshots"
DEFAULT_CYCLE_ROOT = "data/probe/e2e_msal_cycles"


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


def as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def path_size_bytes(path: Path) -> int:
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    if path.is_dir():
        for item in path.rglob("*"):
            try:
                if item.is_file():
                    total += item.stat().st_size
            except OSError:
                continue
    return total


def is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def sort_time_from_json(path: Path, keys: tuple[str, ...]) -> float:
    obj = load_json_object(path)
    for key in keys:
        dt = parse_iso_datetime(obj.get(key))
        if dt is not None:
            return dt.timestamp()
    try:
        return path.parent.stat().st_mtime
    except OSError:
        return 0.0


def p8_run_record(run_dir: Path) -> dict[str, Any]:
    summary = load_json_object(run_dir / "pipeline_summary.json")
    p8_acc = parse_acceptance(run_dir / "checks" / "P8_CROSS_PROBE_PIPELINE_ACCEPTANCE.txt")
    p6_acc = parse_acceptance(run_dir / "p6" / "checks" / "P6_MINIO_ARCHIVE_ACCEPTANCE.txt")
    p7_acc = parse_acceptance(run_dir / "p7" / "checks" / "P7_MINIO_ARCHIVE_VERIFY_ACCEPTANCE.txt")
    p8_status = p8_acc.get("P8_CROSS_PROBE_PIPELINE") or str(summary.get("status") or "MISSING")
    p6_status = p6_acc.get("P6_MINIO_ARCHIVE") or "MISSING"
    p7_status = p7_acc.get("P7_MINIO_ARCHIVE_VERIFY") or "MISSING"
    window_quality = str(summary.get("window_quality") or p8_acc.get("window_quality") or "")
    sort_ts = 0.0
    for key in ("finished_at_utc", "started_at_utc"):
        dt = parse_iso_datetime(summary.get(key))
        if dt is not None:
            sort_ts = dt.timestamp()
            break
    if not sort_ts:
        try:
            sort_ts = run_dir.stat().st_mtime
        except OSError:
            sort_ts = 0.0
    return {
        "target_type": "p8_run",
        "path": str(run_dir),
        "name": run_dir.name,
        "sort_timestamp": sort_ts,
        "p8_status": p8_status,
        "p6_status": p6_status,
        "p7_status": p7_status,
        "window_quality": window_quality,
        "verified_all_pass": p8_status == "PASS" and p6_status == "PASS" and p7_status == "PASS",
        "window_incomplete": window_quality == "WINDOW_INCOMPLETE",
        "size_bytes": path_size_bytes(run_dir),
    }


def discover_p8_runs(p8_root: Path) -> list[dict[str, Any]]:
    if not p8_root.is_dir():
        return []
    records = []
    for item in p8_root.iterdir():
        if not item.is_dir():
            continue
        if (item / "pipeline_summary.json").is_file() or (item / "checks" / "P8_CROSS_PROBE_PIPELINE_ACCEPTANCE.txt").is_file():
            records.append(p8_run_record(item))
    records.sort(key=lambda item: (float(item.get("sort_timestamp") or 0), str(item.get("name"))), reverse=True)
    return records


def snapshot_history_records(snapshot_root: Path, probe_id: str) -> list[dict[str, Any]]:
    history_dir = snapshot_root / probe_id / "history"
    if not history_dir.is_dir():
        return []
    records = []
    for item in history_dir.iterdir():
        if not item.is_dir():
            continue
        ts = sort_time_from_json(item / "metadata.json", ("capture_time_utc", "finished_at_utc", "started_at_utc"))
        records.append({"target_type": "snapshot_history", "probe_id": probe_id, "path": str(item), "name": item.name, "sort_timestamp": ts, "size_bytes": path_size_bytes(item)})
    records.sort(key=lambda item: (float(item.get("sort_timestamp") or 0), str(item.get("name"))), reverse=True)
    return records


def e2_cycle_records(cycle_root: Path, probe_id: str) -> list[dict[str, Any]]:
    probe_dir = cycle_root / probe_id
    if not probe_dir.is_dir():
        return []
    records = []
    for item in probe_dir.iterdir():
        if not item.is_dir():
            continue
        ts = sort_time_from_json(item / "cycle_summary.json", ("finished_at_utc", "started_at_utc", "created_at_utc"))
        records.append({"target_type": "e2_cycle", "probe_id": probe_id, "path": str(item), "name": item.name, "sort_timestamp": ts, "size_bytes": path_size_bytes(item)})
    records.sort(key=lambda item: (float(item.get("sort_timestamp") or 0), str(item.get("name"))), reverse=True)
    return records


def old_enough(sort_timestamp: Any, days: int | None) -> bool:
    if days is None:
        return False
    try:
        ts = float(sort_timestamp)
    except (TypeError, ValueError):
        return False
    return ts < utc_now_dt().timestamp() - days * 86400


def delete_target(record: dict[str, Any], allowed_root: Path, apply: bool) -> dict[str, Any]:
    path = Path(str(record.get("path") or ""))
    result = {
        "target_type": record.get("target_type"),
        "path": str(path),
        "reason": record.get("delete_reason"),
        "dry_run": not apply,
        "deleted": False,
        "error": "",
    }
    if not path.is_dir() or not is_relative_to(path, allowed_root) or path.resolve() == allowed_root.resolve():
        result["error"] = "unsafe target path"
        return result
    if apply:
        try:
            shutil.rmtree(path)
            result["deleted"] = True
        except Exception as exc:
            result["error"] = str(exc)
    return result


def load_optional_reports(paths: list[str], root: Path) -> list[dict[str, Any]]:
    reports = []
    for value in paths:
        path = resolve_path(value, root)
        report = load_json_object(path)
        if report:
            report["_path"] = str(path)
            reports.append(report)
    return reports


def bool_text(value: Any) -> str:
    return "true" if bool(value) else "false"


def write_acceptance(out_dir: Path, report: dict[str, Any]) -> None:
    checks = report.get("checks") if isinstance(report.get("checks"), dict) else {}
    status = "PASS" if checks and all(bool(value) for value in checks.values()) else "FAIL"
    lines = [
        f"{ACCEPTANCE_NAME}={status}",
        f"mode={report.get('mode')}",
        f"p8_run_count={report.get('p8_run_count')}",
        f"p8_candidate_delete_count={report.get('p8_candidate_delete_count')}",
        f"snapshot_candidate_delete_count={report.get('snapshot_candidate_delete_count')}",
        f"cycle_candidate_delete_count={report.get('cycle_candidate_delete_count')}",
        f"delete_error_count={report.get('delete_error_count')}",
        f"rollup_upload_requested={bool_text(report.get('rollup_upload_requested'))}",
        f"checkpoint_report_count={report.get('checkpoint_report_count')}",
        f"checkpoint_report_skipped_count={report.get('checkpoint_report_skipped_count')}",
        f"checkpoint_report_failed_count={report.get('checkpoint_report_failed_count')}",
        f"retention_report_json={out_dir / 'retention_report.json'}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={bool_text(value)}" for key, value in checks.items())
    atomic_write_text(out_dir / "checks" / "P9_RUNTIME_RETENTION_ACCEPTANCE.txt", "\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage local P8/probe runtime retention and emit P9 acceptance.")
    parser.add_argument("--p8-root", default=DEFAULT_P8_ROOT)
    parser.add_argument("--snapshot-root", default=DEFAULT_SNAPSHOT_ROOT)
    parser.add_argument("--cycle-root", default=DEFAULT_CYCLE_ROOT)
    parser.add_argument("--probe-id", action="append", default=[], help="Probe id for local snapshot/E2 retention. Repeatable.")
    parser.add_argument("--keep-p8-runs", type=int, default=12)
    parser.add_argument("--keep-snapshots", type=int, default=6)
    parser.add_argument("--keep-cycles", type=int, default=24)
    parser.add_argument("--delete-failed-before-days", type=int)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--p8-rollup-summary")
    parser.add_argument("--rollup-upload-requested", action="store_true")
    parser.add_argument("--checkpoint-report", action="append", default=[])
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if min(args.keep_p8_runs, args.keep_snapshots, args.keep_cycles) < 0:
        parser.error("keep counts must be >= 0")
    root = repo_root()
    p8_root = resolve_path(args.p8_root, root)
    snapshot_root = resolve_path(args.snapshot_root, root)
    cycle_root = resolve_path(args.cycle_root, root)
    out_dir = resolve_path(args.out_dir, root)
    out_dir.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()

    p8_runs = discover_p8_runs(p8_root)
    retained_p8 = p8_runs[: args.keep_p8_runs]
    retained_p8_paths = {record["path"] for record in retained_p8}
    p8_candidates: list[dict[str, Any]] = []
    unverified_delete_without_override = 0
    for record in p8_runs[args.keep_p8_runs :]:
        candidate = dict(record)
        if candidate.get("verified_all_pass"):
            candidate["delete_reason"] = "old_verified_p8_p6_p7_pass"
            p8_candidates.append(candidate)
        elif old_enough(candidate.get("sort_timestamp"), args.delete_failed_before_days):
            candidate["delete_reason"] = "old_failed_or_incomplete_explicit_delete"
            candidate["explicit_failed_delete"] = True
            p8_candidates.append(candidate)
        elif candidate.get("window_incomplete") or candidate.get("p8_status") != "PASS":
            candidate["retention_reason"] = "failed_or_window_incomplete_retained"
    for candidate in p8_candidates:
        if not candidate.get("verified_all_pass") and not candidate.get("explicit_failed_delete"):
            unverified_delete_without_override += 1

    snapshot_candidates: list[dict[str, Any]] = []
    cycle_candidates: list[dict[str, Any]] = []
    snapshot_records_by_probe: dict[str, list[dict[str, Any]]] = {}
    cycle_records_by_probe: dict[str, list[dict[str, Any]]] = {}
    for probe_id in args.probe_id:
        s_records = snapshot_history_records(snapshot_root, probe_id)
        c_records = e2_cycle_records(cycle_root, probe_id)
        snapshot_records_by_probe[probe_id] = s_records
        cycle_records_by_probe[probe_id] = c_records
        for record in s_records[args.keep_snapshots :]:
            candidate = dict(record)
            candidate["delete_reason"] = "old_snapshot_history"
            snapshot_candidates.append(candidate)
        for record in c_records[args.keep_cycles :]:
            candidate = dict(record)
            candidate["delete_reason"] = "old_e2_cycle"
            cycle_candidates.append(candidate)

    delete_results: list[dict[str, Any]] = []
    for candidate in p8_candidates:
        delete_results.append(delete_target(candidate, p8_root, args.apply))
    for candidate in snapshot_candidates:
        delete_results.append(delete_target(candidate, snapshot_root, args.apply))
    for candidate in cycle_candidates:
        delete_results.append(delete_target(candidate, cycle_root, args.apply))

    rollup_summary = load_json_object(resolve_path(args.p8_rollup_summary, root)) if args.p8_rollup_summary else {}
    checkpoint_reports = load_optional_reports(args.checkpoint_report, root)
    rollup_upload_requested = bool(args.rollup_upload_requested or rollup_summary.get("upload_requested"))
    rollup_uploaded_if_requested = (not rollup_upload_requested) or bool(rollup_summary.get("rollup_uploaded"))
    minio_stat_ok_if_uploaded = True
    if rollup_upload_requested:
        minio_stat_ok_if_uploaded = bool(rollup_summary.get("minio_stat_ok"))
    successful_checkpoint_reports = [report for report in checkpoint_reports if report.get("status") == "PASS"]
    skipped_checkpoint_reports = [report for report in checkpoint_reports if report.get("status") == "SKIPPED" or report.get("skipped")]
    failed_checkpoint_reports = [
        report
        for report in checkpoint_reports
        if report.get("status") not in {"PASS", "SKIPPED"} and not report.get("skipped")
    ]
    upload_relevant_checkpoint_reports = [
        report for report in checkpoint_reports if report not in skipped_checkpoint_reports
    ]
    for checkpoint_report in upload_relevant_checkpoint_reports:
        if checkpoint_report.get("upload_requested"):
            minio_stat_ok_if_uploaded = minio_stat_ok_if_uploaded and int(checkpoint_report.get("stat_failed_count") or 0) == 0
    no_large_snapshot_upload_without_allow = all(
        (not report.get("large_snapshot_upload_attempted")) or bool(report.get("allow_large_snapshot_upload"))
        for report in checkpoint_reports
    )

    delete_error_count = sum(1 for item in delete_results if item.get("error"))
    keep_recent_runs_respected = not any(candidate.get("path") in retained_p8_paths for candidate in p8_candidates)
    checks = {
        "report_json_ok": True,
        "rollup_uploaded_if_requested": rollup_uploaded_if_requested,
        "minio_stat_ok_if_uploaded": minio_stat_ok_if_uploaded,
        "deleted_only_verified_pass_runs": unverified_delete_without_override == 0,
        "keep_recent_runs_respected": keep_recent_runs_respected,
        "no_large_snapshot_upload_without_explicit_allow": no_large_snapshot_upload_without_allow,
        "delete_error_count_zero": delete_error_count == 0,
    }
    report = {
        "schema": SCHEMA_REPORT,
        "mode": "apply" if args.apply else "dry-run",
        "p8_root": str(p8_root),
        "snapshot_root": str(snapshot_root),
        "cycle_root": str(cycle_root),
        "probe_ids": args.probe_id,
        "keep_p8_runs": args.keep_p8_runs,
        "keep_snapshots": args.keep_snapshots,
        "keep_cycles": args.keep_cycles,
        "delete_failed_before_days": args.delete_failed_before_days,
        "p8_run_count": len(p8_runs),
        "p8_retained_count": len(retained_p8),
        "p8_candidate_delete_count": len(p8_candidates),
        "snapshot_candidate_delete_count": len(snapshot_candidates),
        "cycle_candidate_delete_count": len(cycle_candidates),
        "delete_error_count": delete_error_count,
        "candidate_delete_size_bytes": sum(int(item.get("size_bytes") or 0) for item in p8_candidates + snapshot_candidates + cycle_candidates),
        "p8_candidates": p8_candidates,
        "snapshot_candidates": snapshot_candidates,
        "cycle_candidates": cycle_candidates,
        "delete_results": delete_results,
        "rollup_upload_requested": rollup_upload_requested,
        "rollup_summary": rollup_summary,
        "checkpoint_report_count": len(successful_checkpoint_reports),
        "checkpoint_report_total_count": len(checkpoint_reports),
        "checkpoint_report_skipped_count": len(skipped_checkpoint_reports),
        "checkpoint_report_failed_count": len(failed_checkpoint_reports),
        "checkpoint_reports": checkpoint_reports,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "checks": checks,
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
    }
    atomic_write_json(out_dir / "retention_report.json", report)
    write_acceptance(out_dir, report)
    return 0 if all(checks.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
