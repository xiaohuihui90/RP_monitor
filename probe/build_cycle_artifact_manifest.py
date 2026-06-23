#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_MANIFEST = "s3.probe.live_msal_cycle_artifact_manifest.v1"
SCHEMA_DB_PREVIEW = "s3.probe.live_msal_cycle_db_rows_preview.v1"
DEFAULT_MINIO_PREFIX = "rp-monitor/live-msal-cycles"
OUTPUT_MANIFEST = "artifact_manifest.json"
OUTPUT_DB_PREVIEW = "db_rows_preview.json"
OUTPUT_ACCEPTANCE = "E4_ARTIFACT_MANIFEST_ACCEPTANCE.txt"


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
    atomic_write_bytes(path, (json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def load_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8-sig") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise RuntimeError(f"expected JSON object at {path}")
    return obj


def parse_key_value_file(path: Path) -> dict[str, str]:
    if not path.exists():
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


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def safe_key_part(value: Any, fallback: str) -> str:
    text = str(value or "").strip() or fallback
    text = text.replace("\\", "/").strip("/")
    text = re.sub(r"[^A-Za-z0-9._=:/-]+", "_", text)
    return text or fallback


def build_minio_run_prefix(minio_prefix: str, probe_id: str, run_id: str) -> str:
    base_parts = [part for part in minio_prefix.strip("/").split("/") if part]
    probe_segment = f"probe_id={probe_id}"
    run_segment = f"run_id={run_id}"
    if base_parts and base_parts[-1] == probe_segment:
        return "/".join([*base_parts, run_segment])
    return "/".join([*base_parts, probe_segment, run_segment])


def posix_relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def get_nested(obj: dict[str, Any], path: list[str]) -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def classify_artifact(relative_path: str) -> str:
    rel = relative_path.replace("\\", "/")
    name = Path(rel).name
    if rel == "cycle_summary.json":
        return "cycle_summary"
    if rel == "artifact_manifest.json":
        return "artifact_manifest"
    if rel == "db_rows_preview.json":
        return "db_rows_preview"
    if rel == "checks/E2_LIVE_MSAL_CYCLE_ACCEPTANCE.txt":
        return "e2_acceptance_check"
    if rel.endswith("/run_summary.json") or rel == "e1_run/run_summary.json":
        return "e1_run_summary"
    if rel.endswith("/diff/events.jsonl"):
        return "vrp_diff_events"
    if rel.endswith("/diff/summary.json"):
        return "vrp_diff_summary"
    if rel.endswith("/msal/attribution_records.jsonl"):
        return "msal_attribution_records"
    if rel.endswith("/msal/latest_attribution_records.jsonl"):
        return "msal_latest_attribution_records"
    if rel.endswith("/msal/summary.json"):
        return "msal_summary"
    if rel.endswith("/msal/latest_msal_summary.json"):
        return "msal_latest_summary"
    if rel.endswith("/msal/index_stats.json"):
        return "msal_index_stats"
    if name.endswith(".jsonl"):
        return "jsonl_artifact"
    if name.endswith(".json"):
        return "json_artifact"
    if name.endswith(".csv"):
        return "csv_artifact"
    if name.endswith(".txt"):
        return "text_artifact"
    if name.endswith(".log"):
        return "log_artifact"
    return "other_artifact"


def should_skip_artifact(path: Path, output_paths: set[Path]) -> bool:
    if not path.is_file():
        return True
    resolved = path.resolve()
    if resolved in output_paths:
        return True
    if ".tmp." in path.name:
        return True
    return False


def extract_cycle_metadata(cycle_run_dir: Path) -> dict[str, Any]:
    cycle_summary_path = cycle_run_dir / "cycle_summary.json"
    acceptance_path = cycle_run_dir / "checks" / "E2_LIVE_MSAL_CYCLE_ACCEPTANCE.txt"
    cycle_summary = load_json_object(cycle_summary_path)
    acceptance = parse_key_value_file(acceptance_path)
    e1_summary = cycle_summary.get("e1_summary") if isinstance(cycle_summary.get("e1_summary"), dict) else {}
    diff_summary = e1_summary.get("diff") if isinstance(e1_summary.get("diff"), dict) else {}
    msal_summary = e1_summary.get("msal") if isinstance(e1_summary.get("msal"), dict) else {}

    event_count = as_int(diff_summary.get("event_count"))
    if event_count is None:
        event_count = as_int(acceptance.get("event_count"))
    msal_output_record_count = as_int(msal_summary.get("output_record_count"))
    if msal_output_record_count is None:
        msal_output_record_count = as_int(acceptance.get("msal_output_record_count"))

    probe_id = cycle_summary.get("probe_id") or acceptance.get("probe_id") or "unknown_probe"
    run_id = cycle_summary.get("run_id") or cycle_run_dir.name
    snapshot_id = cycle_summary.get("new_snapshot_id") or cycle_summary.get("curr_snapshot_id") or acceptance.get("curr_snapshot_id")

    return {
        "probe_id": probe_id,
        "run_id": run_id,
        "cycle_run_dir": str(cycle_run_dir),
        "snapshot_id": snapshot_id,
        "prev_snapshot_id": cycle_summary.get("prev_snapshot_id") or acceptance.get("prev_snapshot_id"),
        "curr_snapshot_id": cycle_summary.get("curr_snapshot_id") or acceptance.get("curr_snapshot_id"),
        "event_count": event_count,
        "msal_output_record_count": msal_output_record_count,
        "evidence_level_distribution": msal_summary.get("evidence_level_distribution") if isinstance(msal_summary.get("evidence_level_distribution"), dict) else {},
        "tal_distribution": msal_summary.get("by_tal") if isinstance(msal_summary.get("by_tal"), dict) else {},
        "status": cycle_summary.get("status") or acceptance.get("E2_LIVE_MSAL_CYCLE"),
        "started_at_utc": cycle_summary.get("started_at_utc"),
        "finished_at_utc": cycle_summary.get("finished_at_utc"),
        "duration_sec": cycle_summary.get("duration_sec"),
        "source_files": {
            "cycle_summary": str(cycle_summary_path),
            "e2_acceptance": str(acceptance_path),
        },
    }


def build_artifacts(cycle_run_dir: Path, minio_prefix: str, metadata: dict[str, Any], output_paths: set[Path]) -> list[dict[str, Any]]:
    probe_id = safe_key_part(metadata.get("probe_id"), "unknown_probe")
    run_id = safe_key_part(metadata.get("run_id"), cycle_run_dir.name)
    run_prefix = build_minio_run_prefix(minio_prefix, probe_id, run_id)
    artifacts: list[dict[str, Any]] = []
    for path in sorted(cycle_run_dir.rglob("*")):
        if should_skip_artifact(path, output_paths):
            continue
        relative_path = posix_relative(path, cycle_run_dir)
        artifacts.append(
            {
                "artifact_type": classify_artifact(relative_path),
                "local_path": str(path.resolve()),
                "relative_path": relative_path,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "suggested_minio_key": f"{run_prefix}/{relative_path}",
            }
        )
    return artifacts


def count_duplicate_probe_id_keys(artifacts: list[dict[str, Any]], probe_id: Any) -> int:
    probe_segment = f"probe_id={safe_key_part(probe_id, 'unknown_probe')}"
    duplicate_count = 0
    for artifact in artifacts:
        key = str(artifact.get("suggested_minio_key") or "")
        segments = [segment for segment in key.split("/") if segment]
        if segments.count(probe_segment) > 1:
            duplicate_count += 1
    return duplicate_count


def count_missing_artifacts(artifacts: list[dict[str, Any]]) -> int:
    missing_count = 0
    for artifact in artifacts:
        local_path = artifact.get("local_path")
        if not local_path or not Path(str(local_path)).is_file():
            missing_count += 1
    return missing_count


def json_file_valid(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            json.load(f)
        return True
    except Exception:
        return False


def bool_text(value: bool) -> str:
    return "true" if value else "false"


def build_acceptance_text(manifest: dict[str, Any], manifest_path: Path, db_preview_path: Path) -> str:
    metadata = manifest.get("cycle_metadata") if isinstance(manifest.get("cycle_metadata"), dict) else {}
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    manifest_json_valid = json_file_valid(manifest_path)
    db_rows_preview_json_valid = json_file_valid(db_preview_path)
    artifact_count = as_int(manifest.get("artifact_count")) or 0
    total_size_bytes = as_int(manifest.get("total_size_bytes")) or 0
    cycle_status = str(metadata.get("status") or "")
    duplicate_probe_id_key_count = count_duplicate_probe_id_keys(artifacts, metadata.get("probe_id"))
    missing_artifact_count = count_missing_artifacts(artifacts)
    checks = {
        "manifest_json_valid": manifest_json_valid,
        "db_rows_preview_json_valid": db_rows_preview_json_valid,
        "artifact_count_gt_zero": artifact_count > 0,
        "cycle_status_pass": cycle_status == "PASS",
        "duplicate_probe_id_key_count_zero": duplicate_probe_id_key_count == 0,
        "missing_artifact_count_zero": missing_artifact_count == 0,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    minio = manifest.get("minio") if isinstance(manifest.get("minio"), dict) else {}
    lines = [
        f"E4_ARTIFACT_MANIFEST={status}",
        f"cycle_run_dir={metadata.get('cycle_run_dir') or ''}",
        f"run_id={metadata.get('run_id') or ''}",
        f"probe_id={metadata.get('probe_id') or ''}",
        f"cycle_status={cycle_status}",
        f"artifact_count={artifact_count}",
        f"total_size_bytes={total_size_bytes}",
        f"manifest_json={manifest_path}",
        f"db_rows_preview_json={db_preview_path}",
        f"minio_bucket={minio.get('bucket') or ''}",
        f"minio_prefix={minio.get('prefix') or ''}",
        f"duplicate_probe_id_key_count={duplicate_probe_id_key_count}",
        f"missing_artifact_count={missing_artifact_count}",
        "",
        "[checks]",
    ]
    lines.extend(f"{name}={bool_text(value)}" for name, value in checks.items())
    return "\n".join(lines) + "\n"


def build_db_rows_preview(metadata: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    run_row = {
        "table": "live_msal_cycle_runs",
        "probe_id": metadata.get("probe_id"),
        "run_id": metadata.get("run_id"),
        "snapshot_id": metadata.get("snapshot_id"),
        "prev_snapshot_id": metadata.get("prev_snapshot_id"),
        "curr_snapshot_id": metadata.get("curr_snapshot_id"),
        "status": metadata.get("status"),
        "event_count": metadata.get("event_count"),
        "msal_output_record_count": metadata.get("msal_output_record_count"),
        "evidence_level_distribution_json": metadata.get("evidence_level_distribution"),
        "tal_distribution_json": metadata.get("tal_distribution"),
        "started_at_utc": metadata.get("started_at_utc"),
        "finished_at_utc": metadata.get("finished_at_utc"),
        "duration_sec": metadata.get("duration_sec"),
    }
    artifact_rows = []
    for artifact in artifacts:
        artifact_rows.append(
            {
                "table": "live_msal_cycle_artifacts",
                "probe_id": metadata.get("probe_id"),
                "run_id": metadata.get("run_id"),
                "artifact_type": artifact["artifact_type"],
                "relative_path": artifact["relative_path"],
                "size_bytes": artifact["size_bytes"],
                "sha256": artifact["sha256"],
                "minio_key": artifact["suggested_minio_key"],
                "local_path": artifact["local_path"],
            }
        )
    metric_rows = []
    for level, count in sorted((metadata.get("evidence_level_distribution") or {}).items()):
        metric_rows.append(
            {
                "table": "live_msal_cycle_metric_counts",
                "probe_id": metadata.get("probe_id"),
                "run_id": metadata.get("run_id"),
                "metric_group": "evidence_level",
                "metric_name": str(level),
                "metric_count": count,
            }
        )
    for tal, count in sorted((metadata.get("tal_distribution") or {}).items()):
        metric_rows.append(
            {
                "table": "live_msal_cycle_metric_counts",
                "probe_id": metadata.get("probe_id"),
                "run_id": metadata.get("run_id"),
                "metric_group": "tal",
                "metric_name": str(tal),
                "metric_count": count,
            }
        )

    return {
        "schema": SCHEMA_DB_PREVIEW,
        "generated_at_utc": utc_now(),
        "note": "Preview only: this script does not connect to MinIO or any database.",
        "tables": {
            "live_msal_cycle_runs": [run_row],
            "live_msal_cycle_artifacts": artifact_rows,
            "live_msal_cycle_metric_counts": metric_rows,
        },
    }


def build_manifest(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    cycle_run_dir = Path(args.cycle_run_dir).resolve()
    if not cycle_run_dir.is_dir():
        raise RuntimeError(f"cycle run directory not found: {cycle_run_dir}")
    out_dir = Path(args.out_dir).resolve() if args.out_dir else cycle_run_dir
    manifest_path = out_dir / OUTPUT_MANIFEST
    db_preview_path = out_dir / OUTPUT_DB_PREVIEW
    acceptance_path = out_dir / "checks" / OUTPUT_ACCEPTANCE
    output_paths = {manifest_path.resolve(), db_preview_path.resolve(), acceptance_path.resolve()}

    metadata = extract_cycle_metadata(cycle_run_dir)
    artifacts = build_artifacts(cycle_run_dir, args.minio_prefix, metadata, output_paths)
    total_size_bytes = sum(as_int(artifact.get("size_bytes")) or 0 for artifact in artifacts)
    manifest = {
        "schema": SCHEMA_MANIFEST,
        "generated_at_utc": utc_now(),
        "cycle_metadata": metadata,
        "artifact_count": len(artifacts),
        "total_size_bytes": total_size_bytes,
        "minio": {
            "mode": "suggested_keys_only",
            "connected": False,
            "bucket": args.minio_bucket,
            "prefix": args.minio_prefix.strip("/"),
        },
        "database": {
            "mode": "db_rows_preview_only",
            "connected": False,
        },
        "artifacts": artifacts,
        "outputs": {
            "artifact_manifest": str(manifest_path),
            "db_rows_preview": str(db_preview_path),
            "e4_acceptance": str(acceptance_path),
        },
    }
    db_preview = build_db_rows_preview(metadata, artifacts)
    return manifest, db_preview


def run(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = Path(args.out_dir).resolve() if args.out_dir else Path(args.cycle_run_dir).resolve()
    manifest_path = out_dir / OUTPUT_MANIFEST
    db_preview_path = out_dir / OUTPUT_DB_PREVIEW
    acceptance_path = out_dir / "checks" / OUTPUT_ACCEPTANCE
    manifest, db_preview = build_manifest(args)
    atomic_write_json(manifest_path, manifest)
    atomic_write_json(db_preview_path, db_preview)
    atomic_write_text(acceptance_path, build_acceptance_text(manifest, manifest_path, db_preview_path))
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))
    return manifest


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build an offline artifact manifest and DB row preview for one E2 live MSAL cycle.")
    parser.add_argument("--cycle-run-dir", required=True, help="E2 cycle run directory containing cycle_summary.json.")
    parser.add_argument("--out-dir", help="Output directory for artifact_manifest.json and db_rows_preview.json. Defaults to cycle-run-dir.")
    parser.add_argument("--minio-prefix", default=DEFAULT_MINIO_PREFIX, help="Suggested MinIO object key prefix.")
    parser.add_argument("--minio-bucket", default="rpki-probe-artifacts", help="Suggested future MinIO bucket name.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        raise SystemExit(1)