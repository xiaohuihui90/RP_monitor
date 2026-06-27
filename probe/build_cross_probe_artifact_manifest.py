#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_MANIFEST = "s3.probe.cross_probe_artifact_manifest.v1"
SCHEMA_DB_PREVIEW = "s3.probe.cross_probe_artifact_db_rows_preview.v1"
DEFAULT_MINIO_BUCKET = "rpki-probe-artifacts"
DEFAULT_MINIO_PREFIX = "rp-monitor"
OUTPUT_MANIFEST = "artifact_manifest.json"
OUTPUT_DB_PREVIEW = "db_rows_preview.json"
OUTPUT_ACCEPTANCE = "P4_CROSS_PROBE_ARTIFACT_MANIFEST_ACCEPTANCE.txt"

P2_EXPECTED_ARTIFACTS = (
    ("p2_cross_probe_summary", Path("cross_probe_summary.json")),
    ("p2_cross_probe_events", Path("cross_probe_events.jsonl")),
    ("p2_candidate_events", Path("candidate_events.jsonl")),
    ("p2_acceptance_check", Path("checks") / "P2_CROSS_PROBE_DIFF_ACCEPTANCE.txt"),
)
P3_EXPECTED_ARTIFACTS = (
    ("p3_summary", Path("summary.json")),
    ("p3_persistent_events", Path("persistent_events.jsonl")),
    ("p3_semantic_divergences", Path("semantic_divergences.jsonl")),
    ("p3_transient_events", Path("transient_events.jsonl")),
    ("p3_acceptance_check", Path("checks") / "P3_CROSS_WINDOW_PERSISTENCE_ACCEPTANCE.txt"),
)


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
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8-sig") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise RuntimeError(f"expected JSON object at {path}")
    return obj


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def safe_key_part(value: Any, fallback: str) -> str:
    text = str(value or "").strip() or fallback
    text = text.replace("\\", "/").strip("/")
    text = re.sub(r"[^A-Za-z0-9._=:-]+", "_", text)
    return text or fallback


def minio_base_prefix(minio_prefix: str, window_id: str) -> str:
    base = "/".join(part for part in minio_prefix.strip("/").split("/") if part)
    window_part = f"window_id={safe_key_part(window_id, 'unknown_window')}"
    return f"{base}/cross_probe/{window_part}" if base else f"cross_probe/{window_part}"


def artifact_relative(stage: str, rel_path: Path) -> str:
    return f"{stage}/{rel_path.as_posix()}"


def is_normalized_vrp_path(path_text: str) -> bool:
    normalized = path_text.replace("\\", "/").lower()
    return "normalized_vrp.jsonl" in normalized or "latest_normalized_vrp.jsonl" in normalized


def build_artifact(
    run_dir: Path,
    stage: str,
    artifact_type: str,
    rel_path: Path,
    base_prefix: str,
) -> dict[str, Any]:
    local_path = (run_dir / rel_path).resolve()
    relative_path = artifact_relative(stage, rel_path)
    exists = local_path.is_file()
    return {
        "artifact_type": artifact_type,
        "stage": stage,
        "local_path": str(local_path),
        "relative_path": relative_path,
        "exists": exists,
        "size_bytes": local_path.stat().st_size if exists else None,
        "sha256": sha256_file(local_path) if exists else None,
        "suggested_minio_key": f"{base_prefix}/{stage}/{rel_path.as_posix()}",
    }


def extract_p2_metadata(p2_run_dir: Path) -> dict[str, Any]:
    summary_path = p2_run_dir / "cross_probe_summary.json"
    summary = load_json_object(summary_path)
    return {
        "p2_run_dir": str(p2_run_dir),
        "summary_path": str(summary_path),
        "window_id": summary.get("window_id"),
        "window_quality": summary.get("window_quality"),
        "probe_ids": summary.get("probe_ids") if isinstance(summary.get("probe_ids"), list) else [],
        "capture_time_by_probe": summary.get("capture_time_by_probe") if isinstance(summary.get("capture_time_by_probe"), dict) else {},
        "capture_time_skew_sec": summary.get("capture_time_skew_sec"),
        "event_count": summary.get("event_count"),
        "candidate_event_count": summary.get("candidate_event_count"),
        "missing_by_probe": summary.get("missing_by_probe") if isinstance(summary.get("missing_by_probe"), dict) else {},
    }


def extract_p3_metadata(p3_run_dir: Path | None) -> dict[str, Any] | None:
    if p3_run_dir is None:
        return None
    summary_path = p3_run_dir / "summary.json"
    summary = load_json_object(summary_path)
    return {
        "p3_run_dir": str(p3_run_dir),
        "summary_path": str(summary_path),
        "accepted_window_count": summary.get("accepted_window_count"),
        "persistent_event_count": summary.get("persistent_event_count"),
        "semantic_divergence_count": summary.get("semantic_divergence_count"),
        "classification_distribution": summary.get("classification_distribution") if isinstance(summary.get("classification_distribution"), dict) else {},
        "semantic_type_distribution": summary.get("semantic_type_distribution") if isinstance(summary.get("semantic_type_distribution"), dict) else {},
    }


def build_artifacts(p2_run_dir: Path, p3_run_dir: Path | None, window_id: str, minio_prefix: str) -> list[dict[str, Any]]:
    base_prefix = minio_base_prefix(minio_prefix, window_id)
    artifacts: list[dict[str, Any]] = []
    for artifact_type, rel_path in P2_EXPECTED_ARTIFACTS:
        artifacts.append(build_artifact(p2_run_dir, "p2", artifact_type, rel_path, base_prefix))
    if p3_run_dir is not None:
        for artifact_type, rel_path in P3_EXPECTED_ARTIFACTS:
            artifacts.append(build_artifact(p3_run_dir, "p3", artifact_type, rel_path, base_prefix))
    return artifacts


def no_normalized_vrp_in_manifest(artifacts: list[dict[str, Any]]) -> bool:
    for artifact in artifacts:
        for key in ("local_path", "relative_path", "suggested_minio_key"):
            if is_normalized_vrp_path(str(artifact.get(key) or "")):
                return False
    return True


def json_file_ok(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            json.load(f)
        return True
    except Exception:
        return False


def build_checks(
    manifest_path: Path,
    artifacts: list[dict[str, Any]],
    p2_run_dir: Path,
    p3_run_dir: Path | None,
) -> dict[str, bool]:
    p2_summary_path = p2_run_dir / "cross_probe_summary.json"
    p2_acceptance_path = p2_run_dir / "checks" / "P2_CROSS_PROBE_DIFF_ACCEPTANCE.txt"
    checks = {
        "manifest_json_ok": json_file_ok(manifest_path),
        "artifact_count_gt_zero": len(artifacts) > 0,
        "all_artifacts_exist": all(bool(artifact.get("exists")) for artifact in artifacts),
        "sha256_generated": all(bool(artifact.get("sha256")) for artifact in artifacts),
        "p2_summary_present": p2_summary_path.is_file(),
        "p2_acceptance_present": p2_acceptance_path.is_file(),
        "no_normalized_vrp_in_manifest": no_normalized_vrp_in_manifest(artifacts),
    }
    if p3_run_dir is not None:
        checks["p3_summary_present"] = (p3_run_dir / "summary.json").is_file()
        checks["p3_acceptance_present"] = (p3_run_dir / "checks" / "P3_CROSS_WINDOW_PERSISTENCE_ACCEPTANCE.txt").is_file()
    return checks


def acceptance_text(
    status: str,
    checks: dict[str, bool],
    manifest: dict[str, Any],
    manifest_path: Path,
    db_preview_path: Path,
) -> str:
    p2 = manifest.get("p2") if isinstance(manifest.get("p2"), dict) else {}
    p3 = manifest.get("p3") if isinstance(manifest.get("p3"), dict) else None
    lines = [
        f"P4_CROSS_PROBE_ARTIFACT_MANIFEST={status}",
        f"p2_run_dir={p2.get('p2_run_dir') or ''}",
        f"p3_run_dir={(p3 or {}).get('p3_run_dir') or ''}",
        f"window_id={p2.get('window_id') or ''}",
        f"window_quality={p2.get('window_quality') or ''}",
        f"artifact_count={manifest.get('artifact_count')}",
        f"total_size_bytes={manifest.get('total_size_bytes')}",
        f"manifest_json={manifest_path}",
        f"db_rows_preview_json={db_preview_path}",
        f"minio_bucket={manifest.get('minio', {}).get('bucket') if isinstance(manifest.get('minio'), dict) else ''}",
        f"minio_prefix={manifest.get('minio', {}).get('prefix') if isinstance(manifest.get('minio'), dict) else ''}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={str(value).lower()}" for key, value in checks.items())
    return "\n".join(lines) + "\n"


def build_db_rows_preview(manifest: dict[str, Any]) -> dict[str, Any]:
    p2 = manifest.get("p2") if isinstance(manifest.get("p2"), dict) else {}
    p3 = manifest.get("p3") if isinstance(manifest.get("p3"), dict) else None
    artifacts = manifest.get("artifacts") if isinstance(manifest.get("artifacts"), list) else []
    window_row = {
        "table": "cross_probe_windows",
        "window_id": p2.get("window_id"),
        "window_quality": p2.get("window_quality"),
        "probe_ids_json": p2.get("probe_ids"),
        "capture_time_by_probe_json": p2.get("capture_time_by_probe"),
        "capture_time_skew_sec": p2.get("capture_time_skew_sec"),
        "event_count": p2.get("event_count"),
        "candidate_event_count": p2.get("candidate_event_count"),
        "missing_by_probe_json": p2.get("missing_by_probe"),
    }
    p3_row = None
    if isinstance(p3, dict):
        p3_row = {
            "table": "cross_probe_persistence_runs",
            "window_id": p2.get("window_id"),
            "accepted_window_count": p3.get("accepted_window_count"),
            "persistent_event_count": p3.get("persistent_event_count"),
            "semantic_divergence_count": p3.get("semantic_divergence_count"),
            "classification_distribution_json": p3.get("classification_distribution"),
            "semantic_type_distribution_json": p3.get("semantic_type_distribution"),
        }
    artifact_rows = [
        {
            "table": "cross_probe_artifacts",
            "window_id": p2.get("window_id"),
            "stage": artifact.get("stage"),
            "artifact_type": artifact.get("artifact_type"),
            "relative_path": artifact.get("relative_path"),
            "size_bytes": artifact.get("size_bytes"),
            "sha256": artifact.get("sha256"),
            "minio_bucket": manifest.get("minio", {}).get("bucket") if isinstance(manifest.get("minio"), dict) else None,
            "minio_key": artifact.get("suggested_minio_key"),
            "local_path": artifact.get("local_path"),
        }
        for artifact in artifacts
    ]
    tables: dict[str, list[dict[str, Any]]] = {
        "cross_probe_windows": [window_row],
        "cross_probe_artifacts": artifact_rows,
    }
    if p3_row is not None:
        tables["cross_probe_persistence_runs"] = [p3_row]
    return {
        "schema": SCHEMA_DB_PREVIEW,
        "generated_at_utc": utc_now(),
        "note": "Preview only: this script does not connect to MinIO or a database.",
        "tables": tables,
    }


def build_manifest(args: argparse.Namespace) -> dict[str, Any]:
    p2_run_dir = Path(args.p2_run_dir).resolve()
    p3_run_dir = Path(args.p3_run_dir).resolve() if args.p3_run_dir else None
    if not p2_run_dir.is_dir():
        raise RuntimeError(f"P2 run directory not found: {p2_run_dir}")
    if p3_run_dir is not None and not p3_run_dir.is_dir():
        raise RuntimeError(f"P3 run directory not found: {p3_run_dir}")

    p2_metadata = extract_p2_metadata(p2_run_dir)
    window_id = str(p2_metadata.get("window_id") or p2_run_dir.name)
    artifacts = build_artifacts(p2_run_dir, p3_run_dir, window_id, args.minio_prefix)
    total_size = sum(int(artifact["size_bytes"] or 0) for artifact in artifacts)
    return {
        "schema": SCHEMA_MANIFEST,
        "generated_at_utc": utc_now(),
        "p2": p2_metadata,
        "p3": extract_p3_metadata(p3_run_dir),
        "artifact_count": len(artifacts),
        "total_size_bytes": total_size,
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
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / OUTPUT_MANIFEST
    db_preview_path = out_dir / OUTPUT_DB_PREVIEW
    acceptance_path = out_dir / "checks" / OUTPUT_ACCEPTANCE

    manifest = build_manifest(args)
    manifest["outputs"] = {
        "artifact_manifest": str(manifest_path),
        "db_rows_preview": str(db_preview_path),
        "acceptance": str(acceptance_path),
    }
    db_preview = build_db_rows_preview(manifest)

    atomic_write_json(manifest_path, manifest)
    atomic_write_json(db_preview_path, db_preview)
    checks = build_checks(
        manifest_path=manifest_path,
        artifacts=manifest["artifacts"],
        p2_run_dir=Path(args.p2_run_dir).resolve(),
        p3_run_dir=Path(args.p3_run_dir).resolve() if args.p3_run_dir else None,
    )
    status = "PASS" if all(checks.values()) else "FAIL"
    atomic_write_text(acceptance_path, acceptance_text(status, checks, manifest, manifest_path, db_preview_path))
    result = dict(manifest)
    result["acceptance_status"] = status
    result["acceptance_checks"] = checks
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return result


def write_json(path: Path, obj: Any) -> None:
    atomic_write_json(path, obj)


def write_text(path: Path, text: str) -> None:
    atomic_write_text(path, text)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    text = "".join(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for row in rows)
    atomic_write_text(path, text)


def make_self_test_inputs(root: Path) -> tuple[Path, Path]:
    p2 = root / "p2_run"
    p3 = root / "p3_run"
    (p2 / "checks").mkdir(parents=True, exist_ok=True)
    (p3 / "checks").mkdir(parents=True, exist_ok=True)
    p2_summary = {
        "schema": "s3.probe.cross_probe_vrp_diff_summary.v1",
        "window_id": "win_20260625T000000Z_1h",
        "window_quality": "OK",
        "probe_ids": ["probe-a", "probe-b", "probe-c"],
        "capture_time_by_probe": {
            "probe-a": "2026-06-25T00:00:00Z",
            "probe-b": "2026-06-25T00:01:00Z",
            "probe-c": "2026-06-25T00:02:00Z",
        },
        "capture_time_skew_sec": 120,
        "event_count": 2,
        "candidate_event_count": 1,
        "missing_by_probe": {"probe-b": 1},
        "causal_claim_allowed_count": 0,
        "root_cause_confirmed": False,
    }
    event = {
        "schema": "s3.probe.cross_probe_vrp_diff_event.v1",
        "event_id": "xevt_self_test",
        "event_type": "CROSS_PROBE_MISSING",
        "window_id": p2_summary["window_id"],
        "vrp_key": "apnic|64500|203.0.113.0/24|24",
        "tal": "apnic",
        "asn": 64500,
        "prefix": "203.0.113.0/24",
        "max_length": 24,
        "present_probes": ["probe-a", "probe-c"],
        "missing_probes": ["probe-b"],
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
    }
    p3_summary = {
        "schema": "s3.probe.cross_window_persistence_summary.v1",
        "status": "PASS",
        "accepted_window_count": 3,
        "persistent_event_count": 1,
        "semantic_divergence_count": 1,
        "classification_distribution": {"PERSISTENT_VIEW_DIVERGENCE": 1},
        "semantic_type_distribution": {"ORIGIN_SET_DIVERGENCE": 1},
        "causal_claim_allowed_count": 0,
        "root_cause_confirmed": False,
    }
    persistent = {
        "schema": "s3.probe.cross_window_persistence_event.v1",
        "event_id": "p3evt_self_test",
        "classification": "PERSISTENT_VIEW_DIVERGENCE",
        "vrp_key": event["vrp_key"],
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
    }
    semantic = {
        "schema": "s3.probe.cross_window_semantic_divergence.v1",
        "event_id": "p3sem_self_test",
        "semantic_type": "ORIGIN_SET_DIVERGENCE",
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
    }
    transient = {
        "schema": "s3.probe.cross_window_persistence_event.v1",
        "event_id": "p3evt_transient_self_test",
        "classification": "SINGLE_WINDOW_TRANSIENT",
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
    }

    write_json(p2 / "cross_probe_summary.json", p2_summary)
    write_jsonl(p2 / "cross_probe_events.jsonl", [event])
    write_jsonl(p2 / "candidate_events.jsonl", [event])
    write_text(p2 / "checks" / "P2_CROSS_PROBE_DIFF_ACCEPTANCE.txt", "P2_CROSS_PROBE_DIFF=PASS\n")
    write_text(p2 / "latest_normalized_vrp.jsonl", "{}\n")

    write_json(p3 / "summary.json", p3_summary)
    write_jsonl(p3 / "persistent_events.jsonl", [persistent])
    write_jsonl(p3 / "semantic_divergences.jsonl", [semantic])
    write_jsonl(p3 / "transient_events.jsonl", [transient])
    write_text(p3 / "checks" / "P3_CROSS_WINDOW_PERSISTENCE_ACCEPTANCE.txt", "P3_CROSS_WINDOW_PERSISTENCE=PASS\n")
    write_text(p3 / "normalized_vrp.jsonl", "{}\n")
    return p2, p3


def run_self_test(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).resolve()
    input_root = out_dir / "self_test_inputs"
    p2, p3 = make_self_test_inputs(input_root)
    test_args = argparse.Namespace(
        p2_run_dir=str(p2),
        p3_run_dir=str(p3),
        out_dir=str(out_dir),
        minio_bucket=args.minio_bucket,
        minio_prefix=args.minio_prefix,
        self_test=False,
    )
    result = run(test_args)
    checks = result.get("acceptance_checks") if isinstance(result.get("acceptance_checks"), dict) else {}
    manifest_path = out_dir / OUTPUT_MANIFEST
    manifest = load_json_object(manifest_path)
    artifact_keys = [artifact.get("suggested_minio_key") for artifact in manifest.get("artifacts", [])]
    self_checks = {
        "acceptance_pass": result.get("acceptance_status") == "PASS",
        "manifest_json_ok": checks.get("manifest_json_ok") is True,
        "p2_artifacts_present": any("/p2/cross_probe_summary.json" in str(key) for key in artifact_keys),
        "p3_artifacts_present": any("/p3/summary.json" in str(key) for key in artifact_keys),
        "no_normalized_vrp": checks.get("no_normalized_vrp_in_manifest") is True,
        "window_prefix_present": all("/cross_probe/window_id=win_20260625T000000Z_1h/" in str(key) for key in artifact_keys),
    }
    if not all(self_checks.values()):
        print(json.dumps({"self_test_checks": self_checks, "result": result}, ensure_ascii=False, indent=2, sort_keys=True), file=sys.stderr)
        return 1
    print("[P4 self-test] PASS " + json.dumps(self_checks, sort_keys=True), file=sys.stderr)
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a cross-probe P2/P3 artifact manifest and DB rows preview.")
    parser.add_argument("--p2-run-dir", help="P2 run directory containing cross_probe_summary.json and cross-probe event artifacts.")
    parser.add_argument("--p3-run-dir", help="Optional P3 run directory containing persistence outputs.")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--minio-bucket", default=DEFAULT_MINIO_BUCKET)
    parser.add_argument("--minio-prefix", default=DEFAULT_MINIO_PREFIX)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if not args.self_test and not args.p2_run_dir:
        parser.error("--p2-run-dir is required unless --self-test is used")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test(args)
    result = run(args)
    return 0 if result.get("acceptance_status") == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
