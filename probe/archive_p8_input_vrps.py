#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_MANIFEST = "s3.probe.p8_input_vrp_manifest.v1"
ACCEPTANCE_FILE = "checks/P8_INPUT_VRP_ARCHIVE_ACCEPTANCE.txt"
DEFAULT_INPUTS = {
    "probe-cd": {
        "metadata": "data/probe/live_vrp_snapshots/probe-cd/latest_metadata.json",
        "vrp": "data/probe/live_vrp_snapshots/probe-cd/latest_normalized_vrp.jsonl",
    },
    "probe-sg": {
        "metadata": "data/probe/remote_snapshots/probe-sg/latest_metadata.json",
        "vrp": "data/probe/remote_snapshots/probe-sg/latest_normalized_vrp.jsonl",
    },
    "probe-k02": {
        "metadata": "data/probe/remote_snapshots/probe-k02/latest_metadata.json",
        "vrp": "data/probe/remote_snapshots/probe-k02/latest_normalized_vrp.jsonl",
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_path(value: str, root: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()


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


def parse_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"expected true or false, got {value}")


def parse_key_value_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    parsed: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("[") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip().lstrip("\ufeff")] = value.strip()
    return parsed


def parse_probe_ids(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def parse_assignment(value: str, option_name: str) -> tuple[str, str]:
    if "=" not in value:
        raise ValueError(f"{option_name} must be PROBE_ID=PATH, got {value}")
    probe_id, path = value.split("=", 1)
    probe_id = probe_id.strip()
    path = path.strip()
    if not probe_id or not path:
        raise ValueError(f"{option_name} must be PROBE_ID=PATH, got {value}")
    return probe_id, path


def parse_assignments(values: list[str], option_name: str) -> dict[str, str]:
    parsed = {}
    for value in values:
        probe_id, path = parse_assignment(value, option_name)
        parsed[probe_id] = path
    return parsed


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def load_p8_summary(p8_run_dir: Path) -> dict[str, Any]:
    for rel in ("cross_probe_summary.json", "p2/cross_probe_summary.json", "pipeline_summary.json"):
        path = p8_run_dir / rel
        if path.is_file():
            obj = load_json_object(path)
            if obj:
                return obj
    return {}


def metadata_capture_time(metadata: dict[str, Any]) -> str:
    value = metadata.get("capture_time_utc")
    if value:
        return str(value)
    raw = metadata.get("raw_metadata")
    if isinstance(raw, dict) and raw.get("generatedTime"):
        return str(raw["generatedTime"])
    return ""


def copy_file_atomic(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f"{dest.name}.tmp.{os.getpid()}.{time.time_ns()}")
    with src.open("rb") as inf, tmp.open("wb") as outf:
        shutil.copyfileobj(inf, outf, length=1024 * 1024)
        outf.flush()
        os.fsync(outf.fileno())
    os.replace(tmp, dest)
    fsync_parent(dest)


def gzip_file_atomic(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(f"{dest.name}.tmp.{os.getpid()}.{time.time_ns()}")
    with src.open("rb") as inf, tmp.open("wb") as raw_out:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_out, compresslevel=6, mtime=0) as outf:
            shutil.copyfileobj(inf, outf, length=1024 * 1024)
        raw_out.flush()
        os.fsync(raw_out.fileno())
    os.replace(tmp, dest)
    fsync_parent(dest)


def write_sha256sums(path: Path, entries: list[tuple[str, Path]]) -> None:
    lines = []
    for rel_name, file_path in entries:
        digest = sha256_file(file_path).split(":", 1)[1]
        lines.append(f"{digest}  {rel_name}")
    atomic_write_text(path, "\n".join(lines) + "\n")


def minio_dest(prefix: str, window_id: str, probe_id: str | None = None) -> str:
    base = prefix.rstrip("/") + f"/p8_input_vrps/window_id={window_id}"
    if probe_id:
        base += f"/probe_id={probe_id}"
    return base


def mc_copy_and_stat(mc_bin: str, local_path: Path, remote: str) -> dict[str, Any]:
    result = {"local_path": str(local_path), "remote": remote, "cp_exit_code": None, "stat_exit_code": None, "ok": False, "error": ""}
    cp = subprocess.run([mc_bin, "cp", str(local_path), remote], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result["cp_exit_code"] = cp.returncode
    if cp.returncode != 0:
        result["error"] = (cp.stderr or cp.stdout or "")[-4000:]
        return result
    stat = subprocess.run([mc_bin, "stat", remote.rstrip("/") + "/" + local_path.name], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result["stat_exit_code"] = stat.returncode
    result["ok"] = stat.returncode == 0
    if stat.returncode != 0:
        result["error"] = (stat.stderr or stat.stdout or "")[-4000:]
    return result


def stable_input_path(input_root: Path, probe_id: str, filename: str) -> Path:
    return input_root / f"probe_id={probe_id}" / filename


def build_inputs(
    root: Path,
    metadata_overrides: list[str],
    vrp_overrides: list[str],
    source_mode: str,
    input_root_value: str | None,
) -> dict[str, dict[str, Path | str]]:
    metadata = {probe_id: item["metadata"] for probe_id, item in DEFAULT_INPUTS.items()}
    vrps = {probe_id: item["vrp"] for probe_id, item in DEFAULT_INPUTS.items()}
    metadata.update(parse_assignments(metadata_overrides, "--metadata"))
    vrps.update(parse_assignments(vrp_overrides, "--vrp"))
    probes = sorted(set(metadata) | set(vrps))
    input_root = resolve_path(input_root_value, root) if input_root_value else Path("")
    inputs: dict[str, dict[str, Path | str]] = {}
    for probe_id in probes:
        original_metadata = resolve_path(metadata.get(probe_id, ""), root) if metadata.get(probe_id) else Path("")
        original_vrp = resolve_path(vrps.get(probe_id, ""), root) if vrps.get(probe_id) else Path("")
        if source_mode == "stable_copy":
            if not input_root_value:
                raise ValueError("--input-root is required when --source-mode stable_copy")
            metadata_path = stable_input_path(input_root, probe_id, "latest_metadata.json")
            vrp_path = stable_input_path(input_root, probe_id, "latest_normalized_vrp.jsonl")
            stable_metadata = metadata_path
            stable_vrp = vrp_path
        else:
            metadata_path = original_metadata
            vrp_path = original_vrp
            stable_metadata = Path("")
            stable_vrp = Path("")
        inputs[probe_id] = {
            "metadata": metadata_path,
            "vrp": vrp_path,
            "source_metadata": str(original_metadata),
            "source_vrp": str(original_vrp),
            "stable_metadata": str(stable_metadata) if source_mode == "stable_copy" else "",
            "stable_vrp": str(stable_vrp) if source_mode == "stable_copy" else "",
        }
    return inputs


def run_archive(args: argparse.Namespace) -> int:
    root = repo_root()
    started_at = utc_now()
    p8_run_dir = resolve_path(args.p8_run_dir, root)
    p8_acceptance_path = p8_run_dir / "checks" / "P8_CROSS_PROBE_PIPELINE_ACCEPTANCE.txt"
    p8_acceptance = parse_key_value_file(p8_acceptance_path)
    p8_summary = load_p8_summary(p8_run_dir)
    p8_status = p8_acceptance.get("P8_CROSS_PROBE_PIPELINE") or p8_acceptance.get("P8_CROSS_PROBE_OBSERVATION") or ""
    window_id = p8_acceptance.get("window_id", "") or str(p8_summary.get("window_id") or "")
    window_quality = p8_acceptance.get("window_quality", "") or str(p8_summary.get("window_quality") or "")
    p8_probe_ids = parse_probe_ids(p8_acceptance.get("probe_ids")) or parse_probe_ids(p8_summary.get("probe_ids"))
    if not p8_status and p8_summary and window_quality == "OK":
        p8_status = "PASS"
    snapshot_id_by_probe = p8_summary.get("snapshot_id_by_probe") if isinstance(p8_summary.get("snapshot_id_by_probe"), dict) else {}
    capture_time_by_probe = p8_summary.get("capture_time_by_probe") if isinstance(p8_summary.get("capture_time_by_probe"), dict) else {}
    vrp_count_by_probe = p8_summary.get("vrp_record_count_by_probe") if isinstance(p8_summary.get("vrp_record_count_by_probe"), dict) else {}

    out_base = resolve_path(args.out_dir, root)
    out_dir = out_base / f"window_id={window_id}" if window_id and out_base.name != f"window_id={window_id}" else out_base
    out_dir.mkdir(parents=True, exist_ok=True)

    inputs = build_inputs(root, args.metadata or [], args.vrp or [], args.source_mode, args.input_root)
    probe_ids = p8_probe_ids or sorted(inputs)
    probe_records: dict[str, Any] = {}
    missing_inputs: list[str] = []
    mismatches: list[str] = []
    warnings: list[str] = []

    if p8_status != "PASS" or window_quality != "OK":
        warnings.append("P8_NOT_PASS_OR_WINDOW_NOT_OK")

    for probe_id in probe_ids:
        srcs = inputs.get(probe_id, {})
        metadata_src = Path(str(srcs.get("metadata", "")))
        vrp_src = Path(str(srcs.get("vrp", "")))
        if not metadata_src.is_file():
            missing_inputs.append(f"{probe_id}:metadata")
            continue
        if not vrp_src.is_file():
            missing_inputs.append(f"{probe_id}:vrp")
            continue

        metadata_obj = load_json_object(metadata_src)
        snapshot_id = str(metadata_obj.get("snapshot_id") or "")
        capture_time = metadata_capture_time(metadata_obj)
        expected_snapshot = str(snapshot_id_by_probe.get(probe_id) or "")
        expected_capture = str(capture_time_by_probe.get(probe_id) or "")
        if expected_snapshot and snapshot_id and expected_snapshot != snapshot_id:
            mismatches.append(f"{probe_id}:snapshot_id")
        if expected_capture and capture_time and expected_capture != capture_time:
            mismatches.append(f"{probe_id}:capture_time_utc")

        probe_dir = out_dir / f"probe_id={probe_id}"
        metadata_dest = probe_dir / "latest_metadata.json"
        vrp_dest = probe_dir / ("latest_normalized_vrp.jsonl.gz" if args.compress == "gzip" else "latest_normalized_vrp.jsonl")
        copy_file_atomic(metadata_src, metadata_dest)
        if args.compress == "gzip":
            gzip_file_atomic(vrp_src, vrp_dest)
        else:
            copy_file_atomic(vrp_src, vrp_dest)
        sha_path = probe_dir / "sha256sums.txt"
        write_sha256sums(sha_path, [(metadata_dest.name, metadata_dest), (vrp_dest.name, vrp_dest)])

        probe_records[probe_id] = {
            "probe_id": probe_id,
            "metadata_path": str(metadata_dest),
            "metadata_sha256": sha256_file(metadata_dest),
            "metadata_size_bytes": metadata_dest.stat().st_size,
            "vrp_path": str(vrp_dest),
            "vrp_sha256": sha256_file(vrp_dest),
            "vrp_size_bytes": vrp_dest.stat().st_size,
            "compression": args.compress,
            "sha256sums_path": str(sha_path),
            "source_metadata_path": str(srcs.get("source_metadata") or metadata_src),
            "source_vrp_path": str(srcs.get("source_vrp") or vrp_src),
            "stable_metadata_path": str(srcs.get("stable_metadata") or ""),
            "stable_vrp_path": str(srcs.get("stable_vrp") or ""),
            "archived_from_metadata_path": str(metadata_src),
            "archived_from_vrp_path": str(vrp_src),
            "snapshot_id": snapshot_id,
            "capture_time_utc": capture_time,
            "vrp_count": metadata_obj.get("normalized_vrp_count", metadata_obj.get("vrp_count", vrp_count_by_probe.get(probe_id))),
            "validator_health": metadata_obj.get("validator_health"),
            "p8_expected_snapshot_id": expected_snapshot,
            "p8_expected_capture_time_utc": expected_capture,
        }

    status = "PASS"
    if p8_status != "PASS" or window_quality != "OK" or missing_inputs:
        status = "FAIL"
    elif mismatches:
        status = "PASS_WITH_EXCLUSIONS"

    manifest = {
        "schema": SCHEMA_MANIFEST,
        "status": status,
        "window_id": window_id,
        "p8_run_dir": str(p8_run_dir),
        "p8_acceptance_file": str(p8_acceptance_path),
        "source_mode": args.source_mode,
        "input_root": str(resolve_path(args.input_root, root)) if args.input_root else "",
        "p8_status": p8_status,
        "window_quality": window_quality,
        "probe_ids": probe_ids,
        "capture_time_skew_sec": p8_acceptance.get("capture_time_skew_sec") or p8_summary.get("capture_time_skew_sec"),
        "probe_inputs": probe_records,
        "missing_inputs": missing_inputs,
        "mismatches": mismatches,
        "warnings": warnings,
        "created_at_utc": utc_now(),
        "started_at_utc": started_at,
        "out_dir": str(out_dir),
        "root_cause_confirmed": False,
        "causal_claim_allowed": False,
    }
    manifest_path = out_dir / "p8_input_vrp_manifest.json"
    atomic_write_json(manifest_path, manifest)

    upload_results: list[dict[str, Any]] = []
    minio_stat_ok = False
    uploaded = False
    if args.upload_minio and status in {"PASS", "PASS_WITH_EXCLUSIONS"}:
        prefix = args.minio_prefix or os.environ.get("MINIO_PREFIX", "")
        if not prefix:
            upload_results.append({"ok": False, "error": "MINIO_PREFIX missing"})
        else:
            mc_bin = shutil.which(args.mc_bin) or args.mc_bin
            window_remote = minio_dest(prefix, window_id)
            upload_results.append(mc_copy_and_stat(mc_bin, manifest_path, window_remote))
            for probe_id, record in probe_records.items():
                remote = minio_dest(prefix, window_id, probe_id)
                for key in ("metadata_path", "vrp_path", "sha256sums_path"):
                    upload_results.append(mc_copy_and_stat(mc_bin, Path(record[key]), remote))
            uploaded = bool(upload_results) and all(item.get("cp_exit_code") == 0 for item in upload_results)
            minio_stat_ok = bool(upload_results) and all(item.get("ok") for item in upload_results)

    manifest["upload_minio"] = bool(args.upload_minio)
    manifest["uploaded"] = uploaded
    manifest["minio_stat_ok"] = minio_stat_ok
    manifest["upload_results"] = upload_results
    atomic_write_json(manifest_path, manifest)

    checks = {
        "p8_acceptance_ok": p8_status == "PASS",
        "window_quality_ok": window_quality == "OK",
        "probe_count_eq_expected": len(probe_records) == len(probe_ids) and len(probe_records) > 0,
        "missing_inputs_empty": not missing_inputs,
        "metadata_p8_consistent": not mismatches,
        "archive_from_stable_copy": args.source_mode != "stable_copy" or all(
            bool(record.get("stable_metadata_path")) and bool(record.get("stable_vrp_path"))
            for record in probe_records.values()
        ),
        "manifest_written": manifest_path.is_file(),
        "uploaded_if_requested": (not args.upload_minio) or uploaded,
        "minio_stat_ok_if_uploaded": (not args.upload_minio) or minio_stat_ok,
        "no_strong_root_cause_claim": True,
    }
    write_acceptance(out_dir, status, manifest, checks)
    return 0 if status in {"PASS", "PASS_WITH_EXCLUSIONS"} else 2


def write_acceptance(out_dir: Path, status: str, manifest: dict[str, Any], checks: dict[str, bool]) -> None:
    lines = [
        f"P8_INPUT_VRP_ARCHIVE={status}",
        f"window_id={manifest.get('window_id', '')}",
        f"probe_count={len(manifest.get('probe_inputs', {}))}",
        f"uploaded={str(manifest.get('uploaded', False)).lower()}",
        f"minio_stat_ok={str(manifest.get('minio_stat_ok', False)).lower()}",
        f"manifest_json={out_dir / 'p8_input_vrp_manifest.json'}",
        f"source_mode={manifest.get('source_mode', '')}",
        f"input_root={manifest.get('input_root', '')}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={str(value).lower()}" for key, value in checks.items())
    atomic_write_text(out_dir / ACCEPTANCE_FILE, "\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Archive P8 input VRP snapshots for window-bound P10 replay.")
    parser.add_argument("--p8-run-dir", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--upload-minio", type=parse_bool, default=False)
    parser.add_argument("--compress", choices=["gzip", "none"], default="gzip")
    parser.add_argument("--minio-prefix", default=os.environ.get("MINIO_PREFIX", ""))
    parser.add_argument("--mc-bin", default="mc")
    parser.add_argument("--metadata", action="append", default=[], help="Optional PROBE_ID=latest_metadata.json override.")
    parser.add_argument("--vrp", action="append", default=[], help="Optional PROBE_ID=latest_normalized_vrp.jsonl override.")
    parser.add_argument("--source-mode", choices=["latest", "stable_copy"], default="latest")
    parser.add_argument("--input-root", help="Stable input root containing probe_id=<probe>/latest_* files.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run_archive(args)
    except ValueError as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
