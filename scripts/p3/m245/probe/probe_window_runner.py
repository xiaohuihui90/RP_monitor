#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.p3.m245.common.m245_hash import sha256_bytes, sha256_file
from scripts.p3.m245.common.m245_jsonl import write_jsonl, write_json
from scripts.p3.m245.common.m245_paths import probe_run_dir, ensure_standard_dirs
from scripts.p3.m245.common.m245_window import make_window, parse_window_id, M245Window


RRDP_NOTIFICATION_URIS = {
    "arin": "https://rrdp-rps.arin.net/notification.xml",
    "ripe": "https://rrdp.ripe.net/notification.xml",
    "apnic": "https://rrdp.apnic.net/notification.xml",
}

OBJECT_SUFFIXES = {
    ".cer", ".roa", ".mft", ".crl", ".gbr", ".asa", ".tak", ".bin"
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except Exception:
        return str(path)


def fetch_url(url: str, timeout_sec: int = 20) -> dict[str, Any]:
    started = time.time()
    started_utc = utc_now()
    http_status = None
    data = b""
    fetch_status = "failed"
    failure_stage = "http_fetch"
    error_class = "unknown"
    err = None

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "s3-radar-m245/0.1"},
        )
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            http_status = getattr(resp, "status", None)
            data = resp.read()
        fetch_status = "success"
        failure_stage = "none"
        error_class = "NO_ERROR"
    except TimeoutError as e:
        fetch_status = "timeout"
        error_class = "timeout"
        err = repr(e)
    except urllib.error.HTTPError as e:
        http_status = e.code
        fetch_status = "failed"
        if e.code == 404:
            error_class = "http_404"
        elif e.code == 403:
            error_class = "http_403"
        elif 500 <= e.code <= 599:
            error_class = "http_5xx"
        else:
            error_class = "unknown"
        err = repr(e)
    except urllib.error.URLError as e:
        fetch_status = "failed"
        reason = str(getattr(e, "reason", e))
        if "timed out" in reason.lower():
            fetch_status = "timeout"
            error_class = "timeout"
        elif "name or service" in reason.lower() or "temporary failure" in reason.lower():
            failure_stage = "dns_resolve"
            error_class = "dns_servfail"
        elif "connection refused" in reason.lower():
            error_class = "connection_refused"
        else:
            error_class = "unknown"
        err = repr(e)
    except Exception as e:
        fetch_status = "failed"
        error_class = "unknown"
        err = repr(e)

    ended = time.time()
    return {
        "started_utc": started_utc,
        "ended_utc": utc_now(),
        "latency_ms": int((ended - started) * 1000),
        "http_status": http_status,
        "data": data,
        "data_len": len(data),
        "data_sha256": sha256_bytes(data) if data else None,
        "fetch_status": fetch_status,
        "failure_stage": failure_stage,
        "error_class": error_class,
        "error": err,
    }


def parse_rrdp_notification(data: bytes) -> dict[str, Any]:
    result = {
        "session_id": None,
        "serial": None,
        "snapshot_uri": None,
        "delta_uris": [],
        "parse_status": "not_parsed",
        "parse_error": None,
    }

    try:
        root = ET.fromstring(data)
        result["session_id"] = root.attrib.get("session_id") or root.attrib.get("sessionId")
        serial = root.attrib.get("serial")
        result["serial"] = int(serial) if serial is not None and str(serial).isdigit() else serial

        for elem in root.iter():
            tag = elem.tag.split("}", 1)[-1]
            if tag == "snapshot":
                result["snapshot_uri"] = elem.attrib.get("uri")
            elif tag == "delta":
                uri = elem.attrib.get("uri")
                if uri:
                    result["delta_uris"].append(uri)

        result["parse_status"] = "parsed"
    except Exception as e:
        result["parse_status"] = "parse_failed"
        result["parse_error"] = repr(e)

    return result


def collect_advertised_view(window: Any, probe_id: str, timeout_sec: int) -> list[dict[str, Any]]:
    rows = []
    for pp_id, uri in RRDP_NOTIFICATION_URIS.items():
        fetched = fetch_url(uri, timeout_sec=timeout_sec)
        parsed = parse_rrdp_notification(fetched["data"]) if fetched["data"] else {
            "session_id": None,
            "serial": None,
            "snapshot_uri": None,
            "delta_uris": [],
            "parse_status": "not_available",
            "parse_error": None,
        }

        rows.append({
            "schema": "s3.m245.advertised_view_record.v1",
            "window_id": window.window_id,
            "window_start_utc": window.window_start_utc,
            "window_end_utc": window.window_end_utc,
            "probe_id": probe_id,
            "layer": "advertised_view",
            "pp_id": pp_id,
            "observed_at_utc": fetched["ended_utc"],
            "notification_uri": uri,
            "session_id": parsed.get("session_id"),
            "serial": parsed.get("serial"),
            "notif_digest": fetched["data_sha256"],
            "snapshot_uri": parsed.get("snapshot_uri"),
            "delta_uris": parsed.get("delta_uris") or [],
            "notification_parse_status": parsed.get("parse_status"),
            "notification_parse_error": parsed.get("parse_error"),
            "fetch_status": fetched["fetch_status"],
            "failure_stage": fetched["failure_stage"],
            "error_class": fetched["error_class"],
            "latency_ms": fetched["latency_ms"],
            "http_status": fetched["http_status"],
            "data_len": fetched["data_len"],
            "error": fetched["error"],
        })
    return rows


def candidate_cache_dirs() -> list[Path]:
    cands = []

    for env_name in [
        "M245_ROUTINATOR_CACHE_DIR",
        "ROUTINATOR_CACHE_DIR",
        "RPKI_CACHE_DIR",
    ]:
        v = os.environ.get(env_name)
        if v:
            cands.append(Path(v).expanduser())

    home = Path.home()
    cands.extend([
        home / ".rpki-cache",
        home / ".routinator",
        home / ".cache" / "routinator",
        home / ".local" / "share" / "routinator",
        Path("/var/lib/routinator"),
        Path("data"),
    ])

    out = []
    seen = set()
    for p in cands:
        try:
            rp = p.resolve()
        except Exception:
            rp = p
        if str(rp) in seen:
            continue
        seen.add(str(rp))
        if p.exists() and p.is_dir():
            out.append(p)
    return out


def looks_like_object_file(path: Path) -> bool:
    if not path.is_file():
        return False
    suffix = path.suffix.lower()
    if suffix in OBJECT_SUFFIXES:
        return True
    # Routinator cache wrappers may not always have RPKI suffix.
    if suffix == "" and path.stat().st_size > 0:
        return True
    return False


def choose_cache_dir(max_probe_files: int = 50) -> Path | None:
    best = None
    best_count = 0

    for cand in candidate_cache_dirs():
        count = 0
        try:
            for p in cand.rglob("*"):
                if looks_like_object_file(p):
                    count += 1
                    if count >= max_probe_files:
                        break
        except Exception:
            continue

        if count > best_count:
            best = cand
            best_count = count

    return best if best_count > 0 else None


def collect_object_view_light(
    window: Any,
    probe_id: str,
    max_files: int = 200000,
    max_seconds: int = 180,
) -> list[dict[str, Any]]:
    started = time.time()
    cache_dir = choose_cache_dir()
    observed_at = utc_now()

    if cache_dir is None:
        return [{
            "schema": "s3.m245.object_view_light_record.v1",
            "window_id": window.window_id,
            "window_start_utc": window.window_start_utc,
            "window_end_utc": window.window_end_utc,
            "probe_id": probe_id,
            "layer": "object_view",
            "pp_id": "all",
            "observed_at_utc": observed_at,
            "object_set_root": None,
            "object_count": 0,
            "manifest_count": 0,
            "manifest_summary_root": None,
            "cache_source": "not_found",
            "cache_dir": None,
            "object_inventory_mode": "light",
            "full_inventory_saved": False,
            "scan_status": "cache_dir_not_found",
            "scan_truncated": False,
            "by_suffix": {},
            "fetch_status": "skipped",
            "failure_stage": "local_cache_lookup",
            "error_class": "local_index_miss",
            "latency_ms": int((time.time() - started) * 1000),
        }]

    lines = []
    manifest_lines = []
    suffix_counter = Counter()
    object_count = 0
    manifest_count = 0
    scan_truncated = False
    scan_error = None

    try:
        for p in cache_dir.rglob("*"):
            if time.time() - started > max_seconds:
                scan_truncated = True
                break
            if object_count >= max_files:
                scan_truncated = True
                break
            if not looks_like_object_file(p):
                continue

            try:
                size = p.stat().st_size
                digest = sha256_file(p)
                rel = safe_rel(p, cache_dir)
                suffix = p.suffix.lower() or "<no_suffix>"
                line = f"{rel}\t{size}\t{digest}"
                lines.append(line)
                suffix_counter[suffix] += 1
                object_count += 1
                if p.suffix.lower() == ".mft":
                    manifest_count += 1
                    manifest_lines.append(line)
            except Exception:
                continue
    except Exception as e:
        scan_error = repr(e)

    root_material = "\n".join(sorted(lines)).encode("utf-8")
    manifest_material = "\n".join(sorted(manifest_lines)).encode("utf-8")

    fetch_status = "success" if object_count > 0 and scan_error is None else "partial"
    failure_stage = "none" if fetch_status == "success" else "local_cache_lookup"
    error_class = "NO_ERROR" if fetch_status == "success" else "unknown"

    return [{
        "schema": "s3.m245.object_view_light_record.v1",
        "window_id": window.window_id,
        "window_start_utc": window.window_start_utc,
        "window_end_utc": window.window_end_utc,
        "probe_id": probe_id,
        "layer": "object_view",
        "pp_id": "all",
        "observed_at_utc": utc_now(),
        "object_set_root": sha256_bytes(root_material) if lines else None,
        "object_count": object_count,
        "manifest_count": manifest_count,
        "manifest_summary_root": sha256_bytes(manifest_material) if manifest_lines else None,
        "cache_source": "routinator_or_local_cache_auto_detected",
        "cache_dir": str(cache_dir),
        "object_inventory_mode": "light",
        "full_inventory_saved": False,
        "scan_status": "scanned",
        "scan_truncated": scan_truncated,
        "scan_error": scan_error,
        "by_suffix": dict(suffix_counter),
        "fetch_status": fetch_status,
        "failure_stage": failure_stage,
        "error_class": error_class,
        "latency_ms": int((time.time() - started) * 1000),
    }]


def run_cmd_to_file(cmd: list[str], output_path: Path, timeout_sec: int) -> dict[str, Any]:
    started = time.time()
    started_utc = utc_now()
    try:
        with output_path.open("wb") as out:
            p = subprocess.run(
                cmd,
                stdout=out,
                stderr=subprocess.PIPE,
                timeout=timeout_sec,
            )
        return {
            "started_utc": started_utc,
            "ended_utc": utc_now(),
            "latency_ms": int((time.time() - started) * 1000),
            "returncode": p.returncode,
            "stderr": p.stderr.decode("utf-8", errors="replace")[:4000],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "started_utc": started_utc,
            "ended_utc": utc_now(),
            "latency_ms": int((time.time() - started) * 1000),
            "returncode": -1,
            "stderr": f"timeout: {e}",
            "timed_out": True,
        }


def extract_vrp_records(obj: Any) -> list[Any]:
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for key in ["roas", "vrps", "validated_roa_payloads", "validated_roas", "payloads"]:
            v = obj.get(key)
            if isinstance(v, list):
                return v
    return []


def canonical_vrp_root(records: list[Any]) -> str:
    lines = []
    for r in records:
        lines.append(json.dumps(r, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
    return sha256_bytes("\n".join(sorted(lines)).encode("utf-8"))


def collect_validation_output_light(
    window: Any,
    probe_id: str,
    full_dir: Path,
    timeout_sec: int = 300,
    validator_update_mode: str = "noupdate",
    vrp_count_low_threshold: int = 500000,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    full_dir.mkdir(parents=True, exist_ok=True)
    tmp_vrp = full_dir / "vrp_tmp.json"

    version_text = None
    if shutil.which("routinator"):
        try:
            v = subprocess.run(
                ["routinator", "--version"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
            )
            version_text = (v.stdout or v.stderr).strip()
        except Exception as e:
            version_text = f"version_error:{e!r}"

    if validator_update_mode == "noupdate":
        cmd = ["routinator", "vrps", "--format", "json", "--noupdate", "--output", str(tmp_vrp)]
    else:
        cmd = ["routinator", "vrps", "--format", "json", "--output", str(tmp_vrp)]

    if not shutil.which("routinator"):
        cmd = []

    export_status = "failed"
    failure_stage = "validator_vrp_export"
    error_class = "validator_export_error"
    latency_ms = None
    stderr = None
    vrp_count = 0
    vrp_root = None
    vrp_digest = None
    full_vrp_saved = False
    full_vrp_path = None

    if not cmd:
        stderr = "routinator_not_in_path"
    else:
        r = run_cmd_to_file(cmd, tmp_vrp, timeout_sec=timeout_sec)
        latency_ms = r["latency_ms"]
        stderr = r["stderr"]

        if r["timed_out"]:
            export_status = "timeout"
            error_class = "timeout"
        elif r["returncode"] != 0 or not tmp_vrp.exists() or tmp_vrp.stat().st_size == 0:
            if validator_update_mode == "noupdate":
                # Fallback for routinator builds that do not accept --noupdate.
                cmd2 = ["routinator", "vrps", "--format", "json", "--output", str(tmp_vrp)]
                r2 = run_cmd_to_file(cmd2, tmp_vrp, timeout_sec=timeout_sec)
                latency_ms = r2["latency_ms"]
                stderr = (stderr or "") + "\nFALLBACK_STDERR:\n" + (r2["stderr"] or "")
                if r2["timed_out"]:
                    export_status = "timeout"
                    error_class = "timeout"
                elif r2["returncode"] != 0 or not tmp_vrp.exists() or tmp_vrp.stat().st_size == 0:
                    export_status = "failed"
                    error_class = "validator_export_error"
                else:
                    export_status = "success"
                    failure_stage = "none"
                    error_class = "NO_ERROR"
            else:
                export_status = "failed"
                error_class = "validator_export_error"
        else:
            export_status = "success"
            failure_stage = "none"
            error_class = "NO_ERROR"

    if export_status == "success" and tmp_vrp.exists():
        try:
            raw = tmp_vrp.read_bytes()
            vrp_digest = sha256_bytes(raw)
            obj = json.loads(raw.decode("utf-8"))
            records = extract_vrp_records(obj)
            vrp_count = len(records)
            vrp_root = canonical_vrp_root(records)
        except Exception as e:
            export_status = "failed"
            failure_stage = "validator_vrp_export"
            error_class = "validator_export_error"
            stderr = (stderr or "") + f"\nparse_error:{e!r}"

    save_full = os.environ.get("M245_SAVE_FULL_VRP", "0") == "1"
    if save_full and tmp_vrp.exists() and tmp_vrp.stat().st_size > 0:
        gz_path = full_dir / "vrp_full.json.gz"
        with tmp_vrp.open("rb") as src, gzip.open(gz_path, "wb") as dst:
            shutil.copyfileobj(src, dst)
        full_vrp_saved = True
        full_vrp_path = str(gz_path)

    try:
        tmp_vrp.unlink()
    except Exception:
        pass

    suspicious_low_count = (
        export_status == "success"
        and isinstance(vrp_count, int)
        and vrp_count_low_threshold > 0
        and vrp_count < vrp_count_low_threshold
    )

    row = {
        "schema": "s3.m245.validation_output_light_record.v1",
        "window_id": window.window_id,
        "window_start_utc": window.window_start_utc,
        "window_end_utc": window.window_end_utc,
        "probe_id": probe_id,
        "layer": "validation_output",
        "observed_at_utc": utc_now(),
        "validator_name": "routinator",
        "validator_version": version_text,
        "validator_refresh_interval_sec": 600,
        "validator_update_mode": validator_update_mode,
        "validator_observation_policy": "external_refresh_plus_noupdate" if validator_update_mode == "noupdate" else "inline_update",
        "vrp_count_low_threshold": vrp_count_low_threshold,
        "suspicious_low_count": suspicious_low_count,
        "validation_output_quality": "suspicious_low_count" if suspicious_low_count else ("ok" if export_status == "success" else "failed"),
        "vrp_count": vrp_count,
        "vrp_root": vrp_root,
        "vrp_digest": vrp_digest,
        "router_key_count": None,
        "aspa_count": None,
        "full_vrp_saved": full_vrp_saved,
        "full_vrp_path": full_vrp_path,
        "export_status": export_status,
        "failure_stage": failure_stage,
        "error_class": error_class,
        "latency_ms": latency_ms,
        "stderr_sample": stderr[:4000] if stderr else None,
    }

    ctx = {
        "schema": "s3.m245.validator_context_record.v1",
        "window_id": window.window_id,
        "probe_id": probe_id,
        "observed_at_utc": utc_now(),
        "validator_name": "routinator",
        "validator_version": version_text,
        "validator_refresh_interval_sec": 600,
        "validator_update_mode": validator_update_mode,
        "validator_observation_policy": "external_refresh_plus_noupdate" if validator_update_mode == "noupdate" else "inline_update",
        "vrp_count_low_threshold": vrp_count_low_threshold,
        "suspicious_low_count": suspicious_low_count,
        "context_status": "available" if version_text else "partial",
        "vrp_count": vrp_count,
        "vrp_root": vrp_root,
    }

    return [row], [ctx]


def artifact_entry(path: Path, artifact_type: str, retention_class: str = "summary") -> dict[str, Any]:
    if not path.exists():
        return {
            "artifact_type": artifact_type,
            "path": str(path),
            "exists": False,
        }
    return {
        "artifact_type": artifact_type,
        "path": str(path),
        "exists": True,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "compressed": path.suffix == ".gz",
        "retention_class": retention_class,
    }


def build_summary(
    window: Any,
    probe_id: str,
    run_dir: Path,
    advertised: list[dict[str, Any]],
    object_rows: list[dict[str, Any]],
    validation: list[dict[str, Any]],
) -> dict[str, Any]:
    adv_by_status = Counter(r.get("fetch_status") for r in advertised)
    obj_by_status = Counter(r.get("fetch_status") for r in object_rows)
    val_by_status = Counter(r.get("export_status") for r in validation)

    return {
        "schema": "s3.m245.probe_window_summary.v1",
        "run_id": run_dir.name,
        "window_id": window.window_id,
        "window_start_utc": window.window_start_utc,
        "window_end_utc": window.window_end_utc,
        "probe_id": probe_id,
        "created_at_utc": utc_now(),
        "run_mode": getattr(window, "run_mode", None),
        "window_quality": getattr(window, "window_quality", None),
        "record_counts": {
            "advertised_view": len(advertised),
            "object_view_light": len(object_rows),
            "validation_output_light": len(validation),
        },
        "advertised_view": {
            "by_fetch_status": dict(adv_by_status),
            "pp_ids": sorted({r.get("pp_id") for r in advertised if r.get("pp_id")}),
        },
        "object_view": {
            "by_fetch_status": dict(obj_by_status),
            "object_count_total": sum(int(r.get("object_count") or 0) for r in object_rows),
            "manifest_count_total": sum(int(r.get("manifest_count") or 0) for r in object_rows),
            "cache_dirs": sorted({r.get("cache_dir") for r in object_rows if r.get("cache_dir")}),
        },
        "validation_output": {
            "by_export_status": dict(val_by_status),
            "vrp_count": validation[0].get("vrp_count") if validation else None,
            "vrp_root": validation[0].get("vrp_root") if validation else None,
            "validator_version": validation[0].get("validator_version") if validation else None,
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--timeout-sec", type=int, default=20)
    ap.add_argument("--vrp-timeout-sec", type=int, default=300)
    ap.add_argument("--window-size-sec", type=int, default=600)
    ap.add_argument("--window-id", default=None, help="Fixed M24.5 window_id, e.g. win_20260520T070000Z_10m")
    ap.add_argument("--run-mode", default="manual_test", choices=["manual_test", "scheduled", "replay"])
    ap.add_argument("--window-quality", default="diagnostic_only", choices=["on_time", "slightly_late", "late", "replay", "diagnostic_only"])
    ap.add_argument("--validator-update-mode", default="noupdate", choices=["update", "noupdate"])
    ap.add_argument("--vrp-count-low-threshold", type=int, default=500000)
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()

    if args.window_id:
        parsed_window = parse_window_id(args.window_id)
        window = M245Window(
            window_id=parsed_window["window_id"],
            window_start_utc=parsed_window["window_start_utc"],
            window_end_utc=parsed_window["window_end_utc"],
            window_size_sec=parsed_window["window_size_sec"],
        )
    else:
        window = make_window(window_size_sec=args.window_size_sec)

    object.__setattr__(window, "run_mode", args.run_mode)
    object.__setattr__(window, "window_quality", args.window_quality)

    run_dir = probe_run_dir(project_dir, args.probe_id, window.window_id)
    dirs = ensure_standard_dirs(run_dir)

    advertised = collect_advertised_view(window, args.probe_id, timeout_sec=args.timeout_sec)
    object_rows = collect_object_view_light(window, args.probe_id)
    validation, validator_context = collect_validation_output_light(
        window,
        args.probe_id,
        dirs["full"],
        timeout_sec=args.vrp_timeout_sec,
        validator_update_mode=args.validator_update_mode,
        vrp_count_low_threshold=args.vrp_count_low_threshold,
    )

    adv_path = dirs["indexes"] / "advertised_view_records.jsonl"
    obj_path = dirs["indexes"] / "object_view_light_records.jsonl"
    val_path = dirs["indexes"] / "validation_output_light_records.jsonl"
    ctx_path = dirs["indexes"] / "validator_context_records.jsonl"

    write_jsonl(adv_path, advertised)
    write_jsonl(obj_path, object_rows)
    write_jsonl(val_path, validation)
    write_jsonl(ctx_path, validator_context)

    summary = build_summary(window, args.probe_id, run_dir, advertised, object_rows, validation)
    summary_path = dirs["outputs"] / "m245_probe_window_summary.json"
    write_json(summary_path, summary)

    artifacts = [
        artifact_entry(adv_path, "advertised_view_records"),
        artifact_entry(obj_path, "object_view_light_records"),
        artifact_entry(val_path, "validation_output_light_records"),
        artifact_entry(ctx_path, "validator_context_records"),
        artifact_entry(summary_path, "m245_probe_window_summary"),
    ]

    for p in dirs["full"].glob("*"):
        artifacts.append(artifact_entry(p, f"full_{p.name}", retention_class="full"))

    manifest = {
        "schema": "s3.m245.run_manifest.v1",
        "run_id": run_dir.name,
        "window_id": window.window_id,
        "window_start_utc": window.window_start_utc,
        "window_end_utc": window.window_end_utc,
        "created_at_utc": utc_now(),
        "role": "probe",
        "probe_id": args.probe_id,
        "run_mode": args.run_mode,
        "window_quality": args.window_quality,
        "validator_update_mode": args.validator_update_mode,
        "vrp_count_low_threshold": args.vrp_count_low_threshold,
        "artifacts": artifacts,
        "summaries": {
            "probe_window_summary": str(summary_path),
        },
        "checks": {
            "probe_window_check": str(dirs["checks"] / "M245_probe_window_check.txt"),
        },
    }
    write_json(run_dir / "run_manifest.json", manifest)

    adv_success = sum(1 for r in advertised if r.get("fetch_status") == "success")
    obj_records = len(object_rows)
    val_success = sum(1 for r in validation if r.get("export_status") == "success")
    status = "PASS" if adv_success >= 1 and obj_records >= 1 and val_success == 1 else "PARTIAL"

    check_path = dirs["checks"] / "M245_probe_window_check.txt"
    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"M245_PROBE_WINDOW={status}\n\n")
        f.write(f"created_at_utc = {utc_now()}\n")
        f.write(f"run_dir = {run_dir}\n")
        f.write(f"window_id = {window.window_id}\n")
        f.write(f"window_start_utc = {window.window_start_utc}\n")
        f.write(f"window_end_utc = {window.window_end_utc}\n")
        f.write(f"probe_id = {args.probe_id}\n")
        f.write(f"run_mode = {args.run_mode}\n")
        f.write(f"window_quality = {args.window_quality}\n")
        f.write(f"validator_update_mode = {args.validator_update_mode}\n")
        f.write(f"vrp_count_low_threshold = {args.vrp_count_low_threshold}\n")
        if validation:
            f.write(f"suspicious_low_count = {validation[0].get('suspicious_low_count')}\n")
            f.write(f"validation_output_quality = {validation[0].get('validation_output_quality')}\n")
        f.write(f"advertised_view_records_count = {len(advertised)}\n")
        f.write(f"advertised_view_success_count = {adv_success}\n")
        f.write(f"object_view_light_records_count = {obj_records}\n")
        f.write(f"object_count_total = {summary['object_view']['object_count_total']}\n")
        f.write(f"manifest_count_total = {summary['object_view']['manifest_count_total']}\n")
        f.write(f"cache_dirs = {summary['object_view']['cache_dirs']}\n")
        f.write(f"validation_output_light_records_count = {len(validation)}\n")
        f.write(f"validation_output_success_count = {val_success}\n")
        f.write(f"vrp_count = {summary['validation_output']['vrp_count']}\n")
        f.write(f"vrp_root = {summary['validation_output']['vrp_root']}\n")
        f.write(f"validator_version = {summary['validation_output']['validator_version']}\n")
        f.write(f"summary_path = {summary_path}\n")
        f.write(f"run_manifest_path = {run_dir / 'run_manifest.json'}\n")

    print(f"M245_PROBE_WINDOW_RUN_DIR={run_dir}")
    print(f"M245_PROBE_WINDOW_CHECK={check_path}")
    print(f"M245_PROBE_WINDOW_STATUS={status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
