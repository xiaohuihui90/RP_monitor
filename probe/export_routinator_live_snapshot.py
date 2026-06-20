#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_METADATA = "s3.probe.routinator_live_snapshot_metadata.v1"
SCHEMA_VRP = "s3.probe.normalized_live_vrp.v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_snapshot_id() -> str:
    return "snap_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


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
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
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


def atomic_publish_existing(tmp_path: Path, final_path: Path) -> None:
    final_path.parent.mkdir(parents=True, exist_ok=True)
    with tmp_path.open("rb+") as f:
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, final_path)
    fsync_parent(final_path)


def join_url(base: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return base.rstrip("/") + "/" + path.lstrip("/")


def http_get(url: str, timeout_sec: int) -> dict[str, Any]:
    started = time.time()
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "rp-monitor-live-vrp/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            data = resp.read()
            return {
                "ok": True,
                "url": url,
                "status": int(getattr(resp, "status", 200)),
                "data": data,
                "duration_sec": time.time() - started,
                "error": None,
            }
    except urllib.error.HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        return {
            "ok": False,
            "url": url,
            "status": int(exc.code),
            "data": body,
            "duration_sec": time.time() - started,
            "error": f"http_error:{exc}",
        }
    except Exception as exc:
        return {
            "ok": False,
            "url": url,
            "status": None,
            "data": b"",
            "duration_sec": time.time() - started,
            "error": repr(exc),
        }


def detect_routinator_version(binary: str) -> tuple[str | None, int | None, str | None]:
    try:
        proc = subprocess.run(
            [binary, "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
        text = (proc.stdout or proc.stderr or "").strip()
        return (text.splitlines()[0] if text else None), int(proc.returncode), None
    except Exception as exc:
        return None, None, repr(exc)


def command_capture(
    binary: str,
    output_tmp: Path,
    fmt: str,
    timeout_sec: int,
    use_noupdate: bool,
    extra_args: list[str],
) -> dict[str, Any]:
    def tail_text(value: Any, limit: int) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        return str(value)[-limit:]

    output_tmp.parent.mkdir(parents=True, exist_ok=True)

    cmd = [binary, "vrps", "-f", fmt, "-o", str(output_tmp)]
    if use_noupdate:
        cmd.append("-n")
    cmd.extend(extra_args)

    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec,
        )
        output_exists = output_tmp.exists()
        output_size = output_tmp.stat().st_size if output_exists else 0
        return {
            "ok": proc.returncode == 0 and output_exists and output_size > 0,
            "command": cmd,
            "exit_code": int(proc.returncode),
            "stdout_excerpt": tail_text(proc.stdout, 4000),
            "stderr_excerpt": tail_text(proc.stderr, 4000),
            "stdout_tail": tail_text(proc.stdout, 1000),
            "stderr_tail": tail_text(proc.stderr, 2000),
            "duration_sec": time.time() - started,
            "error": None,
            "output_tmp": str(output_tmp),
            "output_tmp_exists": output_exists,
            "output_tmp_size": output_size,
        }
    except subprocess.TimeoutExpired as exc:
        output_exists = output_tmp.exists()
        output_size = output_tmp.stat().st_size if output_exists else 0
        return {
            "ok": False,
            "command": cmd,
            "exit_code": None,
            "stdout_excerpt": tail_text(getattr(exc, "stdout", None), 4000),
            "stderr_excerpt": tail_text(getattr(exc, "stderr", None), 4000),
            "stdout_tail": tail_text(getattr(exc, "stdout", None), 1000),
            "stderr_tail": tail_text(getattr(exc, "stderr", None), 2000),
            "duration_sec": time.time() - started,
            "error": f"timeout:{exc}",
            "output_tmp": str(output_tmp),
            "output_tmp_exists": output_exists,
            "output_tmp_size": output_size,
        }
    except Exception as exc:
        output_exists = output_tmp.exists()
        output_size = output_tmp.stat().st_size if output_exists else 0
        return {
            "ok": False,
            "command": cmd,
            "exit_code": None,
            "stdout_excerpt": "",
            "stderr_excerpt": "",
            "stdout_tail": "",
            "stderr_tail": "",
            "duration_sec": time.time() - started,
            "error": repr(exc),
            "output_tmp": str(output_tmp),
            "output_tmp_exists": output_exists,
            "output_tmp_size": output_size,
        }


def capture_http(args: argparse.Namespace) -> tuple[bytes, dict[str, Any], dict[str, Any] | None]:
    status_result = http_get(join_url(args.routinator_url, args.status_path), args.http_timeout_sec)
    if not status_result["ok"] and args.status_path != "/api/v1/status":
        fallback_status = http_get(join_url(args.routinator_url, "/api/v1/status"), args.http_timeout_sec)
        if fallback_status["ok"]:
            status_result = fallback_status

    json_result = http_get(join_url(args.routinator_url, args.json_path), args.http_timeout_sec)
    if not json_result["ok"]:
        raise RuntimeError(f"http_json_capture_failed:{json_result.get('error')}")

    status_json = None
    if status_result["ok"] and status_result.get("data"):
        try:
            status_json = json.loads(status_result["data"].decode("utf-8"))
        except Exception:
            status_json = None

    details = {
        "capture_method": "http",
        "http_json_url": json_result["url"],
        "http_status_url": status_result["url"],
        "http_status": json_result["status"],
        "http_status_endpoint_status": status_result["status"],
        "json_duration_sec": json_result["duration_sec"],
        "status_duration_sec": status_result["duration_sec"],
        "status_endpoint_error": status_result["error"],
    }
    return json_result["data"], details, status_json


def capture_command(args: argparse.Namespace, snapshot_dir: Path, raw_path: Path) -> tuple[bytes, dict[str, Any], None]:
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = raw_path.with_name(f"{raw_path.name}.tmp.{os.getpid()}")
    try:
        if tmp.exists():
            tmp.unlink()

        first = command_capture(
            binary=args.routinator_bin,
            output_tmp=tmp,
            fmt=args.command_format,
            timeout_sec=args.command_timeout_sec,
            use_noupdate=not args.command_allow_update,
            extra_args=list(args.command_extra_arg or []),
        )
        attempts = [first]

        if not first["ok"] and not args.command_allow_update and args.retry_command_with_update:
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            second = command_capture(
                binary=args.routinator_bin,
                output_tmp=tmp,
                fmt=args.command_format,
                timeout_sec=args.command_timeout_sec,
                use_noupdate=False,
                extra_args=list(args.command_extra_arg or []),
            )
            attempts.append(second)

        ok_attempt = next((item for item in reversed(attempts) if item["ok"]), None)
        if ok_attempt is None:
            debug_attempts = []
            for item in attempts:
                debug_attempts.append({
                    "command": item.get("command"),
                    "exit_code": item.get("exit_code"),
                    "duration_sec": item.get("duration_sec"),
                    "stdout_tail": item.get("stdout_tail") or (item.get("stdout_excerpt") or "")[-1000:],
                    "stderr_tail": item.get("stderr_tail") or (item.get("stderr_excerpt") or "")[-2000:],
                    "error": item.get("error"),
                    "output_tmp": item.get("output_tmp"),
                    "output_tmp_exists": item.get("output_tmp_exists"),
                    "output_tmp_size": item.get("output_tmp_size"),
                })
            raise RuntimeError("command_capture_failed:" + json.dumps(debug_attempts, ensure_ascii=False))

        atomic_publish_existing(tmp, raw_path)
        data = raw_path.read_bytes()
        details = {
            "capture_method": "command",
            "command_exit_code": ok_attempt["exit_code"],
            "command": ok_attempt["command"],
            "command_attempts": attempts,
            "command_duration_sec": ok_attempt["duration_sec"],
            "command_format": args.command_format,
            "command_output_file": str(raw_path),
            "command_output_bytes": raw_path.stat().st_size if raw_path.exists() else 0,
        }
        return data, details, None
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def extract_vrp_records(raw_obj: Any) -> tuple[str | None, list[dict[str, Any]], dict[str, Any]]:
    if isinstance(raw_obj, list):
        return "__top_level_list__", [x for x in raw_obj if isinstance(x, dict)], {}

    if isinstance(raw_obj, dict):
        metadata = raw_obj.get("metadata") if isinstance(raw_obj.get("metadata"), dict) else {}
        for key in ["roas", "vrps", "validated_roa_payloads", "validated_roas", "payloads", "records", "data", "items"]:
            value = raw_obj.get(key)
            if isinstance(value, list):
                return key, [x for x in value if isinstance(x, dict)], metadata
    return None, [], {}


def get_first(record: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


def parse_asn(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    try:
        return int(text)
    except Exception:
        return None


def parse_prefix(value: Any) -> tuple[str | None, int | None, str | None]:
    if value is None:
        return None, None, None
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
        return str(net), int(net.prefixlen), "ipv4" if net.version == 4 else "ipv6"
    except Exception:
        return None, None, None


def uri_like(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return lowered.startswith(("rsync://", "https://", "http://"))


def extract_sources(record: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    sources: list[dict[str, Any]] = []
    raw_source = record.get("source")
    if isinstance(raw_source, list):
        sources = [x for x in raw_source if isinstance(x, dict)]
    elif isinstance(raw_source, dict):
        sources = [raw_source]
    elif uri_like(raw_source):
        sources = [{"uri": raw_source}]

    for key in ["source_uri", "sourceUri", "uri", "roa_uri", "roaUri", "object_uri"]:
        value = record.get(key)
        if uri_like(value):
            sources.append({"uri": value})

    uris: list[str] = []
    tals: list[str] = []
    for source in sources:
        uri = source.get("uri") or source.get("source_uri") or source.get("roa_uri")
        tal = source.get("tal") or source.get("ta")
        if uri_like(uri):
            uris.append(str(uri))
        if tal not in (None, ""):
            tals.append(str(tal).strip().lower())

    return sources, sorted(set(uris)), sorted(set(tals))


def canonical_record_hash(record: dict[str, Any]) -> str:
    payload = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(payload)


def normalize_one(record: dict[str, Any], raw_index: int, snapshot_id: str, probe_id: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    prefix, prefix_len, afi = parse_prefix(get_first(record, ["prefix", "ipPrefix", "ip_prefix", "vrp_prefix"]))
    asn = parse_asn(get_first(record, ["asn", "asID", "as_id", "origin_asn", "originAS", "origin", "origin_as"]))
    max_length_raw = get_first(record, ["maxLength", "max_length", "maxlength", "maxLen", "max_len"])
    raw_tal = get_first(record, ["tal", "ta", "trust_anchor", "trustAnchor"])
    sources, source_uris, source_tals = extract_sources(record)

    warnings: list[str] = []
    if prefix is None:
        warnings.append("prefix_parse_failed")
    if asn is None:
        warnings.append("asn_parse_failed")

    if max_length_raw in (None, ""):
        max_length = prefix_len
        warnings.append("max_length_missing_default_to_prefix_len")
    else:
        try:
            max_length = int(max_length_raw)
        except Exception:
            max_length = prefix_len
            warnings.append("max_length_parse_failed_default_to_prefix_len")

    tal = str(raw_tal).strip().lower() if raw_tal not in (None, "") else None
    if tal is None and source_tals:
        tal = source_tals[0]
    if tal is None:
        tal = "unknown_tal"
        warnings.append("tal_missing")

    if prefix is None or prefix_len is None or afi is None or asn is None or max_length is None:
        return None, {
            "raw_index": raw_index,
            "raw_record_sha256": canonical_record_hash(record),
            "warnings": warnings,
        }

    source_uri = source_uris[0] if source_uris else None
    vrp_key = f"{afi}|{tal}|{prefix}|{asn}|{max_length}"

    normalized = {
        "schema": SCHEMA_VRP,
        "snapshot_id": snapshot_id,
        "probe_id": probe_id,
        "vrp_key": vrp_key,
        "afi": afi,
        "tal": tal,
        "asn": asn,
        "prefix": prefix,
        "prefix_len": prefix_len,
        "max_length": max_length,
        "source_uri": source_uri,
        "source_uris": source_uris,
        "source_tals": source_tals,
        "raw_source": {
            "raw_index": raw_index,
            "raw_record_sha256": canonical_record_hash(record),
            "raw_tal": raw_tal,
            "raw_asn": get_first(record, ["asn", "asID", "as_id", "origin_asn", "originAS", "origin", "origin_as"]),
            "raw_prefix": get_first(record, ["prefix", "ipPrefix", "ip_prefix", "vrp_prefix"]),
            "raw_max_length": max_length_raw,
            "source_sample": sources[:5],
            "normalization_warnings": warnings,
        },
    }
    return normalized, None


def atomic_write_normalized_jsonl(
    path: Path,
    raw_records: list[dict[str, Any]],
    snapshot_id: str,
    probe_id: str,
) -> tuple[int, int, list[dict[str, Any]]]:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    normalized_count = 0
    failures: list[dict[str, Any]] = []
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as f:
            for i, record in enumerate(raw_records):
                normalized, failure = normalize_one(record, i, snapshot_id, probe_id)
                if normalized is not None:
                    f.write(json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                    normalized_count += 1
                elif failure is not None:
                    failures.append(failure)
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
    return normalized_count, path.stat().st_size if path.exists() else 0, failures[:20]


def summarize_status(status_json: Any) -> dict[str, Any] | None:
    if not isinstance(status_json, dict):
        return None
    wanted = [
        "version",
        "current_serial",
        "last_update_start",
        "last_update_done",
        "lastUpdateStart",
        "lastUpdateDone",
        "state",
        "status",
    ]
    summary = {key: status_json.get(key) for key in wanted if key in status_json}
    if "repositories" in status_json and isinstance(status_json["repositories"], dict):
        summary["repository_count"] = len(status_json["repositories"])
    return summary


def infer_refresh_status(capture_method: str, status_json: Any, raw_metadata: dict[str, Any]) -> str:
    if isinstance(status_json, dict):
        for key in ["status", "state", "refresh_status", "lastUpdateDone", "last_update_done"]:
            value = status_json.get(key)
            if value not in (None, ""):
                return str(value)
        return "status_endpoint_available"
    if raw_metadata:
        if raw_metadata.get("generatedTime"):
            return "raw_metadata_generated_time_available"
        return "raw_metadata_available"
    return f"{capture_method}_snapshot_only"


def build_validator_health(checks: dict[str, bool], capture_method: str) -> str:
    required = [
        "raw_snapshot_non_empty",
        "json_parse_ok",
        "vrp_count_gt_zero",
        "normalized_file_non_empty",
        "latest_metadata_generated",
        "latest_raw_generated",
        "latest_normalized_generated",
    ]
    if not all(checks.get(key) for key in required):
        return "unhealthy"
    if capture_method == "command" and not (checks.get("routinator_binary_exists") and checks.get("routinator_version_executable")):
        return "unhealthy"
    if not checks.get("routinator_version_executable"):
        return "degraded"
    return "healthy"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export a live Routinator VRP snapshot for probe-side time-series diffing.")
    parser.add_argument("--probe-id", default=os.environ.get("PROBE_ID", "probe-cd"))
    parser.add_argument("--out-root", default="data/probe/live_vrp_snapshots")
    parser.add_argument("--capture-mode", choices=["auto", "http", "command"], default="auto")
    parser.add_argument("--routinator-url", default=os.environ.get("ROUTINATOR_HTTP_URL", "http://127.0.0.1:9556"))
    parser.add_argument("--json-path", default="/json")
    parser.add_argument("--status-path", default="/status")
    parser.add_argument("--http-timeout-sec", type=int, default=30)
    parser.add_argument("--routinator-bin", default=os.environ.get("ROUTINATOR_BIN", "routinator"))
    parser.add_argument("--command-format", choices=["json", "jsonext"], default="json")
    parser.add_argument("--command-timeout-sec", type=int, default=900)
    parser.add_argument("--command-allow-update", action="store_true", help="omit --noupdate in command mode")
    parser.add_argument("--retry-command-with-update", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--command-extra-arg", action="append", default=[])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started = time.time()
    capture_time = utc_now()
    snapshot_id = make_snapshot_id()

    base_dir = Path(args.out_root) / args.probe_id
    snapshot_dir = base_dir / "history" / snapshot_id
    raw_path = snapshot_dir / "raw_vrp.json"
    normalized_path = snapshot_dir / "normalized_vrp.jsonl"
    metadata_path = snapshot_dir / "metadata.json"

    latest_metadata = base_dir / "latest_metadata.json"
    latest_raw = base_dir / "latest_raw_vrp.json"
    latest_normalized = base_dir / "latest_normalized_vrp.jsonl"
    latest_snapshot = base_dir / "latest_snapshot_id.txt"

    binary_path = shutil.which(args.routinator_bin)
    routinator_version, version_exit_code, version_error = detect_routinator_version(args.routinator_bin) if binary_path else (None, None, "routinator_binary_not_found")

    capture_errors: list[str] = []
    raw_data: bytes | None = None
    capture_details: dict[str, Any] = {}
    status_json = None

    if args.capture_mode in {"auto", "http"}:
        try:
            raw_data, capture_details, status_json = capture_http(args)
            atomic_write_bytes(raw_path, raw_data)
        except Exception as exc:
            capture_errors.append(f"http:{exc}")
            if args.capture_mode == "http":
                raise

    if raw_data is None and args.capture_mode in {"auto", "command"}:
        try:
            raw_data, capture_details, status_json = capture_command(args, snapshot_dir, raw_path)
        except Exception as exc:
            capture_errors.append(f"command:{exc}")
            raise RuntimeError("; ".join(capture_errors)) from exc

    if raw_data is None:
        raise RuntimeError("; ".join(capture_errors) or "no_capture_attempted")

    raw_vrp_bytes = raw_path.stat().st_size if raw_path.exists() else 0
    raw_obj: Any = None
    json_parse_ok = False
    raw_parse_error = None
    raw_metadata: dict[str, Any] = {}
    raw_array_key = None
    raw_records: list[dict[str, Any]] = []
    try:
        raw_obj = json.loads(raw_data.decode("utf-8"))
        json_parse_ok = True
        raw_array_key, raw_records, raw_metadata = extract_vrp_records(raw_obj)
    except Exception as exc:
        raw_parse_error = repr(exc)

    vrp_count = len(raw_records)
    normalized_count = 0
    normalized_vrp_bytes = 0
    normalization_failures: list[dict[str, Any]] = []
    if json_parse_ok:
        normalized_count, normalized_vrp_bytes, normalization_failures = atomic_write_normalized_jsonl(
            normalized_path,
            raw_records,
            snapshot_id,
            args.probe_id,
        )
    else:
        atomic_write_text(normalized_path, "")

    pre_latest_checks = {
        "routinator_binary_exists": bool(binary_path),
        "routinator_version_executable": routinator_version is not None and version_exit_code == 0,
        "raw_snapshot_non_empty": raw_vrp_bytes > 0,
        "json_parse_ok": json_parse_ok,
        "vrp_count_gt_zero": vrp_count > 0,
        "normalized_file_non_empty": normalized_vrp_bytes > 0 and normalized_count > 0,
    }

    refresh_status = infer_refresh_status(capture_details.get("capture_method", "unknown"), status_json, raw_metadata)

    metadata = {
        "schema": SCHEMA_METADATA,
        "snapshot_id": snapshot_id,
        "probe_id": args.probe_id,
        "capture_time_utc": capture_time,
        "routinator_version": routinator_version,
        "refresh_status": refresh_status,
        "vrp_count": vrp_count,
        "normalized_vrp_count": normalized_count,
        "raw_vrp_file": str(raw_path),
        "normalized_vrp_file": str(normalized_path),
        "metadata_file": str(metadata_path),
        "validator_health": "pending_latest_publish",
        "capture_method": capture_details.get("capture_method"),
        "command_exit_code": capture_details.get("command_exit_code"),
        "http_status": capture_details.get("http_status"),
        "duration_sec": round(time.time() - started, 6),
        "raw_vrp_bytes": raw_vrp_bytes,
        "normalized_vrp_bytes": normalized_vrp_bytes,
        "raw_vrp_sha256": sha256_file(raw_path),
        "normalized_vrp_sha256": sha256_file(normalized_path),
        "raw_vrp_array_key": raw_array_key,
        "routinator_binary": args.routinator_bin,
        "routinator_binary_path": binary_path,
        "routinator_version_exit_code": version_exit_code,
        "routinator_version_error": version_error,
        "health_checks": pre_latest_checks,
        "capture_details": capture_details,
        "capture_errors": capture_errors,
        "raw_metadata": raw_metadata,
        "status_endpoint_summary": summarize_status(status_json),
        "raw_parse_error": raw_parse_error,
        "normalization_failure_sample": normalization_failures,
        "diff_engine_input": {
            "format": "jsonl",
            "file": str(normalized_path),
            "key_fields": ["tal", "asn", "prefix", "max_length"],
            "optional_source_field": "source_uri",
        },
        "latest_files": {
            "latest_metadata": str(latest_metadata),
            "latest_raw_vrp": str(latest_raw),
            "latest_normalized_vrp": str(latest_normalized),
            "latest_snapshot_id": str(latest_snapshot),
        },
    }

    atomic_write_json(metadata_path, metadata)
    atomic_write_bytes(latest_raw, raw_path.read_bytes())
    atomic_write_bytes(latest_normalized, normalized_path.read_bytes())
    atomic_write_bytes(latest_metadata, metadata_path.read_bytes())
    atomic_write_text(latest_snapshot, snapshot_id + "\n")

    latest_checks = {
        "latest_metadata_generated": latest_metadata.exists() and latest_metadata.stat().st_size > 0,
        "latest_raw_generated": latest_raw.exists() and latest_raw.stat().st_size == raw_vrp_bytes,
        "latest_normalized_generated": latest_normalized.exists() and latest_normalized.stat().st_size == normalized_vrp_bytes,
        "latest_snapshot_id_generated": latest_snapshot.exists() and latest_snapshot.read_text(encoding="utf-8").strip() == snapshot_id,
    }
    all_checks = {**pre_latest_checks, **latest_checks}
    metadata["health_checks"] = all_checks
    metadata["validator_health"] = build_validator_health(all_checks, str(metadata.get("capture_method")))
    metadata["duration_sec"] = round(time.time() - started, 6)

    atomic_write_json(metadata_path, metadata)
    atomic_write_bytes(latest_metadata, metadata_path.read_bytes())

    print(json.dumps({
        "status": "done" if metadata["validator_health"] in {"healthy", "degraded"} else "failed",
        "snapshot_id": snapshot_id,
        "probe_id": args.probe_id,
        "capture_method": metadata["capture_method"],
        "validator_health": metadata["validator_health"],
        "vrp_count": vrp_count,
        "normalized_vrp_count": normalized_count,
        "metadata": str(metadata_path),
        "latest_metadata": str(latest_metadata),
    }, ensure_ascii=False, indent=2, sort_keys=True))

    return 0 if metadata["validator_health"] in {"healthy", "degraded"} else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
