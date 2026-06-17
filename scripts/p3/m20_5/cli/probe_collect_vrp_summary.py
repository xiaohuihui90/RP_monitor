#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.request import urlopen


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")


def sha256_text_lines(lines: Iterable[str]) -> str:
    h = hashlib.sha256()
    for line in lines:
        h.update(line.encode("utf-8"))
        if not line.endswith("\n"):
            h.update(b"\n")
    return "sha256:" + h.hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def run_cmd(cmd: List[str], timeout: int) -> Tuple[int, str, str, int]:
    start = time.time()
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        latency_ms = int((time.time() - start) * 1000)
        return p.returncode, p.stdout, p.stderr, latency_ms
    except subprocess.TimeoutExpired as exc:
        latency_ms = int((time.time() - start) * 1000)
        return 124, exc.stdout or "", exc.stderr or "timeout", latency_ms


def try_get_routinator_status(status_url: str, timeout: int = 5) -> Dict[str, Any]:
    if not status_url:
        return {}

    try:
        with urlopen(status_url, timeout=timeout) as resp:
            raw = resp.read()
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as exc:
        return {
            "_status_fetch_error": str(exc),
        }


def extract_status_fields(status: Dict[str, Any]) -> Dict[str, Any]:
    payload = status.get("payload") or {}

    route_v4 = payload.get("routeOriginsIPv4") or {}
    route_v6 = payload.get("routeOriginsIPv6") or {}
    router_keys = payload.get("routerKeys") or {}
    aspas = payload.get("aspas") or {}

    return {
        "status_api_version": status.get("version"),
        "status_api_serial": status.get("serial"),
        "status_api_now": status.get("now"),
        "last_update_start": status.get("lastUpdateStart"),
        "last_update_done": status.get("lastUpdateDone"),
        "last_update_duration": status.get("lastUpdateDuration"),

        "status_route_origins_ipv4_final": route_v4.get("final"),
        "status_route_origins_ipv6_final": route_v6.get("final"),
        "status_route_origins_final_total": (
            (route_v4.get("final") or 0) + (route_v6.get("final") or 0)
            if isinstance(route_v4.get("final"), int) and isinstance(route_v6.get("final"), int)
            else None
        ),
        "status_router_key_final": router_keys.get("final"),
        "status_aspa_final": aspas.get("final"),
    }


def load_json_any(path: Path) -> Any:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def parse_asn(value: Any) -> int | None:
    if value is None:
        return None
    s = str(value).strip()
    if s.upper().startswith("AS"):
        s = s[2:]
    try:
        return int(s)
    except Exception:
        return None


def parse_max_length(row: Dict[str, Any]) -> int | None:
    for k in ["maxLength", "max_length", "max-len", "maxlen"]:
        if k in row and row.get(k) is not None:
            try:
                return int(row.get(k))
            except Exception:
                return None

    prefix = row.get("prefix")
    if isinstance(prefix, str) and "/" in prefix:
        try:
            return int(prefix.rsplit("/", 1)[1])
        except Exception:
            return None

    return None


def normalize_vrp_entry(row: Dict[str, Any]) -> Dict[str, Any] | None:
    asn = None
    for k in ["asn", "asID", "asid", "origin_asn", "origin"]:
        if k in row:
            asn = parse_asn(row.get(k))
            if asn is not None:
                break

    prefix = None
    for k in ["prefix", "ipPrefix", "ip_prefix", "prefixes"]:
        v = row.get(k)
        if isinstance(v, str) and v:
            prefix = v
            break

    max_length = parse_max_length(row)

    ta = None
    for k in ["ta", "tal", "trustAnchor", "trust_anchor"]:
        v = row.get(k)
        if isinstance(v, str) and v:
            ta = v
            break

    if asn is None or not prefix or max_length is None:
        return None

    return {
        "asn": asn,
        "max_length": max_length,
        "prefix": prefix,
        "ta": ta or "unknown",
    }


def iter_vrp_rows(obj: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(obj, list):
        for x in obj:
            if isinstance(x, dict):
                yield x
        return

    if not isinstance(obj, dict):
        return

    candidate_keys = [
        "roas",
        "vrps",
        "routeOrigins",
        "route_origins",
        "validated_roa_payloads",
        "validated_roa_payload",
    ]

    for key in candidate_keys:
        val = obj.get(key)
        if isinstance(val, list):
            for x in val:
                if isinstance(x, dict):
                    yield x
            return

    for val in obj.values():
        if isinstance(val, list):
            if val and isinstance(val[0], dict) and any(k in val[0] for k in ["asn", "asID", "prefix", "ipPrefix"]):
                for x in val:
                    if isinstance(x, dict):
                        yield x
                return


def iter_router_key_rows(obj: Any) -> Iterable[Dict[str, Any]]:
    if not isinstance(obj, dict):
        return
    for key in ["routerKeys", "router_keys", "routerkeys"]:
        val = obj.get(key)
        if isinstance(val, list):
            for x in val:
                if isinstance(x, dict):
                    yield x
            return


def iter_aspa_rows(obj: Any) -> Iterable[Dict[str, Any]]:
    if not isinstance(obj, dict):
        return
    for key in ["aspas", "aspa"]:
        val = obj.get(key)
        if isinstance(val, list):
            for x in val:
                if isinstance(x, dict):
                    yield x
            return


def canonical_lines_for_rows(rows: List[Dict[str, Any]]) -> List[str]:
    return [
        json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for row in sorted(
            rows,
            key=lambda r: (
                str(r.get("ta")),
                int(r.get("asn")),
                str(r.get("prefix")),
                int(r.get("max_length")),
            ),
        )
    ]


def digest_generic_rows(rows: Iterable[Dict[str, Any]]) -> tuple[int, str]:
    lines = []
    count = 0
    for row in rows:
        count += 1
        lines.append(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    lines.sort()
    return count, sha256_text_lines(lines)


def gzip_copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as fin, gzip.open(dst, "wb", compresslevel=6) as fout:
        shutil.copyfileobj(fin, fout)


def create_archive(archive_path: Path, root: Path, members: List[Path]) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "w:gz") as tar:
        for member in members:
            if member.exists():
                tar.add(member, arcname=str(member.relative_to(root)))


def main() -> int:
    parser = argparse.ArgumentParser(description="M20.5-A probe-side Routinator VRP summary collector")
    parser.add_argument("--probe-id", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--validator-id", default="routinator")
    parser.add_argument("--routinator-bin", default="routinator")
    parser.add_argument("--status-url", default="http://127.0.0.1:8323/api/v1/status")
    parser.add_argument("--mode", default="summary_only", choices=["summary_only", "canonical_snapshot", "raw_and_canonical"])
    parser.add_argument("--refresh-before-export", action="store_true", help="omit --noupdate and let Routinator refresh before exporting VRPs")
    parser.add_argument("--timeout-seconds", type=int, default=600)
    args = parser.parse_args()

    created_at = utc_now_iso()
    run_ts = utc_run_id()
    run_id = f"m20_5a_vrp_summary_{args.probe_id}_{run_ts}"

    root = Path(args.out_dir).expanduser().resolve()
    latest_dir = root / "latest"
    records_dir = root / "records"
    exports_dir = root / "exports"
    checks_dir = root / "checks"
    logs_dir = root / "logs"
    history_dir = root / "history" / run_id

    for d in [latest_dir, records_dir, exports_dir, checks_dir, logs_dir, history_dir]:
        d.mkdir(parents=True, exist_ok=True)

    raw_tmp = history_dir / "vrps.raw.json.tmp"
    raw_final = history_dir / "vrps.raw.json"
    canonical_gz = history_dir / "vrps.canonical.jsonl.gz"
    raw_gz = history_dir / "vrps.raw.json.gz"

    warnings: List[str] = []
    errors: List[str] = []

    version_code, version_out, version_err, _ = run_cmd([args.routinator_bin, "--version"], timeout=30)
    validator_version = version_out.strip() or version_err.strip() or "unknown"

    status_obj = try_get_routinator_status(args.status_url)
    status_fields = extract_status_fields(status_obj) if isinstance(status_obj, dict) else {}

    if isinstance(status_obj, dict) and status_obj.get("_status_fetch_error"):
        warnings.append("routinator_status_api_fetch_failed")

    collection_started = utc_now_iso()
    start = time.time()

    cmd = [
        args.routinator_bin,
        "vrps",
        "--format",
        "json",
    ]

    if not args.refresh_before_export:
        cmd.append("--noupdate")

    cmd.extend([
        "--output",
        str(raw_tmp),
    ])

    code, stdout, stderr, cmd_latency_ms = run_cmd(cmd, timeout=args.timeout_seconds)
    collection_finished = utc_now_iso()
    latency_ms = int((time.time() - start) * 1000)

    export_status = "success"
    if code != 0:
        export_status = "failed"
        errors.append(f"routinator_vrps_failed_exit_code:{code}")
        if stderr:
            errors.append(stderr[-1000:])

    vrp_count = 0
    vrp_digest = "sha256:" + hashlib.sha256(b"").hexdigest()
    router_key_count = 0
    router_key_digest = "sha256:" + hashlib.sha256(b"").hexdigest()
    aspa_count = 0
    aspa_digest = "sha256:" + hashlib.sha256(b"").hexdigest()

    raw_sha256 = None
    raw_size_bytes = None
    full_snapshot_saved = False
    full_snapshot_path = None
    full_snapshot_reason = None

    if export_status == "success" and raw_tmp.exists():
        raw_tmp.rename(raw_final)
        raw_sha256 = sha256_file(raw_final)
        raw_size_bytes = raw_final.stat().st_size

        try:
            obj = load_json_any(raw_final)
            vrp_rows = []
            skipped_vrp_rows = 0

            for row in iter_vrp_rows(obj):
                n = normalize_vrp_entry(row)
                if n is None:
                    skipped_vrp_rows += 1
                    continue
                vrp_rows.append(n)

            canonical_lines = canonical_lines_for_rows(vrp_rows)
            vrp_count = len(vrp_rows)
            vrp_digest = sha256_text_lines(canonical_lines)

            if skipped_vrp_rows:
                warnings.append(f"skipped_unrecognized_vrp_rows:{skipped_vrp_rows}")

            router_key_count, router_key_digest = digest_generic_rows(iter_router_key_rows(obj))
            aspa_count, aspa_digest = digest_generic_rows(iter_aspa_rows(obj))

            if args.mode in {"canonical_snapshot", "raw_and_canonical"}:
                with gzip.open(canonical_gz, "wt", encoding="utf-8", compresslevel=6) as f:
                    for line in canonical_lines:
                        f.write(line + "\n")
                full_snapshot_saved = True
                full_snapshot_path = str(canonical_gz)
                full_snapshot_reason = args.mode

            if args.mode == "raw_and_canonical":
                gzip_copy(raw_final, raw_gz)
                full_snapshot_saved = True
                full_snapshot_path = str(raw_gz)
                full_snapshot_reason = args.mode

        except Exception as exc:
            export_status = "parse_failed"
            errors.append(f"parse_vrp_json_failed:{exc}")

    else:
        if raw_tmp.exists():
            raw_tmp.unlink(missing_ok=True)

    if raw_final.exists() and args.mode == "summary_only":
        raw_final.unlink(missing_ok=True)

    summary = {
        "schema": "s3.m20_5.probe_vrp_summary.v1",
        "created_at_utc": created_at,
        "run_id": run_id,

        "probe_id": args.probe_id,
        "validator_id": args.validator_id,
        "validator_version": validator_version,
        "validator_backend": "cli",

        "collection_started_at_utc": collection_started,
        "collection_finished_at_utc": collection_finished,
        "latency_ms": latency_ms,
        "command_latency_ms": cmd_latency_ms,

        "export_status": export_status,
        "vrp_count": vrp_count,
        "vrp_digest": vrp_digest,
        "router_key_count": router_key_count,
        "router_key_digest": router_key_digest,
        "aspa_count": aspa_count,
        "aspa_digest": aspa_digest,

        "last_update_start": status_fields.get("last_update_start"),
        "last_update_done": status_fields.get("last_update_done"),
        "last_update_duration": status_fields.get("last_update_duration"),
        "validator_cycle_status": "known" if status_fields.get("last_update_done") else "unknown",

        "status_api": status_fields,

        "raw_sha256": raw_sha256,
        "raw_size_bytes": raw_size_bytes,

        "full_snapshot_saved": full_snapshot_saved,
        "full_snapshot_path": full_snapshot_path,
        "full_snapshot_reason": full_snapshot_reason,

        "mode": args.mode,
        "refresh_before_export": bool(args.refresh_before_export),
        "cli_export_policy": "allow_update" if args.refresh_before_export else "noupdate",
        "warnings": warnings,
        "errors": errors,
    }

    compact = {
        "schema": "s3.m20_5.probe_vrp_summary_compact.v1",
        "created_at_utc": created_at,
        "run_id": run_id,
        "probe_id": args.probe_id,
        "validator_id": args.validator_id,
        "validator_version": validator_version,
        "collection_finished_at_utc": collection_finished,
        "export_status": export_status,
        "vrp_count": vrp_count,
        "vrp_digest": vrp_digest,
        "router_key_count": router_key_count,
        "aspa_count": aspa_count,
        "last_update_done": status_fields.get("last_update_done"),
        "latency_ms": latency_ms,
        "full_snapshot_saved": full_snapshot_saved,
        "refresh_before_export": bool(args.refresh_before_export),
        "cli_export_policy": "allow_update" if args.refresh_before_export else "noupdate",
        "warnings": warnings,
        "errors": errors,
    }

    summary_path = history_dir / "probe_vrp_summary.json"
    compact_path = history_dir / "probe_vrp_summary.compact.json"
    latest_summary = latest_dir / "probe_vrp_summary.json"
    latest_compact = latest_dir / "probe_vrp_summary.compact.json"
    records_path = records_dir / "probe_vrp_summary_records.jsonl"

    write_json(summary_path, summary)
    write_json(compact_path, compact)
    write_json(latest_summary, summary)
    write_json(latest_compact, compact)
    append_jsonl(records_path, compact)

    archive_name = f"{run_id}.tar.gz"
    archive_path = exports_dir / archive_name

    members = [
        history_dir / "probe_vrp_summary.json",
        history_dir / "probe_vrp_summary.compact.json",
        latest_summary,
        latest_compact,
        records_path,
    ]

    if canonical_gz.exists():
        members.append(canonical_gz)
    if raw_gz.exists():
        members.append(raw_gz)

    create_archive(archive_path, root, members)

    sha_path = exports_dir / f"{archive_name}.sha256"
    sha_path.write_text(
        f"{sha256_file(archive_path).split(':', 1)[1]}  {archive_path}\n",
        encoding="utf-8",
    )

    status = "PASS" if export_status == "success" and vrp_count > 0 and vrp_digest.startswith("sha256:") else "FAIL"

    check_text = "\n".join([
        f"M20_5A_PROBE_VRP_SUMMARY_COLLECTOR={status}",
        "",
        f"probe_id = {args.probe_id}",
        f"run_id = {run_id}",
        f"validator_id = {args.validator_id}",
        f"validator_version = {validator_version}",
        f"export_status = {export_status}",
        f"vrp_count = {vrp_count}",
        f"vrp_digest = {vrp_digest}",
        f"router_key_count = {router_key_count}",
        f"aspa_count = {aspa_count}",
        f"last_update_done = {status_fields.get('last_update_done')}",
        f"latency_ms = {latency_ms}",
        f"mode = {args.mode}",
        f"refresh_before_export = {bool(args.refresh_before_export)}",
        f"cli_export_policy = {'allow_update' if args.refresh_before_export else 'noupdate'}",
        f"full_snapshot_saved = {full_snapshot_saved}",
        f"summary_path = {summary_path}",
        f"compact_path = {compact_path}",
        f"latest_summary = {latest_summary}",
        f"records_path = {records_path}",
        f"archive_path = {archive_path}",
        f"archive_sha256 = {sha_path}",
        f"warnings = {warnings}",
        f"errors = {errors}",
    ]) + "\n"

    check_path = checks_dir / "M20_5A_probe_vrp_summary.txt"
    check_path.write_text(check_text, encoding="utf-8")

    print(check_text)

    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
