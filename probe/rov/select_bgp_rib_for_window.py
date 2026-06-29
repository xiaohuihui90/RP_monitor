#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bz2
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


SCHEMA_RIB_SELECTION = "s3.probe.rov.rib_selection.v1"
SCHEMA_P10C_SUMMARY = "s3.probe.rov.p10c_time_aligned_rov_summary.v1"
ACCEPTANCE_FILE = "checks/P10C_TIME_ALIGNED_ROV_ACCEPTANCE.txt"
DEFAULT_PROBE_INPUTS = {
    "probe-cd": {
        "vrp": "data/probe/live_vrp_snapshots/probe-cd/latest_normalized_vrp.jsonl",
        "metadata": "data/probe/live_vrp_snapshots/probe-cd/latest_metadata.json",
    },
    "probe-sg": {
        "vrp": "data/probe/remote_snapshots/probe-sg/latest_normalized_vrp.jsonl",
        "metadata": "data/probe/remote_snapshots/probe-sg/latest_metadata.json",
    },
    "probe-k02": {
        "vrp": "data/probe/remote_snapshots/probe-k02/latest_normalized_vrp.jsonl",
        "metadata": "data/probe/remote_snapshots/probe-k02/latest_metadata.json",
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso_z(value: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError("empty UTC timestamp")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


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


def read_compressed_stream(path: Path, opener: Any) -> None:
    with opener(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            if not chunk:
                break


def check_rib_integrity(path: Path) -> dict[str, Any]:
    exists = path.is_file()
    size_bytes = path.stat().st_size if exists else 0
    result = {
        "path": str(path),
        "exists": exists,
        "size_bytes": size_bytes,
        "ok": False,
        "method": "",
        "error": "",
        "exit_code": None,
    }
    if not exists:
        result["error"] = "rib file missing"
        return result
    if size_bytes <= 0:
        result["error"] = "rib file is empty"
        return result

    suffix = path.suffix.lower()
    if suffix == ".bz2":
        bzip2_bin = shutil.which("bzip2")
        if bzip2_bin:
            result["method"] = "bzip2_tv"
            try:
                proc = subprocess.run([bzip2_bin, "-tv", str(path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900)
                result["exit_code"] = proc.returncode
                result["ok"] = proc.returncode == 0
                result["error"] = "" if result["ok"] else (proc.stderr or proc.stdout or "")[-4000:]
            except Exception as exc:
                result["error"] = str(exc)
            return result
        result["method"] = "python_bz2"
        try:
            read_compressed_stream(path, bz2.open)
            result["ok"] = True
        except Exception as exc:
            result["error"] = str(exc)
        return result

    if suffix == ".gz":
        result["method"] = "python_gzip"
        try:
            read_compressed_stream(path, gzip.open)
            result["ok"] = True
        except Exception as exc:
            result["error"] = str(exc)
        return result

    result["method"] = "size_only_uncompressed"
    result["ok"] = True
    return result


def corrupt_path_for(path: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return path.with_name(f"{path.name}.corrupt_{stamp}")


def parse_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"expected true or false, got {value}")


def parse_assignment(value: str, option_name: str) -> tuple[str, str]:
    if "=" not in value:
        raise ValueError(f"{option_name} must be PROBE_ID=PATH, got {value}")
    left, right = value.split("=", 1)
    left = left.strip()
    right = right.strip()
    if not left or not right:
        raise ValueError(f"{option_name} must be PROBE_ID=PATH, got {value}")
    return left, right


def parse_assignments(values: list[str], option_name: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for value in values:
        probe_id, path = parse_assignment(value, option_name)
        if probe_id in parsed:
            raise ValueError(f"duplicate {option_name} for probe_id={probe_id}")
        parsed[probe_id] = path
    return parsed


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


def parse_p8_window_id(window_id: str) -> tuple[datetime, datetime, datetime]:
    match = re.fullmatch(r"win_(\d{8}T\d{6}Z)_1h", str(window_id or "").strip())
    if not match:
        raise ValueError(f"unsupported P8 window_id format: {window_id}")
    start = parse_iso_z(match.group(1))
    end = start + timedelta(hours=1)
    center = start + timedelta(minutes=30)
    return start, end, center


def load_p8_acceptance(p8_run_dir: Path) -> dict[str, Any]:
    path = p8_run_dir / "checks" / "P8_CROSS_PROBE_PIPELINE_ACCEPTANCE.txt"
    raw = parse_key_value_file(path)
    status = raw.get("P8_CROSS_PROBE_PIPELINE") or raw.get("P8_CROSS_PROBE_OBSERVATION") or raw.get("P2_CROSS_PROBE_DIFF")
    window_id = raw.get("window_id") or ""
    window_start = window_end = window_center = None
    error = ""
    if window_id:
        try:
            window_start, window_end, window_center = parse_p8_window_id(window_id)
        except ValueError as exc:
            error = str(exc)
    else:
        error = "window_id missing"
    return {
        "path": str(path),
        "exists": path.is_file(),
        "raw": raw,
        "status": status or "",
        "pass": status == "PASS",
        "window_id": window_id,
        "window_quality": raw.get("window_quality") or "",
        "capture_time_skew_sec": int(raw["capture_time_skew_sec"]) if str(raw.get("capture_time_skew_sec", "")).isdigit() else None,
        "max_skew_sec": int(raw["max_skew_sec"]) if str(raw.get("max_skew_sec", "")).isdigit() else None,
        "probe_ids": parse_probe_ids(raw.get("probe_ids")),
        "window_start_utc": iso_z(window_start) if window_start else "",
        "window_end_utc": iso_z(window_end) if window_end else "",
        "window_center_utc": iso_z(window_center) if window_center else "",
        "error": error,
    }


def floor_to_interval(dt: datetime, interval_minutes: int) -> datetime:
    epoch = int(dt.timestamp())
    interval = interval_minutes * 60
    return datetime.fromtimestamp(epoch - (epoch % interval), timezone.utc)


def ceil_to_interval(dt: datetime, interval_minutes: int) -> datetime:
    floor = floor_to_interval(dt, interval_minutes)
    if floor == dt.replace(microsecond=0):
        return floor
    return floor + timedelta(minutes=interval_minutes)


def choose_rib_time(reference: datetime, policy: str, source: str) -> datetime:
    interval_minutes = 120 if source == "routeviews" else 480
    leq = floor_to_interval(reference, interval_minutes)
    geq = ceil_to_interval(reference, interval_minutes)
    if policy == "nearest_leq":
        return leq
    if policy == "nearest_geq":
        return geq
    if abs((reference - leq).total_seconds()) <= abs((geq - reference).total_seconds()):
        return leq
    return geq


def routeviews_url(collector: str, rib_time: datetime) -> str:
    month = rib_time.strftime("%Y.%m")
    filename = f"rib.{rib_time.strftime('%Y%m%d.%H%M')}.bz2"
    if collector == "routeviews2":
        return f"https://archive.routeviews.org/bgpdata/{month}/RIBS/{filename}"
    return f"https://archive.routeviews.org/{collector}/bgpdata/{month}/RIBS/{filename}"


def ris_url(collector: str, rib_time: datetime) -> str:
    month = rib_time.strftime("%Y.%m")
    filename = f"bview.{rib_time.strftime('%Y%m%d.%H%M')}.gz"
    return f"https://data.ris.ripe.net/{collector}/{month}/{filename}"


def local_rib_path(root: Path, source: str, rib_time: datetime) -> Path:
    if source == "routeviews":
        filename = f"rib.{rib_time.strftime('%Y%m%d.%H%M')}.bz2"
        return root / "data" / "bgp" / "routeviews" / "ribs" / filename
    filename = f"bview.{rib_time.strftime('%Y%m%d.%H%M')}.gz"
    return root / "data" / "bgp" / "ris" / "ribs" / filename


def build_rib_selection(p8_run_dir: Path, p8: dict[str, Any], collector: str, source: str, policy: str, align_to: str, root: Path) -> dict[str, Any]:
    reference = parse_iso_z(p8["window_start_utc"] if align_to == "window_start" else p8["window_center_utc"])
    rib_time = choose_rib_time(reference, policy, source)
    url = routeviews_url(collector, rib_time) if source == "routeviews" else ris_url(collector, rib_time)
    path = local_rib_path(root, source, rib_time)
    return {
        "schema": SCHEMA_RIB_SELECTION,
        "p8_run_dir": str(p8_run_dir),
        "window_id": p8["window_id"],
        "window_start_utc": p8["window_start_utc"],
        "window_end_utc": p8["window_end_utc"],
        "window_center_utc": p8["window_center_utc"],
        "collector": collector,
        "source": source,
        "rib_time_policy": policy,
        "align_to": align_to,
        "selected_rib_time_utc": iso_z(rib_time),
        "selected_rib_url": url,
        "selected_local_path": str(path),
        "rib_time_delta_sec": abs(int((rib_time - reference).total_seconds())),
    }


def download_file(url: str, dest: Path, enabled: bool) -> dict[str, Any]:
    initial_integrity = check_rib_integrity(dest)
    status = {
        "enabled": enabled,
        "status": "",
        "url": url,
        "local_path": str(dest),
        "exists_before": initial_integrity["exists"] and initial_integrity["size_bytes"] > 0,
        "exists_after": False,
        "exit_code": None,
        "command": [],
        "error": "",
        "download_skipped_existing": False,
        "download_tmp_path": "",
        "corrupt_path": "",
        "initial_integrity": initial_integrity,
        "download_integrity": {},
        "final_integrity": initial_integrity,
    }
    if initial_integrity["ok"]:
        status["status"] = "exists"
        status["download_skipped_existing"] = True
        status["exists_after"] = True
        return status
    if not enabled:
        status["status"] = "existing_corrupt_download_false" if status["exists_before"] else "skipped_download_false"
        status["exists_after"] = False
        return status

    downloader = shutil.which("curl")
    tmp = dest.with_name(f"{dest.name}.tmp.{os.getpid()}.{time.time_ns()}")
    if downloader:
        cmd = [
            downloader,
            "-L",
            "--fail",
            "--retry",
            "3",
            "--connect-timeout",
            "20",
            "--speed-time",
            "60",
            "--speed-limit",
            "1024",
            "--output",
            str(tmp),
            url,
        ]
    else:
        downloader = shutil.which("wget")
        if downloader:
            cmd = [downloader, "--timeout=20", "--tries=3", "-O", str(tmp), url]
        else:
            status["status"] = "downloader_missing"
            status["error"] = "curl or wget is required for download=true"
            return status

    dest.parent.mkdir(parents=True, exist_ok=True)
    status["command"] = cmd
    status["download_tmp_path"] = str(tmp)
    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    status["exit_code"] = proc.returncode
    if proc.returncode == 0 and tmp.is_file() and tmp.stat().st_size > 0:
        tmp_integrity = check_rib_integrity(tmp)
        status["download_integrity"] = tmp_integrity
        if not tmp_integrity["ok"]:
            corrupt_path = corrupt_path_for(dest)
            os.replace(tmp, corrupt_path)
            status["status"] = "failed_integrity"
            status["corrupt_path"] = str(corrupt_path)
            status["error"] = tmp_integrity.get("error") or "downloaded file failed integrity check"
            status["final_integrity"] = check_rib_integrity(dest)
            status["exists_after"] = False
            return status
        os.replace(tmp, dest)
        status["status"] = "downloaded"
        status["final_integrity"] = check_rib_integrity(dest)
        status["exists_after"] = True
        return status
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    status["status"] = "failed"
    status["error"] = (proc.stderr or proc.stdout or "")[-4000:]
    status["final_integrity"] = check_rib_integrity(dest)
    status["exists_after"] = bool(status["final_integrity"].get("ok"))
    return status


def sanitize_run_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.=-]+", "_", value)


def default_out_dir(root: Path, p8: dict[str, Any], collector: str) -> Path:
    run_id = f"{sanitize_run_part(p8.get('window_id') or 'unknown_window')}_{sanitize_run_part(collector)}"
    return root / "data" / "probe" / "p10c_time_aligned_rov" / run_id


def default_p10b_dir(root: Path, collector: str, rib_time_utc: str, max_routes: int | None) -> Path:
    stamp = rib_time_utc.replace("-", "").replace(":", "")
    suffix = f"_max{max_routes}" if max_routes is not None else ""
    return root / "data" / "bgp" / "p10_route_tables" / f"{collector}_{stamp}{suffix}"


def default_p10a_dir(root: Path, p8: dict[str, Any], collector: str, rib_time_utc: str, max_routes: int | None) -> Path:
    stamp = rib_time_utc.replace("-", "").replace(":", "")
    suffix = f"_max{max_routes}" if max_routes is not None else ""
    run_id = f"{sanitize_run_part(p8.get('window_id') or 'unknown_window')}_{sanitize_run_part(collector)}_{stamp}{suffix}"
    return root / "data" / "probe" / "p10_rov_impact" / run_id


def executable_command_for_module(wrapper: Path, module: str, prefer_wrappers: bool) -> tuple[list[str], str]:
    bash = shutil.which("bash")
    if prefer_wrappers and bash:
        return [bash, str(wrapper)], str(wrapper)
    return [sys.executable, "-m", module], module


def run_command(cmd: list[str], cwd: Path) -> dict[str, Any]:
    started = utc_now()
    proc = subprocess.run(cmd, cwd=str(cwd), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return {
        "command": cmd,
        "exit_code": proc.returncode,
        "started_at_utc": started,
        "finished_at_utc": utc_now(),
        "stdout_tail": (proc.stdout or "")[-4000:],
        "stderr_tail": (proc.stderr or "")[-4000:],
    }


def acceptance_status(path: Path, key: str) -> str:
    parsed = parse_key_value_file(path)
    return parsed.get(key, "")


def prepare_probe_inputs(root: Path, vrp_args: list[str], metadata_args: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    vrps = {probe_id: item["vrp"] for probe_id, item in DEFAULT_PROBE_INPUTS.items()}
    metadata = {probe_id: item["metadata"] for probe_id, item in DEFAULT_PROBE_INPUTS.items()}
    vrps.update(parse_assignments(vrp_args, "--vrp"))
    metadata.update(parse_assignments(metadata_args, "--metadata"))
    return {k: str(resolve_path(v, root)) for k, v in sorted(vrps.items())}, {k: str(resolve_path(v, root)) for k, v in sorted(metadata.items())}


def p10b_route_count(summary_path: Path) -> int:
    try:
        with summary_path.open("r", encoding="utf-8-sig") as f:
            obj = json.load(f)
        return int(obj.get("unique_prefix_origin_count") or 0)
    except Exception:
        return 0


def route_time_alignment_expected(rib_delta: int | None, max_skew: int, p10a_status: str, p10a_acceptance: dict[str, str]) -> bool:
    if rib_delta is None:
        return False
    route_ok = str(p10a_acceptance.get("route_time_alignment_ok", "")).lower() == "true"
    if rib_delta <= max_skew:
        return route_ok
    return p10a_status in {"PASS_WITH_EXCLUSIONS", "SKIPPED"} and not route_ok


def write_acceptance(out_dir: Path, status: str, summary: dict[str, Any], checks: dict[str, bool]) -> None:
    lines = [
        f"P10C_TIME_ALIGNED_ROV={status}",
        f"p8_run_dir={summary.get('p8_run_dir', '')}",
        f"window_id={summary.get('window_id', '')}",
        f"collector={summary.get('collector', '')}",
        f"selected_rib_time_utc={summary.get('selected_rib_time_utc', '')}",
        f"rib_time_delta_sec={summary.get('rib_time_delta_sec', '')}",
        f"rib_local_path={summary.get('rib_local_path', '')}",
        f"rib_local_exists={str(summary.get('rib_local_exists', False)).lower()}",
        f"rib_size_bytes={summary.get('rib_size_bytes', 0)}",
        f"rib_integrity_ok={str(summary.get('rib_integrity_ok', False)).lower()}",
        f"rib_integrity_check_method={summary.get('rib_integrity_check_method', '')}",
        f"download_skipped_existing={str(summary.get('download_skipped_existing', False)).lower()}",
        f"p10b_run_dir={summary.get('p10b_run_dir', '')}",
        f"p10a_run_dir={summary.get('p10a_run_dir', '')}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={str(value).lower()}" for key, value in checks.items())
    atomic_write_text(out_dir / ACCEPTANCE_FILE, "\n".join(lines) + "\n")


def run_p10c(args: argparse.Namespace) -> int:
    root = repo_root()
    started_at = utc_now()
    p8_run_dir = resolve_path(args.p8_run_dir, root)
    p8 = load_p8_acceptance(p8_run_dir)
    out_dir = resolve_path(args.out_dir, root) if args.out_dir else default_out_dir(root, p8, args.collector)
    out_dir.mkdir(parents=True, exist_ok=True)

    p10b_run_dir = resolve_path(args.p10b_out_dir, root) if args.p10b_out_dir else None
    p10a_run_dir = resolve_path(args.p10a_out_dir, root) if args.p10a_out_dir else None
    rib_selection: dict[str, Any] = {
        "schema": SCHEMA_RIB_SELECTION,
        "p8_run_dir": str(p8_run_dir),
        "window_id": p8.get("window_id", ""),
        "collector": args.collector,
        "source": args.source,
        "selected_rib_time_utc": "",
        "selected_rib_url": "",
        "selected_local_path": "",
        "rib_time_delta_sec": None,
        "error": p8.get("error", ""),
    }

    p10b_result: dict[str, Any] = {}
    p10a_result: dict[str, Any] = {}
    download_status: dict[str, Any] = {}
    p10a_acceptance: dict[str, str] = {}
    p10b_acceptance: dict[str, str] = {}

    if p8["exists"] and p8["window_id"] and not p8["error"]:
        rib_selection = build_rib_selection(p8_run_dir, p8, args.collector, args.source, args.rib_time_policy, args.align_to, root)
    atomic_write_json(out_dir / "rib_selection.json", rib_selection)

    rib_path = Path(rib_selection.get("selected_local_path") or "")
    rib_selected = bool(rib_selection.get("selected_rib_time_utc") and rib_selection.get("selected_rib_url"))
    if rib_selected:
        download_status = download_file(str(rib_selection["selected_rib_url"]), rib_path, bool(args.download))
    else:
        download_status = {
            "enabled": bool(args.download),
            "status": "not_selected",
            "exists_after": False,
            "download_skipped_existing": False,
            "final_integrity": {"exists": False, "size_bytes": 0, "ok": False, "method": "", "error": "rib not selected"},
        }
    rib_integrity = download_status.get("final_integrity") or check_rib_integrity(rib_path)

    p10b_acceptance_path = None
    p10a_acceptance_path = None
    if rib_selected and rib_integrity.get("ok"):
        p10b_run_dir = p10b_run_dir or default_p10b_dir(root, args.collector, rib_selection["selected_rib_time_utc"], args.max_routes)
        p10b_cmd, p10b_entrypoint = executable_command_for_module(
            root / "scripts" / "runtime" / "run_p10_build_route_table_once.sh",
            "probe.rov.build_bgp_route_table",
            bool(args.prefer_wrappers),
        )
        p10b_cmd += [
            "--rib", str(rib_path),
            "--collector", args.collector,
            "--rib-time-utc", rib_selection["selected_rib_time_utc"],
            "--out-dir", str(p10b_run_dir),
            "--bgpdump-bin", args.bgpdump_bin,
            "--as-set-policy", args.as_set_policy,
        ]
        if args.max_routes is not None:
            p10b_cmd += ["--max-routes", str(args.max_routes)]
        if args.no_include_ipv6:
            p10b_cmd += ["--no-include-ipv6"]
        p10b_result = run_command(p10b_cmd, root)
        p10b_result["entrypoint"] = p10b_entrypoint
        p10b_acceptance_path = p10b_run_dir / "checks" / "P10_BGP_ROUTE_TABLE_ACCEPTANCE.txt"
        p10b_acceptance = parse_key_value_file(p10b_acceptance_path)

    p10b_status = p10b_acceptance.get("P10_BGP_ROUTE_TABLE", "")
    route_count = p10b_route_count(p10b_run_dir / "route_build_summary.json") if p10b_run_dir else 0
    if p10b_status == "PASS" and route_count > 0:
        p10a_run_dir = p10a_run_dir or default_p10a_dir(root, p8, args.collector, rib_selection["selected_rib_time_utc"], args.max_routes)
        vrps, metadata = prepare_probe_inputs(root, args.vrp or [], args.metadata or [])
        p10a_cmd, p10a_entrypoint = executable_command_for_module(
            root / "scripts" / "runtime" / "run_p10_rov_impact_once.sh",
            "probe.rov.analyze_rov_impact",
            bool(args.prefer_wrappers),
        )
        p10a_cmd += [
            "--mode", "rib_snapshot",
            "--routes", str(p10b_run_dir / "routes.jsonl"),
            "--p8-run-dir", str(p8_run_dir),
            "--out-dir", str(p10a_run_dir),
            "--window-id", p8["window_id"],
            "--window-start-utc", p8["window_start_utc"],
            "--window-end-utc", p8["window_end_utc"],
            "--max-route-time-skew-sec", str(args.max_route_time_skew_sec),
        ]
        for probe_id in sorted(vrps):
            p10a_cmd += ["--vrp", f"{probe_id}={vrps[probe_id]}"]
            if probe_id in metadata:
                p10a_cmd += ["--metadata", f"{probe_id}={metadata[probe_id]}"]
        p10a_result = run_command(p10a_cmd, root)
        p10a_result["entrypoint"] = p10a_entrypoint
        p10a_acceptance_path = p10a_run_dir / "checks" / "P10_ROV_IMPACT_ACCEPTANCE.txt"
        p10a_acceptance = parse_key_value_file(p10a_acceptance_path)

    p10a_status = p10a_acceptance.get("P10_ROV_IMPACT", "")
    checks = {
        "p8_acceptance_ok": bool(p8["exists"] and p8["pass"] and not p8["error"]),
        "window_quality_ok": p8.get("window_quality") == "OK",
        "rib_selected": rib_selected,
        "rib_downloaded_or_exists": bool(rib_integrity.get("ok")),
        "rib_local_exists": bool(rib_integrity.get("exists")),
        "rib_integrity_ok": bool(rib_integrity.get("ok")),
        "p10b_acceptance_pass": p10b_status == "PASS",
        "p10b_route_count_gt_zero": route_count > 0,
        "p10a_acceptance_exists": bool(p10a_acceptance_path and p10a_acceptance_path.is_file()),
        "p10a_not_fail": p10a_status in {"PASS", "PASS_WITH_EXCLUSIONS", "SKIPPED"},
        "route_time_alignment_behavior_expected": route_time_alignment_expected(
            rib_selection.get("rib_time_delta_sec"),
            int(args.max_route_time_skew_sec),
            p10a_status,
            p10a_acceptance,
        ),
        "no_strong_root_cause_claim": True,
    }
    if not all(checks.values()):
        status = "FAIL"
    elif p10a_status == "PASS":
        status = "PASS"
    else:
        status = "PASS_WITH_EXCLUSIONS"

    summary = {
        "schema": SCHEMA_P10C_SUMMARY,
        "status": status,
        "p8_run_dir": str(p8_run_dir),
        "p8_acceptance": p8,
        "window_id": p8.get("window_id", ""),
        "collector": args.collector,
        "source": args.source,
        "selected_rib_time_utc": rib_selection.get("selected_rib_time_utc", ""),
        "rib_time_delta_sec": rib_selection.get("rib_time_delta_sec"),
        "rib_local_path": str(rib_path) if rib_selected else "",
        "rib_local_exists": bool(rib_integrity.get("exists")),
        "rib_size_bytes": int(rib_integrity.get("size_bytes") or 0),
        "rib_integrity_ok": bool(rib_integrity.get("ok")),
        "rib_integrity_check_method": rib_integrity.get("method") or "",
        "rib_integrity_error": rib_integrity.get("error") or "",
        "rib_integrity": rib_integrity,
        "download_skipped_existing": bool(download_status.get("download_skipped_existing")),
        "download_status": download_status,
        "rib_selection_json": str(out_dir / "rib_selection.json"),
        "p10b_run_dir": str(p10b_run_dir) if p10b_run_dir else "",
        "p10b_exit_code": p10b_result.get("exit_code"),
        "p10b_acceptance_status": p10b_status,
        "p10b_route_count": route_count,
        "p10b_acceptance_file": str(p10b_acceptance_path) if p10b_acceptance_path else "",
        "p10b_result": p10b_result,
        "p10a_run_dir": str(p10a_run_dir) if p10a_run_dir else "",
        "p10a_exit_code": p10a_result.get("exit_code"),
        "p10a_acceptance_status": p10a_status,
        "p10a_acceptance_file": str(p10a_acceptance_path) if p10a_acceptance_path else "",
        "p10a_result": p10a_result,
        "checks": checks,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
    }
    atomic_write_json(out_dir / "p10c_summary.json", summary)
    write_acceptance(out_dir, status, summary, checks)
    return 0 if status in {"PASS", "PASS_WITH_EXCLUSIONS"} else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="P10-C time-aligned BGP RIB fetcher and P10 runner.")
    parser.add_argument("--p8-run-dir", required=True)
    parser.add_argument("--collector", default="routeviews2")
    parser.add_argument("--source", choices=["routeviews", "ris"], default="routeviews")
    parser.add_argument("--rib-time-policy", choices=["nearest_leq", "nearest", "nearest_geq"], default="nearest_leq")
    parser.add_argument("--align-to", choices=["window_start", "window_center"], default="window_center")
    parser.add_argument("--download", type=parse_bool, default=True)
    parser.add_argument("--out-dir")
    parser.add_argument("--p10b-out-dir")
    parser.add_argument("--p10a-out-dir")
    parser.add_argument("--bgpdump-bin", default="bgpdump")
    parser.add_argument("--max-routes", type=int)
    parser.add_argument("--as-set-policy", choices=["skip", "mark_uncertain"], default="skip")
    parser.add_argument("--no-include-ipv6", action="store_true")
    parser.add_argument("--max-route-time-skew-sec", type=int, default=7200)
    parser.add_argument("--prefer-wrappers", type=parse_bool, default=True)
    parser.add_argument("--vrp", action="append", default=[], help="Optional PROBE_ID=normalized_vrp.jsonl override. Repeatable.")
    parser.add_argument("--metadata", action="append", default=[], help="Optional PROBE_ID=metadata.json override. Repeatable.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run_p10c(args)
    except ValueError as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
