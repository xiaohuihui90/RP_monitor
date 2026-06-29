#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from typing import Any, TextIO

try:
    from .build_bgp_route_table import build_route_table
    from .compute_rov_state_by_probe import compute_route_state
    from .load_bgp_routes import load_routes
    from .load_vrps import load_vrp_jsonl
    from .rov_validate import stable_id
except ImportError:  # pragma: no cover - direct script execution fallback
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from probe.rov.build_bgp_route_table import build_route_table
    from probe.rov.compute_rov_state_by_probe import compute_route_state
    from probe.rov.load_bgp_routes import load_routes
    from probe.rov.load_vrps import load_vrp_jsonl
    from probe.rov.rov_validate import stable_id


SCHEMA_ROUTE_STATE = "s3.probe.rov.route_state_by_probe.v1"
SCHEMA_TRANSITION = "s3.probe.rov.validation_transition_event.v1"
SCHEMA_ABNORMAL = "s3.probe.rov.abnormal_window_report.v1"
SCHEMA_SUMMARY = "s3.probe.rov.impact_summary.v1"
SCHEMA_INPUT_MANIFEST = "s3.probe.rov.input_manifest.v1"
DEFAULT_REQUIRED_TALS = "apnic,arin,ripe,lacnic,afrinic"
EXPECTED_OUTPUT_FILES = (
    "route_state_by_probe.jsonl",
    "validation_transition_events.jsonl",
    "transition_matrix.csv",
    "affected_prefix_summary.csv",
    "affected_origin_as_summary.csv",
    "tal_impact_summary.csv",
    "abnormal_window_report.json",
    "rov_impact_summary.json",
    "p10_input_manifest.json",
)
ACCEPTANCE_OUTPUT_FILE = "checks/P10_ROV_IMPACT_ACCEPTANCE.txt"
TRANSITION_IMPACT_CLASS = {
    "Valid->NotFound": "ROV_DOWNGRADE_CANDIDATE",
    "Valid->Invalid": "FALSE_REJECT_RISK",
    "Invalid->Valid": "STALE_OR_OVERPERMISSIVE_VALID_CANDIDATE",
    "NotFound->Invalid": "NEW_REJECT_RISK",
    "Invalid->NotFound": "REJECT_TO_UNKNOWN_CHANGE",
    "NotFound->Valid": "NEW_AUTHORIZATION_VISIBLE",
}


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
    return Path(__file__).resolve().parents[2]


def resolve_path(value: str, root: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()


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


def iso_z(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json_object(path: Path) -> tuple[dict[str, Any], str | None]:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            return {}, "expected JSON object"
        return obj, None
    except Exception as exc:
        return {}, str(exc)


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


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def file_info(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": str(path), "exists": False, "sha256": "", "size_bytes": 0}
    return {
        "path": str(path),
        "exists": True,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def metadata_record(probe_id: str, path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"probe_id": probe_id, "path": "", "exists": False, "json_ok": False, "error": "metadata not provided"}
    exists = path.is_file()
    obj, error = load_json_object(path) if exists else ({}, "metadata missing")
    capture_time = parse_iso_datetime(obj.get("capture_time_utc"))
    if capture_time is None and isinstance(obj.get("raw_metadata"), dict):
        capture_time = parse_iso_datetime(obj["raw_metadata"].get("generatedTime"))
    return {
        "probe_id": probe_id,
        "path": str(path),
        "exists": exists,
        "json_ok": exists and error is None,
        "error": error,
        "validator_health": obj.get("validator_health"),
        "snapshot_id": obj.get("snapshot_id"),
        "capture_time_utc": iso_z(capture_time),
        "capture_time_epoch": capture_time.timestamp() if capture_time else None,
        "metadata_vrp_count": obj.get("normalized_vrp_count", obj.get("vrp_count")),
    }


def capture_time_skew_sec(metadata: dict[str, dict[str, Any]]) -> int | None:
    epochs = [float(item["capture_time_epoch"]) for item in metadata.values() if item.get("capture_time_epoch") is not None]
    if len(epochs) < 2:
        return None
    return int(max(epochs) - min(epochs))


def window_center(
    window_start: str | None,
    window_end: str | None,
    metadata: dict[str, dict[str, Any]],
) -> datetime | None:
    start = parse_iso_datetime(window_start)
    end = parse_iso_datetime(window_end)
    if start and end:
        return datetime.fromtimestamp((start.timestamp() + end.timestamp()) / 2, timezone.utc)
    epochs = [float(item["capture_time_epoch"]) for item in metadata.values() if item.get("capture_time_epoch") is not None]
    if epochs:
        return datetime.fromtimestamp((min(epochs) + max(epochs)) / 2, timezone.utc)
    return start or end


def median_route_time(routes: list[dict[str, Any]]) -> datetime | None:
    epochs = []
    for route in routes:
        dt = parse_iso_datetime(route.get("observed_time_utc"))
        if dt is not None:
            epochs.append(dt.timestamp())
    if not epochs:
        return None
    return datetime.fromtimestamp(statistics.median(epochs), timezone.utc)


def route_time_profile(
    routes: list[dict[str, Any]],
    explicit_route_time: datetime | None,
    center: datetime | None,
    max_route_time_skew_sec: int,
) -> dict[str, Any]:
    observed_times = []
    deltas = []
    for route in routes:
        dt = parse_iso_datetime(route.get("observed_time_utc"))
        if dt is None:
            continue
        observed_times.append(dt)
        if center is not None:
            deltas.append(abs(int(dt.timestamp() - center.timestamp())))

    if observed_times:
        min_dt = min(observed_times)
        max_dt = max(observed_times)
        max_delta = max(deltas) if deltas else None
        return {
            "route_time_policy": "observed_time_strict",
            "route_time_utc": iso_z(datetime.fromtimestamp(statistics.median([dt.timestamp() for dt in observed_times]), timezone.utc)),
            "min_route_time_utc": iso_z(min_dt),
            "max_route_time_utc": iso_z(max_dt),
            "max_route_time_delta_sec": max_delta,
            "route_time_alignment_ok": max_delta is not None and max_delta <= max_route_time_skew_sec,
            "route_observed_time_count": len(observed_times),
        }

    if explicit_route_time is not None and center is not None:
        delta = abs(int(explicit_route_time.timestamp() - center.timestamp()))
        return {
            "route_time_policy": "explicit_route_time_utc",
            "route_time_utc": iso_z(explicit_route_time),
            "min_route_time_utc": "",
            "max_route_time_utc": "",
            "max_route_time_delta_sec": delta,
            "route_time_alignment_ok": delta <= max_route_time_skew_sec,
            "route_observed_time_count": 0,
        }

    return {
        "route_time_policy": "missing_route_time",
        "route_time_utc": iso_z(explicit_route_time),
        "min_route_time_utc": "",
        "max_route_time_utc": "",
        "max_route_time_delta_sec": None,
        "route_time_alignment_ok": False,
        "route_observed_time_count": 0,
    }


def route_time_for_route(route: dict[str, Any], explicit_route_time: datetime | None) -> datetime | None:
    return parse_iso_datetime(route.get("observed_time_utc")) or explicit_route_time


def route_time_delta_for_route(route: dict[str, Any], explicit_route_time: datetime | None, center: datetime | None) -> int | None:
    dt = route_time_for_route(route, explicit_route_time)
    if dt is None or center is None:
        return None
    return abs(int(dt.timestamp() - center.timestamp()))


def read_p8_candidate_vrp_keys(p8_run_dir: Path | None) -> set[str]:
    if p8_run_dir is None:
        return set()
    path = p8_run_dir / "candidate_events.jsonl"
    if not path.is_file():
        path = p8_run_dir / "p2" / "candidate_events.jsonl"
    if not path.is_file():
        return set()
    keys: set[str] = set()
    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("vrp_key"):
                keys.add(str(obj["vrp_key"]))
    return keys


def load_p8_summary(p8_run_dir: Path | None) -> dict[str, Any]:
    if p8_run_dir is None:
        return {}
    obj, error = load_json_object(p8_run_dir / "cross_probe_summary.json")
    if error is None:
        return obj
    obj, error = load_json_object(p8_run_dir / "p2" / "cross_probe_summary.json")
    return obj if error is None else {}


def parse_probe_id_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    if not text:
        return []
    return [part.strip() for part in text.split(",") if part.strip()]


def load_p8_context(p8_run_dir: Path | None) -> dict[str, Any]:
    if p8_run_dir is None:
        return {
            "p8_run_dir": "",
            "p8_window_id": "",
            "p8_window_quality": "",
            "p8_capture_time_skew_sec": None,
            "p8_max_skew_sec": None,
            "p8_probe_ids": [],
            "p8_summary_available": False,
            "p8_acceptance_available": False,
            "snapshot_id_by_probe": {},
            "capture_time_by_probe": {},
        }

    pipeline_summary, _ = load_json_object(p8_run_dir / "pipeline_summary.json")
    p2_summary = load_p8_summary(p8_run_dir)
    acceptance = parse_acceptance(p8_run_dir / "checks" / "P8_CROSS_PROBE_PIPELINE_ACCEPTANCE.txt")
    if not acceptance:
        acceptance = parse_acceptance(p8_run_dir / "checks" / "P2_CROSS_PROBE_DIFF_ACCEPTANCE.txt")
    if not acceptance:
        acceptance = parse_acceptance(p8_run_dir / "p2" / "checks" / "P2_CROSS_PROBE_DIFF_ACCEPTANCE.txt")

    p8_window_id = acceptance.get("window_id") or str(p2_summary.get("window_id") or pipeline_summary.get("window_id") or "")
    p8_window_quality = acceptance.get("window_quality") or str(p2_summary.get("window_quality") or pipeline_summary.get("window_quality") or "")
    p8_capture_time_skew_sec = as_int(
        acceptance.get("capture_time_skew_sec")
        or p2_summary.get("capture_time_skew_sec")
        or pipeline_summary.get("capture_time_skew_sec")
    )
    p8_max_skew_sec = as_int(acceptance.get("max_skew_sec") or pipeline_summary.get("max_skew_sec"))
    p8_probe_ids = parse_probe_id_list(acceptance.get("probe_ids") or p2_summary.get("probe_ids") or pipeline_summary.get("probe_ids"))
    snapshot_id_by_probe = p2_summary.get("snapshot_id_by_probe") if isinstance(p2_summary.get("snapshot_id_by_probe"), dict) else {}
    capture_time_by_probe = p2_summary.get("capture_time_by_probe") if isinstance(p2_summary.get("capture_time_by_probe"), dict) else {}
    if not capture_time_by_probe and isinstance(pipeline_summary.get("capture_time_by_probe"), dict):
        capture_time_by_probe = pipeline_summary.get("capture_time_by_probe") or {}

    return {
        "p8_run_dir": str(p8_run_dir),
        "p8_window_id": p8_window_id,
        "p8_window_quality": p8_window_quality,
        "p8_capture_time_skew_sec": p8_capture_time_skew_sec,
        "p8_max_skew_sec": p8_max_skew_sec,
        "p8_probe_ids": p8_probe_ids,
        "p8_summary_available": bool(p2_summary or pipeline_summary),
        "p8_acceptance_available": bool(acceptance),
        "snapshot_id_by_probe": snapshot_id_by_probe,
        "capture_time_by_probe": capture_time_by_probe,
    }


def p8_input_metadata_match(p8_context: dict[str, Any], metadata: dict[str, dict[str, Any]]) -> bool | str:
    p8_probe_ids = set(p8_context.get("p8_probe_ids") or [])
    if not p8_context.get("p8_run_dir") or not p8_probe_ids:
        return "not_available"
    input_probe_ids = set(metadata)
    if input_probe_ids != p8_probe_ids:
        return False

    snapshot_id_by_probe = p8_context.get("snapshot_id_by_probe") if isinstance(p8_context.get("snapshot_id_by_probe"), dict) else {}
    if snapshot_id_by_probe:
        comparable = True
        for probe_id in sorted(input_probe_ids):
            p8_snapshot = str(snapshot_id_by_probe.get(probe_id) or "").strip()
            input_snapshot = str(metadata.get(probe_id, {}).get("snapshot_id") or "").strip()
            if not p8_snapshot or not input_snapshot:
                comparable = False
                break
            if p8_snapshot != input_snapshot:
                return False
        if comparable:
            return True

    capture_time_by_probe = p8_context.get("capture_time_by_probe") if isinstance(p8_context.get("capture_time_by_probe"), dict) else {}
    if capture_time_by_probe:
        comparable = True
        for probe_id in sorted(input_probe_ids):
            p8_time = iso_z(parse_iso_datetime(capture_time_by_probe.get(probe_id)))
            input_time = iso_z(parse_iso_datetime(metadata.get(probe_id, {}).get("capture_time_utc")))
            if not p8_time or not input_time:
                comparable = False
                break
            if p8_time != input_time:
                return False
        if comparable:
            return True

    return "not_available"


def vrp_key(vrp: dict[str, Any]) -> str:
    return f"{vrp.get('tal')}|{vrp.get('asn')}|{vrp.get('prefix')}|{vrp.get('max_length')}"


def mapping_to_p8_for_event(event_covering: dict[str, list[dict[str, Any]]], p8_keys: set[str], p8_requested: bool) -> str:
    if not p8_requested:
        return "not_requested"
    for vrps in event_covering.values():
        for vrp in vrps:
            if vrp_key(vrp) in p8_keys:
                return "matched_vrp_diff"
    return "not_matched"


def csv_text(fieldnames: list[str], rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({name: row.get(name, "") for name in fieldnames})
    return buf.getvalue()


def write_empty_outputs(out_dir: Path) -> None:
    for name in ("route_state_by_probe.jsonl", "validation_transition_events.jsonl"):
        tmp, f = open_tmp_jsonl(out_dir / name)
        with f:
            pass
        publish_existing_atomically(tmp, out_dir / name)
    atomic_write_text(
        out_dir / "transition_matrix.csv",
        csv_text(["window_id", "probe_a", "probe_b", "state_a", "state_b", "route_count", "unique_prefix_count", "unique_origin_as_count"], []),
    )
    atomic_write_text(
        out_dir / "affected_prefix_summary.csv",
        csv_text(["window_id", "prefix", "origin_asn", "transition_types", "probe_pairs", "collector_count", "first_seen_utc", "last_seen_utc"], []),
    )
    atomic_write_text(
        out_dir / "affected_origin_as_summary.csv",
        csv_text(["window_id", "origin_asn", "affected_prefix_count", "transition_types", "probe_pairs"], []),
    )
    atomic_write_text(
        out_dir / "tal_impact_summary.csv",
        csv_text(["window_id", "tal", "transition_type", "route_count", "unique_prefix_count", "unique_origin_as_count"], []),
    )


def output_files_complete(out_dir: Path, *, include_acceptance: bool = False) -> bool:
    names = list(EXPECTED_OUTPUT_FILES)
    if include_acceptance:
        names.append(ACCEPTANCE_OUTPUT_FILE)
    return all((out_dir / name).is_file() for name in names)


def build_input_manifest(
    *,
    p8_context: dict[str, Any],
    routes_path: Path | None,
    route_load: dict[str, Any] | None,
    routes: list[dict[str, Any]],
    vrp_paths: dict[str, Path],
    metadata_paths: dict[str, Path],
    metadata: dict[str, dict[str, Any]],
    vrp_loads: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    route_info = file_info(routes_path) if routes_path is not None else {"path": "", "exists": False, "sha256": "", "size_bytes": 0}
    observed = [parse_iso_datetime(route.get("observed_time_utc")) for route in routes]
    observed = [dt for dt in observed if dt is not None]
    route_info.update({
        "route_count": len(routes),
        "input_route_count": route_load.get("route_count") if route_load else 0,
        "parse_error_count": route_load.get("parse_error_count") if route_load else 0,
        "min_observed_time_utc": iso_z(min(observed)) if observed else "",
        "max_observed_time_utc": iso_z(max(observed)) if observed else "",
    })

    vrp_inputs: dict[str, Any] = {}
    for probe_id in sorted(vrp_paths):
        vinfo = file_info(vrp_paths[probe_id])
        minfo = file_info(metadata_paths[probe_id]) if probe_id in metadata_paths else {"path": "", "exists": False, "sha256": "", "size_bytes": 0}
        mrec = metadata.get(probe_id, {})
        vrp_inputs[probe_id] = {
            "vrp_path": vinfo["path"],
            "vrp_sha256": vinfo["sha256"],
            "vrp_size_bytes": vinfo["size_bytes"],
            "metadata_path": minfo["path"],
            "metadata_sha256": minfo["sha256"],
            "metadata_size_bytes": minfo["size_bytes"],
            "snapshot_id": mrec.get("snapshot_id"),
            "capture_time_utc": mrec.get("capture_time_utc"),
            "validator_health": mrec.get("validator_health"),
            "vrp_count": vrp_loads.get(probe_id, {}).get("record_count", 0),
            "metadata_vrp_count": mrec.get("metadata_vrp_count"),
            "tal_distribution": vrp_loads.get(probe_id, {}).get("tal_distribution", {}),
        }

    return {
        "schema": SCHEMA_INPUT_MANIFEST,
        "p8_run_dir": p8_context.get("p8_run_dir", ""),
        "p8_window_id": p8_context.get("p8_window_id", ""),
        "p8_window_quality": p8_context.get("p8_window_quality", ""),
        "p8_capture_time_skew_sec": p8_context.get("p8_capture_time_skew_sec"),
        "routes": route_info,
        "vrp_inputs": vrp_inputs,
        "created_at_utc": utc_now(),
    }


def classify_quality(
    probe_ids: list[str],
    metadata: dict[str, dict[str, Any]],
    vrp_loads: dict[str, dict[str, Any]],
    required_tals: set[str],
    min_vrp_count_ratio: float,
    max_vrp_skew_sec: int,
    route_time_info: dict[str, Any],
    p8_context: dict[str, Any],
    p8_metadata_match: bool | str,
) -> dict[str, Any]:
    reasons: list[str] = []
    missing_tal_by_probe: dict[str, list[str]] = {}
    all_metadata_exist = all(metadata.get(probe_id, {}).get("exists") for probe_id in probe_ids)
    metadata_json_ok = all(metadata.get(probe_id, {}).get("json_ok") for probe_id in probe_ids)
    all_healthy = all(metadata.get(probe_id, {}).get("validator_health") == "healthy" for probe_id in probe_ids)
    if not all_metadata_exist:
        reasons.append("METADATA_MISSING")
    if not metadata_json_ok:
        reasons.append("METADATA_JSON_INVALID")
    if not all_healthy:
        reasons.append("VALIDATOR_NOT_HEALTHY")

    input_metadata_skew = capture_time_skew_sec(metadata)
    input_metadata_skew_ok = input_metadata_skew is not None and input_metadata_skew <= max_vrp_skew_sec
    if not input_metadata_skew_ok:
        reasons.append("VRP_SKEW_TOO_LARGE")

    p8_skew = p8_context.get("p8_capture_time_skew_sec")
    p8_max_skew = p8_context.get("p8_max_skew_sec") or max_vrp_skew_sec
    if p8_context.get("p8_run_dir"):
        p8_window_skew_ok = p8_skew is not None and int(p8_skew) <= int(p8_max_skew)
    else:
        p8_window_skew_ok = True
    if not p8_window_skew_ok:
        reasons.append("P8_WINDOW_SKEW_TOO_LARGE")

    tal_coverage_complete = True
    for probe_id in probe_ids:
        dist = vrp_loads.get(probe_id, {}).get("tal_distribution") or {}
        present = {str(tal).lower() for tal, count in dist.items() if int(count or 0) > 0}
        missing = sorted(required_tals - present)
        missing_tal_by_probe[probe_id] = missing
        if missing:
            tal_coverage_complete = False
    if not tal_coverage_complete:
        reasons.append("PARTIAL_TAL_VIEW")

    counts = [int(vrp_loads.get(probe_id, {}).get("record_count") or 0) for probe_id in probe_ids]
    median_count = statistics.median(counts) if counts else 0
    min_count = min(counts) if counts else 0
    ratio = (min_count / median_count) if median_count else 0
    vrp_count_ratio_ok = ratio >= min_vrp_count_ratio
    if not vrp_count_ratio_ok:
        reasons.append("VRP_COUNT_RATIO_LOW")

    route_time_alignment_ok = bool(route_time_info.get("route_time_alignment_ok"))
    if not route_time_alignment_ok:
        reasons.append("ROUTE_TIME_TOO_FAR")

    if p8_context.get("p8_window_quality") not in {None, "", "OK"}:
        reasons.append("P8_WINDOW_NOT_OK")
    if p8_metadata_match is False:
        reasons.append("P8_INPUT_METADATA_MISMATCH")

    usable = not reasons
    return {
        "usable_window": usable,
        "exclusion_reasons": sorted(set(reasons)),
        "all_metadata_exist": all_metadata_exist,
        "metadata_json_ok": metadata_json_ok,
        "all_validator_healthy": all_healthy,
        "input_metadata_capture_time_skew_sec": input_metadata_skew,
        "p8_capture_time_skew_sec": p8_skew,
        "input_metadata_skew_ok": input_metadata_skew_ok,
        "p8_window_skew_ok": p8_window_skew_ok,
        "vrp_capture_skew_ok": input_metadata_skew_ok,
        "p8_input_metadata_match": p8_metadata_match,
        "tal_coverage_complete": tal_coverage_complete,
        "missing_tal_by_probe": missing_tal_by_probe,
        "partial_view_detected": not tal_coverage_complete,
        "probe_vrp_counts": {probe_id: int(vrp_loads.get(probe_id, {}).get("record_count") or 0) for probe_id in probe_ids},
        "probe_tal_distributions": {probe_id: vrp_loads.get(probe_id, {}).get("tal_distribution") or {} for probe_id in probe_ids},
        "min_vrp_count": min_count,
        "median_vrp_count": median_count,
        "vrp_count_ratio": ratio,
        "vrp_count_ratio_ok": vrp_count_ratio_ok,
        "route_time_utc": route_time_info.get("route_time_utc"),
        "window_center_utc": route_time_info.get("window_center_utc"),
        "route_time_policy": route_time_info.get("route_time_policy"),
        "min_route_time_utc": route_time_info.get("min_route_time_utc"),
        "max_route_time_utc": route_time_info.get("max_route_time_utc"),
        "max_route_time_delta_sec": route_time_info.get("max_route_time_delta_sec"),
        "route_time_delta_sec": route_time_info.get("max_route_time_delta_sec"),
        "route_time_alignment_ok": route_time_alignment_ok,
    }


def impact_class(transition: str) -> str:
    return TRANSITION_IMPACT_CLASS.get(transition, "ROV_STATE_CHANGE")


def run_update_replay(args: argparse.Namespace, out_dir: Path) -> int:
    write_empty_outputs(out_dir)
    atomic_write_json(out_dir / "p10_input_manifest.json", {
        "schema": SCHEMA_INPUT_MANIFEST,
        "p8_run_dir": args.p8_run_dir or "",
        "p8_window_id": args.window_id or "",
        "p8_window_quality": "",
        "p8_capture_time_skew_sec": None,
        "routes": {
            "path": "",
            "sha256": "",
            "size_bytes": 0,
            "route_count": 0,
            "min_observed_time_utc": "",
            "max_observed_time_utc": "",
        },
        "vrp_inputs": {},
        "update_replay_inputs": {
            "rib": args.rib,
            "updates_dir": args.updates_dir,
            "collector": args.collector,
            "window_start_utc": args.window_start_utc,
            "window_end_utc": args.window_end_utc,
        },
        "created_at_utc": utc_now(),
    })
    abnormal = {
        "schema": SCHEMA_ABNORMAL,
        "mode": "update_replay",
        "window_id": args.window_id or "",
        "excluded_from_normal_analysis": True,
        "exclusion_reasons": ["UPDATE_REPLAY_NOT_IMPLEMENTED"],
        "update_replay_schema": {
            "rib": args.rib,
            "updates_dir": args.updates_dir,
            "collector": args.collector,
            "window_start_utc": args.window_start_utc,
            "window_end_utc": args.window_end_utc,
            "output": "future window route table compatible with --routes JSONL schema",
        },
    }
    atomic_write_json(out_dir / "abnormal_window_report.json", abnormal)
    summary = {
        "schema": SCHEMA_SUMMARY,
        "mode": "update_replay",
        "status": "SKIPPED",
        "p8_window_id": args.window_id or "",
        "p8_capture_time_skew_sec": None,
        "input_metadata_capture_time_skew_sec": None,
        "p8_input_metadata_match": "not_available",
        "route_count": 0,
        "probe_count": 0,
        "transition_event_count": 0,
        "affected_prefix_count": 0,
        "affected_origin_as_count": 0,
        "usable_window": False,
        "partial_view_detected": False,
        "normal_impact_analysis_executed": False,
    }
    atomic_write_json(out_dir / "rov_impact_summary.json", summary)
    checks = {
        "route_count_gt_zero": False,
        "all_probe_vrp_loaded": False,
        "metadata_json_ok": False,
        "tal_coverage_complete": False,
        "vrp_count_ratio_ok": False,
        "vrp_capture_skew_ok": False,
        "input_metadata_skew_ok": False,
        "p8_window_skew_ok": True,
        "route_time_alignment_ok": False,
        "transition_matrix_written": True,
        "abnormal_window_report_written": True,
        "p10_input_manifest_written": (out_dir / "p10_input_manifest.json").is_file(),
        "p8_input_metadata_match": "not_available",
        "output_files_complete": output_files_complete(out_dir),
        "no_strong_root_cause_claim": True,
    }
    write_acceptance(out_dir, summary, checks)
    return 0


def write_acceptance(out_dir: Path, summary: dict[str, Any], checks: dict[str, Any]) -> None:
    status = summary.get("status") or ("PASS" if all(checks.values()) else "FAIL")

    def render() -> str:
        lines = [
            f"P10_ROV_IMPACT={status}",
            f"mode={summary.get('mode')}",
            f"route_count={summary.get('route_count', 0)}",
            f"probe_count={summary.get('probe_count', 0)}",
            f"transition_event_count={summary.get('transition_event_count', 0)}",
            f"affected_prefix_count={summary.get('affected_prefix_count', 0)}",
            f"affected_origin_as_count={summary.get('affected_origin_as_count', 0)}",
            f"usable_window={str(summary.get('usable_window')).lower()}",
            f"partial_view_detected={str(summary.get('partial_view_detected')).lower()}",
            f"normal_impact_analysis_executed={str(summary.get('normal_impact_analysis_executed')).lower()}",
            "",
            "[checks]",
        ]
        lines.extend(f"{key}={str(value).lower()}" for key, value in checks.items())
        return "\n".join(lines) + "\n"

    if "output_files_complete" in checks:
        checks["output_files_complete"] = output_files_complete(out_dir)
    acceptance_path = out_dir / ACCEPTANCE_OUTPUT_FILE
    atomic_write_text(acceptance_path, render())
    if "output_files_complete" in checks:
        complete_with_acceptance = output_files_complete(out_dir, include_acceptance=True)
        if checks["output_files_complete"] != complete_with_acceptance:
            checks["output_files_complete"] = complete_with_acceptance
            atomic_write_text(acceptance_path, render())


def run_rib_snapshot(args: argparse.Namespace, out_dir: Path) -> int:
    root = repo_root()
    started_at = utc_now()
    vrp_assignments = parse_assignments(args.vrp or [], "--vrp")
    metadata_assignments = parse_assignments(args.metadata or [], "--metadata")
    probe_ids = sorted(vrp_assignments)
    p8_run_dir = resolve_path(args.p8_run_dir, root) if args.p8_run_dir else None
    p8_context = load_p8_context(p8_run_dir)
    p8_keys = read_p8_candidate_vrp_keys(p8_run_dir)

    vrp_loads: dict[str, dict[str, Any]] = {}
    vrp_indexes = {}
    vrp_paths: dict[str, Path] = {}
    for probe_id in probe_ids:
        vrp_path = resolve_path(vrp_assignments[probe_id], root)
        vrp_paths[probe_id] = vrp_path
        load = load_vrp_jsonl(vrp_path, probe_id=probe_id)
        vrp_loads[probe_id] = load
        vrp_indexes[probe_id] = load["index"]

    metadata_paths = {
        probe_id: resolve_path(metadata_assignments[probe_id], root)
        for probe_id in probe_ids
        if probe_id in metadata_assignments
    }
    metadata = {
        probe_id: metadata_record(probe_id, metadata_paths.get(probe_id))
        for probe_id in probe_ids
    }

    routes_path = resolve_path(args.routes, root)
    route_load = load_routes(routes_path)
    route_table_info = build_route_table(route_load["routes"])
    routes = route_table_info["routes"]
    center = window_center(args.window_start_utc, args.window_end_utc, metadata)
    explicit_route_time = parse_iso_datetime(args.route_time_utc)
    route_time_info = route_time_profile(route_load["routes"], explicit_route_time, center, int(args.max_route_time_skew_sec))
    route_time_info["window_center_utc"] = iso_z(center)
    p8_metadata_match = p8_input_metadata_match(p8_context, metadata)

    input_manifest = build_input_manifest(
        p8_context=p8_context,
        routes_path=routes_path,
        route_load=route_load,
        routes=route_load["routes"],
        vrp_paths=vrp_paths,
        metadata_paths=metadata_paths,
        metadata=metadata,
        vrp_loads=vrp_loads,
    )
    atomic_write_json(out_dir / "p10_input_manifest.json", input_manifest)

    required_tals = {part.strip().lower() for part in args.required_tals.split(",") if part.strip()}
    quality = classify_quality(
        probe_ids,
        metadata,
        vrp_loads,
        required_tals,
        float(args.min_vrp_count_ratio),
        int(args.max_vrp_skew_sec),
        route_time_info,
        p8_context,
        p8_metadata_match,
    )
    window_id = args.window_id or str(p8_context.get("p8_window_id") or "")
    if not window_id and center is not None:
        window_id = "win_" + center.strftime("%Y%m%dT%H%M%SZ")

    abnormal = {
        "schema": SCHEMA_ABNORMAL,
        "mode": "rib_snapshot",
        "window_id": window_id,
        "p8_window_id": p8_context.get("p8_window_id", ""),
        "p8_window_quality": p8_context.get("p8_window_quality", ""),
        "p8_capture_time_skew_sec": quality["p8_capture_time_skew_sec"],
        "input_metadata_capture_time_skew_sec": quality["input_metadata_capture_time_skew_sec"],
        "p8_input_metadata_match": quality["p8_input_metadata_match"],
        "probe_vrp_counts": quality["probe_vrp_counts"],
        "probe_tal_distributions": quality["probe_tal_distributions"],
        "missing_tal_by_probe": quality["missing_tal_by_probe"],
        "excluded_from_normal_analysis": not quality["usable_window"],
        "exclusion_reasons": quality["exclusion_reasons"],
        "route_time_utc": quality["route_time_utc"],
        "route_time_policy": quality["route_time_policy"],
        "min_route_time_utc": quality["min_route_time_utc"],
        "max_route_time_utc": quality["max_route_time_utc"],
        "max_route_time_delta_sec": quality["max_route_time_delta_sec"],
        "window_center_utc": quality["window_center_utc"],
        "route_time_delta_sec": quality["route_time_delta_sec"],
        "p8_run_dir": str(p8_run_dir) if p8_run_dir else "",
    }
    atomic_write_json(out_dir / "abnormal_window_report.json", abnormal)

    if not quality["usable_window"]:
        write_empty_outputs(out_dir)
        status = "PASS_WITH_EXCLUSIONS"
        checks = {
            "route_count_gt_zero": len(routes) > 0,
            "all_probe_vrp_loaded": len(vrp_indexes) == len(probe_ids) and all(vrp_loads[p]["record_count"] > 0 for p in probe_ids),
            "metadata_json_ok": bool(quality["metadata_json_ok"]),
            "tal_coverage_complete": bool(quality["tal_coverage_complete"]),
            "vrp_count_ratio_ok": bool(quality["vrp_count_ratio_ok"]),
            "vrp_capture_skew_ok": bool(quality["vrp_capture_skew_ok"]),
            "input_metadata_skew_ok": bool(quality["input_metadata_skew_ok"]),
            "p8_window_skew_ok": bool(quality["p8_window_skew_ok"]),
            "route_time_alignment_ok": bool(quality["route_time_alignment_ok"]),
            "transition_matrix_written": (out_dir / "transition_matrix.csv").is_file(),
            "abnormal_window_report_written": (out_dir / "abnormal_window_report.json").is_file(),
            "p10_input_manifest_written": (out_dir / "p10_input_manifest.json").is_file(),
            "p8_input_metadata_match": quality["p8_input_metadata_match"],
            "output_files_complete": False,
            "no_strong_root_cause_claim": True,
        }
        summary = {
            "schema": SCHEMA_SUMMARY,
            "status": status,
            "mode": "rib_snapshot",
            "window_id": window_id,
            "p8_window_id": p8_context.get("p8_window_id", ""),
            "p8_window_quality": p8_context.get("p8_window_quality", ""),
            "p8_capture_time_skew_sec": quality["p8_capture_time_skew_sec"],
            "input_metadata_capture_time_skew_sec": quality["input_metadata_capture_time_skew_sec"],
            "p8_input_metadata_match": quality["p8_input_metadata_match"],
            "route_count": len(routes),
            "input_route_count": route_load["route_count"],
            "probe_count": len(probe_ids),
            "transition_event_count": 0,
            "affected_prefix_count": 0,
            "affected_origin_as_count": 0,
            "usable_window": False,
            "partial_view_detected": quality["partial_view_detected"],
            "normal_impact_analysis_executed": False,
            "quality": quality,
            "route_parse_error_count": route_load["parse_error_count"],
            "vrp_parse_error_count_by_probe": {p: vrp_loads[p]["parse_error_count"] for p in probe_ids},
            "started_at_utc": started_at,
            "finished_at_utc": utc_now(),
        }
        atomic_write_json(out_dir / "rov_impact_summary.json", summary)
        checks["output_files_complete"] = output_files_complete(out_dir)
        write_acceptance(out_dir, summary, checks)
        return 0

    state_tmp, state_f = open_tmp_jsonl(out_dir / "route_state_by_probe.jsonl")
    event_tmp, event_f = open_tmp_jsonl(out_dir / "validation_transition_events.jsonl")
    transition_matrix: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    prefix_summary: dict[tuple[str, int], dict[str, Any]] = {}
    origin_summary: dict[int, dict[str, Any]] = {}
    tal_summary: dict[tuple[str, str], dict[str, Any]] = {}
    transition_event_count = 0
    try:
        with state_f, event_f:
            for route in routes:
                state_result = compute_route_state(route, vrp_indexes, max_covering_vrps=int(args.max_covering_vrps))
                route_effective_time = route_time_for_route(route, explicit_route_time)
                route_delta = route_time_delta_for_route(route, explicit_route_time, center)
                state_record = {
                    "schema": SCHEMA_ROUTE_STATE,
                    "window_id": window_id,
                    "route_prefix": route["route_prefix"],
                    "origin_asn": route["origin_asn"],
                    "collector": route.get("collector") or "",
                    "collector_set": route.get("collector_set") or [],
                    "collector_count": route.get("collector_count") or 0,
                    "route_time_utc": iso_z(route_effective_time),
                    "route_observed_time_utc": route.get("observed_time_utc") or "",
                    "route_time_delta_sec": route_delta,
                    "route_source_type": route.get("source_type") or "",
                    "states": state_result["states"],
                    "covering_vrps": state_result["covering_vrps"],
                    "matched_vrps": state_result["matched_vrps"],
                }
                state_f.write(json.dumps(state_record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                states = state_result["states"]
                if len(set(states.values())) <= 1:
                    continue
                for probe_a, probe_b in combinations(sorted(states), 2):
                    state_a = states[probe_a]
                    state_b = states[probe_b]
                    if state_a == state_b:
                        continue
                    transition = f"{state_a}->{state_b}"
                    event_covering = {
                        probe_a: state_result["covering_vrps"].get(probe_a, []),
                        probe_b: state_result["covering_vrps"].get(probe_b, []),
                    }
                    event = {
                        "schema": SCHEMA_TRANSITION,
                        "event_id": stable_id("rov_transition", {
                            "window_id": window_id,
                            "prefix": route["route_prefix"],
                            "origin_asn": route["origin_asn"],
                            "probe_a": probe_a,
                            "probe_b": probe_b,
                            "transition": transition,
                        }),
                        "window_id": window_id,
                        "p8_window_id": p8_context.get("p8_window_id", ""),
                        "p8_capture_time_skew_sec": quality["p8_capture_time_skew_sec"],
                        "input_metadata_capture_time_skew_sec": quality["input_metadata_capture_time_skew_sec"],
                        "route_prefix": route["route_prefix"],
                        "origin_asn": route["origin_asn"],
                        "collector": route.get("collector") or "",
                        "route_collector": route.get("collector") or "",
                        "collector_set": route.get("collector_set") or [],
                        "collector_count": route.get("collector_count") or 0,
                        "route_observed_time_utc": route.get("observed_time_utc") or "",
                        "route_time_delta_sec": route_delta,
                        "route_source_type": route.get("source_type") or "",
                        "probe_a": probe_a,
                        "probe_b": probe_b,
                        "state_a": state_a,
                        "state_b": state_b,
                        "transition": transition,
                        "impact_class": impact_class(transition),
                        "security_relevance": "potential",
                        "reason": "state_diff_under_same_route_table",
                        "p8_run_dir": str(p8_run_dir) if p8_run_dir else "",
                        "mapping_to_p8": mapping_to_p8_for_event(event_covering, p8_keys, p8_run_dir is not None),
                        "causal_claim_allowed": False,
                        "root_cause_confirmed": False,
                    }
                    event_f.write(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                    transition_event_count += 1

                    mkey = (probe_a, probe_b, state_a, state_b)
                    matrix = transition_matrix.setdefault(mkey, {"routes": 0, "prefixes": set(), "origins": set()})
                    matrix["routes"] += 1
                    matrix["prefixes"].add(route["route_prefix"])
                    matrix["origins"].add(route["origin_asn"])

                    pkey = (route["route_prefix"], int(route["origin_asn"]))
                    psum = prefix_summary.setdefault(pkey, {
                        "transition_types": set(),
                        "probe_pairs": set(),
                        "collectors": set(),
                        "first_seen_utc": route.get("first_seen_utc") or "",
                        "last_seen_utc": route.get("last_seen_utc") or "",
                    })
                    psum["transition_types"].add(transition)
                    psum["probe_pairs"].add(f"{probe_a}:{probe_b}")
                    for collector in route.get("collector_set") or []:
                        psum["collectors"].add(collector)

                    osum = origin_summary.setdefault(int(route["origin_asn"]), {"prefixes": set(), "transition_types": set(), "probe_pairs": set()})
                    osum["prefixes"].add(route["route_prefix"])
                    osum["transition_types"].add(transition)
                    osum["probe_pairs"].add(f"{probe_a}:{probe_b}")

                    tals = set()
                    for vrps in event_covering.values():
                        for vrp in vrps:
                            if vrp.get("tal"):
                                tals.add(str(vrp["tal"]))
                    for tal in tals:
                        tsum = tal_summary.setdefault((tal, transition), {"routes": 0, "prefixes": set(), "origins": set()})
                        tsum["routes"] += 1
                        tsum["prefixes"].add(route["route_prefix"])
                        tsum["origins"].add(route["origin_asn"])
            state_f.flush()
            os.fsync(state_f.fileno())
            event_f.flush()
            os.fsync(event_f.fileno())
        publish_existing_atomically(state_tmp, out_dir / "route_state_by_probe.jsonl")
        publish_existing_atomically(event_tmp, out_dir / "validation_transition_events.jsonl")
    except Exception:
        for tmp in (state_tmp, event_tmp):
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
        raise

    matrix_rows = [
        {
            "window_id": window_id,
            "probe_a": key[0],
            "probe_b": key[1],
            "state_a": key[2],
            "state_b": key[3],
            "route_count": value["routes"],
            "unique_prefix_count": len(value["prefixes"]),
            "unique_origin_as_count": len(value["origins"]),
        }
        for key, value in sorted(transition_matrix.items())
    ]
    atomic_write_text(out_dir / "transition_matrix.csv", csv_text(["window_id", "probe_a", "probe_b", "state_a", "state_b", "route_count", "unique_prefix_count", "unique_origin_as_count"], matrix_rows))

    prefix_rows = [
        {
            "window_id": window_id,
            "prefix": key[0],
            "origin_asn": key[1],
            "transition_types": "|".join(sorted(value["transition_types"])),
            "probe_pairs": "|".join(sorted(value["probe_pairs"])),
            "collector_count": len(value["collectors"]),
            "first_seen_utc": value["first_seen_utc"],
            "last_seen_utc": value["last_seen_utc"],
        }
        for key, value in sorted(prefix_summary.items())
    ]
    atomic_write_text(out_dir / "affected_prefix_summary.csv", csv_text(["window_id", "prefix", "origin_asn", "transition_types", "probe_pairs", "collector_count", "first_seen_utc", "last_seen_utc"], prefix_rows))

    origin_rows = [
        {
            "window_id": window_id,
            "origin_asn": asn,
            "affected_prefix_count": len(value["prefixes"]),
            "transition_types": "|".join(sorted(value["transition_types"])),
            "probe_pairs": "|".join(sorted(value["probe_pairs"])),
        }
        for asn, value in sorted(origin_summary.items())
    ]
    atomic_write_text(out_dir / "affected_origin_as_summary.csv", csv_text(["window_id", "origin_asn", "affected_prefix_count", "transition_types", "probe_pairs"], origin_rows))

    tal_rows = [
        {
            "window_id": window_id,
            "tal": key[0],
            "transition_type": key[1],
            "route_count": value["routes"],
            "unique_prefix_count": len(value["prefixes"]),
            "unique_origin_as_count": len(value["origins"]),
        }
        for key, value in sorted(tal_summary.items())
    ]
    atomic_write_text(out_dir / "tal_impact_summary.csv", csv_text(["window_id", "tal", "transition_type", "route_count", "unique_prefix_count", "unique_origin_as_count"], tal_rows))

    checks = {
        "route_count_gt_zero": len(routes) > 0,
        "all_probe_vrp_loaded": len(vrp_indexes) == len(probe_ids) and all(vrp_loads[p]["record_count"] > 0 for p in probe_ids),
        "metadata_json_ok": bool(quality["metadata_json_ok"]),
        "tal_coverage_complete": bool(quality["tal_coverage_complete"]),
        "vrp_count_ratio_ok": bool(quality["vrp_count_ratio_ok"]),
        "vrp_capture_skew_ok": bool(quality["vrp_capture_skew_ok"]),
        "input_metadata_skew_ok": bool(quality["input_metadata_skew_ok"]),
        "p8_window_skew_ok": bool(quality["p8_window_skew_ok"]),
        "route_time_alignment_ok": bool(quality["route_time_alignment_ok"]),
        "transition_matrix_written": (out_dir / "transition_matrix.csv").is_file(),
        "abnormal_window_report_written": (out_dir / "abnormal_window_report.json").is_file(),
        "p10_input_manifest_written": (out_dir / "p10_input_manifest.json").is_file(),
        "p8_input_metadata_match": quality["p8_input_metadata_match"],
        "output_files_complete": False,
        "no_strong_root_cause_claim": True,
    }
    summary = {
        "schema": SCHEMA_SUMMARY,
        "status": "PASS",
        "mode": "rib_snapshot",
        "window_id": window_id,
        "p8_window_id": p8_context.get("p8_window_id", ""),
        "p8_window_quality": p8_context.get("p8_window_quality", ""),
        "p8_capture_time_skew_sec": quality["p8_capture_time_skew_sec"],
        "input_metadata_capture_time_skew_sec": quality["input_metadata_capture_time_skew_sec"],
        "p8_input_metadata_match": quality["p8_input_metadata_match"],
        "route_count": len(routes),
        "input_route_count": route_load["route_count"],
        "probe_count": len(probe_ids),
        "transition_event_count": transition_event_count,
        "affected_prefix_count": len(prefix_summary),
        "affected_origin_as_count": len(origin_summary),
        "usable_window": True,
        "partial_view_detected": False,
        "normal_impact_analysis_executed": True,
        "quality": quality,
        "route_parse_error_count": route_load["parse_error_count"],
        "vrp_parse_error_count_by_probe": {p: vrp_loads[p]["parse_error_count"] for p in probe_ids},
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
    }
    atomic_write_json(out_dir / "rov_impact_summary.json", summary)
    checks["output_files_complete"] = output_files_complete(out_dir)
    write_acceptance(out_dir, summary, checks)
    return 0 if all(checks.values()) else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="P10 ROV impact engine: time-aware control-plane ROV state impact analysis.")
    parser.add_argument("--mode", choices=["rib_snapshot", "update_replay"], default="rib_snapshot")
    parser.add_argument("--routes", help="CSV or JSONL route table with prefix and origin_asn.")
    parser.add_argument("--vrp", action="append", default=[], help="PROBE_ID=normalized_vrp.jsonl. Repeatable.")
    parser.add_argument("--metadata", action="append", default=[], help="PROBE_ID=latest_metadata.json. Repeatable.")
    parser.add_argument("--p8-run-dir")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--window-id")
    parser.add_argument("--window-start-utc")
    parser.add_argument("--window-end-utc")
    parser.add_argument("--route-time-utc")
    parser.add_argument("--max-route-time-skew-sec", type=int, default=7200)
    parser.add_argument("--max-vrp-skew-sec", type=int, default=600)
    parser.add_argument("--required-tals", default=DEFAULT_REQUIRED_TALS)
    parser.add_argument("--min-vrp-count-ratio", type=float, default=0.95)
    parser.add_argument("--max-covering-vrps", type=int, default=5)
    parser.add_argument("--rib", help="update_replay mode future input.")
    parser.add_argument("--updates-dir", help="update_replay mode future input.")
    parser.add_argument("--collector", help="update_replay mode future input.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = repo_root()
    out_dir = resolve_path(args.out_dir, root)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        if args.mode == "update_replay":
            return run_update_replay(args, out_dir)
        if not args.routes:
            parser.error("--routes is required in rib_snapshot mode")
        if not args.vrp:
            parser.error("--vrp is required in rib_snapshot mode")
        return run_rib_snapshot(args, out_dir)
    except ValueError as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        return 130
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
