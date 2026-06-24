#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO


SCHEMA_EVENT = "s3.probe.cross_probe_vrp_diff_event.v1"
SCHEMA_SUMMARY = "s3.probe.cross_probe_vrp_diff_summary.v1"
EVENT_COMMON = "CROSS_PROBE_COMMON"
EVENT_MISSING = "CROSS_PROBE_MISSING"
EVENT_RECORD_DIVERGENCE = "CROSS_PROBE_RECORD_DIVERGENCE"
EVENT_SOURCE_URI_DIVERGENCE = "CROSS_PROBE_SOURCE_URI_DIVERGENCE"
EVENT_DUPLICATE_KEY = "CROSS_PROBE_DUPLICATE_KEY"
EVENT_WINDOW_INCOMPLETE = "WINDOW_INCOMPLETE"
EVENT_WINDOW_SKEW_TOO_HIGH = "WINDOW_SKEW_TOO_HIGH"
PROGRESS_EVERY = 100_000

VOLATILE_TOP_LEVEL_FIELDS = {
    "snapshot_id",
    "probe_id",
    "vrp_key",
    "window_id",
    "diff_id",
    "capture_time_utc",
    "created_at_utc",
    "generated_at_utc",
    "updated_at_utc",
    "raw_index",
    "raw_record_index",
}


@dataclass(frozen=True, slots=True)
class VrpKey:
    tal: str
    asn: int | str
    prefix: str
    max_length: int

    def as_string(self) -> str:
        return f"{self.tal}|{self.asn}|{self.prefix}|{self.max_length}"


@dataclass(frozen=True, slots=True)
class CompactRecord:
    source_uri: str | None
    raw_record_sha256: str | None
    record_hash: str


@dataclass(slots=True)
class ProbeSnapshot:
    probe_id: str
    normalized_path: Path | None
    metadata_path: Path | None
    snapshot_id: str | None
    capture_time: datetime | None
    window_id: str | None
    record_count: int
    duplicate_count: int
    index: dict[str, CompactRecord]
    duplicate_keys: dict[str, int]
    missing: bool = False
    missing_reason: str | None = None


def utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


def utc_now() -> str:
    return utc_now_dt().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iso_z(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def progress(stage: str, line_no: int) -> None:
    if line_no > 0 and line_no % PROGRESS_EVERY == 0:
        print(f"[{utc_now()}] {stage}: read {line_no} lines", file=sys.stderr, flush=True)


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def stable_id(prefix: str, obj: Any, length: int = 32) -> str:
    payload = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{prefix}_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]


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
    data = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    atomic_write_bytes(path, data.encode("utf-8"))


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def publish_existing_atomically(tmp_path: Path, final_path: Path) -> None:
    final_path.parent.mkdir(parents=True, exist_ok=True)
    with tmp_path.open("rb+") as f:
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, final_path)
    fsync_parent(final_path)


def open_tmp_jsonl(path: Path) -> tuple[Path, TextIO]:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    return tmp, tmp.open("w", encoding="utf-8", newline="\n")


def write_jsonl_event(out_f: TextIO, event: dict[str, Any]) -> None:
    out_f.write(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def read_jsonl(path: Path, stage: str):
    with path.open("r", encoding="utf-8-sig", errors="strict") as f:
        for line_no, line in enumerate(f, 1):
            progress(stage, line_no)
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at {path}:{line_no}: {exc}") from exc
            if not isinstance(obj, dict):
                raise ValueError(f"JSONL record is not an object at {path}:{line_no}")
            yield line_no, obj


def load_json_object(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    with path.open("r", encoding="utf-8-sig") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise RuntimeError(f"expected JSON object at {path}")
    return obj


def get_first(record: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        value = record.get(key)
        if value is not None and value != "":
            return value
    return None


def parse_asn(value: Any) -> int | str | None:
    if value is None or value == "":
        return None
    text = str(value).strip()
    if text.upper().startswith("AS"):
        text = text[2:]
    try:
        return int(text)
    except ValueError:
        return text


def parse_asn_text(value: str) -> int | str:
    try:
        return int(value)
    except ValueError:
        return value


def normalize_prefix(value: Any) -> str | None:
    if value is None or value == "":
        return None
    text = str(value).strip()
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return text


def parse_max_length(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def make_vrp_key(record: dict[str, Any], path: Path, line_no: int) -> VrpKey:
    tal_raw = get_first(record, ["tal", "ta", "trust_anchor", "trustAnchor"])
    asn_raw = get_first(record, ["asn", "asID", "as_id", "origin_asn", "originAS", "origin", "origin_as"])
    prefix_raw = get_first(record, ["prefix", "ipPrefix", "ip_prefix", "vrp_prefix"])
    max_length_raw = get_first(record, ["max_length", "maxLength", "maxlength", "maxLen", "max_len"])

    tal = str(tal_raw).strip().lower() if tal_raw is not None and str(tal_raw).strip() else None
    asn = parse_asn(asn_raw)
    prefix = normalize_prefix(prefix_raw)
    max_length = parse_max_length(max_length_raw)

    missing = []
    if tal is None:
        missing.append("tal")
    if asn is None:
        missing.append("asn")
    if prefix is None:
        missing.append("prefix")
    if max_length is None:
        missing.append("max_length")
    if missing:
        raise ValueError(f"missing or invalid VRP key fields at {path}:{line_no}: {','.join(missing)}")
    return VrpKey(tal=tal, asn=asn, prefix=prefix, max_length=max_length)


def clean_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def extract_source_uri(record: dict[str, Any]) -> str | None:
    direct = get_first(record, ["source_uri", "roa_uri", "sourceUri", "roaUri", "uri", "object_uri"])
    if direct is not None:
        return clean_string(direct)
    source_uris = record.get("source_uris")
    if isinstance(source_uris, list):
        for value in source_uris:
            text = clean_string(value)
            if text:
                return text
    raw_source = record.get("source")
    if isinstance(raw_source, str):
        return clean_string(raw_source)
    if isinstance(raw_source, dict):
        return clean_string(raw_source.get("uri") or raw_source.get("source_uri") or raw_source.get("roa_uri"))
    if isinstance(raw_source, list):
        for item in raw_source:
            if isinstance(item, dict):
                text = clean_string(item.get("uri") or item.get("source_uri") or item.get("roa_uri"))
                if text:
                    return text
    return None


def extract_raw_record_sha256(record: dict[str, Any]) -> str | None:
    direct = get_first(record, ["raw_record_sha256", "raw_record_hash", "raw_sha256"])
    if direct is not None:
        return clean_string(direct)
    raw_source = record.get("raw_source")
    if isinstance(raw_source, dict):
        nested = get_first(raw_source, ["raw_record_sha256", "raw_record_hash", "raw_sha256"])
        if nested is not None:
            return clean_string(nested)
    return None


def key_from_text(key_text: str) -> VrpKey:
    parts = key_text.split("|")
    if len(parts) != 4:
        raise ValueError(f"invalid compact VRP key: {key_text}")
    return VrpKey(tal=parts[0], asn=parse_asn_text(parts[1]), prefix=parts[2], max_length=int(parts[3]))


def hash_projection(record: dict[str, Any], compact_dict: dict[str, Any]) -> dict[str, Any]:
    projection: dict[str, Any] = {"compact_record": compact_dict}
    for key, value in record.items():
        if key in VOLATILE_TOP_LEVEL_FIELDS or key == "raw_source":
            continue
        projection[key] = value
    return projection


def make_compact_record(record: dict[str, Any], path: Path, line_no: int) -> tuple[str, CompactRecord]:
    key = make_vrp_key(record, path, line_no)
    key_text = key.as_string()
    source_uri = extract_source_uri(record)
    raw_record_sha256 = extract_raw_record_sha256(record)
    compact_without_hash = {
        "tal": key.tal,
        "asn": key.asn,
        "prefix": key.prefix,
        "max_length": key.max_length,
        "source_uri": source_uri,
        "vrp_key": key_text,
        "raw_record_sha256": raw_record_sha256,
    }
    record_hash = sha256_text(json.dumps(
        hash_projection(record, compact_without_hash),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ))
    return key_text, CompactRecord(
        source_uri=source_uri,
        raw_record_sha256=raw_record_sha256,
        record_hash=record_hash,
    )


def infer_snapshot_id_from_path(path: Path | None) -> str | None:
    if path is None:
        return None
    if path.parent.name:
        return path.parent.name
    return path.stem


def parse_iso_datetime(value: Any) -> datetime | None:
    if not value:
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


def parse_time_token(text: str) -> datetime | None:
    import re

    match = re.search(r"(\d{8}T\d{6})(\d{1,6})?Z", text)
    if match:
        base = match.group(1)
        frac = (match.group(2) or "").ljust(6, "0")
        try:
            return datetime.strptime(base + frac + "Z", "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return parse_iso_datetime(text)


def window_suffix(window_size_sec: int) -> str:
    if window_size_sec % 3600 == 0:
        return f"{window_size_sec // 3600}h"
    if window_size_sec % 60 == 0:
        return f"{window_size_sec // 60}m"
    return f"{window_size_sec}s"


def make_window_id(capture_time: datetime, window_size_sec: int) -> str:
    epoch = int(capture_time.timestamp())
    floored = epoch - (epoch % window_size_sec)
    floored_dt = datetime.fromtimestamp(floored, tz=timezone.utc)
    return "win_" + floored_dt.strftime("%Y%m%dT%H%M%SZ") + "_" + window_suffix(window_size_sec)


def extract_capture_time(metadata: dict[str, Any], snapshot_path: Path | None) -> datetime | None:
    dt = parse_iso_datetime(metadata.get("capture_time_utc"))
    if dt is not None:
        return dt
    raw_metadata = metadata.get("raw_metadata")
    if isinstance(raw_metadata, dict):
        dt = parse_iso_datetime(raw_metadata.get("generatedTime"))
        if dt is not None:
            return dt
    snapshot_id = metadata.get("snapshot_id") or infer_snapshot_id_from_path(snapshot_path)
    if snapshot_id:
        return parse_time_token(str(snapshot_id))
    return None


def parse_assignment(value: str, option_name: str) -> tuple[str, Path]:
    if "=" not in value:
        raise ValueError(f"{option_name} must be probe_id=path, got: {value}")
    probe_id, path_text = value.split("=", 1)
    probe_id = probe_id.strip()
    path_text = path_text.strip()
    if not probe_id:
        raise ValueError(f"{option_name} has empty probe_id: {value}")
    if not path_text:
        raise ValueError(f"{option_name} has empty path: {value}")
    return probe_id, Path(path_text).resolve()


def parse_assignments(values: list[str], option_name: str) -> dict[str, Path]:
    parsed: dict[str, Path] = {}
    for value in values:
        probe_id, path = parse_assignment(value, option_name)
        if probe_id in parsed:
            raise ValueError(f"duplicate {option_name} probe_id: {probe_id}")
        parsed[probe_id] = path
    return parsed


def load_probe_snapshot(
    probe_id: str,
    normalized_path: Path | None,
    metadata_path: Path | None,
    window_size_sec: int,
    user_window_id: str | None,
) -> ProbeSnapshot:
    metadata = load_json_object(metadata_path)
    snapshot_id = str(metadata.get("snapshot_id") or infer_snapshot_id_from_path(normalized_path) or "")
    capture_time = extract_capture_time(metadata, normalized_path)
    derived_window_id = make_window_id(capture_time, window_size_sec) if capture_time else None
    window_id = user_window_id or derived_window_id

    if normalized_path is None:
        return ProbeSnapshot(
            probe_id=probe_id,
            normalized_path=None,
            metadata_path=metadata_path,
            snapshot_id=snapshot_id or None,
            capture_time=capture_time,
            window_id=window_id,
            record_count=0,
            duplicate_count=0,
            index={},
            duplicate_keys={},
            missing=True,
            missing_reason="snapshot_argument_missing",
        )

    if not normalized_path.exists() or not normalized_path.is_file():
        return ProbeSnapshot(
            probe_id=probe_id,
            normalized_path=normalized_path,
            metadata_path=metadata_path,
            snapshot_id=snapshot_id or None,
            capture_time=capture_time,
            window_id=window_id,
            record_count=0,
            duplicate_count=0,
            index={},
            duplicate_keys={},
            missing=True,
            missing_reason="normalized_snapshot_missing",
        )

    index: dict[str, CompactRecord] = {}
    duplicate_keys: dict[str, int] = {}
    record_count = 0
    duplicate_count = 0
    for line_no, record in read_jsonl(normalized_path, probe_id):
        record_count += 1
        key_text, compact = make_compact_record(record, normalized_path, line_no)
        if key_text in index:
            duplicate_count += 1
            duplicate_keys[key_text] = duplicate_keys.get(key_text, 0) + 1
            continue
        index[key_text] = compact

    print(
        f"[{utc_now()}] {probe_id}: finished records={record_count} "
        f"unique_keys={len(index)} duplicates={duplicate_count}",
        file=sys.stderr,
        flush=True,
    )
    return ProbeSnapshot(
        probe_id=probe_id,
        normalized_path=normalized_path,
        metadata_path=metadata_path,
        snapshot_id=snapshot_id or None,
        capture_time=capture_time,
        window_id=window_id,
        record_count=record_count,
        duplicate_count=duplicate_count,
        index=index,
        duplicate_keys=duplicate_keys,
        missing=False,
        missing_reason=None,
    )


def event_base(
    event_type: str,
    window_id: str,
    window_size_sec: int,
    capture_time_skew_sec: int | None,
    probe_ids: list[str],
    present_probes: list[str],
    missing_probes: list[str],
    key_text: str | None,
    snapshots: dict[str, ProbeSnapshot],
    attribution_candidate: bool,
    candidate_reason: str,
    attribution_priority: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    key = key_from_text(key_text) if key_text else None
    source_uri_by_probe: dict[str, str | None] = {}
    record_hash_by_probe: dict[str, str] = {}
    for probe_id in present_probes:
        if key_text and key_text in snapshots[probe_id].index:
            compact = snapshots[probe_id].index[key_text]
            source_uri_by_probe[probe_id] = compact.source_uri
            record_hash_by_probe[probe_id] = compact.record_hash

    event = {
        "schema": SCHEMA_EVENT,
        "event_id": stable_id(
            "xevt",
            {
                "event_type": event_type,
                "window_id": window_id,
                "vrp_key": key_text,
                "present_probes": present_probes,
                "missing_probes": missing_probes,
            },
        ),
        "event_type": event_type,
        "window_id": window_id,
        "window_size_sec": window_size_sec,
        "capture_time_skew_sec": capture_time_skew_sec,
        "probe_ids": probe_ids,
        "present_probes": present_probes,
        "missing_probes": missing_probes,
        "vrp_key": key_text,
        "vrp_key_fields": ["tal", "asn", "prefix", "max_length"],
        "tal": key.tal if key else None,
        "asn": key.asn if key else None,
        "prefix": key.prefix if key else None,
        "max_length": key.max_length if key else None,
        "source_uri_by_probe": source_uri_by_probe,
        "record_hash_by_probe": record_hash_by_probe,
        "snapshot_id_by_probe": {probe_id: snapshots[probe_id].snapshot_id for probe_id in probe_ids},
        "capture_time_by_probe": {probe_id: iso_z(snapshots[probe_id].capture_time) for probe_id in probe_ids},
        "attribution_candidate": attribution_candidate,
        "candidate_reason": candidate_reason,
        "attribution_priority": attribution_priority,
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
    }
    if extra:
        event.update(extra)
    return event


def key_complete(key_text: str | None) -> bool:
    if not key_text:
        return False
    try:
        key_from_text(key_text)
        return True
    except Exception:
        return False


def is_candidate(
    event_type: str,
    key_text: str | None,
    skew_ok: bool,
    loaded_probe_count: int,
) -> bool:
    return (
        event_type in {EVENT_MISSING, EVENT_RECORD_DIVERGENCE, EVENT_SOURCE_URI_DIVERGENCE}
        and skew_ok
        and loaded_probe_count >= 2
        and key_complete(key_text)
    )


def priority_for_event(event_type: str, missing_count: int, tal_missing_count: int) -> str:
    if event_type in {EVENT_RECORD_DIVERGENCE, EVENT_SOURCE_URI_DIVERGENCE}:
        return "HIGH"
    if event_type == EVENT_MISSING:
        if missing_count >= 2 or tal_missing_count >= 10:
            return "HIGH"
        return "MEDIUM"
    return "LOW"


def make_window_quality(
    snapshots: dict[str, ProbeSnapshot],
    probe_ids: list[str],
    window_id: str,
    window_size_sec: int,
    max_skew_sec: int,
) -> tuple[str, int | None, list[str]]:
    reasons: list[str] = []
    capture_times = [snapshots[probe_id].capture_time for probe_id in probe_ids if snapshots[probe_id].capture_time is not None]
    missing_snapshot_probes = [probe_id for probe_id in probe_ids if snapshots[probe_id].missing]
    missing_time_probes = [probe_id for probe_id in probe_ids if snapshots[probe_id].capture_time is None]
    window_mismatch_probes = [
        probe_id
        for probe_id in probe_ids
        if snapshots[probe_id].capture_time is not None
        and make_window_id(snapshots[probe_id].capture_time, window_size_sec) != window_id
    ]
    if missing_snapshot_probes:
        reasons.append("missing_snapshot:" + ",".join(missing_snapshot_probes))
    if missing_time_probes:
        reasons.append("missing_capture_time:" + ",".join(missing_time_probes))
    if window_mismatch_probes:
        reasons.append("window_mismatch:" + ",".join(window_mismatch_probes))

    skew_sec: int | None = None
    if capture_times:
        skew_sec = int(max(capture_times).timestamp() - min(capture_times).timestamp())
    if reasons:
        return "WINDOW_INCOMPLETE", skew_sec, reasons
    if skew_sec is not None and skew_sec > max_skew_sec:
        return "WINDOW_SKEW_TOO_HIGH", skew_sec, [f"capture_time_skew_sec:{skew_sec}"]
    return "OK", skew_sec, []


def counter_top(counter: Counter[Any], limit: int = 20) -> list[dict[str, Any]]:
    return [{"value": key, "count": count} for key, count in counter.most_common(limit)]


def write_acceptance(
    out_dir: Path,
    summary: dict[str, Any],
    events_path: Path,
    candidates_path: Path,
    summary_path: Path,
) -> None:
    acceptance_path = out_dir / "checks" / "P2_CROSS_PROBE_DIFF_ACCEPTANCE.txt"
    checks = {
        "cross_probe_events_jsonl_exists": events_path.exists() and events_path.is_file(),
        "candidate_events_jsonl_exists": candidates_path.exists() and candidates_path.is_file(),
        "cross_probe_summary_json_exists": summary_path.exists() and summary_path.is_file(),
        "probe_count_gte_two": int(summary.get("probe_count") or 0) >= 2,
        "causal_claim_allowed_count_zero": summary.get("causal_claim_allowed_count") == 0,
        "root_cause_confirmed_false": summary.get("root_cause_confirmed") is False,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    fields = [
        ("P2_CROSS_PROBE_DIFF", status),
        ("window_id", summary.get("window_id")),
        ("window_quality", summary.get("window_quality")),
        ("probe_count", summary.get("probe_count")),
        ("event_count", summary.get("event_count")),
        ("candidate_event_count", summary.get("candidate_event_count")),
        ("cross_probe_events", str(events_path)),
        ("candidate_events", str(candidates_path)),
        ("cross_probe_summary", str(summary_path)),
    ]
    lines = [f"{key}={value}" for key, value in fields]
    lines.extend(["", "[checks]"])
    lines.extend(f"{key}={str(value).lower()}" for key, value in checks.items())
    atomic_write_text(acceptance_path, "\n".join(lines) + "\n")


def run_cross_probe_diff(
    snapshot_specs: dict[str, Path],
    metadata_specs: dict[str, Path],
    out_dir: Path,
    window_id_arg: str | None,
    window_size_sec: int,
    max_skew_sec: int,
    emit_common: bool,
) -> dict[str, Any]:
    started_at_utc = utc_now()
    started = time.monotonic()
    probe_ids = sorted(set(snapshot_specs) | set(metadata_specs))
    if len(probe_ids) < 2:
        raise ValueError("P2 cross-probe diff requires at least two probe ids across --snapshot/--metadata")

    snapshots: dict[str, ProbeSnapshot] = {}
    for probe_id in probe_ids:
        snapshots[probe_id] = load_probe_snapshot(
            probe_id=probe_id,
            normalized_path=snapshot_specs.get(probe_id),
            metadata_path=metadata_specs.get(probe_id),
            window_size_sec=window_size_sec,
            user_window_id=window_id_arg,
        )

    available_windows = [snap.window_id for snap in snapshots.values() if snap.window_id]
    window_id = window_id_arg or (available_windows[0] if available_windows else "win_unknown")
    window_quality, capture_time_skew_sec, window_quality_reasons = make_window_quality(
        snapshots,
        probe_ids,
        window_id,
        window_size_sec,
        max_skew_sec,
    )
    skew_ok = capture_time_skew_sec is not None and capture_time_skew_sec <= max_skew_sec
    loaded_probe_ids = [probe_id for probe_id in probe_ids if not snapshots[probe_id].missing]

    events_path = out_dir / "cross_probe_events.jsonl"
    candidates_path = out_dir / "candidate_events.jsonl"
    summary_path = out_dir / "cross_probe_summary.json"
    events_tmp, events_f = open_tmp_jsonl(events_path)
    candidates_tmp, candidates_f = open_tmp_jsonl(candidates_path)

    event_count = 0
    candidate_event_count = 0
    common_key_count = 0
    cross_probe_missing_count = 0
    record_divergence_count = 0
    source_uri_divergence_count = 0
    duplicate_event_count = 0
    missing_by_probe: Counter[str] = Counter()
    tal_counter: Counter[str] = Counter()
    asn_counter: Counter[Any] = Counter()
    prefix_counter: Counter[str] = Counter()

    union_keys: set[str] = set()
    for probe_id in loaded_probe_ids:
        union_keys.update(snapshots[probe_id].index)
    for key_text in union_keys:
        key = key_from_text(key_text)
        tal_counter[key.tal] += 1
        asn_counter[key.asn] += 1
        prefix_counter[key.prefix] += 1

    tal_missing_counter: Counter[str] = Counter()
    for key_text in union_keys:
        missing = [probe_id for probe_id in loaded_probe_ids if key_text not in snapshots[probe_id].index]
        if missing:
            tal_missing_counter[key_from_text(key_text).tal] += 1

    def emit(event: dict[str, Any]) -> None:
        nonlocal event_count, candidate_event_count
        write_jsonl_event(events_f, event)
        event_count += 1
        if event.get("attribution_candidate"):
            write_jsonl_event(candidates_f, event)
            candidate_event_count += 1

    try:
        with events_f, candidates_f:
            incomplete_probes = [probe_id for probe_id in probe_ids if snapshots[probe_id].missing or snapshots[probe_id].capture_time is None]
            if window_quality == "WINDOW_INCOMPLETE":
                emit(event_base(
                    EVENT_WINDOW_INCOMPLETE,
                    window_id,
                    window_size_sec,
                    capture_time_skew_sec,
                    probe_ids,
                    [probe_id for probe_id in probe_ids if probe_id not in incomplete_probes],
                    incomplete_probes,
                    None,
                    snapshots,
                    False,
                    ";".join(window_quality_reasons) or "window_incomplete",
                    "LOW",
                    {"window_quality_reasons": window_quality_reasons},
                ))
            if window_quality == "WINDOW_SKEW_TOO_HIGH":
                emit(event_base(
                    EVENT_WINDOW_SKEW_TOO_HIGH,
                    window_id,
                    window_size_sec,
                    capture_time_skew_sec,
                    probe_ids,
                    loaded_probe_ids,
                    [],
                    None,
                    snapshots,
                    False,
                    "capture_time_skew_too_high",
                    "LOW",
                    {"max_skew_sec": max_skew_sec},
                ))

            for probe_id in loaded_probe_ids:
                for key_text, duplicate_extra_count in sorted(snapshots[probe_id].duplicate_keys.items()):
                    duplicate_event_count += 1
                    emit(event_base(
                        EVENT_DUPLICATE_KEY,
                        window_id,
                        window_size_sec,
                        capture_time_skew_sec,
                        probe_ids,
                        [probe_id],
                        [],
                        key_text,
                        snapshots,
                        False,
                        "duplicate_key_within_single_probe",
                        "LOW",
                        {"duplicate_probe_id": probe_id, "duplicate_extra_count": duplicate_extra_count},
                    ))

            for key_text in sorted(union_keys):
                present = [probe_id for probe_id in loaded_probe_ids if key_text in snapshots[probe_id].index]
                missing = [probe_id for probe_id in loaded_probe_ids if probe_id not in present]
                if len(present) == len(loaded_probe_ids):
                    common_key_count += 1
                    if emit_common:
                        emit(event_base(
                            EVENT_COMMON,
                            window_id,
                            window_size_sec,
                            capture_time_skew_sec,
                            probe_ids,
                            present,
                            [],
                            key_text,
                            snapshots,
                            False,
                            "key_present_in_all_loaded_probes",
                            "LOW",
                        ))
                if missing:
                    cross_probe_missing_count += 1
                    for probe_id in missing:
                        missing_by_probe[probe_id] += 1
                    key = key_from_text(key_text)
                    candidate = is_candidate(EVENT_MISSING, key_text, skew_ok, len(loaded_probe_ids))
                    emit(event_base(
                        EVENT_MISSING,
                        window_id,
                        window_size_sec,
                        capture_time_skew_sec,
                        probe_ids,
                        present,
                        missing,
                        key_text,
                        snapshots,
                        candidate,
                        "valid_cross_probe_missing" if candidate else "not_candidate_due_to_window_or_probe_count",
                        priority_for_event(EVENT_MISSING, len(missing), tal_missing_counter[key.tal]),
                    ))
                if len(present) < 2:
                    continue

                record_hashes = {snapshots[probe_id].index[key_text].record_hash for probe_id in present}
                if len(record_hashes) > 1:
                    record_divergence_count += 1
                    candidate = is_candidate(EVENT_RECORD_DIVERGENCE, key_text, skew_ok, len(loaded_probe_ids))
                    emit(event_base(
                        EVENT_RECORD_DIVERGENCE,
                        window_id,
                        window_size_sec,
                        capture_time_skew_sec,
                        probe_ids,
                        present,
                        missing,
                        key_text,
                        snapshots,
                        candidate,
                        "valid_cross_probe_record_divergence" if candidate else "not_candidate_due_to_window_or_probe_count",
                        priority_for_event(EVENT_RECORD_DIVERGENCE, len(missing), 0),
                    ))

                source_values = {snapshots[probe_id].index[key_text].source_uri for probe_id in present}
                if len(source_values) > 1:
                    source_uri_divergence_count += 1
                    candidate = is_candidate(EVENT_SOURCE_URI_DIVERGENCE, key_text, skew_ok, len(loaded_probe_ids))
                    emit(event_base(
                        EVENT_SOURCE_URI_DIVERGENCE,
                        window_id,
                        window_size_sec,
                        capture_time_skew_sec,
                        probe_ids,
                        present,
                        missing,
                        key_text,
                        snapshots,
                        candidate,
                        "valid_cross_probe_source_uri_divergence" if candidate else "not_candidate_due_to_window_or_probe_count",
                        priority_for_event(EVENT_SOURCE_URI_DIVERGENCE, len(missing), 0),
                    ))

            events_f.flush()
            os.fsync(events_f.fileno())
            candidates_f.flush()
            os.fsync(candidates_f.fileno())
        publish_existing_atomically(events_tmp, events_path)
        publish_existing_atomically(candidates_tmp, candidates_path)
    except Exception:
        try:
            events_f.close()
        except Exception:
            pass
        try:
            candidates_f.close()
        except Exception:
            pass
        for tmp in (events_tmp, candidates_tmp):
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
        raise

    summary = {
        "schema": SCHEMA_SUMMARY,
        "window_id": window_id,
        "window_size_sec": window_size_sec,
        "max_skew_sec": max_skew_sec,
        "probe_count": len(probe_ids),
        "loaded_probe_count": len(loaded_probe_ids),
        "probe_ids": probe_ids,
        "loaded_probe_ids": loaded_probe_ids,
        "snapshot_id_by_probe": {probe_id: snapshots[probe_id].snapshot_id for probe_id in probe_ids},
        "capture_time_by_probe": {probe_id: iso_z(snapshots[probe_id].capture_time) for probe_id in probe_ids},
        "capture_time_skew_sec": capture_time_skew_sec,
        "window_quality": window_quality,
        "window_quality_reasons": window_quality_reasons,
        "vrp_record_count_by_probe": {probe_id: snapshots[probe_id].record_count for probe_id in probe_ids},
        "unique_key_count_by_probe": {probe_id: len(snapshots[probe_id].index) for probe_id in probe_ids},
        "duplicate_key_count_by_probe": {probe_id: snapshots[probe_id].duplicate_count for probe_id in probe_ids},
        "union_key_count": len(union_keys),
        "common_key_count": common_key_count,
        "cross_probe_missing_count": cross_probe_missing_count,
        "record_divergence_count": record_divergence_count,
        "source_uri_divergence_count": source_uri_divergence_count,
        "duplicate_event_count": duplicate_event_count,
        "candidate_event_count": candidate_event_count,
        "event_count": event_count,
        "tal_distribution": dict(sorted(tal_counter.items())),
        "missing_by_probe": dict(sorted(missing_by_probe.items())),
        "top_asn": counter_top(asn_counter),
        "top_prefix": counter_top(prefix_counter),
        "causal_claim_allowed_count": 0,
        "root_cause_confirmed": False,
        "emit_common": emit_common,
        "key_fields": ["tal", "asn", "prefix", "max_length"],
        "source_uri_in_primary_key": False,
        "outputs": {
            "cross_probe_events": str(events_path),
            "candidate_events": str(candidates_path),
            "cross_probe_summary": str(summary_path),
        },
        "started_at_utc": started_at_utc,
        "finished_at_utc": utc_now(),
        "duration_sec": round(time.monotonic() - started, 6),
    }
    atomic_write_json(summary_path, summary)
    write_acceptance(out_dir, summary, events_path, candidates_path, summary_path)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return summary


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    text = "".join(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for record in records)
    atomic_write_bytes(path, text.encode("utf-8"))


def write_metadata(path: Path, probe_id: str, snapshot_id: str, capture_time: str) -> None:
    atomic_write_json(path, {
        "schema": "s3.probe.routinator_live_snapshot_metadata.v1",
        "probe_id": probe_id,
        "snapshot_id": snapshot_id,
        "capture_time_utc": capture_time,
        "raw_metadata": {"generatedTime": capture_time},
    })


def self_test_records() -> dict[str, list[dict[str, Any]]]:
    common = {"tal": "apnic", "asn": 64500, "prefix": "203.0.113.0/24", "max_length": 24, "source_uri": "rsync://repo/common.roa"}
    missing = {"tal": "apnic", "asn": 64501, "prefix": "198.51.100.0/24", "max_length": 24, "source_uri": "rsync://repo/missing.roa"}
    source_a = {"tal": "ripe", "asn": 64502, "prefix": "192.0.2.0/24", "max_length": 24, "source_uri": "rsync://repo/a.roa"}
    source_b = {"tal": "ripe", "asn": 64502, "prefix": "192.0.2.0/24", "max_length": 24, "source_uri": "rsync://repo/b.roa"}
    record_a = {"tal": "arin", "asn": 64503, "prefix": "2001:db8::/32", "max_length": 48, "source_uri": "rsync://repo/record.roa", "expires": "2026-06-24T00:00:00Z"}
    record_b = {"tal": "arin", "asn": 64503, "prefix": "2001:db8::/32", "max_length": 48, "source_uri": "rsync://repo/record.roa", "expires": "2026-06-25T00:00:00Z"}
    duplicate = {"tal": "afrinic", "asn": 64504, "prefix": "10.0.0.0/24", "max_length": 24, "source_uri": "rsync://repo/dup.roa"}
    return {
        "probe-a": [common, missing, source_a, record_a, duplicate, duplicate],
        "probe-b": [common, missing, source_b, record_a, duplicate],
        "probe-c": [common, source_a, record_b, duplicate],
    }


def run_self_test(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).resolve()
    input_dir = out_dir / "self_test_inputs"
    input_dir.mkdir(parents=True, exist_ok=True)
    snapshots: dict[str, Path] = {}
    metadata: dict[str, Path] = {}
    capture_times = {
        "probe-a": "2026-06-23T00:05:00Z",
        "probe-b": "2026-06-23T00:06:00Z",
        "probe-c": "2026-06-23T00:07:00Z",
    }
    for probe_id, records in self_test_records().items():
        probe_dir = input_dir / probe_id / "history" / f"snap_{capture_times[probe_id].replace('-', '').replace(':', '').replace('T', 'T').replace('+00:00', '').replace('Z', 'Z')}"
        probe_dir.mkdir(parents=True, exist_ok=True)
        snapshots[probe_id] = probe_dir / "normalized_vrp.jsonl"
        metadata[probe_id] = probe_dir / "metadata.json"
        write_jsonl(snapshots[probe_id], records)
        write_metadata(metadata[probe_id], probe_id, probe_dir.name, capture_times[probe_id])

    normal_summary = run_cross_probe_diff(
        snapshot_specs=snapshots,
        metadata_specs=metadata,
        out_dir=out_dir,
        window_id_arg=args.window_id,
        window_size_sec=args.window_size_sec,
        max_skew_sec=args.max_skew_sec,
        emit_common=args.emit_common,
    )

    skew_dir = out_dir / "skew_case"
    skew_input_dir = out_dir / "self_test_inputs_skew"
    skew_snapshots: dict[str, Path] = {}
    skew_metadata: dict[str, Path] = {}
    skew_times = {"probe-a": "2026-06-23T00:00:00Z", "probe-b": "2026-06-23T00:40:00Z"}
    skew_record = [{"tal": "apnic", "asn": 64500, "prefix": "203.0.113.0/24", "max_length": 24, "source_uri": "rsync://repo/common.roa"}]
    for probe_id, capture_time in skew_times.items():
        probe_dir = skew_input_dir / probe_id / "history" / f"snap_{capture_time.replace('-', '').replace(':', '')}"
        probe_dir.mkdir(parents=True, exist_ok=True)
        skew_snapshots[probe_id] = probe_dir / "normalized_vrp.jsonl"
        skew_metadata[probe_id] = probe_dir / "metadata.json"
        write_jsonl(skew_snapshots[probe_id], skew_record)
        write_metadata(skew_metadata[probe_id], probe_id, probe_dir.name, capture_time)

    skew_summary = run_cross_probe_diff(
        snapshot_specs=skew_snapshots,
        metadata_specs=skew_metadata,
        out_dir=skew_dir,
        window_id_arg="win_20260623T000000Z_1h",
        window_size_sec=args.window_size_sec,
        max_skew_sec=args.max_skew_sec,
        emit_common=False,
    )

    checks = {
        "normal_window_ok": normal_summary.get("window_quality") == "OK",
        "missing_event_present": int(normal_summary.get("cross_probe_missing_count") or 0) >= 1,
        "record_divergence_present": int(normal_summary.get("record_divergence_count") or 0) >= 1,
        "source_uri_divergence_present": int(normal_summary.get("source_uri_divergence_count") or 0) >= 1,
        "duplicate_key_present": sum((normal_summary.get("duplicate_key_count_by_probe") or {}).values()) >= 1,
        "candidate_events_present": int(normal_summary.get("candidate_event_count") or 0) >= 1,
        "skew_window_detected": skew_summary.get("window_quality") == "WINDOW_SKEW_TOO_HIGH",
        "skew_candidates_suppressed": int(skew_summary.get("candidate_event_count") or 0) == 0,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    lines = [
        f"P2_CROSS_PROBE_DIFF={status}",
        f"normal_summary={out_dir / 'cross_probe_summary.json'}",
        f"skew_summary={skew_dir / 'cross_probe_summary.json'}",
        f"normal_event_count={normal_summary.get('event_count')}",
        f"normal_candidate_event_count={normal_summary.get('candidate_event_count')}",
        f"skew_window_quality={skew_summary.get('window_quality')}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={str(value).lower()}" for key, value in checks.items())
    atomic_write_text(out_dir / "checks" / "P2_CROSS_PROBE_DIFF_ACCEPTANCE.txt", "\n".join(lines) + "\n")
    print(json.dumps({"self_test_status": status, "checks": checks}, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if status == "PASS" else 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Diff normalized VRP snapshots across multiple probes in one observation window.")
    parser.add_argument("--snapshot", action="append", default=[], help="Probe snapshot assignment: probe_id=path/to/normalized_vrp.jsonl. Repeatable.")
    parser.add_argument("--metadata", action="append", default=[], help="Optional probe metadata assignment: probe_id=path/to/metadata.json. Repeatable.")
    parser.add_argument("--window-id", help="Optional explicit window id. Otherwise derived by flooring capture_time_utc.")
    parser.add_argument("--window-size-sec", type=int, default=3600)
    parser.add_argument("--max-skew-sec", type=int, default=1200)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--emit-common", action="store_true", help="Emit CROSS_PROBE_COMMON events. Default: false.")
    parser.add_argument("--self-test", action="store_true", help="Run synthetic P2 acceptance test.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.window_size_sec <= 0:
        raise ValueError("--window-size-sec must be positive")
    if args.max_skew_sec < 0:
        raise ValueError("--max-skew-sec must be non-negative")
    if args.self_test:
        return run_self_test(args)

    snapshot_specs = parse_assignments(args.snapshot, "--snapshot")
    metadata_specs = parse_assignments(args.metadata, "--metadata")
    run_cross_probe_diff(
        snapshot_specs=snapshot_specs,
        metadata_specs=metadata_specs,
        out_dir=Path(args.out_dir).resolve(),
        window_id_arg=args.window_id,
        window_size_sec=args.window_size_sec,
        max_skew_sec=args.max_skew_sec,
        emit_common=args.emit_common,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
