#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO


SCHEMA_SUMMARY = "s3.probe.cross_window_persistence_summary.v1"
SCHEMA_PERSISTENCE_EVENT = "s3.probe.cross_window_persistence_event.v1"
SCHEMA_SEMANTIC_EVENT = "s3.probe.cross_window_semantic_divergence.v1"
ACCEPTANCE_NAME = "P3_CROSS_WINDOW_PERSISTENCE"
PROGRESS_EVERY = 100_000

EVENT_MISSING = "CROSS_PROBE_MISSING"
EVENT_RECORD_DIVERGENCE = "CROSS_PROBE_RECORD_DIVERGENCE"
EVENT_SOURCE_URI_DIVERGENCE = "CROSS_PROBE_SOURCE_URI_DIVERGENCE"
TRACKED_EVENT_TYPES = {EVENT_MISSING, EVENT_RECORD_DIVERGENCE, EVENT_SOURCE_URI_DIVERGENCE}

CLASS_SINGLE_WINDOW = "SINGLE_WINDOW_TRANSIENT"
CLASS_PROPAGATION = "PROPAGATION_TRANSIENT"
CLASS_PERSISTENT = "PERSISTENT_VIEW_DIVERGENCE"
CLASS_FLAPPING = "DIRECTION_FLAPPING"
SEMANTIC_ORIGIN_SET = "ORIGIN_SET_DIVERGENCE"
SEMANTIC_MAX_LENGTH_SET = "MAX_LENGTH_SET_DIVERGENCE"


@dataclass(frozen=True, slots=True)
class VrpKey:
    tal: str
    asn: int | str
    prefix: str
    max_length: int


@dataclass(frozen=True, slots=True)
class WindowRun:
    p2_run_dir: Path
    candidate_events_path: Path
    window_id: str
    sort_dt: datetime | None
    sort_key: tuple[str, str]
    capture_time_skew_sec: int
    probe_ids: tuple[str, ...]
    summary: dict[str, Any]


@dataclass(slots=True)
class SequenceState:
    vrp_key: str
    missing_signature: tuple[str, ...]
    tal: str | None = None
    asn: int | str | None = None
    prefix: str | None = None
    max_length: int | None = None
    window_indexes: set[int] = field(default_factory=set)
    evidence_windows: list[dict[str, Any]] = field(default_factory=list)
    event_types: Counter[str] = field(default_factory=Counter)
    present_probes: set[str] = field(default_factory=set)
    missing_probes: set[str] = field(default_factory=set)
    probe_ids: set[str] = field(default_factory=set)
    source_uri_available: bool = False


@dataclass(slots=True)
class SemanticState:
    semantic_type: str
    semantic_key: tuple[Any, ...]
    semantic_key_dict: dict[str, Any]
    probe_value_sets: dict[str, list[Any]]
    window_indexes: set[int] = field(default_factory=set)
    evidence_windows: list[dict[str, Any]] = field(default_factory=list)


def utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


def utc_now() -> str:
    return utc_now_dt().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iso_z(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def progress(message: str) -> None:
    print(f"[{utc_now()}] {message}", file=sys.stderr, flush=True)


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


def write_jsonl_record(f: TextIO, record: dict[str, Any]) -> None:
    f.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def stable_id(prefix: str, obj: Any, length: int = 32) -> str:
    payload = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{prefix}_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]


def load_json_object(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise RuntimeError(f"expected JSON object at {path}")
    return obj


def read_jsonl(path: Path, stage: str):
    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            if line_no % PROGRESS_EVERY == 0:
                progress(f"{stage}: read {line_no} candidate events")
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


def as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
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


def parse_window_time(window_id: str, summary: dict[str, Any]) -> datetime | None:
    match = re.search(r"win_(\d{8}T\d{6})Z", window_id or "")
    if match:
        try:
            return datetime.strptime(match.group(1) + "Z", "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    capture_times = summary.get("capture_time_by_probe")
    if isinstance(capture_times, dict):
        parsed = [parse_iso_datetime(value) for value in capture_times.values()]
        parsed = [value for value in parsed if value is not None]
        if parsed:
            return min(parsed)
    for key in ("started_at_utc", "finished_at_utc", "checked_at_utc"):
        parsed = parse_iso_datetime(summary.get(key))
        if parsed is not None:
            return parsed
    return None


def key_from_text(key_text: str | None) -> VrpKey | None:
    if not key_text:
        return None
    parts = str(key_text).split("|")
    if len(parts) != 4:
        return None
    max_length = as_int(parts[3])
    if max_length is None:
        return None
    asn = parse_asn(parts[1])
    if asn is None:
        return None
    return VrpKey(tal=parts[0], asn=asn, prefix=parts[2], max_length=max_length)


def clean_probe_list(values: Any) -> tuple[str, ...]:
    if not isinstance(values, list):
        return ()
    return tuple(sorted(str(value) for value in values if str(value)))


def source_uri_available(source_uri_by_probe: Any) -> bool:
    if not isinstance(source_uri_by_probe, dict):
        return False
    for value in source_uri_by_probe.values():
        if value is not None and str(value).strip():
            return True
    return False


def compact_event_evidence(event: dict[str, Any], window: WindowRun, window_index: int) -> dict[str, Any]:
    return {
        "window_index": window_index,
        "window_id": window.window_id,
        "p2_run_dir": str(window.p2_run_dir),
        "event_id": event.get("event_id"),
        "event_type": event.get("event_type"),
        "present_probes": clean_probe_list(event.get("present_probes")),
        "missing_probes": clean_probe_list(event.get("missing_probes")),
        "candidate_reason": event.get("candidate_reason"),
        "attribution_priority": event.get("attribution_priority"),
        "capture_time_skew_sec": event.get("capture_time_skew_sec"),
        "source_uri_by_probe": event.get("source_uri_by_probe") if isinstance(event.get("source_uri_by_probe"), dict) else {},
    }


def discover_p2_run_dirs(p2_run_dirs: list[str], p2_root: str | None) -> list[Path]:
    found: dict[Path, None] = {}
    for value in p2_run_dirs:
        path = Path(value).resolve()
        if path.exists():
            found[path] = None
    if p2_root:
        root = Path(p2_root).resolve()
        if (root / "cross_probe_summary.json").is_file():
            found[root] = None
        elif root.exists():
            for summary_path in root.rglob("cross_probe_summary.json"):
                found[summary_path.parent.resolve()] = None
    return list(found.keys())


def load_window_run(run_dir: Path, max_skew_sec: int) -> tuple[WindowRun | None, dict[str, Any]]:
    summary_path = run_dir / "cross_probe_summary.json"
    candidate_path = run_dir / "candidate_events.jsonl"
    if not summary_path.is_file():
        return None, {"p2_run_dir": str(run_dir), "skip_reason": "missing_cross_probe_summary_json"}
    if not candidate_path.is_file():
        return None, {"p2_run_dir": str(run_dir), "skip_reason": "missing_candidate_events_jsonl"}

    summary = load_json_object(summary_path)
    window_id = str(summary.get("window_id") or run_dir.name)
    skew = as_int(summary.get("capture_time_skew_sec"))
    quality = summary.get("window_quality")
    if quality != "OK":
        return None, {
            "p2_run_dir": str(run_dir),
            "window_id": window_id,
            "window_quality": quality,
            "capture_time_skew_sec": skew,
            "skip_reason": "window_quality_not_ok",
        }
    if skew is None or skew > max_skew_sec:
        return None, {
            "p2_run_dir": str(run_dir),
            "window_id": window_id,
            "window_quality": quality,
            "capture_time_skew_sec": skew,
            "max_skew_sec": max_skew_sec,
            "skip_reason": "capture_time_skew_too_high",
        }

    probe_ids_raw = summary.get("probe_ids")
    probe_ids = tuple(sorted(str(value) for value in probe_ids_raw)) if isinstance(probe_ids_raw, list) else ()
    sort_dt = parse_window_time(window_id, summary)
    sort_key = (iso_z(sort_dt) or "", window_id)
    return WindowRun(
        p2_run_dir=run_dir,
        candidate_events_path=candidate_path,
        window_id=window_id,
        sort_dt=sort_dt,
        sort_key=sort_key,
        capture_time_skew_sec=skew,
        probe_ids=probe_ids,
        summary=summary,
    ), {}


def longest_consecutive(indexes: set[int]) -> int:
    if not indexes:
        return 0
    ordered = sorted(indexes)
    best = 1
    current = 1
    prev = ordered[0]
    for value in ordered[1:]:
        if value == prev + 1:
            current += 1
        else:
            best = max(best, current)
            current = 1
        prev = value
    return max(best, current)


def classify(total_windows: int, consecutive_windows: int, min_consecutive: int) -> str:
    if consecutive_windows >= min_consecutive:
        return CLASS_PERSISTENT
    if total_windows <= 1:
        return CLASS_SINGLE_WINDOW
    return CLASS_PROPAGATION


def add_sequence_event(
    sequences: dict[tuple[str, tuple[str, ...]], SequenceState],
    event: dict[str, Any],
    window: WindowRun,
    window_index: int,
) -> None:
    event_type = str(event.get("event_type") or "")
    if event_type not in TRACKED_EVENT_TYPES:
        return
    vrp_key = str(event.get("vrp_key") or "")
    key = key_from_text(vrp_key)
    if key is None:
        return
    missing_signature = clean_probe_list(event.get("missing_probes"))
    seq_key = (vrp_key, missing_signature)
    seq = sequences.get(seq_key)
    if seq is None:
        seq = SequenceState(
            vrp_key=vrp_key,
            missing_signature=missing_signature,
            tal=key.tal,
            asn=key.asn,
            prefix=key.prefix,
            max_length=key.max_length,
        )
        sequences[seq_key] = seq

    seq.window_indexes.add(window_index)
    seq.event_types[event_type] += 1
    seq.present_probes.update(clean_probe_list(event.get("present_probes")))
    seq.missing_probes.update(missing_signature)
    seq.probe_ids.update(clean_probe_list(event.get("probe_ids")) or window.probe_ids)
    if source_uri_available(event.get("source_uri_by_probe")):
        seq.source_uri_available = True
    seq.evidence_windows.append(compact_event_evidence(event, window, window_index))


def ensure_probe_sets(probe_ids: tuple[str, ...]) -> dict[str, set[Any]]:
    return {probe_id: set() for probe_id in probe_ids}


def update_semantic_maps(
    origin_sets: dict[tuple[Any, ...], dict[str, set[Any]]],
    maxlen_sets: dict[tuple[Any, ...], dict[str, set[Any]]],
    event: dict[str, Any],
    window: WindowRun,
) -> None:
    tal = event.get("tal")
    asn = parse_asn(event.get("asn"))
    prefix = event.get("prefix")
    max_length = as_int(event.get("max_length"))
    if tal is None or asn is None or prefix is None or max_length is None:
        return
    probe_ids = clean_probe_list(event.get("probe_ids")) or window.probe_ids
    present = clean_probe_list(event.get("present_probes"))
    if not probe_ids:
        probe_ids = tuple(sorted(set(present) | set(clean_probe_list(event.get("missing_probes")))))

    origin_key = (str(tal), str(prefix), max_length)
    origin_by_probe = origin_sets.setdefault(origin_key, ensure_probe_sets(probe_ids))
    for probe_id in probe_ids:
        origin_by_probe.setdefault(probe_id, set())
    for probe_id in present:
        origin_by_probe.setdefault(probe_id, set()).add(asn)

    maxlen_key = (str(tal), asn, str(prefix))
    maxlen_by_probe = maxlen_sets.setdefault(maxlen_key, ensure_probe_sets(probe_ids))
    for probe_id in probe_ids:
        maxlen_by_probe.setdefault(probe_id, set())
    for probe_id in present:
        maxlen_by_probe.setdefault(probe_id, set()).add(max_length)


def normalized_probe_value_sets(by_probe: dict[str, set[Any]]) -> dict[str, list[Any]]:
    return {
        probe_id: sorted(values, key=lambda value: str(value))
        for probe_id, values in sorted(by_probe.items())
    }


def has_set_divergence(by_probe: dict[str, set[Any]]) -> bool:
    if len(by_probe) < 2:
        return False
    signatures = {tuple(sorted(values, key=lambda value: str(value))) for values in by_probe.values()}
    return len(signatures) > 1


def add_semantic_state(
    semantic_sequences: dict[tuple[str, tuple[Any, ...], str], SemanticState],
    semantic_type: str,
    semantic_key: tuple[Any, ...],
    semantic_key_dict: dict[str, Any],
    by_probe: dict[str, set[Any]],
    window: WindowRun,
    window_index: int,
) -> None:
    probe_value_sets = normalized_probe_value_sets(by_probe)
    signature = json.dumps(probe_value_sets, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    state_key = (semantic_type, semantic_key, signature)
    state = semantic_sequences.get(state_key)
    if state is None:
        state = SemanticState(
            semantic_type=semantic_type,
            semantic_key=semantic_key,
            semantic_key_dict=semantic_key_dict,
            probe_value_sets=probe_value_sets,
        )
        semantic_sequences[state_key] = state
    state.window_indexes.add(window_index)
    state.evidence_windows.append({
        "window_index": window_index,
        "window_id": window.window_id,
        "p2_run_dir": str(window.p2_run_dir),
        "capture_time_skew_sec": window.capture_time_skew_sec,
        "probe_value_sets": probe_value_sets,
    })


def process_window(
    window: WindowRun,
    window_index: int,
    sequences: dict[tuple[str, tuple[str, ...]], SequenceState],
    semantic_sequences: dict[tuple[str, tuple[Any, ...], str], SemanticState],
) -> int:
    progress(f"processing accepted P2 window {window_index + 1}: {window.window_id} from {window.p2_run_dir}")
    origin_sets: dict[tuple[Any, ...], dict[str, set[Any]]] = {}
    maxlen_sets: dict[tuple[Any, ...], dict[str, set[Any]]] = {}
    count = 0
    for _, event in read_jsonl(window.candidate_events_path, window.window_id):
        count += 1
        add_sequence_event(sequences, event, window, window_index)
        update_semantic_maps(origin_sets, maxlen_sets, event, window)

    for semantic_key, by_probe in origin_sets.items():
        if not has_set_divergence(by_probe):
            continue
        tal, prefix, max_length = semantic_key
        add_semantic_state(
            semantic_sequences,
            SEMANTIC_ORIGIN_SET,
            semantic_key,
            {"tal": tal, "prefix": prefix, "max_length": max_length},
            by_probe,
            window,
            window_index,
        )
    for semantic_key, by_probe in maxlen_sets.items():
        if not has_set_divergence(by_probe):
            continue
        tal, asn, prefix = semantic_key
        add_semantic_state(
            semantic_sequences,
            SEMANTIC_MAX_LENGTH_SET,
            semantic_key,
            {"tal": tal, "asn": asn, "prefix": prefix},
            by_probe,
            window,
            window_index,
        )
    progress(f"finished window {window.window_id}: candidate_events={count}")
    return count


def recovery_fields(indexes: set[int], windows: list[WindowRun]) -> dict[str, Any]:
    if not indexes:
        return {
            "recovered": False,
            "recovered_at_window_id": None,
            "recovered_at_utc": None,
            "recovery_duration_sec_since_last_seen": None,
        }
    last_index = max(indexes)
    if last_index >= len(windows) - 1:
        return {
            "recovered": False,
            "recovered_at_window_id": None,
            "recovered_at_utc": None,
            "recovery_duration_sec_since_last_seen": None,
        }
    last_dt = windows[last_index].sort_dt
    recovered_window = windows[last_index + 1]
    recovered_dt = recovered_window.sort_dt
    duration_sec = None
    if last_dt is not None and recovered_dt is not None:
        duration_sec = int((recovered_dt - last_dt).total_seconds())
    return {
        "recovered": True,
        "recovered_at_window_id": recovered_window.window_id,
        "recovered_at_utc": iso_z(recovered_dt),
        "recovery_duration_sec_since_last_seen": duration_sec,
    }


def sequence_to_event(seq: SequenceState, windows: list[WindowRun], min_consecutive: int) -> dict[str, Any]:
    first_index = min(seq.window_indexes)
    last_index = max(seq.window_indexes)
    consecutive = longest_consecutive(seq.window_indexes)
    total = len(seq.window_indexes)
    classification = classify(total, consecutive, min_consecutive)
    event = {
        "schema": SCHEMA_PERSISTENCE_EVENT,
        "event_id": stable_id("p3evt", {
            "vrp_key": seq.vrp_key,
            "missing_probes": seq.missing_signature,
            "classification": classification,
            "first_window": windows[first_index].window_id,
        }),
        "classification": classification,
        "analysis_key": "vrp_key+missing_probes",
        "vrp_key": seq.vrp_key,
        "tal": seq.tal,
        "asn": seq.asn,
        "prefix": seq.prefix,
        "max_length": seq.max_length,
        "event_types": dict(sorted(seq.event_types.items())),
        "missing_probes": sorted(seq.missing_probes),
        "present_probes": sorted(seq.present_probes),
        "probe_ids": sorted(seq.probe_ids),
        "first_seen_window_id": windows[first_index].window_id,
        "last_seen_window_id": windows[last_index].window_id,
        "first_seen_at_utc": iso_z(windows[first_index].sort_dt),
        "last_seen_at_utc": iso_z(windows[last_index].sort_dt),
        "consecutive_window_count": consecutive,
        "total_window_count": total,
        "observed_window_indexes": sorted(seq.window_indexes),
        "source_uri_available": seq.source_uri_available,
        "evidence_level": "P3_PATTERN_WITH_SOURCE_URI" if seq.source_uri_available else "P3_PATTERN_ONLY",
        "evidence_windows": seq.evidence_windows,
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
    }
    event.update(recovery_fields(seq.window_indexes, windows))
    return event


def flapping_events(sequences: dict[tuple[str, tuple[str, ...]], SequenceState], windows: list[WindowRun]) -> list[dict[str, Any]]:
    by_vrp_key: dict[str, list[SequenceState]] = defaultdict(list)
    for seq in sequences.values():
        by_vrp_key[seq.vrp_key].append(seq)

    events: list[dict[str, Any]] = []
    for vrp_key, seqs in sorted(by_vrp_key.items()):
        signatures = {seq.missing_signature for seq in seqs}
        signatures = {signature for signature in signatures if signature}
        if len(signatures) < 2:
            continue
        all_indexes: set[int] = set()
        evidence: list[dict[str, Any]] = []
        directions: list[dict[str, Any]] = []
        source_present = False
        present_probes: set[str] = set()
        missing_probes: set[str] = set()
        probe_ids: set[str] = set()
        parsed = key_from_text(vrp_key)
        for seq in sorted(seqs, key=lambda value: value.missing_signature):
            all_indexes.update(seq.window_indexes)
            evidence.extend(seq.evidence_windows)
            source_present = source_present or seq.source_uri_available
            present_probes.update(seq.present_probes)
            missing_probes.update(seq.missing_probes)
            probe_ids.update(seq.probe_ids)
            directions.append({
                "missing_probes": list(seq.missing_signature),
                "window_ids": [windows[index].window_id for index in sorted(seq.window_indexes)],
                "total_window_count": len(seq.window_indexes),
                "consecutive_window_count": longest_consecutive(seq.window_indexes),
            })
        first_index = min(all_indexes)
        last_index = max(all_indexes)
        event = {
            "schema": SCHEMA_PERSISTENCE_EVENT,
            "event_id": stable_id("p3evt", {
                "vrp_key": vrp_key,
                "classification": CLASS_FLAPPING,
                "directions": directions,
            }),
            "classification": CLASS_FLAPPING,
            "analysis_key": "vrp_key+multiple_missing_probe_directions",
            "vrp_key": vrp_key,
            "tal": parsed.tal if parsed else None,
            "asn": parsed.asn if parsed else None,
            "prefix": parsed.prefix if parsed else None,
            "max_length": parsed.max_length if parsed else None,
            "missing_probes": sorted(missing_probes),
            "present_probes": sorted(present_probes),
            "probe_ids": sorted(probe_ids),
            "direction_count": len(signatures),
            "directions": directions,
            "first_seen_window_id": windows[first_index].window_id,
            "last_seen_window_id": windows[last_index].window_id,
            "first_seen_at_utc": iso_z(windows[first_index].sort_dt),
            "last_seen_at_utc": iso_z(windows[last_index].sort_dt),
            "consecutive_window_count": longest_consecutive(all_indexes),
            "total_window_count": len(all_indexes),
            "observed_window_indexes": sorted(all_indexes),
            "source_uri_available": source_present,
            "evidence_level": "P3_PATTERN_WITH_SOURCE_URI" if source_present else "P3_PATTERN_ONLY",
            "evidence_windows": sorted(evidence, key=lambda item: (item.get("window_index", -1), str(item.get("event_id")))),
            "causal_claim_allowed": False,
            "root_cause_confirmed": False,
        }
        event.update(recovery_fields(all_indexes, windows))
        events.append(event)
    return events


def semantic_to_event(state: SemanticState, windows: list[WindowRun], min_consecutive: int) -> dict[str, Any]:
    first_index = min(state.window_indexes)
    last_index = max(state.window_indexes)
    consecutive = longest_consecutive(state.window_indexes)
    total = len(state.window_indexes)
    classification = classify(total, consecutive, min_consecutive)
    event = {
        "schema": SCHEMA_SEMANTIC_EVENT,
        "event_id": stable_id("p3sem", {
            "semantic_type": state.semantic_type,
            "semantic_key": state.semantic_key,
            "probe_value_sets": state.probe_value_sets,
            "first_window": windows[first_index].window_id,
        }),
        "semantic_type": state.semantic_type,
        "classification": classification,
        "semantic_key": state.semantic_key_dict,
        "probe_value_sets": state.probe_value_sets,
        "first_seen_window_id": windows[first_index].window_id,
        "last_seen_window_id": windows[last_index].window_id,
        "first_seen_at_utc": iso_z(windows[first_index].sort_dt),
        "last_seen_at_utc": iso_z(windows[last_index].sort_dt),
        "consecutive_window_count": consecutive,
        "total_window_count": total,
        "observed_window_indexes": sorted(state.window_indexes),
        "evidence_windows": state.evidence_windows,
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
    }
    event.update(recovery_fields(state.window_indexes, windows))
    return event


def write_summary_csv(path: Path, summary: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    fields = [
        "status",
        "input_p2_run_count",
        "accepted_window_count",
        "skipped_window_count",
        "candidate_event_input_count",
        "persistent_event_count",
        "transient_event_count",
        "semantic_divergence_count",
        "direction_flapping_count",
        "causal_claim_allowed_count",
        "root_cause_confirmed",
    ]
    try:
        with tmp.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerow({field: summary.get(field) for field in fields})
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


def write_acceptance(out_dir: Path, summary: dict[str, Any]) -> None:
    checks = {
        "summary_json_exists": Path(summary["outputs"]["summary_json"]).is_file(),
        "summary_csv_exists": Path(summary["outputs"]["summary_csv"]).is_file(),
        "persistent_events_jsonl_exists": Path(summary["outputs"]["persistent_events_jsonl"]).is_file(),
        "transient_events_jsonl_exists": Path(summary["outputs"]["transient_events_jsonl"]).is_file(),
        "semantic_divergences_jsonl_exists": Path(summary["outputs"]["semantic_divergences_jsonl"]).is_file(),
        "accepted_window_count_gt_zero": int(summary.get("accepted_window_count") or 0) > 0,
        "causal_claim_allowed_count_zero": summary.get("causal_claim_allowed_count") == 0,
        "root_cause_confirmed_false": summary.get("root_cause_confirmed") is False,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    lines = [
        f"{ACCEPTANCE_NAME}={status}",
        f"out_dir={out_dir}",
        f"input_p2_run_count={summary.get('input_p2_run_count')}",
        f"accepted_window_count={summary.get('accepted_window_count')}",
        f"skipped_window_count={summary.get('skipped_window_count')}",
        f"candidate_event_input_count={summary.get('candidate_event_input_count')}",
        f"persistent_event_count={summary.get('persistent_event_count')}",
        f"transient_event_count={summary.get('transient_event_count')}",
        f"semantic_divergence_count={summary.get('semantic_divergence_count')}",
        f"direction_flapping_count={summary.get('direction_flapping_count')}",
        f"causal_claim_allowed_count={summary.get('causal_claim_allowed_count')}",
        f"root_cause_confirmed={str(summary.get('root_cause_confirmed')).lower()}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={str(value).lower()}" for key, value in checks.items())
    atomic_write_text(out_dir / "checks" / "P3_CROSS_WINDOW_PERSISTENCE_ACCEPTANCE.txt", "\n".join(lines) + "\n")


def analyze(args: argparse.Namespace) -> dict[str, Any]:
    started_at_utc = utc_now()
    started = time.monotonic()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    run_dirs = discover_p2_run_dirs(args.p2_run_dir or [], args.p2_root)
    windows: list[WindowRun] = []
    skipped: list[dict[str, Any]] = []
    for run_dir in run_dirs:
        window, skip = load_window_run(run_dir, int(args.max_skew_sec))
        if window is None:
            skipped.append(skip)
        else:
            windows.append(window)
    windows.sort(key=lambda item: item.sort_key)

    sequences: dict[tuple[str, tuple[str, ...]], SequenceState] = {}
    semantic_sequences: dict[tuple[str, tuple[Any, ...], str], SemanticState] = {}
    candidate_event_input_count = 0
    for index, window in enumerate(windows):
        candidate_event_input_count += process_window(window, index, sequences, semantic_sequences)

    sequence_events = [sequence_to_event(seq, windows, int(args.min_consecutive)) for seq in sequences.values()] if windows else []
    flapping = flapping_events(sequences, windows) if windows else []
    persistent_events = sorted(
        [event for event in sequence_events if event.get("classification") == CLASS_PERSISTENT],
        key=lambda item: (str(item.get("first_seen_window_id")), str(item.get("vrp_key")), json.dumps(item.get("missing_probes"))),
    )
    transient_events = sorted(
        [event for event in sequence_events if event.get("classification") != CLASS_PERSISTENT] + flapping,
        key=lambda item: (str(item.get("first_seen_window_id")), str(item.get("classification")), str(item.get("vrp_key"))),
    )
    semantic_events = sorted(
        [semantic_to_event(state, windows, int(args.min_consecutive)) for state in semantic_sequences.values()] if windows else [],
        key=lambda item: (str(item.get("first_seen_window_id")), str(item.get("semantic_type")), json.dumps(item.get("semantic_key"), sort_keys=True)),
    )

    persistent_path = out_dir / "persistent_events.jsonl"
    transient_path = out_dir / "transient_events.jsonl"
    semantic_path = out_dir / "semantic_divergences.jsonl"
    summary_path = out_dir / "summary.json"
    summary_csv_path = out_dir / "summary.csv"

    for path, records in (
        (persistent_path, persistent_events),
        (transient_path, transient_events),
        (semantic_path, semantic_events),
    ):
        tmp, f = open_tmp_jsonl(path)
        try:
            with f:
                for record in records:
                    write_jsonl_record(f, record)
                f.flush()
                os.fsync(f.fileno())
            publish_existing_atomically(tmp, path)
        except Exception:
            try:
                f.close()
            except Exception:
                pass
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            raise

    classification_counter = Counter(event.get("classification") for event in sequence_events + flapping)
    semantic_type_counter = Counter(event.get("semantic_type") for event in semantic_events)
    tal_counter = Counter(event.get("tal") for event in sequence_events if event.get("tal"))
    causal_count = sum(1 for event in persistent_events + transient_events + semantic_events if event.get("causal_claim_allowed"))
    root_true = any(event.get("root_cause_confirmed") is True for event in persistent_events + transient_events + semantic_events)

    status = "PASS"
    if not windows or causal_count != 0 or root_true:
        status = "FAIL"

    summary = {
        "schema": SCHEMA_SUMMARY,
        "status": status,
        "min_consecutive": int(args.min_consecutive),
        "max_skew_sec": int(args.max_skew_sec),
        "input_p2_run_count": len(run_dirs),
        "accepted_window_count": len(windows),
        "skipped_window_count": len(skipped),
        "skipped_windows": skipped,
        "accepted_windows": [
            {
                "window_index": index,
                "window_id": window.window_id,
                "p2_run_dir": str(window.p2_run_dir),
                "capture_time_skew_sec": window.capture_time_skew_sec,
                "sort_time_utc": iso_z(window.sort_dt),
                "probe_ids": list(window.probe_ids),
            }
            for index, window in enumerate(windows)
        ],
        "candidate_event_input_count": candidate_event_input_count,
        "tracked_direction_count": len(sequences),
        "persistent_event_count": len(persistent_events),
        "transient_event_count": len(transient_events),
        "semantic_divergence_count": len(semantic_events),
        "direction_flapping_count": len(flapping),
        "classification_distribution": dict(sorted(classification_counter.items())),
        "semantic_type_distribution": dict(sorted(semantic_type_counter.items())),
        "tal_distribution": dict(sorted(tal_counter.items())),
        "causal_claim_allowed_count": causal_count,
        "root_cause_confirmed": bool(root_true),
        "outputs": {
            "persistent_events_jsonl": str(persistent_path),
            "transient_events_jsonl": str(transient_path),
            "semantic_divergences_jsonl": str(semantic_path),
            "summary_json": str(summary_path),
            "summary_csv": str(summary_csv_path),
            "acceptance": str(out_dir / "checks" / "P3_CROSS_WINDOW_PERSISTENCE_ACCEPTANCE.txt"),
        },
        "started_at_utc": started_at_utc,
        "finished_at_utc": utc_now(),
        "duration_sec": round(time.monotonic() - started, 6),
    }

    atomic_write_json(summary_path, summary)
    write_summary_csv(summary_csv_path, summary)
    write_acceptance(out_dir, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return summary


def self_test_event(
    event_type: str,
    window_id: str,
    vrp_key: str,
    present: list[str],
    missing: list[str],
    source_uri: str | None = "rsync://repo/test.roa",
) -> dict[str, Any]:
    key = key_from_text(vrp_key)
    source_by_probe = {probe_id: source_uri for probe_id in present} if source_uri else {probe_id: None for probe_id in present}
    return {
        "schema": "s3.probe.cross_probe_vrp_diff_event.v1",
        "event_id": stable_id("xevt", {"window_id": window_id, "event_type": event_type, "vrp_key": vrp_key, "present": present, "missing": missing}),
        "event_type": event_type,
        "window_id": window_id,
        "window_size_sec": 3600,
        "capture_time_skew_sec": 60,
        "probe_ids": ["probe-a", "probe-b", "probe-c"],
        "present_probes": present,
        "missing_probes": missing,
        "vrp_key": vrp_key,
        "tal": key.tal if key else None,
        "asn": key.asn if key else None,
        "prefix": key.prefix if key else None,
        "max_length": key.max_length if key else None,
        "source_uri_by_probe": source_by_probe,
        "record_hash_by_probe": {probe_id: stable_id("hash", {"probe": probe_id, "vrp_key": vrp_key}) for probe_id in present},
        "attribution_candidate": True,
        "candidate_reason": "synthetic_p3_self_test",
        "attribution_priority": "MEDIUM",
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
    }


def write_self_test_p2_run(root: Path, name: str, window_id: str, quality: str, skew: int, events: list[dict[str, Any]]) -> Path:
    run_dir = root / name
    run_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "schema": "s3.probe.cross_probe_vrp_diff_summary.v1",
        "window_id": window_id,
        "window_quality": quality,
        "capture_time_skew_sec": skew,
        "probe_count": 3,
        "probe_ids": ["probe-a", "probe-b", "probe-c"],
        "candidate_event_count": len(events),
        "causal_claim_allowed_count": 0,
        "root_cause_confirmed": False,
    }
    atomic_write_json(run_dir / "cross_probe_summary.json", summary)
    text = "".join(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for event in events)
    atomic_write_text(run_dir / "candidate_events.jsonl", text)
    return run_dir


def run_self_test(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).resolve()
    input_root = out_dir / "self_test_p2_runs"
    input_root.mkdir(parents=True, exist_ok=True)
    windows = [
        "win_20260625T000000Z_1h",
        "win_20260625T010000Z_1h",
        "win_20260625T020000Z_1h",
        "win_20260625T030000Z_1h",
    ]
    persistent_key = "apnic|64500|203.0.113.0/24|24"
    single_key = "apnic|64501|198.51.100.0/24|24"
    propagation_key = "apnic|64505|198.51.101.0/24|24"
    flapping_key = "ripe|64502|192.0.2.0/24|24"
    origin_key_a = "arin|64510|10.10.0.0/24|24"
    origin_key_b = "arin|64511|10.10.0.0/24|24"
    maxlen_key_a = "afrinic|64520|10.20.0.0/24|24"
    maxlen_key_b = "afrinic|64520|10.20.0.0/24|25"
    bad_key = "apnic|64599|10.99.0.0/24|24"

    write_self_test_p2_run(input_root, "p2_00", windows[0], "OK", 60, [
        self_test_event(EVENT_MISSING, windows[0], persistent_key, ["probe-a", "probe-c"], ["probe-b"]),
        self_test_event(EVENT_MISSING, windows[0], single_key, ["probe-a"], ["probe-b", "probe-c"], source_uri=None),
        self_test_event(EVENT_MISSING, windows[0], propagation_key, ["probe-a", "probe-b"], ["probe-c"]),
        self_test_event(EVENT_MISSING, windows[0], flapping_key, ["probe-a", "probe-c"], ["probe-b"]),
        self_test_event(EVENT_MISSING, windows[0], origin_key_a, ["probe-a"], ["probe-b"]),
        self_test_event(EVENT_MISSING, windows[0], origin_key_b, ["probe-b"], ["probe-a"]),
        self_test_event(EVENT_MISSING, windows[0], maxlen_key_a, ["probe-a"], ["probe-b"]),
        self_test_event(EVENT_MISSING, windows[0], maxlen_key_b, ["probe-b"], ["probe-a"]),
    ])
    write_self_test_p2_run(input_root, "p2_01", windows[1], "OK", 60, [
        self_test_event(EVENT_MISSING, windows[1], persistent_key, ["probe-a", "probe-c"], ["probe-b"]),
        self_test_event(EVENT_MISSING, windows[1], propagation_key, ["probe-a", "probe-b"], ["probe-c"]),
        self_test_event(EVENT_MISSING, windows[1], flapping_key, ["probe-a", "probe-b"], ["probe-c"]),
    ])
    write_self_test_p2_run(input_root, "p2_02", windows[2], "OK", 60, [
        self_test_event(EVENT_MISSING, windows[2], persistent_key, ["probe-a", "probe-c"], ["probe-b"]),
    ])
    write_self_test_p2_run(input_root, "p2_03", windows[3], "OK", 60, [])
    write_self_test_p2_run(input_root, "p2_bad_quality", "win_20260625T040000Z_1h", "WINDOW_SKEW_TOO_HIGH", 5000, [
        self_test_event(EVENT_MISSING, "win_20260625T040000Z_1h", bad_key, ["probe-a"], ["probe-b"]),
    ])

    test_args = argparse.Namespace(
        p2_run_dir=[],
        p2_root=str(input_root),
        min_consecutive=args.min_consecutive,
        max_skew_sec=args.max_skew_sec,
        out_dir=str(out_dir),
        self_test=False,
    )
    summary = analyze(test_args)
    distribution = summary.get("classification_distribution", {})
    semantic_distribution = summary.get("semantic_type_distribution", {})
    checks = {
        "persistent_present": int(distribution.get(CLASS_PERSISTENT, 0)) >= 1,
        "single_window_present": int(distribution.get(CLASS_SINGLE_WINDOW, 0)) >= 1,
        "propagation_present": int(distribution.get(CLASS_PROPAGATION, 0)) >= 1,
        "flapping_present": int(distribution.get(CLASS_FLAPPING, 0)) >= 1,
        "origin_set_divergence_present": int(semantic_distribution.get(SEMANTIC_ORIGIN_SET, 0)) >= 1,
        "max_length_set_divergence_present": int(semantic_distribution.get(SEMANTIC_MAX_LENGTH_SET, 0)) >= 1,
        "bad_window_filtered": int(summary.get("skipped_window_count") or 0) >= 1,
        "causal_false": summary.get("causal_claim_allowed_count") == 0 and summary.get("root_cause_confirmed") is False,
    }
    if not all(checks.values()):
        print(json.dumps({"self_test_checks": checks, "summary": summary}, ensure_ascii=False, indent=2, sort_keys=True), file=sys.stderr)
        return 1
    progress("P3 self-test PASS: " + json.dumps(checks, sort_keys=True))
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze cross-window persistence for P2 cross-probe VRP candidate events.")
    parser.add_argument("--p2-run-dir", action="append", default=[], help="P2 run directory containing cross_probe_summary.json and candidate_events.jsonl. Repeatable.")
    parser.add_argument("--p2-root", help="Root directory to recursively scan for P2 run directories.")
    parser.add_argument("--min-consecutive", type=int, default=3)
    parser.add_argument("--max-skew-sec", type=int, default=600)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.min_consecutive <= 0:
        parser.error("--min-consecutive must be > 0")
    if args.max_skew_sec < 0:
        parser.error("--max-skew-sec must be >= 0")
    if not args.self_test and not args.p2_run_dir and not args.p2_root:
        parser.error("provide at least one --p2-run-dir or --p2-root, or use --self-test")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test(args)
    summary = analyze(args)
    return 0 if summary.get("status") == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
