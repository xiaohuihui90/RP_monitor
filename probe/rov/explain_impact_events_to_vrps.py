#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import gzip
import ipaddress
import json
import os
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

try:
    from .load_vrps import vrp_from_record
    from .rov_validate import STATE_INVALID, STATE_NOT_FOUND, STATE_VALID, VrpRecord, parse_asn, stable_id
except ImportError:  # pragma: no cover - direct script execution fallback
    from probe.rov.load_vrps import vrp_from_record
    from probe.rov.rov_validate import STATE_INVALID, STATE_NOT_FOUND, STATE_VALID, VrpRecord, parse_asn, stable_id


SCHEMA_EXPLANATION = "s3.probe.rov.impact_vrp_explanation.v1"
SCHEMA_SUMMARY = "s3.probe.rov.impact_vrp_explainer_summary.v1"
ACCEPTANCE_FILE = "checks/P11A_IMPACT_VRP_EXPLAINER_ACCEPTANCE.txt"
PROGRESS_EVERY = 100_000

EXPLANATION_FIELDS = [
    "window_id",
    "route_prefix",
    "origin_asn",
    "probe_a",
    "probe_b",
    "state_a",
    "state_b",
    "transition_type",
    "explainer_type",
    "candidate_vrp_probe",
    "candidate_vrp_key",
    "candidate_vrp_asn",
    "candidate_vrp_prefix",
    "candidate_vrp_max_length",
    "candidate_vrp_tal",
    "candidate_vrp_present_in_probes",
    "candidate_vrp_missing_in_probes",
    "covering_vrp_count_by_probe",
    "matching_vrp_count_by_probe",
    "recomputed_state_by_probe",
    "mapping_strength",
    "root_cause_confirmed",
    "causal_claim_allowed",
]

ROUTE_SUMMARY_FIELDS = [
    "window_id",
    "route_prefix",
    "origin_asn",
    "transition_event_count",
    "probe_pairs",
    "transition_types",
    "best_mapping_strength",
    "candidate_vrp_count",
    "strong_mapping_count",
    "medium_mapping_count",
    "weak_mapping_count",
    "covering_vrp_count_by_probe",
    "matching_vrp_count_by_probe",
    "recomputed_state_by_probe",
    "root_cause_confirmed",
    "causal_claim_allowed",
]

TOP_CANDIDATE_FIELDS = [
    "candidate_vrp_key",
    "candidate_vrp_asn",
    "candidate_vrp_prefix",
    "candidate_vrp_max_length",
    "candidate_vrp_tal",
    "explanation_row_count",
    "route_count",
    "transition_types",
    "probe_pairs",
    "present_in_probes",
    "missing_in_probes",
    "best_mapping_strength",
    "root_cause_confirmed",
    "causal_claim_allowed",
]


@dataclass(frozen=True, slots=True)
class CandidateVrp:
    probe_id: str
    explainer_type: str
    vrp: VrpRecord


class FullVrpIndex:
    def __init__(self, probe_id: str) -> None:
        self.probe_id = probe_id
        self.index: dict[int, dict[int, dict[ipaddress.IPv4Network | ipaddress.IPv6Network, list[VrpRecord]]]] = {
            4: {},
            6: {},
        }
        self.key_set: set[str] = set()
        self.record_count = 0
        self.parse_error_count = 0

    def add(self, vrp: VrpRecord) -> None:
        network = vrp.network
        bucket = self.index[network.version].setdefault(network.prefixlen, {})
        bucket.setdefault(network, []).append(vrp)
        self.key_set.add(vrp_key(vrp))
        self.record_count += 1

    def classify(self, route_prefix: str, origin_asn: int) -> dict[str, Any]:
        route_net = ipaddress.ip_network(route_prefix, strict=False)
        covered: list[VrpRecord] = []
        matched: list[VrpRecord] = []
        for prefix_len in range(route_net.prefixlen, -1, -1):
            bucket = self.index.get(route_net.version, {}).get(prefix_len, {})
            if not bucket:
                continue
            supernet = route_net if prefix_len == route_net.prefixlen else route_net.supernet(new_prefix=prefix_len)
            for vrp in bucket.get(supernet, []):
                if route_net.prefixlen <= vrp.max_length:
                    covered.append(vrp)
                    if origin_asn == vrp.asn:
                        matched.append(vrp)
        if matched:
            state = STATE_VALID
        elif covered:
            state = STATE_INVALID
        else:
            state = STATE_NOT_FOUND
        return {"state": state, "covering": covered, "matching": matched}


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


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


def resolve_path(value: str, root: Path, base: Path | None = None) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    if base is not None:
        candidate = (base / path).resolve()
        if candidate.exists():
            return candidate
    return (root / path).resolve()


def load_json_object(path: Path) -> tuple[dict[str, Any], str | None]:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            return {}, "expected JSON object"
        return obj, None
    except Exception as exc:
        return {}, str(exc)


def parse_probe_ids(value: str) -> list[str]:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def jsonl_opener(path: Path) -> Any:
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8-sig", errors="replace")
    return path.open("r", encoding="utf-8-sig", errors="replace")


def open_tmp_text(path: Path) -> tuple[Path, TextIO]:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    return tmp, tmp.open("w", encoding="utf-8", newline="\n")


def publish_tmp(tmp: Path, dest: Path) -> None:
    os.replace(tmp, dest)
    fsync_parent(dest)


def vrp_key(vrp: VrpRecord) -> str:
    return f"{vrp.asn},{vrp.prefix},{vrp.max_length},{vrp.tal}"


def compact_vrp(vrp: VrpRecord) -> dict[str, Any]:
    return {
        "vrp_key": vrp_key(vrp),
        "asn": vrp.asn,
        "prefix": vrp.prefix,
        "max_length": vrp.max_length,
        "tal": vrp.tal,
        "source_uri": vrp.source_uri,
        "roa_uri": vrp.roa_uri,
        "manifest_uri": vrp.manifest_uri,
    }


def resolve_manifest_vrp_path(record: dict[str, Any], manifest_dir: Path, root: Path) -> Path:
    path_text = str(
        record.get("vrp_path")
        or record.get("prepared_vrp_path")
        or record.get("stable_vrp_path")
        or record.get("archived_from_vrp_path")
        or ""
    )
    if not path_text:
        return Path("")
    return resolve_path(path_text, root, manifest_dir)


def load_manifest_inputs(manifest_path: Path, probe_ids: list[str], root: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    manifest, error = load_json_object(manifest_path)
    raw_inputs = manifest.get("probe_inputs") if isinstance(manifest.get("probe_inputs"), dict) else manifest.get("vrp_inputs")
    if not isinstance(raw_inputs, dict):
        raw_inputs = {}
    selected = probe_ids or sorted(str(key) for key in raw_inputs)
    inputs: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    manifest_dir = manifest_path.parent
    for probe_id in selected:
        raw = raw_inputs.get(probe_id)
        if not isinstance(raw, dict):
            missing.append(f"{probe_id}:manifest_record")
            continue
        vrp_path = resolve_manifest_vrp_path(raw, manifest_dir, root)
        if not vrp_path.is_file():
            missing.append(f"{probe_id}:vrp")
        inputs[probe_id] = {
            "probe_id": probe_id,
            "record": raw,
            "vrp_path": str(vrp_path),
            "vrp_exists": vrp_path.is_file(),
            "snapshot_id": raw.get("snapshot_id"),
            "capture_time_utc": raw.get("capture_time_utc"),
            "validator_health": raw.get("validator_health"),
            "vrp_count": raw.get("vrp_count"),
        }
    return inputs, {
        "manifest_loaded": error is None and bool(manifest),
        "manifest_error": error,
        "window_id": manifest.get("window_id", ""),
        "source_mode": manifest.get("source_mode", ""),
        "missing_inputs": missing,
        "manifest_status": manifest.get("status", ""),
    }


def load_vrp_index(path: Path, probe_id: str) -> FullVrpIndex:
    index = FullVrpIndex(probe_id)
    with jsonl_opener(path) as f:
        for line_no, line in enumerate(f, 1):
            if line_no % PROGRESS_EVERY == 0:
                print(f"[P11A] load_vrps {probe_id}: read {line_no} lines", file=sys.stderr, flush=True)
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                index.parse_error_count += 1
                continue
            if not isinstance(obj, dict):
                index.parse_error_count += 1
                continue
            vrp, err = vrp_from_record(obj)
            if err or vrp is None:
                index.parse_error_count += 1
                continue
            index.add(vrp)
    return index


def state_rank(strength: str) -> int:
    return {"weak": 0, "medium": 1, "strong": 2}.get(strength, -1)


def best_strength(values: set[str]) -> str:
    if "strong" in values:
        return "strong"
    if "medium" in values:
        return "medium"
    return "weak"


def present_missing_for_key(key: str, indexes: dict[str, FullVrpIndex], probe_ids: list[str]) -> tuple[list[str], list[str]]:
    present = [probe_id for probe_id in probe_ids if key in indexes[probe_id].key_set]
    missing = [probe_id for probe_id in probe_ids if key not in indexes[probe_id].key_set]
    return present, missing


def nonmatching_vrps(covered: list[VrpRecord], origin_asn: int) -> list[VrpRecord]:
    return [vrp for vrp in covered if vrp.asn != origin_asn]


def choose_candidates(
    transition: str,
    probe_a: str,
    probe_b: str,
    state_a: str,
    state_b: str,
    origin_asn: int,
    by_probe: dict[str, dict[str, Any]],
) -> list[CandidateVrp]:
    candidates: list[CandidateVrp] = []

    def add_matching(probe_id: str, explainer_type: str) -> None:
        for vrp in by_probe.get(probe_id, {}).get("matching", []):
            candidates.append(CandidateVrp(probe_id, explainer_type, vrp))

    def add_covering_nonmatching(probe_id: str, explainer_type: str) -> None:
        for vrp in nonmatching_vrps(by_probe.get(probe_id, {}).get("covering", []), origin_asn):
            candidates.append(CandidateVrp(probe_id, explainer_type, vrp))

    if transition == f"{STATE_VALID}->{STATE_NOT_FOUND}":
        add_matching(probe_a, "candidate_missing_matching_vrp")
    elif transition == f"{STATE_NOT_FOUND}->{STATE_VALID}":
        add_matching(probe_b, "candidate_extra_matching_vrp")
    elif transition == f"{STATE_INVALID}->{STATE_NOT_FOUND}":
        add_covering_nonmatching(probe_a, "candidate_missing_covering_vrp")
    elif transition == f"{STATE_NOT_FOUND}->{STATE_INVALID}":
        add_covering_nonmatching(probe_b, "candidate_extra_covering_vrp")
    elif transition == f"{STATE_VALID}->{STATE_INVALID}":
        add_matching(probe_a, "valid_side_matching_vrp")
        add_covering_nonmatching(probe_b, "invalid_side_covering_vrp")
    elif transition == f"{STATE_INVALID}->{STATE_VALID}":
        add_matching(probe_b, "valid_side_matching_vrp")
        add_covering_nonmatching(probe_a, "invalid_side_covering_vrp")
    else:
        if state_a == STATE_VALID:
            add_matching(probe_a, "valid_side_matching_vrp")
        if state_b == STATE_VALID:
            add_matching(probe_b, "valid_side_matching_vrp")
        if state_a == STATE_INVALID:
            add_covering_nonmatching(probe_a, "invalid_side_covering_vrp")
        if state_b == STATE_INVALID:
            add_covering_nonmatching(probe_b, "invalid_side_covering_vrp")

    seen: set[tuple[str, str, str]] = set()
    deduped: list[CandidateVrp] = []
    for item in candidates:
        key = (item.probe_id, item.explainer_type, vrp_key(item.vrp))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def mapping_strength_for_candidate(
    candidate: CandidateVrp,
    probe_a: str,
    probe_b: str,
    indexes: dict[str, FullVrpIndex],
    probe_ids: list[str],
    by_probe: dict[str, dict[str, Any]],
    origin_asn: int,
) -> str:
    key = vrp_key(candidate.vrp)
    _, missing = present_missing_for_key(key, indexes, probe_ids)
    other_probe = probe_b if candidate.probe_id == probe_a else probe_a
    if "matching" in candidate.explainer_type:
        return "strong" if other_probe in missing else "medium"
    if "covering" in candidate.explainer_type:
        covering_nonmatch = nonmatching_vrps(by_probe.get(candidate.probe_id, {}).get("covering", []), origin_asn)
        if other_probe in missing and len(covering_nonmatch) == 1:
            return "strong"
        return "medium"
    return "weak"


def json_compact(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def explanation_row(
    event: dict[str, Any],
    candidate: CandidateVrp | None,
    indexes: dict[str, FullVrpIndex],
    probe_ids: list[str],
    by_probe: dict[str, dict[str, Any]],
    mapping_strength: str,
    explainer_type: str,
) -> dict[str, Any]:
    probe_a = str(event.get("probe_a") or "")
    probe_b = str(event.get("probe_b") or "")
    candidate_key = ""
    present: list[str] = []
    missing: list[str] = []
    candidate_compact: dict[str, Any] = {}
    if candidate is not None:
        candidate_compact = compact_vrp(candidate.vrp)
        candidate_key = str(candidate_compact["vrp_key"])
        present, missing = present_missing_for_key(candidate_key, indexes, probe_ids)

    covering_counts = {probe_id: len(by_probe.get(probe_id, {}).get("covering", [])) for probe_id in probe_ids}
    matching_counts = {probe_id: len(by_probe.get(probe_id, {}).get("matching", [])) for probe_id in probe_ids}
    states = {probe_id: by_probe.get(probe_id, {}).get("state", "") for probe_id in probe_ids}
    transition = str(event.get("transition") or event.get("transition_type") or f"{event.get('state_a', '')}->{event.get('state_b', '')}")
    return {
        "schema": SCHEMA_EXPLANATION,
        "explanation_id": stable_id("p11a_expl", {
            "event_id": event.get("event_id"),
            "route_prefix": event.get("route_prefix"),
            "origin_asn": event.get("origin_asn"),
            "probe_a": probe_a,
            "probe_b": probe_b,
            "transition": transition,
            "candidate_vrp_key": candidate_key,
            "candidate_vrp_probe": candidate.probe_id if candidate is not None else "",
            "explainer_type": explainer_type,
        }),
        "p10a_event_id": event.get("event_id", ""),
        "window_id": event.get("window_id", ""),
        "route_prefix": event.get("route_prefix", ""),
        "origin_asn": event.get("origin_asn", ""),
        "route_collector": event.get("route_collector") or event.get("collector") or "",
        "route_observed_time_utc": event.get("route_observed_time_utc") or "",
        "probe_a": probe_a,
        "probe_b": probe_b,
        "state_a": event.get("state_a", ""),
        "state_b": event.get("state_b", ""),
        "transition_type": transition,
        "explainer_type": explainer_type,
        "candidate_vrp_probe": candidate.probe_id if candidate is not None else "",
        "candidate_vrp_key": candidate_key,
        "candidate_vrp_asn": candidate_compact.get("asn", ""),
        "candidate_vrp_prefix": candidate_compact.get("prefix", ""),
        "candidate_vrp_max_length": candidate_compact.get("max_length", ""),
        "candidate_vrp_tal": candidate_compact.get("tal", ""),
        "candidate_vrp_source_uri": candidate_compact.get("source_uri", ""),
        "candidate_vrp_roa_uri": candidate_compact.get("roa_uri", ""),
        "candidate_vrp_manifest_uri": candidate_compact.get("manifest_uri", ""),
        "candidate_vrp_present_in_probes": "|".join(present),
        "candidate_vrp_missing_in_probes": "|".join(missing),
        "covering_vrp_count_by_probe": json_compact(covering_counts),
        "matching_vrp_count_by_probe": json_compact(matching_counts),
        "recomputed_state_by_probe": json_compact(states),
        "mapping_strength": mapping_strength,
        "security_relevance": "potential",
        "root_cause_confirmed": False,
        "causal_claim_allowed": False,
    }


def csv_projection(row: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    return {field: row.get(field, "") for field in fields}


def update_route_summary(store: dict[tuple[str, str, int], dict[str, Any]], row: dict[str, Any]) -> None:
    key = (str(row.get("window_id") or ""), str(row.get("route_prefix") or ""), int(row.get("origin_asn") or 0))
    item = store.setdefault(key, {
        "transition_event_ids": set(),
        "probe_pairs": set(),
        "transition_types": set(),
        "mapping_strengths": Counter(),
        "candidate_vrps": set(),
        "covering_counts": row.get("covering_vrp_count_by_probe", "{}"),
        "matching_counts": row.get("matching_vrp_count_by_probe", "{}"),
        "states": row.get("recomputed_state_by_probe", "{}"),
    })
    if row.get("p10a_event_id"):
        item["transition_event_ids"].add(str(row["p10a_event_id"]))
    item["probe_pairs"].add(f"{row.get('probe_a', '')}:{row.get('probe_b', '')}")
    item["transition_types"].add(str(row.get("transition_type") or ""))
    item["mapping_strengths"][str(row.get("mapping_strength") or "weak")] += 1
    if row.get("candidate_vrp_key"):
        item["candidate_vrps"].add(str(row["candidate_vrp_key"]))


def update_candidate_summary(store: dict[str, dict[str, Any]], row: dict[str, Any]) -> None:
    key = str(row.get("candidate_vrp_key") or "")
    if not key:
        return
    item = store.setdefault(key, {
        "candidate_vrp_asn": row.get("candidate_vrp_asn", ""),
        "candidate_vrp_prefix": row.get("candidate_vrp_prefix", ""),
        "candidate_vrp_max_length": row.get("candidate_vrp_max_length", ""),
        "candidate_vrp_tal": row.get("candidate_vrp_tal", ""),
        "rows": 0,
        "routes": set(),
        "transition_types": set(),
        "probe_pairs": set(),
        "present": set(),
        "missing": set(),
        "mapping_strengths": set(),
    })
    item["rows"] += 1
    item["routes"].add(f"{row.get('route_prefix')}|{row.get('origin_asn')}")
    item["transition_types"].add(str(row.get("transition_type") or ""))
    item["probe_pairs"].add(f"{row.get('probe_a', '')}:{row.get('probe_b', '')}")
    item["present"].update(part for part in str(row.get("candidate_vrp_present_in_probes") or "").split("|") if part)
    item["missing"].update(part for part in str(row.get("candidate_vrp_missing_in_probes") or "").split("|") if part)
    item["mapping_strengths"].add(str(row.get("mapping_strength") or "weak"))


def write_csv_atomic(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    tmp, f = open_tmp_text(path)
    try:
        with f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow(csv_projection(row, fields))
            f.flush()
            os.fsync(f.fileno())
        publish_tmp(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def write_acceptance(out_dir: Path, status: str, summary: dict[str, Any], checks: dict[str, bool]) -> None:
    lines = [
        f"P11A_IMPACT_VRP_EXPLAINER={status}",
        f"p10a_run_dir={summary.get('p10a_run_dir', '')}",
        f"p8_input_vrp_manifest={summary.get('p8_input_vrp_manifest', '')}",
        f"out_dir={summary.get('out_dir', '')}",
        f"transition_event_count={summary.get('transition_event_count', 0)}",
        f"explained_event_count={summary.get('explained_event_count', 0)}",
        f"strong_or_medium_mapping_count={summary.get('strong_or_medium_mapping_count', 0)}",
        f"route_level_candidate_count={summary.get('route_level_candidate_count', 0)}",
        f"probe_count={summary.get('probe_count', 0)}",
        f"p8_input_vrp_manifest_loaded={str(summary.get('p8_input_vrp_manifest_loaded', False)).lower()}",
        f"all_probe_vrps_loaded={str(summary.get('all_probe_vrps_loaded', False)).lower()}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={str(value).lower()}" for key, value in checks.items())
    atomic_write_text(out_dir / ACCEPTANCE_FILE, "\n".join(lines) + "\n")


def run(args: argparse.Namespace) -> int:
    root = repo_root()
    started_at = utc_now()
    started = time.monotonic()
    p10a_run_dir = resolve_path(args.p10a_run_dir, root)
    manifest_path = resolve_path(args.p8_input_vrp_manifest, root)
    out_dir = resolve_path(args.out_dir, root)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "checks").mkdir(parents=True, exist_ok=True)
    transition_path = p10a_run_dir / "validation_transition_events.jsonl"
    requested_probe_ids = parse_probe_ids(args.probe_ids)

    manifest_inputs, manifest_info = load_manifest_inputs(manifest_path, requested_probe_ids, root)
    probe_ids = requested_probe_ids or sorted(manifest_inputs)
    indexes: dict[str, FullVrpIndex] = {}
    vrp_load_errors: dict[str, str] = {}
    for probe_id in probe_ids:
        path_text = str(manifest_inputs.get(probe_id, {}).get("vrp_path") or "")
        path = Path(path_text)
        if not path.is_file():
            vrp_load_errors[probe_id] = "vrp missing"
            continue
        try:
            indexes[probe_id] = load_vrp_index(path, probe_id)
        except Exception as exc:
            vrp_load_errors[probe_id] = str(exc)

    event_count = 0
    explained_event_ids: set[str] = set()
    strong_or_medium_events: set[str] = set()
    explanation_row_count = 0
    mapping_distribution: Counter[str] = Counter()
    route_summary: dict[tuple[str, str, int], dict[str, Any]] = {}
    candidate_summary: dict[str, dict[str, Any]] = {}
    parse_error_count = 0

    jsonl_tmp, jsonl_f = open_tmp_text(out_dir / "impact_vrp_explanations.jsonl")
    csv_tmp, csv_f = open_tmp_text(out_dir / "impact_vrp_explanations.csv")
    try:
        with jsonl_f, csv_f:
            csv_writer = csv.DictWriter(csv_f, fieldnames=EXPLANATION_FIELDS, extrasaction="ignore")
            csv_writer.writeheader()
            if transition_path.is_file() and len(indexes) == len(probe_ids):
                with transition_path.open("r", encoding="utf-8-sig", errors="replace") as f:
                    for line_no, line in enumerate(f, 1):
                        if args.max_events is not None and event_count >= args.max_events:
                            break
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            parse_error_count += 1
                            continue
                        if not isinstance(event, dict):
                            parse_error_count += 1
                            continue
                        event_count += 1
                        route_prefix = str(event.get("route_prefix") or "")
                        origin_asn = parse_asn(event.get("origin_asn"))
                        event_id = str(event.get("event_id") or f"line_{line_no}")
                        if origin_asn is None:
                            parse_error_count += 1
                            continue

                        by_probe: dict[str, dict[str, Any]] = {}
                        try:
                            for probe_id in probe_ids:
                                by_probe[probe_id] = indexes[probe_id].classify(route_prefix, origin_asn)
                        except ValueError:
                            parse_error_count += 1
                            continue

                        probe_a = str(event.get("probe_a") or "")
                        probe_b = str(event.get("probe_b") or "")
                        state_a = str(event.get("state_a") or by_probe.get(probe_a, {}).get("state", ""))
                        state_b = str(event.get("state_b") or by_probe.get(probe_b, {}).get("state", ""))
                        transition = str(event.get("transition") or event.get("transition_type") or f"{state_a}->{state_b}")
                        candidates = choose_candidates(transition, probe_a, probe_b, state_a, state_b, origin_asn, by_probe)
                        if not candidates:
                            row = explanation_row(
                                event,
                                None,
                                indexes,
                                probe_ids,
                                by_probe,
                                "weak",
                                "route_level_only",
                            )
                            jsonl_f.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                            csv_writer.writerow(csv_projection(row, EXPLANATION_FIELDS))
                            update_route_summary(route_summary, row)
                            mapping_distribution["weak"] += 1
                            explanation_row_count += 1
                            continue

                        event_strengths: set[str] = set()
                        for candidate in candidates:
                            strength = mapping_strength_for_candidate(candidate, probe_a, probe_b, indexes, probe_ids, by_probe, origin_asn)
                            row = explanation_row(
                                event,
                                candidate,
                                indexes,
                                probe_ids,
                                by_probe,
                                strength,
                                candidate.explainer_type,
                            )
                            jsonl_f.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                            csv_writer.writerow(csv_projection(row, EXPLANATION_FIELDS))
                            update_route_summary(route_summary, row)
                            update_candidate_summary(candidate_summary, row)
                            mapping_distribution[strength] += 1
                            event_strengths.add(strength)
                            explanation_row_count += 1
                        explained_event_ids.add(event_id)
                        if any(state_rank(strength) >= state_rank("medium") for strength in event_strengths):
                            strong_or_medium_events.add(event_id)
            jsonl_f.flush()
            os.fsync(jsonl_f.fileno())
            csv_f.flush()
            os.fsync(csv_f.fileno())
        publish_tmp(jsonl_tmp, out_dir / "impact_vrp_explanations.jsonl")
        publish_tmp(csv_tmp, out_dir / "impact_vrp_explanations.csv")
    except Exception:
        for tmp in (jsonl_tmp, csv_tmp):
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
        raise

    route_rows: list[dict[str, Any]] = []
    for (window_id, route_prefix, origin_asn), item in sorted(route_summary.items()):
        strengths = set(item["mapping_strengths"].keys())
        route_rows.append({
            "window_id": window_id,
            "route_prefix": route_prefix,
            "origin_asn": origin_asn,
            "transition_event_count": len(item["transition_event_ids"]),
            "probe_pairs": "|".join(sorted(item["probe_pairs"])),
            "transition_types": "|".join(sorted(item["transition_types"])),
            "best_mapping_strength": best_strength(strengths),
            "candidate_vrp_count": len(item["candidate_vrps"]),
            "strong_mapping_count": item["mapping_strengths"].get("strong", 0),
            "medium_mapping_count": item["mapping_strengths"].get("medium", 0),
            "weak_mapping_count": item["mapping_strengths"].get("weak", 0),
            "covering_vrp_count_by_probe": item["covering_counts"],
            "matching_vrp_count_by_probe": item["matching_counts"],
            "recomputed_state_by_probe": item["states"],
            "root_cause_confirmed": False,
            "causal_claim_allowed": False,
        })
    write_csv_atomic(out_dir / "route_level_vrp_summary.csv", ROUTE_SUMMARY_FIELDS, route_rows)

    top_rows: list[dict[str, Any]] = []
    for key, item in sorted(candidate_summary.items(), key=lambda pair: (-int(pair[1]["rows"]), pair[0])):
        top_rows.append({
            "candidate_vrp_key": key,
            "candidate_vrp_asn": item["candidate_vrp_asn"],
            "candidate_vrp_prefix": item["candidate_vrp_prefix"],
            "candidate_vrp_max_length": item["candidate_vrp_max_length"],
            "candidate_vrp_tal": item["candidate_vrp_tal"],
            "explanation_row_count": item["rows"],
            "route_count": len(item["routes"]),
            "transition_types": "|".join(sorted(item["transition_types"])),
            "probe_pairs": "|".join(sorted(item["probe_pairs"])),
            "present_in_probes": "|".join(sorted(item["present"])),
            "missing_in_probes": "|".join(sorted(item["missing"])),
            "best_mapping_strength": best_strength(set(item["mapping_strengths"])),
            "root_cause_confirmed": False,
            "causal_claim_allowed": False,
        })
    write_csv_atomic(out_dir / "top_candidate_vrps.csv", TOP_CANDIDATE_FIELDS, top_rows)

    p8_loaded = bool(manifest_info.get("manifest_loaded"))
    all_probe_vrps_loaded = len(indexes) == len(probe_ids) and all(indexes[p].record_count > 0 for p in probe_ids)
    checks = {
        "transition_event_count_gt_zero": event_count > 0,
        "explained_event_count_gt_zero": len(explained_event_ids) > 0,
        "strong_or_medium_mapping_count_gt_zero": len(strong_or_medium_events) > 0,
        "p8_input_vrp_manifest_loaded": p8_loaded,
        "all_probe_vrps_loaded": all_probe_vrps_loaded,
        "impact_vrp_explanations_jsonl_written": (out_dir / "impact_vrp_explanations.jsonl").is_file(),
        "impact_vrp_explanations_csv_written": (out_dir / "impact_vrp_explanations.csv").is_file(),
        "route_level_vrp_summary_written": (out_dir / "route_level_vrp_summary.csv").is_file(),
        "top_candidate_vrps_written": (out_dir / "top_candidate_vrps.csv").is_file(),
        "no_strong_root_cause_claim": True,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    summary = {
        "schema": SCHEMA_SUMMARY,
        "status": status,
        "p10a_run_dir": str(p10a_run_dir),
        "p8_input_vrp_manifest": str(manifest_path),
        "out_dir": str(out_dir),
        "window_id": manifest_info.get("window_id") or "",
        "manifest_source_mode": manifest_info.get("source_mode") or "",
        "transition_event_count": event_count,
        "explained_event_count": len(explained_event_ids),
        "explanation_row_count": explanation_row_count,
        "strong_or_medium_mapping_count": len(strong_or_medium_events),
        "route_level_candidate_count": len(route_summary),
        "top_candidate_vrp_count": len(candidate_summary),
        "mapping_strength_distribution": dict(sorted(mapping_distribution.items())),
        "probe_count": len(probe_ids),
        "probe_ids": probe_ids,
        "p8_input_vrp_manifest_loaded": p8_loaded,
        "all_probe_vrps_loaded": all_probe_vrps_loaded,
        "vrp_record_count_by_probe": {probe_id: indexes[probe_id].record_count for probe_id in indexes},
        "vrp_parse_error_count_by_probe": {probe_id: indexes[probe_id].parse_error_count for probe_id in indexes},
        "vrp_load_errors": vrp_load_errors,
        "transition_parse_error_count": parse_error_count,
        "root_cause_confirmed": False,
        "causal_claim_allowed": False,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "duration_sec": round(time.monotonic() - started, 6),
        "outputs": {
            "impact_vrp_explanations_jsonl": str(out_dir / "impact_vrp_explanations.jsonl"),
            "impact_vrp_explanations_csv": str(out_dir / "impact_vrp_explanations.csv"),
            "route_level_vrp_summary_csv": str(out_dir / "route_level_vrp_summary.csv"),
            "top_candidate_vrps_csv": str(out_dir / "top_candidate_vrps.csv"),
            "acceptance_check_file": str(out_dir / ACCEPTANCE_FILE),
        },
        "checks": checks,
    }
    atomic_write_json(out_dir / "p11a_impact_vrp_explainer_summary.json", summary)
    write_acceptance(out_dir, status, summary, checks)
    return 0 if status == "PASS" else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Explain P10-A impact-bearing ROV transition events with window-bound VRP candidates.")
    parser.add_argument("--p10a-run-dir", required=True)
    parser.add_argument("--p8-input-vrp-manifest", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--max-events", type=int)
    parser.add_argument("--probe-ids", default="probe-cd,probe-sg,probe-k02")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
