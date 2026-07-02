#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, TextIO
from urllib.parse import urlparse


SCHEMA_MAPPING = "s3.probe.rov.candidate_vrp_object_mapping.v1"
SCHEMA_SUMMARY = "s3.probe.rov.candidate_vrp_object_mapping_summary.v1"
ACCEPTANCE_FILE = "checks/P11B_VRP_OBJECT_MAPPING_ACCEPTANCE.txt"

DEFAULT_INDEX_CANDIDATES = [
    "data/p3_analysis/sec27/b4c_candidate_evidence_table/candidate_evidence_table.jsonl",
    "data/p3_analysis/sec27/b5_paper_stats/object_or_manifest_supported_subset.jsonl",
    "data/p3_analysis/sec27/b6_final_paper_tables/selected_persistent_cases.jsonl",
    "data/p3_analysis/sec27/l2b_effective_input_r2/l2b_candidate_effective_input.jsonl",
]

MAPPING_FIELDS = [
    "window_id",
    "route_prefix",
    "origin_asn",
    "candidate_vrp_key",
    "candidate_vrp_asn",
    "candidate_vrp_prefix",
    "candidate_vrp_max_length",
    "candidate_vrp_tal",
    "candidate_vrp_present_in_probes",
    "candidate_vrp_missing_in_probes",
    "roa_uri",
    "roa_hash",
    "manifest_uri",
    "manifest_hash",
    "manifest_number",
    "manifest_this_update",
    "manifest_next_update",
    "publication_point",
    "ca_repository_uri",
    "tal",
    "object_mapping_strength",
    "object_mapping_reason",
    "root_cause_confirmed",
    "causal_claim_allowed",
]

TOP_PP_FIELDS = [
    "publication_point",
    "candidate_vrp_count",
    "route_count",
    "mapping_record_count",
    "object_mapping_strengths",
    "tals",
    "candidate_vrp_keys",
]

TOP_CA_FIELDS = [
    "ca_repository_uri",
    "candidate_vrp_count",
    "route_count",
    "mapping_record_count",
    "object_mapping_strengths",
    "tals",
    "candidate_vrp_keys",
]

TOP_TAL_FIELDS = [
    "tal",
    "candidate_vrp_count",
    "route_count",
    "mapping_record_count",
    "object_mapping_strengths",
    "publication_points",
]

UNRESOLVED_FIELDS = [
    "candidate_vrp_key",
    "candidate_vrp_asn",
    "candidate_vrp_prefix",
    "candidate_vrp_max_length",
    "candidate_vrp_tal",
    "route_count",
    "present_in_probes",
    "missing_in_probes",
    "object_mapping_reason",
]

ROA_URI_FIELDS = [
    "roa_uri",
    "matched_roa_uri",
    "object_uri",
    "file_uri",
    "source_uri",
    "sourceUri",
    "uri",
]
ROA_HASH_FIELDS = [
    "roa_hash",
    "object_hash",
    "manifest_file_hash",
    "roa_hash_from_manifest",
    "target_roa_hash_from_manifest",
    "file_hash",
    "hash",
]
MANIFEST_URI_FIELDS = [
    "manifest_uri",
    "matched_manifest_uri",
    "mft_uri",
    "manifest",
]
MANIFEST_HASH_FIELDS = [
    "manifest_hash",
    "manifest_raw_sha256",
    "best_manifest_raw_sha256",
    "manifest_cms_der_sha256",
    "best_manifest_cms_der_sha256",
]
PP_FIELDS = [
    "publication_point",
    "publication_point_dir",
    "pp_uri",
    "repo_base",
    "repository_base",
    "matched_source_pp",
]
CA_FIELDS = [
    "ca_repository_uri",
    "ca_repo_uri",
    "repository_base",
    "repo_base",
    "publication_point",
    "publication_point_dir",
    "pp_uri",
]
TAL_FIELDS = ["tal", "candidate_vrp_tal", "trust_anchor", "ta"]


@dataclass(slots=True)
class IndexMatch:
    index_name: str
    key_type: str
    key_value: str
    row: dict[str, Any]
    strength: str
    reason: str


@dataclass(slots=True)
class ObjectIndexes:
    by_key: dict[str, list[IndexMatch]] = field(default_factory=lambda: defaultdict(list))
    by_uri: dict[str, list[IndexMatch]] = field(default_factory=lambda: defaultdict(list))
    loaded_paths: list[str] = field(default_factory=list)
    loaded_record_count: int = 0
    parse_error_count: int = 0


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


def resolve_path(value: str | None, root: Path) -> Path | None:
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else (root / path).resolve()


def load_json_object(path: Path) -> tuple[dict[str, Any], str | None]:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            return {}, "expected JSON object"
        return obj, None
    except Exception as exc:
        return {}, str(exc)


def clean(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return text


def stable_id(prefix: str, obj: Any, length: int = 24) -> str:
    payload = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{prefix}_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]


def first_present(row: dict[str, Any], fields: list[str]) -> str:
    for field_name in fields:
        value = row.get(field_name)
        if value not in (None, ""):
            return clean(value)
    return ""


def parse_asn_text(value: Any) -> str:
    text = clean(value).upper()
    if text.startswith("AS"):
        text = text[2:]
    return text if re.fullmatch(r"\d+", text or "") else ""


def normalize_key_text(value: Any) -> str:
    text = clean(value)
    if not text:
        return ""
    return re.sub(r"\s+", "", text.lower().replace("AS", "as"))


def tuple_key_variants(tal: Any, asn: Any, prefix: Any, max_length: Any, raw_key: Any = "") -> set[str]:
    variants: set[str] = set()
    raw = normalize_key_text(raw_key)
    if raw:
        variants.add(raw)
    tal_text = clean(tal).lower()
    asn_text = parse_asn_text(asn)
    prefix_text = clean(prefix)
    max_text = clean(max_length)
    if not (tal_text and asn_text and prefix_text and max_text):
        return variants
    variants.update(
        normalize_key_text(item)
        for item in [
            f"{asn_text},{prefix_text},{max_text},{tal_text}",
            f"{tal_text},{asn_text},{prefix_text},{max_text}",
            f"{tal_text}|{asn_text}|{prefix_text}|{max_text}",
            f"{tal_text}|AS{asn_text}|{prefix_text}|{max_text}",
            f"{tal_text}|as{asn_text}|{prefix_text}|{max_text}",
            f"tal={tal_text}|asn={asn_text}|prefix={prefix_text}|max_length={max_text}",
            f"tal={tal_text}|asn=AS{asn_text}|prefix={prefix_text}|maxLength={max_text}",
        ]
    )
    return {item for item in variants if item}


def candidate_keys_from_p11a(row: dict[str, Any]) -> set[str]:
    return tuple_key_variants(
        row.get("candidate_vrp_tal"),
        row.get("candidate_vrp_asn"),
        row.get("candidate_vrp_prefix"),
        row.get("candidate_vrp_max_length"),
        row.get("candidate_vrp_key"),
    )


def keys_from_index_row(row: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for field_name in ["candidate_vrp_key", "vrp_key", "derived_tuple_key", "diff_vrp_key", "key"]:
        value = normalize_key_text(row.get(field_name))
        if value:
            keys.add(value)
    tal = first_present(row, ["candidate_vrp_tal", "tal", "trust_anchor", "ta"])
    asn = first_present(row, ["candidate_vrp_asn", "asn", "asID", "as_id", "origin_asn", "originAS"])
    prefix = first_present(row, ["candidate_vrp_prefix", "prefix", "ipPrefix", "vrp_prefix"])
    max_len = first_present(row, ["candidate_vrp_max_length", "max_length", "maxLength", "max_len", "maxlength"])
    keys.update(tuple_key_variants(tal, asn, prefix, max_len))
    return keys


def uri_values(row: dict[str, Any]) -> set[str]:
    fields = set(ROA_URI_FIELDS + MANIFEST_URI_FIELDS + PP_FIELDS + CA_FIELDS)
    out: set[str] = set()
    for field_name in fields:
        value = row.get(field_name)
        if isinstance(value, str) and value.strip():
            out.add(value.strip())
    for field_name in ["roa_candidates", "parsed_candidates", "evidence_chain"]:
        value = row.get(field_name)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    out.update(uri_values(item))
    return out


def repo_base_from_uri(uri: str) -> str:
    text = clean(uri)
    if not text or "/" not in text:
        return ""
    return text.rsplit("/", 1)[0] + "/"


def host_from_uri(uri: str) -> str:
    parsed = urlparse(uri)
    return parsed.netloc.lower() if parsed.netloc else ""


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def read_csv_rows(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            yield dict(row)


def iter_records(path: Path) -> Iterable[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        yield from read_jsonl(path)
    elif suffix == ".csv":
        yield from read_csv_rows(path)
    elif suffix == ".json":
        obj, error = load_json_object(path)
        if error is not None:
            return
        for key in ["records", "rows", "items", "artifacts", "probe_inputs", "vrp_inputs"]:
            value = obj.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        yield item
                return
            if isinstance(value, dict):
                for item in value.values():
                    if isinstance(item, dict):
                        yield item
                return
        yield obj


def discover_index_paths(root: Path, mapping_index: str | None, evidence_root: str | None) -> list[Path]:
    candidates: list[Path] = []
    explicit = resolve_path(mapping_index, root)
    if explicit is not None:
        if explicit.is_dir():
            candidates.extend(sorted(path for path in explicit.rglob("*") if path.suffix.lower() in {".jsonl", ".csv", ".json"}))
        elif explicit.is_file():
            candidates.append(explicit)
    evidence = resolve_path(evidence_root, root)
    if evidence is not None and evidence.is_dir():
        candidates.extend(sorted(path for path in evidence.rglob("*") if path.suffix.lower() in {".jsonl", ".csv", ".json"}))
    for rel in DEFAULT_INDEX_CANDIDATES:
        path = root / rel
        if path.is_file():
            candidates.append(path)
    seen: set[str] = set()
    out: list[Path] = []
    for path in candidates:
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        out.append(path.resolve())
    return out


def strength_for_row(row: dict[str, Any]) -> tuple[str, str]:
    final_level = clean(row.get("final_evidence_level") or row.get("evidence_level"))
    if final_level == "A4_OBJECT_HASH_VERIFIED":
        return "strong", f"final_evidence_level={final_level}"
    if clean(row.get("object_hash_status")) == "hash_verified":
        return "strong", "object_hash_status=hash_verified"
    if clean(row.get("b4b_join_status")) == "object_hash_verified":
        return "strong", "b4b_join_status=object_hash_verified"
    verdict = clean(row.get("m22d_verdict"))
    if "roa_uri_manifest_object_hash_chain_verified" in verdict:
        return "strong", "m22d_verdict=roa_uri_manifest_object_hash_chain_verified"
    if final_level in {"A3_MANIFEST_FILELIST_DECLARED", "A2_7_L2_OBJECT_EXACT_HIT"}:
        return "medium", f"final_evidence_level={final_level}"
    if clean(row.get("mapping_strength")):
        raw = clean(row.get("mapping_strength"))
        if "strong" in raw:
            return "strong", f"mapping_strength={raw}"
        if "medium" in raw or "manifest" in raw:
            return "medium", f"mapping_strength={raw}"
    if any(first_present(row, fields) for fields in [ROA_URI_FIELDS, MANIFEST_URI_FIELDS, PP_FIELDS]):
        return "medium", "object_context_fields_present"
    return "weak", "tuple_or_uri_index_hit"


def add_index_match(indexes: ObjectIndexes, path: Path, row: dict[str, Any]) -> None:
    strength, reason = strength_for_row(row)
    source_name = path.name
    for key in keys_from_index_row(row):
        indexes.by_key[key].append(IndexMatch(source_name, "vrp_key", key, row, strength, reason))
    for uri in uri_values(row):
        indexes.by_uri[uri].append(IndexMatch(source_name, "uri", uri, row, strength, reason))


def load_object_indexes(paths: list[Path]) -> ObjectIndexes:
    indexes = ObjectIndexes()
    for path in paths:
        loaded_for_path = 0
        try:
            for row in iter_records(path):
                if not isinstance(row, dict):
                    continue
                add_index_match(indexes, path, row)
                indexes.loaded_record_count += 1
                loaded_for_path += 1
        except Exception:
            indexes.parse_error_count += 1
            continue
        if loaded_for_path > 0:
            indexes.loaded_paths.append(str(path))
    return indexes


def read_p11a_explanations(path: Path, max_candidates: int | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for row in read_jsonl(path):
        key = clean(row.get("candidate_vrp_key"))
        if not key:
            continue
        marker = (
            clean(row.get("window_id")),
            clean(row.get("route_prefix")),
            clean(row.get("origin_asn")),
            clean(row.get("probe_a")) + ":" + clean(row.get("probe_b")),
            key,
        )
        if marker in seen:
            continue
        seen.add(marker)
        rows.append(row)
        if max_candidates is not None and len(rows) >= max_candidates:
            break
    return rows


def read_top_candidates(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in read_csv_rows(path):
        key = clean(row.get("candidate_vrp_key"))
        if key:
            out[key] = row
    return out


def candidate_uri_values(row: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for field_name in ["candidate_vrp_source_uri", "candidate_vrp_roa_uri", "candidate_vrp_manifest_uri", "roa_uri", "manifest_uri"]:
        value = clean(row.get(field_name))
        if value:
            out.add(value)
    return out


def collect_matches(row: dict[str, Any], indexes: ObjectIndexes) -> list[IndexMatch]:
    matches: list[IndexMatch] = []
    for key in candidate_keys_from_p11a(row):
        matches.extend(indexes.by_key.get(key, []))
    for uri in candidate_uri_values(row):
        matches.extend(indexes.by_uri.get(uri, []))
        base = repo_base_from_uri(uri)
        if base:
            matches.extend(indexes.by_uri.get(base, []))
    seen: set[tuple[str, str, str, int]] = set()
    out: list[IndexMatch] = []
    for match in matches:
        marker = (match.index_name, match.key_type, match.key_value, id(match.row))
        if marker in seen:
            continue
        seen.add(marker)
        out.append(match)
    return out


def match_rank(match: IndexMatch) -> tuple[int, int, str]:
    strength_rank = {"strong": 3, "medium": 2, "weak": 1}.get(match.strength, 0)
    context_rank = 0
    if first_present(match.row, ROA_URI_FIELDS):
        context_rank += 1
    if first_present(match.row, MANIFEST_URI_FIELDS):
        context_rank += 1
    if first_present(match.row, PP_FIELDS):
        context_rank += 1
    return strength_rank, context_rank, match.index_name


def best_match(matches: list[IndexMatch]) -> IndexMatch | None:
    if not matches:
        return None
    return sorted(matches, key=match_rank, reverse=True)[0]


def context_from_match(match: IndexMatch | None, row: dict[str, Any], indexes_loaded: bool) -> dict[str, Any]:
    if match is None:
        reason = "NO_MAPPING_INDEX" if not indexes_loaded else "NO_OBJECT_MAPPING_MATCH"
        return {
            "roa_uri": "",
            "roa_hash": "",
            "manifest_uri": "",
            "manifest_hash": "",
            "manifest_number": "",
            "manifest_this_update": "",
            "manifest_next_update": "",
            "publication_point": repo_base_from_uri(clean(row.get("candidate_vrp_source_uri"))),
            "ca_repository_uri": "",
            "tal": clean(row.get("candidate_vrp_tal")),
            "object_mapping_strength": "weak",
            "object_mapping_reason": reason,
            "matched_index_name": "",
            "matched_index_key_type": "",
            "matched_index_key": "",
        }
    source = match.row
    roa_uri = first_present(source, ROA_URI_FIELDS)
    manifest_uri = first_present(source, MANIFEST_URI_FIELDS)
    publication_point = first_present(source, PP_FIELDS)
    if not publication_point:
        publication_point = repo_base_from_uri(roa_uri or clean(row.get("candidate_vrp_source_uri")))
    ca_repository_uri = first_present(source, CA_FIELDS)
    return {
        "roa_uri": roa_uri,
        "roa_hash": first_present(source, ROA_HASH_FIELDS),
        "manifest_uri": manifest_uri,
        "manifest_hash": first_present(source, MANIFEST_HASH_FIELDS),
        "manifest_number": first_present(source, ["manifest_number", "best_manifest_number"]),
        "manifest_this_update": first_present(source, ["manifest_this_update", "this_update"]),
        "manifest_next_update": first_present(source, ["manifest_next_update", "next_update"]),
        "publication_point": publication_point,
        "ca_repository_uri": ca_repository_uri,
        "tal": first_present(source, TAL_FIELDS) or clean(row.get("candidate_vrp_tal")),
        "object_mapping_strength": match.strength,
        "object_mapping_reason": match.reason,
        "matched_index_name": match.index_name,
        "matched_index_key_type": match.key_type,
        "matched_index_key": match.key_value,
    }


def mapping_record(row: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    record = {
        "schema": SCHEMA_MAPPING,
        "mapping_id": stable_id("p11b_mapping", {
            "window_id": row.get("window_id"),
            "route_prefix": row.get("route_prefix"),
            "origin_asn": row.get("origin_asn"),
            "candidate_vrp_key": row.get("candidate_vrp_key"),
            "roa_uri": ctx.get("roa_uri"),
            "manifest_uri": ctx.get("manifest_uri"),
            "reason": ctx.get("object_mapping_reason"),
        }),
        "window_id": row.get("window_id", ""),
        "route_prefix": row.get("route_prefix", ""),
        "origin_asn": row.get("origin_asn", ""),
        "candidate_vrp_key": row.get("candidate_vrp_key", ""),
        "candidate_vrp_asn": row.get("candidate_vrp_asn", ""),
        "candidate_vrp_prefix": row.get("candidate_vrp_prefix", ""),
        "candidate_vrp_max_length": row.get("candidate_vrp_max_length", ""),
        "candidate_vrp_tal": row.get("candidate_vrp_tal", ""),
        "candidate_vrp_present_in_probes": row.get("candidate_vrp_present_in_probes", ""),
        "candidate_vrp_missing_in_probes": row.get("candidate_vrp_missing_in_probes", ""),
        "mapping_strength_from_p11a": row.get("mapping_strength", ""),
        "recomputed_state_by_probe": row.get("recomputed_state_by_probe", ""),
        "root_cause_confirmed": False,
        "causal_claim_allowed": False,
    }
    record.update(ctx)
    return record


def open_tmp_text(path: Path) -> tuple[Path, TextIO]:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
    return tmp, tmp.open("w", encoding="utf-8", newline="\n")


def publish_tmp(tmp: Path, path: Path) -> None:
    os.replace(tmp, path)
    fsync_parent(path)


def csv_value(row: dict[str, Any], field_name: str) -> Any:
    value = row.get(field_name, "")
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return value


def write_csv_atomic(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    tmp, f = open_tmp_text(path)
    try:
        with f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({field: csv_value(row, field) for field in fields})
            f.flush()
            os.fsync(f.fileno())
        publish_tmp(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def pipe_set(value: str) -> set[str]:
    return {item for item in clean(value).split("|") if item}


def add_top(store: dict[str, dict[str, Any]], group_key: str, record: dict[str, Any]) -> None:
    if not group_key:
        return
    item = store.setdefault(group_key, {
        "candidate_vrps": set(),
        "routes": set(),
        "records": 0,
        "strengths": Counter(),
        "tals": set(),
        "pps": set(),
    })
    item["candidate_vrps"].add(clean(record.get("candidate_vrp_key")))
    item["routes"].add(f"{record.get('route_prefix')}|{record.get('origin_asn')}")
    item["records"] += 1
    item["strengths"][clean(record.get("object_mapping_strength")) or "weak"] += 1
    if record.get("tal"):
        item["tals"].add(clean(record["tal"]))
    if record.get("publication_point"):
        item["pps"].add(clean(record["publication_point"]))


def build_top_rows(store: dict[str, dict[str, Any]], key_name: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for group_key, item in sorted(store.items(), key=lambda pair: (-int(pair[1]["records"]), pair[0])):
        rows.append({
            key_name: group_key,
            "candidate_vrp_count": len(item["candidate_vrps"]),
            "route_count": len(item["routes"]),
            "mapping_record_count": item["records"],
            "object_mapping_strengths": "|".join(f"{k}:{v}" for k, v in sorted(item["strengths"].items())),
            "tals": "|".join(sorted(item["tals"])),
            "candidate_vrp_keys": "|".join(sorted(item["candidate_vrps"])),
            "publication_points": "|".join(sorted(item["pps"])),
        })
    return rows


def write_acceptance(out_dir: Path, status: str, summary: dict[str, Any], checks: dict[str, bool]) -> None:
    lines = [
        f"P11B_VRP_OBJECT_MAPPING={status}",
        f"p11a_run_dir={summary.get('p11a_run_dir', '')}",
        f"p8_input_vrp_manifest={summary.get('p8_input_vrp_manifest', '')}",
        f"candidate_vrp_count={summary.get('candidate_vrp_count', 0)}",
        f"mapped_candidate_vrp_count={summary.get('mapped_candidate_vrp_count', 0)}",
        f"unresolved_candidate_vrp_count={summary.get('unresolved_candidate_vrp_count', 0)}",
        f"mapping_index_count={summary.get('mapping_index_count', 0)}",
        f"mapping_index_record_count={summary.get('mapping_index_record_count', 0)}",
        "",
        "[checks]",
    ]
    lines.extend(f"{key}={str(value).lower()}" for key, value in checks.items())
    atomic_write_text(out_dir / ACCEPTANCE_FILE, "\n".join(lines) + "\n")


def run(args: argparse.Namespace) -> int:
    root = repo_root()
    started_at = utc_now()
    started = time.monotonic()
    p11a_run_dir = resolve_path(args.p11a_run_dir, root)
    manifest_path = resolve_path(args.p8_input_vrp_manifest, root)
    out_dir = resolve_path(args.out_dir, root)
    if p11a_run_dir is None or manifest_path is None or out_dir is None:
        raise SystemExit("required paths are missing")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "checks").mkdir(parents=True, exist_ok=True)

    p11a_path = p11a_run_dir / "impact_vrp_explanations.jsonl"
    top_path = p11a_run_dir / "top_candidate_vrps.csv"
    p11a_loaded = p11a_path.is_file()
    if not p11a_loaded:
        candidate_rows: list[dict[str, Any]] = []
    else:
        candidate_rows = read_p11a_explanations(p11a_path, args.max_candidates)
    top_candidates = read_top_candidates(top_path)

    index_paths = discover_index_paths(root, args.mapping_index, args.object_evidence_root)
    indexes = load_object_indexes(index_paths) if index_paths else ObjectIndexes()
    indexes_loaded = indexes.loaded_record_count > 0

    jsonl_tmp, jsonl_f = open_tmp_text(out_dir / "candidate_vrp_object_mapping.jsonl")
    csv_tmp, csv_f = open_tmp_text(out_dir / "candidate_vrp_object_mapping.csv")
    pp_top: dict[str, dict[str, Any]] = {}
    ca_top: dict[str, dict[str, Any]] = {}
    tal_top: dict[str, dict[str, Any]] = {}
    unresolved: dict[str, dict[str, Any]] = {}
    candidate_keys: set[str] = set()
    mapped_candidate_keys: set[str] = set()
    strength_dist: Counter[str] = Counter()

    try:
        with jsonl_f, csv_f:
            writer = csv.DictWriter(csv_f, fieldnames=MAPPING_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for row in candidate_rows:
                key = clean(row.get("candidate_vrp_key"))
                if not key:
                    continue
                candidate_keys.add(key)
                matches = collect_matches(row, indexes)
                match = best_match(matches)
                ctx = context_from_match(match, row, indexes_loaded)
                record = mapping_record(row, ctx)
                jsonl_f.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                writer.writerow({field: csv_value(record, field) for field in MAPPING_FIELDS})
                strength = clean(record.get("object_mapping_strength")) or "weak"
                strength_dist[strength] += 1
                if match is not None:
                    mapped_candidate_keys.add(key)
                add_top(pp_top, clean(record.get("publication_point")), record)
                add_top(ca_top, clean(record.get("ca_repository_uri")), record)
                add_top(tal_top, clean(record.get("tal") or record.get("candidate_vrp_tal")), record)
                if match is None:
                    item = unresolved.setdefault(key, {
                        "candidate_vrp_key": key,
                        "candidate_vrp_asn": row.get("candidate_vrp_asn", ""),
                        "candidate_vrp_prefix": row.get("candidate_vrp_prefix", ""),
                        "candidate_vrp_max_length": row.get("candidate_vrp_max_length", ""),
                        "candidate_vrp_tal": row.get("candidate_vrp_tal", ""),
                        "routes": set(),
                        "present": set(),
                        "missing": set(),
                        "object_mapping_reason": record.get("object_mapping_reason", ""),
                    })
                    item["routes"].add(f"{row.get('route_prefix')}|{row.get('origin_asn')}")
                    item["present"].update(pipe_set(clean(row.get("candidate_vrp_present_in_probes"))))
                    item["missing"].update(pipe_set(clean(row.get("candidate_vrp_missing_in_probes"))))
            jsonl_f.flush()
            os.fsync(jsonl_f.fileno())
            csv_f.flush()
            os.fsync(csv_f.fileno())
        publish_tmp(jsonl_tmp, out_dir / "candidate_vrp_object_mapping.jsonl")
        publish_tmp(csv_tmp, out_dir / "candidate_vrp_object_mapping.csv")
    except Exception:
        for tmp in (jsonl_tmp, csv_tmp):
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
        raise

    write_csv_atomic(out_dir / "top_pp_by_candidate_vrp.csv", TOP_PP_FIELDS, build_top_rows(pp_top, "publication_point"))
    write_csv_atomic(out_dir / "top_ca_by_candidate_vrp.csv", TOP_CA_FIELDS, build_top_rows(ca_top, "ca_repository_uri"))
    write_csv_atomic(out_dir / "top_tal_by_candidate_vrp.csv", TOP_TAL_FIELDS, build_top_rows(tal_top, "tal"))
    unresolved_rows = [
        {
            "candidate_vrp_key": key,
            "candidate_vrp_asn": item["candidate_vrp_asn"],
            "candidate_vrp_prefix": item["candidate_vrp_prefix"],
            "candidate_vrp_max_length": item["candidate_vrp_max_length"],
            "candidate_vrp_tal": item["candidate_vrp_tal"],
            "route_count": len(item["routes"]),
            "present_in_probes": "|".join(sorted(item["present"])),
            "missing_in_probes": "|".join(sorted(item["missing"])),
            "object_mapping_reason": item["object_mapping_reason"],
        }
        for key, item in sorted(unresolved.items())
    ]
    write_csv_atomic(out_dir / "unresolved_candidate_vrps.csv", UNRESOLVED_FIELDS, unresolved_rows)

    output_files_written = all(
        (out_dir / name).is_file()
        for name in [
            "candidate_vrp_object_mapping.jsonl",
            "candidate_vrp_object_mapping.csv",
            "top_pp_by_candidate_vrp.csv",
            "top_ca_by_candidate_vrp.csv",
            "top_tal_by_candidate_vrp.csv",
            "unresolved_candidate_vrps.csv",
        ]
    )
    checks = {
        "p11a_loaded": p11a_loaded,
        "candidate_vrp_count_gt_zero": len(candidate_keys) > 0,
        "output_files_written": output_files_written,
        "no_strong_root_cause_claim": True,
    }
    if not p11a_loaded or not candidate_keys or not output_files_written:
        status = "FAIL"
    elif not indexes_loaded and unresolved_rows:
        status = "PASS_WITH_EXCLUSIONS"
    else:
        status = "PASS"

    summary = {
        "schema": SCHEMA_SUMMARY,
        "status": status,
        "p11a_run_dir": str(p11a_run_dir),
        "p8_input_vrp_manifest": str(manifest_path),
        "out_dir": str(out_dir),
        "p11a_loaded": p11a_loaded,
        "p11a_top_candidate_count": len(top_candidates),
        "candidate_vrp_count": len(candidate_keys),
        "mapped_candidate_vrp_count": len(mapped_candidate_keys),
        "unresolved_candidate_vrp_count": len(unresolved_rows),
        "mapping_index_count": len(indexes.loaded_paths),
        "mapping_index_paths": indexes.loaded_paths,
        "mapping_index_record_count": indexes.loaded_record_count,
        "mapping_index_parse_error_count": indexes.parse_error_count,
        "object_mapping_strength_distribution": dict(sorted(strength_dist.items())),
        "root_cause_confirmed": False,
        "causal_claim_allowed": False,
        "started_at_utc": started_at,
        "finished_at_utc": utc_now(),
        "duration_sec": round(time.monotonic() - started, 6),
        "outputs": {
            "candidate_vrp_object_mapping_jsonl": str(out_dir / "candidate_vrp_object_mapping.jsonl"),
            "candidate_vrp_object_mapping_csv": str(out_dir / "candidate_vrp_object_mapping.csv"),
            "top_pp_by_candidate_vrp_csv": str(out_dir / "top_pp_by_candidate_vrp.csv"),
            "top_ca_by_candidate_vrp_csv": str(out_dir / "top_ca_by_candidate_vrp.csv"),
            "top_tal_by_candidate_vrp_csv": str(out_dir / "top_tal_by_candidate_vrp.csv"),
            "unresolved_candidate_vrps_csv": str(out_dir / "unresolved_candidate_vrps.csv"),
            "acceptance_check_file": str(out_dir / ACCEPTANCE_FILE),
        },
        "checks": checks,
    }
    atomic_write_json(out_dir / "p11b_vrp_object_mapping_summary.json", summary)
    write_acceptance(out_dir, status, summary, checks)
    return 0 if status in {"PASS", "PASS_WITH_EXCLUSIONS"} else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Map P11-A candidate VRPs to ROA, manifest, publication point, CA, and TAL evidence context.")
    parser.add_argument("--p11a-run-dir", required=True)
    parser.add_argument("--p8-input-vrp-manifest", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--mapping-index", help="Optional JSONL/CSV/JSON file or directory containing VRP-to-object evidence.")
    parser.add_argument("--object-evidence-root", help="Optional directory to scan for object evidence indexes.")
    parser.add_argument("--max-candidates", type=int)
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
