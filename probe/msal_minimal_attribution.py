#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, TextIO
from urllib.parse import urlparse


SCHEMA_RECORD = "s3.probe.msal_attribution_record.v1"
SCHEMA_SUMMARY = "s3.probe.msal_attribution_summary.v1"
PROGRESS_EVERY = 100_000

EVIDENCE_LEVELS = [
    "A0_UNMAPPED",
    "A1_TAL_ONLY",
    "A2_SOURCE_PP_COVERED",
    "A2_7_L2_OBJECT_EXACT_HIT",
    "A3_MANIFEST_FILELIST_DECLARED",
    "A4_OBJECT_HASH_VERIFIED",
]
EVIDENCE_RANK = {level: i for i, level in enumerate(EVIDENCE_LEVELS)}

URI_FIELDS = [
    "source_uri",
    "sourceUri",
    "roa_uri",
    "roaUri",
    "object_uri",
    "objectUri",
    "uri",
    "file_uri",
    "canonical_uri",
    "fetch_target_uri",
    "matched_roa_uri",
]
PP_FIELDS = [
    "matched_source_pp",
    "source_pp",
    "repo_base",
    "repository_base",
    "pp_uri",
    "publication_point",
    "publication_point_uri",
    "notification_uri",
    "rrdp_notification_uri",
    "repo_uri",
]
HOST_FIELDS = ["repo_host", "source_host", "host", "pp_host"]
MANIFEST_FIELDS = ["matched_manifest_uri", "manifest_uri", "mft_uri"]
HASH_FIELDS = [
    "raw_record_sha256",
    "object_hash",
    "roa_hash",
    "file_hash",
    "hash",
    "sha256",
    "cms_der_sha256",
    "raw_sha256",
    "target_roa_hash_from_manifest",
]

OPTIONAL_INDEXES = [
    "source_pp_coverage",
    "l2_object_index",
    "manifest_filelist_index",
    "hash_evidence_index",
    "candidate_evidence_table",
]

DEFAULT_INDEX_PATHS = {
    "source_pp_coverage": "data/p3_analysis/sec27/coverage_candidate/source_pp_coverage.jsonl",
    "l2_object_index": "data/p3_analysis/sec27/l2b_effective_input_r2/l2b_candidate_effective_input.jsonl",
    "manifest_filelist_index": "data/p3_analysis/sec27/b5_paper_stats/object_or_manifest_supported_subset.jsonl",
    "candidate_evidence_table": "data/p3_analysis/sec27/b4c_candidate_evidence_table/candidate_evidence_table.jsonl",
    "hash_evidence_index": "data/p3_analysis/sec27/b6_final_paper_tables/selected_persistent_cases.jsonl",
}

FINAL_LEVEL_ALIASES = {
    "A2_L2_SOURCE_PP_COVERED": "A2_SOURCE_PP_COVERED",
    "A2_SOURCE_PP_COVERED": "A2_SOURCE_PP_COVERED",
    "A2_7_L2_OBJECT_EXACT_HIT": "A2_7_L2_OBJECT_EXACT_HIT",
    "A3_MANIFEST_FILELIST_DECLARED": "A3_MANIFEST_FILELIST_DECLARED",
    "A4_OBJECT_HASH_VERIFIED": "A4_OBJECT_HASH_VERIFIED",
}


@dataclass(slots=True)
class CompactMatch:
    index_name: str
    key_type: str
    index_key: str
    evidence_level: str
    evidence_reason: str
    matched_source_pp: str | None = None
    matched_roa_uri: str | None = None
    matched_manifest_uri: str | None = None
    hash_verified: bool = False


@dataclass(slots=True)
class CompactIndexes:
    by_uri: dict[str, list[CompactMatch]] = field(default_factory=dict)
    by_repo_base: dict[str, list[CompactMatch]] = field(default_factory=dict)
    by_host: dict[str, list[CompactMatch]] = field(default_factory=dict)
    by_tuple_key: dict[str, list[CompactMatch]] = field(default_factory=dict)
    by_hash: dict[str, list[CompactMatch]] = field(default_factory=dict)
    stats: dict[str, dict[str, Any]] = field(default_factory=dict)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def progress(stage: str, count: int) -> None:
    if count > 0 and count % PROGRESS_EVERY == 0:
        print(f"[{utc_now()}] {stage}: read {count} records", file=sys.stderr, flush=True)


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
    atomic_write_bytes(
        path,
        (json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def atomic_copy_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(f"{dst.name}.tmp.{os.getpid()}.{time.time_ns()}")
    try:
        with src.open("rb") as fin, tmp.open("wb") as fout:
            shutil.copyfileobj(fin, fout, length=1024 * 1024)
            fout.flush()
            os.fsync(fout.fileno())
        os.replace(tmp, dst)
        fsync_parent(dst)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


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


def clean_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "yes", "y", "covered", "present", "matched", "verified", "pass", "ok"}:
            return True
        if text in {"0", "false", "no", "n", "missing", "none", "null", "failed"}:
            return False
    return False


def normalize_hash(value: Any) -> str | None:
    text = clean_string(value)
    if not text:
        return None
    if text.startswith("sha256:"):
        return text.lower()
    if len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text):
        return "sha256:" + text.lower()
    return text


def repo_host_from_uri(uri: str | None) -> str | None:
    if not uri:
        return None
    parsed = urlparse(uri)
    if parsed.scheme and parsed.netloc:
        return parsed.netloc.lower()
    return None


def repo_base_from_uri(uri: str | None) -> str | None:
    if not uri:
        return None
    parsed = urlparse(uri)
    if parsed.scheme and parsed.netloc:
        path = parsed.path or "/"
        if not path.endswith("/"):
            path = path.rsplit("/", 1)[0] + "/"
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
    if "/" in uri:
        return uri.rsplit("/", 1)[0] + "/"
    return uri


def normalize_host(value: Any) -> str | None:
    text = clean_string(value)
    if not text:
        return None
    if "://" in text:
        return repo_host_from_uri(text)
    return text.lower()


def get_first(record: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def collect_uris_from_value(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        text = clean_string(value)
        if text:
            out.append(text)
    elif isinstance(value, list):
        for item in value:
            out.extend(collect_uris_from_value(item))
    elif isinstance(value, dict):
        for key in URI_FIELDS + PP_FIELDS + MANIFEST_FIELDS + ["source", "sources", "source_uris", "source_uri_set"]:
            if key in value:
                out.extend(collect_uris_from_value(value.get(key)))
    return out


def collect_record_uris(record: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key in URI_FIELDS:
        if key in record:
            out.extend(collect_uris_from_value(record.get(key)))
    for key in ["source", "sources", "source_uris", "source_uri_set"]:
        if key in record:
            out.extend(collect_uris_from_value(record.get(key)))
    return sorted({uri for uri in out if uri})


def collect_hashes(record: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key in HASH_FIELDS:
        value = record.get(key)
        if isinstance(value, list):
            for item in value:
                norm = normalize_hash(item)
                if norm:
                    out.append(norm)
        else:
            norm = normalize_hash(value)
            if norm:
                out.append(norm)
    for nested_key in ["prev_record", "curr_record", "raw_source"]:
        nested = record.get(nested_key)
        if isinstance(nested, dict):
            out.extend(collect_hashes(nested))
    return sorted(set(out))


def normalize_final_level(value: Any) -> str | None:
    text = clean_string(value)
    if not text:
        return None
    return FINAL_LEVEL_ALIASES.get(text, text if text in EVIDENCE_RANK else None)


def row_d2_evidence(row: dict[str, Any], index_name: str) -> tuple[str, str, bool]:
    final_level = normalize_final_level(row.get("final_evidence_level"))
    if final_level in EVIDENCE_RANK and final_level not in {"A0_UNMAPPED", "A1_TAL_ONLY"}:
        return final_level, f"final_evidence_level={row.get('final_evidence_level')}", final_level == "A4_OBJECT_HASH_VERIFIED"

    b4b_level = normalize_final_level(row.get("b4b_evidence_level"))
    if b4b_level in {"A3_MANIFEST_FILELIST_DECLARED", "A4_OBJECT_HASH_VERIFIED"}:
        return b4b_level, f"b4b_evidence_level={row.get('b4b_evidence_level')}", b4b_level == "A4_OBJECT_HASH_VERIFIED"

    b4b_status = clean_string(row.get("b4b_join_status"))
    if b4b_status in {"object_hash_verified"}:
        return "A4_OBJECT_HASH_VERIFIED", f"b4b_join_status={b4b_status}", True
    if b4b_status in {"manifest_filelist_declared", "manifest_filelist_only"}:
        return "A3_MANIFEST_FILELIST_DECLARED", f"b4b_join_status={b4b_status}", False

    if row_hash_verified(row):
        return "A4_OBJECT_HASH_VERIFIED", "hash_verified_field_or_m22d_verdict", True

    if manifest_declared(row):
        return "A3_MANIFEST_FILELIST_DECLARED", "manifest_filelist_declared", False

    if truthy(row.get("b4a_l2_object_hit")) or truthy(row.get("l2_object_hit")):
        return "A2_7_L2_OBJECT_EXACT_HIT", "b4a_l2_object_hit=true", False

    if index_name in {"source_pp_coverage", "l2_object_index"}:
        return "A2_SOURCE_PP_COVERED", f"index_hit={index_name}", False

    if normalize_final_level(row.get("evidence_level")) == "A2_SOURCE_PP_COVERED":
        return "A2_SOURCE_PP_COVERED", "evidence_level=A2_L2_SOURCE_PP_COVERED", False

    return "A1_TAL_ONLY", "index_row_no_promotion_rule", False


def compact_match_from_row(row: dict[str, Any], index_name: str, key_type: str, index_key: str) -> CompactMatch:
    matched_source_pp = clean_string(get_first(row, PP_FIELDS))
    if not matched_source_pp:
        matched_source_pp = clean_string(get_first(row, ["repo_base", "repository_base"]))
    matched_roa_uri = clean_string(get_first(row, ["matched_roa_uri", "roa_uri", "roaUri", "object_uri", "file_uri", "source_uri"]))
    matched_manifest_uri = clean_string(get_first(row, MANIFEST_FIELDS))
    evidence_level, evidence_reason, hash_verified = row_d2_evidence(row, index_name)
    if key_type in {"repo_host", "repo_base"} and EVIDENCE_RANK.get(evidence_level, 0) > EVIDENCE_RANK["A2_SOURCE_PP_COVERED"]:
        evidence_reason = f"{key_type}_context_only_from_{evidence_level}"
        evidence_level = "A2_SOURCE_PP_COVERED"
        hash_verified = False
        matched_roa_uri = None
        matched_manifest_uri = None
    if key_type == "repo_host":
        matched_source_pp = None
    return CompactMatch(
        index_name=index_name,
        key_type=key_type,
        index_key=index_key,
        evidence_level=evidence_level,
        evidence_reason=evidence_reason,
        matched_source_pp=matched_source_pp,
        matched_roa_uri=matched_roa_uri,
        matched_manifest_uri=matched_manifest_uri,
        hash_verified=hash_verified,
    )


def row_hash_verified(row: dict[str, Any]) -> bool:
    if clean_string(row.get("object_hash_status")) == "hash_verified":
        return True
    if clean_string(row.get("b4b_join_status")) == "object_hash_verified":
        return True
    verdict = clean_string(row.get("m22d_verdict"))
    if verdict and "roa_uri_manifest_object_hash_chain_verified" in verdict:
        return True
    for key in [
        "hash_verified",
        "object_hash_verified",
        "roa_hash_verified",
        "file_hash_verified",
        "verified",
        "hash_match",
        "file_hash_match",
        "filelist_hash_match",
        "manifest_hash_verified",
    ]:
        if key in row and truthy(row.get(key)):
            return True
    for key, value in row.items():
        lowered = key.lower()
        if ("hash" in lowered or "verify" in lowered) and truthy(value):
            return True
        if isinstance(value, str) and ("verified" in value.lower() or "hash_verified" in value.lower()):
            return True
    return False


def tuple_key_from_fields(row: dict[str, Any]) -> str | None:
    tal = clean_string(get_first(row, ["tal", "ta", "trust_anchor", "trustAnchor"]))
    asn = clean_string(get_first(row, ["asn", "asID", "as_id", "origin_asn", "originAS", "origin", "origin_as"]))
    prefix = clean_string(get_first(row, ["prefix", "ipPrefix", "ip_prefix", "vrp_prefix"]))
    max_length = clean_string(get_first(row, ["max_length", "maxLength", "maxlength", "maxLen", "max_len"]))
    if tal and asn and prefix and max_length:
        if asn.upper().startswith("AS"):
            asn = asn[2:]
        return f"{tal.lower()}|{asn}|{prefix}|{max_length}"
    return None


def normalize_tuple_key(value: Any) -> str | None:
    text = clean_string(value)
    if not text:
        return None
    parts = text.split("|")
    if len(parts) == 4:
        tal, asn, prefix, max_length = parts
    elif len(parts) == 5:
        _, tal, prefix, asn, max_length = parts
    else:
        return text
    if asn.upper().startswith("AS"):
        asn = asn[2:]
    return f"{tal.lower()}|{asn}|{prefix}|{max_length}"


def collect_tuple_keys(row: dict[str, Any]) -> list[str]:
    keys: list[str] = []
    for field in ["derived_tuple_key", "vrp_key", "candidate_vrp_key", "diff_vrp_key", "key"]:
        norm = normalize_tuple_key(row.get(field))
        if norm:
            keys.append(norm)
    field_key = tuple_key_from_fields(row)
    if field_key:
        keys.append(field_key)
    return sorted(set(keys))


def ensure_index_stats(indexes: CompactIndexes, index_name: str) -> dict[str, Any]:
    return indexes.stats.setdefault(
        index_name,
        {
            "records_loaded": 0,
            "loaded_key_type_distribution": Counter(),
            "hit_key_type_distribution": Counter(),
        },
    )


def add_match(
    indexes: CompactIndexes,
    target: dict[str, list[CompactMatch]],
    key_type: str,
    key: str | None,
    row: dict[str, Any],
    index_name: str,
) -> None:
    if not key:
        return
    match = compact_match_from_row(row, index_name, key_type, key)
    bucket = target.setdefault(key, [])
    identity = (match.index_name, match.key_type, match.index_key, match.evidence_level, match.evidence_reason)
    if any((m.index_name, m.key_type, m.index_key, m.evidence_level, m.evidence_reason) == identity for m in bucket):
        return
    bucket.append(match)
    ensure_index_stats(indexes, index_name)["loaded_key_type_distribution"][key_type] += 1


def iter_records(path: Path, label: str) -> Iterable[dict[str, Any]]:
    suffix = path.suffix.lower()
    count = 0
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                count += 1
                progress(f"index:{label}", count)
                yield dict(row)
        return

    if suffix == ".json":
        obj = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
        rows = obj if isinstance(obj, list) else obj.get("records") if isinstance(obj, dict) else []
        if isinstance(rows, list):
            for row in rows:
                count += 1
                progress(f"index:{label}", count)
                if isinstance(row, dict):
                    yield row
        return

    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"WARN index parse failed {path}:{line_no}: {exc}", file=sys.stderr, flush=True)
                continue
            if isinstance(obj, dict):
                count += 1
                progress(f"index:{label}", count)
                yield obj


def load_optional_indexes(args: argparse.Namespace) -> tuple[CompactIndexes, list[str], dict[str, int]]:
    indexes = CompactIndexes()
    missing: list[str] = []
    loaded_counts: dict[str, int] = {}

    paths = {
        "source_pp_coverage": args.source_pp_coverage,
        "l2_object_index": args.l2_object_index,
        "manifest_filelist_index": args.manifest_filelist_index,
        "hash_evidence_index": args.hash_evidence_index,
        "candidate_evidence_table": args.candidate_evidence_table,
    }

    for label in OPTIONAL_INDEXES:
        raw_path = paths.get(label)
        if not raw_path:
            default_path = Path(DEFAULT_INDEX_PATHS[label])
            if default_path.exists():
                raw_path = str(default_path)
        if not raw_path:
            missing.append(label)
            loaded_counts[label] = 0
            ensure_index_stats(indexes, label)
            continue
        path = Path(raw_path)
        if not path.exists():
            missing.append(label)
            loaded_counts[label] = 0
            ensure_index_stats(indexes, label)
            continue
        count = load_index_path(indexes, path, label)
        loaded_counts[label] = count
        print(f"[{utc_now()}] loaded {label}: records={count} path={path}", file=sys.stderr, flush=True)

    return indexes, missing, loaded_counts


def load_index_path(indexes: CompactIndexes, path: Path, label: str) -> int:
    count = 0
    for row in iter_records(path, label):
        count += 1
        uris = collect_record_uris(row)
        hashes = collect_hashes(row)
        repo_base = clean_string(get_first(row, ["repo_base", "repository_base"]))
        repo_host = normalize_host(get_first(row, HOST_FIELDS)) or repo_host_from_uri(repo_base)

        ensure_index_stats(indexes, label)["records_loaded"] += 1

        for uri in uris:
            add_match(indexes, indexes.by_uri, "source_uri", uri, row, label)
            add_match(indexes, indexes.by_repo_base, "repo_base", repo_base_from_uri(uri), row, label)
            add_match(indexes, indexes.by_host, "repo_host", repo_host_from_uri(uri), row, label)
        add_match(indexes, indexes.by_repo_base, "repo_base", repo_base, row, label)
        add_match(indexes, indexes.by_host, "repo_host", repo_host, row, label)

        for tuple_key in collect_tuple_keys(row):
            add_match(indexes, indexes.by_tuple_key, "derived_tuple_key", tuple_key, row, label)

        for h in hashes:
            add_match(indexes, indexes.by_hash, "hash", h, row, label)

    return count


def manifest_declared(row: dict[str, Any]) -> bool:
    if normalize_final_level(row.get("final_evidence_level")) == "A3_MANIFEST_FILELIST_DECLARED":
        return True
    if normalize_final_level(row.get("b4b_evidence_level")) == "A3_MANIFEST_FILELIST_DECLARED":
        return True
    if clean_string(row.get("b4b_join_status")) in {"manifest_filelist_declared", "manifest_filelist_only"}:
        return True
    if clean_string(get_first(row, MANIFEST_FIELDS)):
        return True
    if truthy(row.get("filelist_contains_roa")):
        return True
    if truthy(row.get("manifest_filelist_declared")):
        return True
    if int_like(row.get("manifest_filelist_match_count")) > 0:
        return True
    status = clean_string(row.get("mapping_status") or row.get("mapping_strength") or row.get("filelist_status"))
    if status and any(token in status.lower() for token in ["manifest", "filelist", "declared", "matched"]):
        return True
    return False


def int_like(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def read_event_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", errors="strict") as f:
        for line_no, line in enumerate(f, 1):
            progress("events", line_no)
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid event JSONL at {path}:{line_no}: {exc}") from exc
            if not isinstance(obj, dict):
                raise ValueError(f"event record is not an object at {path}:{line_no}")
            yield obj


def event_field(event: dict[str, Any], keys: list[str]) -> Any:
    direct = get_first(event, keys)
    if direct not in (None, ""):
        return direct
    for nested_key in ["curr_record", "prev_record", "vrp"]:
        nested = event.get(nested_key)
        if isinstance(nested, dict):
            value = get_first(nested, keys)
            if value not in (None, ""):
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


def parse_max_length(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def event_context(event: dict[str, Any], default_probe_id: str) -> dict[str, Any]:
    source_uri = clean_string(event_field(event, ["source_uri", "sourceUri", "roa_uri", "roaUri", "object_uri", "uri"]))
    uris = set(collect_record_uris(event))
    for nested_key in ["curr_record", "prev_record", "vrp"]:
        nested = event.get(nested_key)
        if isinstance(nested, dict):
            uris.update(collect_record_uris(nested))
    if source_uri:
        uris.add(source_uri)
    if not source_uri and uris:
        source_uri = sorted(uris)[0]

    raw_hashes = set(collect_hashes(event))
    for nested_key in ["curr_record", "prev_record", "vrp"]:
        nested = event.get(nested_key)
        if isinstance(nested, dict):
            raw_hashes.update(collect_hashes(nested))

    vrp_key = clean_string(event_field(event, ["vrp_key", "key"]))
    tuple_keys = set()
    normalized_event_key = normalize_tuple_key(vrp_key)
    if normalized_event_key:
        tuple_keys.add(normalized_event_key)
    field_tuple_key = tuple_key_from_fields({
        "tal": event_field(event, ["tal", "ta", "trust_anchor", "trustAnchor"]),
        "asn": event_field(event, ["asn", "asID", "as_id", "origin_asn", "originAS", "origin", "origin_as"]),
        "prefix": event_field(event, ["prefix", "ipPrefix", "ip_prefix", "vrp_prefix"]),
        "max_length": event_field(event, ["max_length", "maxLength", "maxlength", "maxLen", "max_len"]),
    })
    if field_tuple_key:
        tuple_keys.add(field_tuple_key)

    event_repo_host = normalize_host(event_field(event, ["repo_host", "source_host", "host"]))
    event_repo_base = clean_string(event_field(event, ["repo_base", "repository_base"]))

    return {
        "event_id": clean_string(event.get("event_id")) or stable_id("event", event),
        "event_type": clean_string(event.get("event_type")) or "UNKNOWN",
        "probe_id": clean_string(event.get("probe_id")) or default_probe_id,
        "diff_id": clean_string(event.get("diff_id") or event.get("window_id")),
        "window_id": clean_string(event.get("window_id")),
        "vrp_key": vrp_key,
        "tal": clean_string(event_field(event, ["tal", "ta", "trust_anchor", "trustAnchor"])),
        "asn": parse_asn(event_field(event, ["asn", "asID", "as_id", "origin_asn", "originAS", "origin", "origin_as"])),
        "prefix": clean_string(event_field(event, ["prefix", "ipPrefix", "ip_prefix", "vrp_prefix"])),
        "max_length": parse_max_length(event_field(event, ["max_length", "maxLength", "maxlength", "maxLen", "max_len"])),
        "source_uri": source_uri,
        "repo_host": event_repo_host or repo_host_from_uri(source_uri),
        "repo_base": event_repo_base or repo_base_from_uri(source_uri),
        "event_uris": sorted(uris),
        "event_hashes": sorted(raw_hashes),
        "event_tuple_keys": sorted(tuple_keys),
    }


def lookup_matches(target: dict[str, list[CompactMatch]], key: str | None) -> list[CompactMatch]:
    if not key:
        return []
    return list(target.get(key, []))


def collect_index_matches(ctx: dict[str, Any], indexes: CompactIndexes) -> list[CompactMatch]:
    matches: list[CompactMatch] = []

    for tuple_key in ctx.get("event_tuple_keys", []):
        matches.extend(lookup_matches(indexes.by_tuple_key, tuple_key))

    for uri in ctx["event_uris"]:
        matches.extend(lookup_matches(indexes.by_uri, uri))
        matches.extend(lookup_matches(indexes.by_repo_base, repo_base_from_uri(uri)))
        matches.extend(lookup_matches(indexes.by_host, repo_host_from_uri(uri)))

    matches.extend(lookup_matches(indexes.by_repo_base, ctx.get("repo_base")))
    matches.extend(lookup_matches(indexes.by_host, ctx.get("repo_host")))

    for h in ctx["event_hashes"]:
        matches.extend(lookup_matches(indexes.by_hash, h))

    deduped: list[CompactMatch] = []
    seen = set()
    for match in matches:
        ident = (
            match.index_name,
            match.key_type,
            match.index_key,
            match.evidence_level,
            match.evidence_reason,
        )
        if ident in seen:
            continue
        seen.add(ident)
        deduped.append(match)
    return deduped


def match_sort_key(match: CompactMatch) -> tuple[int, int, int, str, str]:
    return (
        EVIDENCE_RANK.get(match.evidence_level, 0),
        1 if match.hash_verified else 0,
        1 if match.matched_manifest_uri else 0,
        match.index_name,
        match.key_type,
    )


def promote(current: str, candidate: str) -> str:
    return candidate if EVIDENCE_RANK[candidate] > EVIDENCE_RANK[current] else current


def build_attribution_record(
    event: dict[str, Any],
    ctx: dict[str, Any],
    indexes: CompactIndexes,
    missing_input_indexes: list[str],
) -> dict[str, Any]:
    warnings: list[str] = []
    evidence_level = "A1_TAL_ONLY" if ctx.get("tal") else "A0_UNMAPPED"

    matched_source_pp = None
    matched_roa_uri = None
    matched_manifest_uri = None
    hash_verified = False

    matches = collect_index_matches(ctx, indexes)
    evidence_chain: list[dict[str, Any]] = []
    for match in sorted(matches, key=match_sort_key, reverse=True):
        evidence_level = promote(evidence_level, match.evidence_level)
        matched_source_pp = matched_source_pp or match.matched_source_pp
        matched_roa_uri = matched_roa_uri or match.matched_roa_uri
        matched_manifest_uri = matched_manifest_uri or match.matched_manifest_uri
        hash_verified = hash_verified or match.hash_verified or match.evidence_level == "A4_OBJECT_HASH_VERIFIED"
        evidence_chain.append(
            {
                "index_name": match.index_name,
                "key_type": match.key_type,
                "index_key": match.index_key,
                "evidence_level": match.evidence_level,
                "evidence_reason": match.evidence_reason,
                "matched_source_pp": match.matched_source_pp,
                "matched_roa_uri": match.matched_roa_uri,
                "matched_manifest_uri": match.matched_manifest_uri,
                "hash_verified": match.hash_verified,
            }
        )

    best_match = max(matches, key=match_sort_key) if matches else None
    evidence_reason = (
        best_match.evidence_reason
        if best_match
        else ("tal_present_no_index_hit" if ctx.get("tal") else "no_tal_no_source_uri_no_index_hit")
    )

    if evidence_level == "A0_UNMAPPED" and ctx.get("source_uri"):
        warnings.append("source_uri_present_but_no_optional_index_hit")

    matched_index_names = sorted({m.index_name for m in matches})
    matched_index_keys = [
        {"index_name": m.index_name, "key_type": m.key_type, "index_key": m.index_key}
        for m in sorted(matches, key=lambda x: (x.index_name, x.key_type, x.index_key, x.evidence_level))
    ]

    return {
        "schema": SCHEMA_RECORD,
        "attribution_id": stable_id(
            "attr",
            {
                "event_id": ctx["event_id"],
                "diff_id": ctx.get("diff_id"),
                "vrp_key": ctx.get("vrp_key"),
                "evidence_level": evidence_level,
            },
        ),
        "vrp_diff_event_id": ctx["event_id"],
        "event_type": ctx["event_type"],
        "probe_id": ctx["probe_id"],
        "diff_id": ctx.get("diff_id"),
        "window_id": ctx.get("window_id"),
        "vrp_key": ctx.get("vrp_key"),
        "tal": ctx.get("tal"),
        "asn": ctx.get("asn"),
        "prefix": ctx.get("prefix"),
        "max_length": ctx.get("max_length"),
        "source_uri": ctx.get("source_uri"),
        "repo_host": ctx.get("repo_host"),
        "evidence_level": evidence_level,
        "matched_source_pp": matched_source_pp,
        "matched_roa_uri": matched_roa_uri,
        "matched_manifest_uri": matched_manifest_uri,
        "hash_verified": hash_verified,
        "causal_claim_allowed": False,
        "root_cause_confirmed": False,
        "matched_index_names": matched_index_names,
        "matched_index_keys": matched_index_keys,
        "evidence_reason": evidence_reason,
        "evidence_chain": evidence_chain,
        "index_match_count": len(matches),
        "missing_inputs": missing_input_indexes,
        "warnings": warnings,
    }


def write_jsonl_record(out: TextIO, record: dict[str, Any]) -> None:
    out.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def record_index_hits(indexes: CompactIndexes, record: dict[str, Any]) -> None:
    for item in record.get("evidence_chain") or []:
        if not isinstance(item, dict):
            continue
        index_name = clean_string(item.get("index_name"))
        key_type = clean_string(item.get("key_type"))
        if not index_name or not key_type:
            continue
        ensure_index_stats(indexes, index_name)["hit_key_type_distribution"][key_type] += 1


def index_stats_summary(indexes: CompactIndexes, loaded_counts: dict[str, int]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for index_name in OPTIONAL_INDEXES:
        raw = ensure_index_stats(indexes, index_name)
        loaded = dict(sorted(raw["loaded_key_type_distribution"].items()))
        hits = dict(sorted(raw["hit_key_type_distribution"].items()))
        out[index_name] = {
            "records_loaded": loaded_counts.get(index_name, raw.get("records_loaded", 0)),
            "key_count": sum(loaded.values()),
            "loaded_key_type_distribution": loaded,
            "hit_key_type_distribution": hits,
            "hit_count": sum(hits.values()),
        }
    return out


def run_attribution(args: argparse.Namespace) -> dict[str, Any]:
    started_at_utc = utc_now()
    started_monotonic = time.monotonic()

    diff_events_path = Path(args.diff_events).resolve()
    if not diff_events_path.exists():
        raise FileNotFoundError(diff_events_path)

    out_dir = Path(args.out_dir).resolve()
    records_path = out_dir / "attribution_records.jsonl"
    latest_records_path = out_dir / "latest_attribution_records.jsonl"
    summary_path = out_dir / "summary.json"
    latest_summary_path = out_dir / "latest_msal_summary.json"

    indexes, missing_input_indexes, loaded_index_counts = load_optional_indexes(args)

    counters = Counter()
    by_event_type = Counter()
    by_tal = Counter()
    by_repo_host = Counter()
    causal_claim_allowed_count = 0

    tmp_records_path, out_f = open_tmp_jsonl(records_path)
    try:
        with out_f:
            for event in read_event_jsonl(diff_events_path):
                counters["input_event_count"] += 1
                ctx = event_context(event, args.probe_id)
                record = build_attribution_record(event, ctx, indexes, missing_input_indexes)
                write_jsonl_record(out_f, record)

                counters["output_record_count"] += 1
                counters[f"evidence:{record['evidence_level']}"] += 1
                if record["evidence_level"] != "A0_UNMAPPED":
                    counters["attributed_count"] += 1
                by_event_type[record["event_type"]] += 1
                by_tal[str(record.get("tal") or "unknown")] += 1
                if record.get("repo_host"):
                    by_repo_host[str(record["repo_host"])] += 1
                if record.get("causal_claim_allowed"):
                    causal_claim_allowed_count += 1
                record_index_hits(indexes, record)

            if counters["input_event_count"] == 0 and not args.allow_empty_events:
                raise RuntimeError("diff-events is empty; pass --allow-empty-events for no-update snapshot windows")

            out_f.flush()
            os.fsync(out_f.fileno())
        publish_existing_atomically(tmp_records_path, records_path)
    except Exception:
        try:
            out_f.close()
        except Exception:
            pass
        try:
            tmp_records_path.unlink()
        except FileNotFoundError:
            pass
        raise

    atomic_copy_file(records_path, latest_records_path)

    finished_at_utc = utc_now()
    evidence_distribution = {
        level: counters.get(f"evidence:{level}", 0)
        for level in EVIDENCE_LEVELS
        if counters.get(f"evidence:{level}", 0)
    }
    summary = {
        "schema": SCHEMA_SUMMARY,
        "status": "PASS",
        "diff_events": str(diff_events_path),
        "probe_id": args.probe_id,
        "input_event_count": counters["input_event_count"],
        "attributed_count": counters["attributed_count"],
        "output_record_count": counters["output_record_count"],
        "evidence_level_distribution": evidence_distribution,
        "by_event_type": dict(sorted(by_event_type.items())),
        "by_tal": dict(sorted(by_tal.items())),
        "by_repo_host_top20": [
            {"repo_host": host, "record_count": count}
            for host, count in by_repo_host.most_common(20)
        ],
        "causal_claim_allowed_count": causal_claim_allowed_count,
        "started_at_utc": started_at_utc,
        "finished_at_utc": finished_at_utc,
        "duration_sec": round(time.monotonic() - started_monotonic, 6),
        "missing_input_indexes": missing_input_indexes,
        "loaded_index_counts": loaded_index_counts,
        "outputs": {
            "attribution_records": str(records_path),
            "summary": str(summary_path),
            "latest_attribution_records": str(latest_records_path),
            "latest_msal_summary": str(latest_summary_path),
        },
        "semantic_boundary": "minimal_evidence_level_attribution_only_no_root_cause_confirmed",
        "root_cause_confirmed": False,
        "control_plane_impact_evaluated": False,
        "l2_time_series_evaluated": False,
    }
    stats = index_stats_summary(indexes, loaded_index_counts)
    summary["index_stats"] = stats
    atomic_write_json(summary_path, summary)
    atomic_write_json(latest_summary_path, summary)
    if getattr(args, "dump_index_stats", False):
        index_stats_path = out_dir / "index_stats.json"
        atomic_write_json(index_stats_path, stats)
        print(json.dumps({"index_stats": stats}, ensure_ascii=False, indent=2, sort_keys=True), file=sys.stderr)
    return summary


def write_self_test_inputs(root: Path) -> dict[str, Path]:
    root.mkdir(parents=True, exist_ok=True)
    events = root / "events.jsonl"
    coverage = root / "source_pp_coverage.csv"
    l2 = root / "l2_object_index.jsonl"
    manifest = root / "manifest_filelist_index.csv"
    hash_index = root / "hash_evidence_index.jsonl"
    candidate = root / "candidate_evidence_table.jsonl"

    event_rows = [
        {
            "event_id": "evt_a0",
            "event_type": "VRP_ADDED",
            "probe_id": "probe-cd",
            "diff_id": "diff_self",
            "vrp_key": "unknown|65000|203.0.113.0/24|24",
            "asn": 65000,
            "prefix": "203.0.113.0/24",
            "max_length": 24,
        },
        {
            "event_id": "evt_a1",
            "event_type": "VRP_REMOVED",
            "probe_id": "probe-cd",
            "diff_id": "diff_self",
            "vrp_key": "apnic|65001|203.0.114.0/24|24",
            "tal": "apnic",
            "asn": 65001,
            "prefix": "203.0.114.0/24",
            "max_length": 24,
        },
        {
            "event_id": "evt_a2",
            "event_type": "VRP_ADDED",
            "probe_id": "probe-cd",
            "diff_id": "diff_self",
            "vrp_key": "arin|65002|203.0.115.0/24|24",
            "tal": "arin",
            "asn": 65002,
            "prefix": "203.0.115.0/24",
            "max_length": 24,
        },
        {
            "event_id": "evt_a27",
            "event_type": "VRP_CHANGED",
            "probe_id": "probe-cd",
            "diff_id": "diff_self",
            "vrp_key": "ripe|65003|203.0.116.0/24|24",
            "tal": "ripe",
            "asn": 65003,
            "prefix": "203.0.116.0/24",
            "max_length": 24,
        },
        {
            "event_id": "evt_a3",
            "event_type": "VRP_CHANGED",
            "probe_id": "probe-cd",
            "diff_id": "diff_self",
            "vrp_key": "lacnic|65004|203.0.117.0/24|24",
            "tal": "lacnic",
            "asn": 65004,
            "prefix": "203.0.117.0/24",
            "max_length": 24,
            "source_uri": "rsync://repo.example/lacnic/a3.roa",
        },
        {
            "event_id": "evt_a4",
            "event_type": "VRP_ADDED",
            "probe_id": "probe-cd",
            "diff_id": "diff_self",
            "vrp_key": "afrinic|65005|203.0.118.0/24|24",
            "tal": "afrinic",
            "asn": 65005,
            "prefix": "203.0.118.0/24",
            "max_length": 24,
            "source_uri": "rsync://repo.example/afrinic/a4.roa",
            "curr_record": {"raw_record_sha256": "sha256:" + "a" * 64},
        },
    ]
    with events.open("w", encoding="utf-8", newline="\n") as f:
        for row in event_rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    with coverage.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["repo_host", "repo_base", "covered_by_l2", "matched_source_pp"])
        writer.writeheader()
        writer.writerow({
            "repo_host": "repo.example",
            "repo_base": "rsync://repo.example/arin/",
            "covered_by_l2": "true",
            "matched_source_pp": "rsync://repo.example/arin/",
        })

    with l2.open("w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps({
            "derived_tuple_key": "arin|65002|203.0.115.0/24|24",
            "final_evidence_level": "A2_L2_SOURCE_PP_COVERED",
            "repo_base": "rsync://repo.example/arin/",
            "repo_host": "repo.example",
            "source_uri": "rsync://repo.example/arin/a2.roa",
        }, sort_keys=True) + "\n")

    with manifest.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["derived_tuple_key", "file_uri", "manifest_uri", "final_evidence_level", "b4b_join_status"])
        writer.writeheader()
        writer.writerow({
            "derived_tuple_key": "lacnic|65004|203.0.117.0/24|24",
            "file_uri": "rsync://repo.example/lacnic/a3.roa",
            "manifest_uri": "rsync://repo.example/lacnic/manifest.mft",
            "final_evidence_level": "A3_MANIFEST_FILELIST_DECLARED",
            "b4b_join_status": "manifest_filelist_declared",
        })

    with candidate.open("w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps({
            "derived_tuple_key": "ripe|65003|203.0.116.0/24|24",
            "source_uri": "rsync://repo.example/ripe/a27.roa",
            "final_evidence_level": "A2_7_L2_OBJECT_EXACT_HIT",
            "b4a_l2_object_hit": True,
            "repo_base": "rsync://repo.example/ripe/",
            "repo_host": "repo.example",
        }, sort_keys=True) + "\n")

    with hash_index.open("w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps({
            "derived_tuple_key": "afrinic|65005|203.0.118.0/24|24",
            "object_uri": "rsync://repo.example/afrinic/a4.roa",
            "object_hash": "sha256:" + "a" * 64,
            "object_hash_status": "hash_verified",
            "m22d_verdict": "roa_uri_manifest_object_hash_chain_verified",
            "manifest_uri": "rsync://repo.example/afrinic/manifest.mft",
        }, sort_keys=True) + "\n")

    return {
        "events": events,
        "coverage": coverage,
        "l2": l2,
        "manifest": manifest,
        "hash": hash_index,
        "candidate": candidate,
    }


def run_self_test(args: argparse.Namespace) -> int:
    base = Path(args.out_dir).resolve() if args.out_dir else Path(tempfile.mkdtemp(prefix="msal_self_test_"))
    inputs = write_self_test_inputs(base / "_self_test_inputs")
    run_args = argparse.Namespace(
        diff_events=str(inputs["events"]),
        probe_id=args.probe_id or "probe-cd",
        out_dir=str(base),
        source_pp_coverage=str(inputs["coverage"]),
        l2_object_index=str(inputs["l2"]),
        manifest_filelist_index=str(inputs["manifest"]),
        hash_evidence_index=str(inputs["hash"]),
        candidate_evidence_table=str(inputs["candidate"]),
        allow_empty_events=False,
        dump_index_stats=True,
    )
    summary = run_attribution(run_args)
    expected = {
        "A0_UNMAPPED": 1,
        "A1_TAL_ONLY": 1,
        "A2_SOURCE_PP_COVERED": 1,
        "A2_7_L2_OBJECT_EXACT_HIT": 1,
        "A3_MANIFEST_FILELIST_DECLARED": 1,
        "A4_OBJECT_HASH_VERIFIED": 1,
    }
    got = summary.get("evidence_level_distribution", {})
    for level, count in expected.items():
        if got.get(level) != count:
            raise RuntimeError(f"self_test evidence promotion failed: {level} expected {count}, got {got.get(level)}")
    if summary.get("causal_claim_allowed_count") != 0:
        raise RuntimeError("self_test causal_claim_allowed_count must be 0")
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    print(f"self_test_out_dir = {base}")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="MSAL minimal evidence-level attribution for live VRP diff events.")
    parser.add_argument("--diff-events", help="B-stage events.jsonl or latest_events.jsonl.")
    parser.add_argument("--probe-id", default="probe-cd")
    parser.add_argument("--out-dir", help="Output directory.")
    parser.add_argument("--source-pp-coverage")
    parser.add_argument("--l2-object-index")
    parser.add_argument("--manifest-filelist-index")
    parser.add_argument("--hash-evidence-index")
    parser.add_argument("--candidate-evidence-table")
    parser.add_argument("--allow-empty-events", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--dump-index-stats", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.self_test:
        return run_self_test(args)

    if not args.diff_events:
        raise SystemExit("--diff-events is required unless --self-test is used")
    if not args.out_dir:
        raise SystemExit("--out-dir is required unless --self-test is used")

    summary = run_attribution(args)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
