#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.p3.m22.lib.rpki_signed_object_parser import (
    parse_manifest_filelist_from_storage_bytes,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def source_host_from_uri(uri: str) -> str | None:
    if not uri or "://" not in uri:
        return None
    rest = uri.split("://", 1)[1]
    return rest.split("/", 1)[0] if rest else None


def publication_point_dir_from_uri(uri: str) -> str | None:
    if not uri or "/" not in uri:
        return None
    return uri.rsplit("/", 1)[0] + "/"


def choose_manifest_candidates(record: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    # Current old M22B format: parsed_candidates already contains manifest_cache_path.
    for c in record.get("parsed_candidates", []) or []:
        if isinstance(c, dict) and c.get("manifest_cache_path"):
            candidates.append(c)

    # Defensive support for other possible M22-B1 names.
    for key in ("manifest_candidates", "candidates"):
        for c in record.get(key, []) or []:
            if isinstance(c, dict) and c.get("manifest_cache_path"):
                candidates.append(c)

    # Deduplicate by manifest_cache_path.
    seen = set()
    out = []
    for c in candidates:
        p = c.get("manifest_cache_path")
        if p in seen:
            continue
        seen.add(p)
        out.append(c)

    return out


def build_parsed_candidate(
    *,
    source_candidate: dict[str, Any],
    target_roa_file: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path_str = source_candidate.get("manifest_cache_path")
    manifest_raw_sha256_hint = source_candidate.get("manifest_raw_sha256")
    path = Path(path_str) if path_str else None

    base: dict[str, Any] = {
        "manifest_cache_path": path_str,
        "manifest_raw_sha256_hint": manifest_raw_sha256_hint,
        "target_roa_file": target_roa_file,
    }

    if not path_str or path is None:
        base.update(
            {
                "parse_status": "parse_failed",
                "parse_error_class": "manifest_path_missing",
                "parse_error": "manifest_cache_path is empty",
                "filelist_contains_roa": None,
                "target_roa_hash_from_manifest": None,
            }
        )
        return base, []

    if not path.exists():
        base.update(
            {
                "parse_status": "parse_failed",
                "parse_error_class": "manifest_path_missing",
                "parse_error": f"manifest path does not exist: {path}",
                "filelist_contains_roa": None,
                "target_roa_hash_from_manifest": None,
            }
        )
        return base, []

    raw = path.read_bytes()
    parsed = parse_manifest_filelist_from_storage_bytes(raw)

    filelist = parsed.get("filelist") or []
    filelist_entries: list[dict[str, Any]] = []

    filelist_contains_roa = False
    target_roa_hash = None

    for item in filelist:
        file_name = item.get("file_name")
        file_hash = item.get("file_hash")

        if target_roa_file and file_name == target_roa_file:
            filelist_contains_roa = True
            target_roa_hash = file_hash

        filelist_entries.append(
            {
                "file_name": file_name,
                "file_hash": file_hash,
                "file_hash_hex": item.get("file_hash_hex"),
                "file_hash_alg": item.get("file_hash_alg"),
                "file_hash_alg_oid": item.get("file_hash_alg_oid"),
            }
        )

    out = {
        **base,
        "storage_format": parsed.get("storage_format"),
        "raw_len": parsed.get("raw_len"),
        "raw_sha256": parsed.get("raw_sha256"),
        "cms_der_offset": parsed.get("cms_der_offset"),
        "cms_der_len": parsed.get("cms_der_len"),
        "cms_der_sha256": parsed.get("cms_der_sha256"),
        "unwrap_ok": parsed.get("unwrap_ok"),
        "parse_status": parsed.get("parse_status"),
        "parse_error_class": parsed.get("parse_error_class"),
        "parse_error": parsed.get("parse_error"),
        "econtent_type": parsed.get("econtent_type"),
        "manifest_number": parsed.get("manifest_number"),
        "this_update": parsed.get("this_update"),
        "next_update": parsed.get("next_update"),
        "file_hash_alg_oid": parsed.get("file_hash_alg_oid"),
        "file_hash_alg": parsed.get("file_hash_alg"),
        "filelist_count": parsed.get("filelist_count"),
        "filelist_contains_roa": (
            filelist_contains_roa if parsed.get("parse_status") == "parsed" else None
        ),
        "target_roa_hash_from_manifest": target_roa_hash,
    }

    return out, filelist_entries


def mapping_status_and_strength(
    parsed_candidates: list[dict[str, Any]],
) -> tuple[str, str]:
    if any(c.get("filelist_contains_roa") is True for c in parsed_candidates):
        return "matched", "strong_manifest_filelist_match"

    if any(c.get("parse_status") == "parsed" for c in parsed_candidates):
        return "manifest_parsed_but_roa_absent", "candidate_manifest_only"

    if parsed_candidates:
        return "manifest_parse_failed", "none"

    return "no_manifest_candidate", "none"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument(
        "--input-records",
        default=None,
        help="Default: <run-dir>/indexes/manifest_filelist_parse_records.jsonl",
    )
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    indexes = run_dir / "indexes"
    outputs = run_dir / "outputs"
    checks = run_dir / "checks"

    input_records_path = (
        Path(args.input_records)
        if args.input_records
        else indexes / "manifest_filelist_parse_records.jsonl"
    )

    parse_records_path = indexes / "manifest_filelist_parse_records.jsonl"
    filelist_entries_path = indexes / "manifest_filelist_entries.jsonl"
    reverse_index_path = indexes / "roa_uri_to_manifest_filelist_index.jsonl"
    summary_path = outputs / "M22B_manifest_filelist_parse_summary.json"
    check_path = checks / "M22B_manifest_filelist_parse_check.txt"

    input_records = read_jsonl(input_records_path)

    parse_records: list[dict[str, Any]] = []
    filelist_entries: list[dict[str, Any]] = []
    reverse_index: list[dict[str, Any]] = []

    by_parse_status = Counter()
    by_storage_format = Counter()
    by_parse_error_class = Counter()
    by_filelist_contains_roa = Counter()
    by_file_hash_alg = Counter()
    unique_manifest_paths = set()

    candidate_count = 0
    parsed_candidate_count = 0
    failed_candidate_count = 0
    roa_filelist_match_count = 0
    roa_filelist_absent_count = 0

    probe_id = None
    trigger_id = None

    for record in input_records:
        probe_id = probe_id or record.get("probe_id")
        trigger_id = trigger_id or record.get("trigger_id")

        source_uri = record.get("source_uri")
        target_roa_file = record.get("target_roa_file")
        request_id = record.get("request_id")
        source_host = record.get("source_host") or source_host_from_uri(source_uri or "")

        source_candidates = choose_manifest_candidates(record)
        candidate_count += len(source_candidates)

        parsed_candidates: list[dict[str, Any]] = []

        for source_candidate in source_candidates:
            path_str = source_candidate.get("manifest_cache_path")
            if path_str:
                unique_manifest_paths.add(path_str)

            parsed_candidate, entries = build_parsed_candidate(
                source_candidate=source_candidate,
                target_roa_file=target_roa_file,
            )

            parsed_candidates.append(parsed_candidate)

            by_parse_status[parsed_candidate.get("parse_status") or "NO_PARSE_STATUS"] += 1
            by_storage_format[parsed_candidate.get("storage_format") or "NO_STORAGE_FORMAT"] += 1
            by_parse_error_class[parsed_candidate.get("parse_error_class") or "NO_PARSE_ERROR"] += 1
            by_filelist_contains_roa[str(parsed_candidate.get("filelist_contains_roa"))] += 1

            if parsed_candidate.get("file_hash_alg"):
                by_file_hash_alg[parsed_candidate.get("file_hash_alg")] += 1

            if parsed_candidate.get("parse_status") == "parsed":
                parsed_candidate_count += 1
            else:
                failed_candidate_count += 1

            if parsed_candidate.get("filelist_contains_roa") is True:
                roa_filelist_match_count += 1
            elif parsed_candidate.get("parse_status") == "parsed":
                roa_filelist_absent_count += 1

            for e in entries:
                filelist_entries.append(
                    {
                        "schema": "s3.m22.probe.manifest_filelist_entry.v1",
                        "probe_id": record.get("probe_id"),
                        "trigger_id": record.get("trigger_id"),
                        "request_id": request_id,
                        "source_uri": source_uri,
                        "source_host": source_host,
                        "target_roa_file": target_roa_file,
                        "manifest_cache_path": parsed_candidate.get("manifest_cache_path"),
                        "manifest_raw_sha256": parsed_candidate.get("raw_sha256"),
                        "manifest_cms_der_sha256": parsed_candidate.get("cms_der_sha256"),
                        "manifest_number": parsed_candidate.get("manifest_number"),
                        "this_update": parsed_candidate.get("this_update"),
                        "next_update": parsed_candidate.get("next_update"),
                        "file_hash_alg": e.get("file_hash_alg"),
                        "file_hash_alg_oid": e.get("file_hash_alg_oid"),
                        "file_name": e.get("file_name"),
                        "file_hash": e.get("file_hash"),
                        "file_hash_hex": e.get("file_hash_hex"),
                    }
                )

        any_contains = any(c.get("filelist_contains_roa") is True for c in parsed_candidates)
        mapping_status, mapping_strength = mapping_status_and_strength(parsed_candidates)

        matched_candidates = [
            c for c in parsed_candidates if c.get("filelist_contains_roa") is True
        ]
        best = matched_candidates[0] if matched_candidates else (
            parsed_candidates[0] if parsed_candidates else {}
        )

        parse_records.append(
            {
                "schema": "s3.m22.probe.manifest_filelist_parse_record.v2",
                "probe_id": record.get("probe_id"),
                "trigger_id": record.get("trigger_id"),
                "request_id": request_id,
                "source_uri": source_uri,
                "source_host": source_host,
                "publication_point_dir": publication_point_dir_from_uri(source_uri or ""),
                "target_roa_file": target_roa_file,
                "candidate_count": len(source_candidates),
                "parsed_candidates": parsed_candidates,
                "any_manifest_contains_roa": any_contains,
                "mapping_status": mapping_status,
                "mapping_strength": mapping_strength,
            }
        )

        reverse_index.append(
            {
                "schema": "s3.m22.probe.roa_uri_to_manifest_filelist_index.v1",
                "probe_id": record.get("probe_id"),
                "trigger_id": record.get("trigger_id"),
                "request_id": request_id,
                "source_uri": source_uri,
                "source_host": source_host,
                "publication_point_dir": publication_point_dir_from_uri(source_uri or ""),
                "target_roa_file": target_roa_file,
                "candidate_manifest_count": len(source_candidates),
                "matched_manifest_count": len(matched_candidates),
                "best_manifest_cache_path": best.get("manifest_cache_path"),
                "best_manifest_raw_sha256": best.get("raw_sha256"),
                "best_manifest_cms_der_sha256": best.get("cms_der_sha256"),
                "best_manifest_number": best.get("manifest_number"),
                "manifest_this_update": best.get("this_update"),
                "manifest_next_update": best.get("next_update"),
                "roa_hash_from_manifest": best.get("target_roa_hash_from_manifest"),
                "mapping_status": mapping_status,
                "mapping_strength": mapping_strength,
                "evidence_source": [
                    "vrp_source_uri",
                    "manifest_candidate_same_publication_point",
                    "manifest_filelist",
                    "routinator_cache_wrapper_unwrapped",
                ],
            }
        )

    request_count = len(input_records)
    filelist_entry_count = len(filelist_entries)

    if request_count == 0:
        final_status = "NO_INPUT"
    elif parsed_candidate_count > 0 and failed_candidate_count == 0:
        final_status = "PASS"
    elif parsed_candidate_count > 0 and failed_candidate_count > 0:
        final_status = "PARTIAL"
    else:
        final_status = "FAIL"

    summary = {
        "schema": "s3.m22b.manifest_filelist_parse_summary.v2",
        "status": final_status,
        "created_at_utc": utc_now(),
        "probe_id": probe_id,
        "trigger_id": trigger_id,
        "run_dir": str(run_dir),
        "input_records_path": str(input_records_path),
        "manifest_request_record_count": request_count,
        "candidate_count": candidate_count,
        "unique_manifest_path_count": len(unique_manifest_paths),
        "parsed_candidate_count": parsed_candidate_count,
        "failed_candidate_count": failed_candidate_count,
        "manifest_filelist_entries_count": filelist_entry_count,
        "roa_uri_to_manifest_filelist_index_count": len(reverse_index),
        "roa_filelist_match_count": roa_filelist_match_count,
        "roa_filelist_absent_count": roa_filelist_absent_count,
        "by_parse_status": dict(by_parse_status),
        "by_storage_format": dict(by_storage_format),
        "by_parse_error_class": dict(by_parse_error_class),
        "by_filelist_contains_roa": dict(by_filelist_contains_roa),
        "by_file_hash_alg": dict(by_file_hash_alg),
        "important_boundary": [
            "M22B parses Routinator cache wrapper by extracting embedded CMS DER.",
            "This still uses validator cache bytes, not validator-independent RRDP snapshot bytes.",
            "For replay_not_strong runs, ROA absence from current manifest supports historical superseded/removed hypothesis, not live-window attribution.",
        ],
        "outputs": {
            "manifest_filelist_parse_records": str(parse_records_path),
            "manifest_filelist_entries": str(filelist_entries_path),
            "roa_uri_to_manifest_filelist_index": str(reverse_index_path),
            "summary": str(summary_path),
            "check": str(check_path),
        },
    }

    write_jsonl(parse_records_path, parse_records)
    write_jsonl(filelist_entries_path, filelist_entries)
    write_jsonl(reverse_index_path, reverse_index)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    check_lines = [
        f"M22B_MANIFEST_FILELIST_PARSE={final_status}",
        "",
        f"created_at_utc = {summary['created_at_utc']}",
        f"probe_id = {probe_id}",
        f"trigger_id = {trigger_id}",
        f"manifest_request_record_count = {request_count}",
        f"candidate_count = {candidate_count}",
        f"unique_manifest_path_count = {len(unique_manifest_paths)}",
        f"parsed_candidate_count = {parsed_candidate_count}",
        f"failed_candidate_count = {failed_candidate_count}",
        f"manifest_filelist_entries_count = {filelist_entry_count}",
        f"roa_uri_to_manifest_filelist_index_count = {len(reverse_index)}",
        f"roa_filelist_match_count = {roa_filelist_match_count}",
        f"roa_filelist_absent_count = {roa_filelist_absent_count}",
        f"by_parse_status = {dict(by_parse_status)}",
        f"by_storage_format = {dict(by_storage_format)}",
        f"by_parse_error_class = {dict(by_parse_error_class)}",
        f"by_filelist_contains_roa = {dict(by_filelist_contains_roa)}",
        f"by_file_hash_alg = {dict(by_file_hash_alg)}",
        f"input_records_path = {input_records_path}",
        f"parse_records_path = {parse_records_path}",
        f"manifest_filelist_entries_path = {filelist_entries_path}",
        f"roa_uri_to_manifest_filelist_index_path = {reverse_index_path}",
        f"summary_path = {summary_path}",
    ]
    write_text(check_path, "\n".join(check_lines) + "\n")

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
