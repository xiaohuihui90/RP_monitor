#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


EXPECTED_PROBES = {"probe-bj", "probe-cd", "probe-sg"}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue
            obj = json.loads(line)
            if isinstance(obj, dict):
                obj["_line_no"] = line_no
                yield obj


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    return n


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_archive_sha256(archive_path: Path) -> Dict[str, Any]:
    sha_path = archive_path.with_suffix(archive_path.suffix + ".sha256")
    if not sha_path.exists():
        return {
            "archive": str(archive_path),
            "sha256_path": str(sha_path),
            "status": "missing_sha256_file",
        }

    expected = sha_path.read_text(encoding="utf-8").split()[0]
    actual = sha256_file(archive_path)

    return {
        "archive": str(archive_path),
        "sha256_path": str(sha_path),
        "expected": expected,
        "actual": actual,
        "status": "OK" if expected == actual else "MISMATCH",
    }


def detect_probe_id_from_name(name: str) -> str | None:
    for probe_id in EXPECTED_PROBES:
        if probe_id in name:
            return probe_id
    return None


def safe_extract_tar(tar_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest_dir.resolve()

    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar.getmembers():
            member_name = member.name

            if member_name.startswith("/"):
                raise RuntimeError(f"unsafe_absolute_path:{member_name}")

            parts = Path(member_name).parts
            if ".." in parts:
                raise RuntimeError(f"unsafe_parent_path:{member_name}")

            if member.issym() or member.islnk():
                raise RuntimeError(f"unsafe_link_member:{member_name}")

            target = (dest_dir / member_name).resolve()
            if not str(target).startswith(str(dest_resolved)):
                raise RuntimeError(f"unsafe_extract_escape:{member_name}")

        tar.extractall(dest_dir)


def load_summary(import_dir: Path) -> Dict[str, Any]:
    summary_path = import_dir / "outputs" / "M20B_probe_raw_cas_export_summary.json"
    if summary_path.exists():
        return json.loads(summary_path.read_text(encoding="utf-8"))
    return {}


def normalize_collector_raw_record(
    row: Dict[str, Any],
    collector_run_id: str,
    source_archive: str,
    summary: Dict[str, Any],
) -> Dict[str, Any]:
    probe_id = row.get("probe_id") or summary.get("probe_id") or "unknown"
    probe_export_run_id = row.get("export_run_id") or Path(str(summary.get("run_dir", ""))).name

    warnings = list(row.get("warnings") or [])
    if not row.get("canonical_uri"):
        warnings.append("canonical_uri_missing_in_probe_index")

    return {
        "schema": "s3.m20c.collector_raw_object_index.v1",
        "created_at_utc": utc_now_iso(),
        "collector_run_id": collector_run_id,
        "source_archive": source_archive,

        "probe_id": probe_id,
        "probe_export_run_id": probe_export_run_id,

        "canonical_uri": row.get("canonical_uri"),
        "object_uri": row.get("object_uri") or row.get("canonical_uri"),
        "object_type": row.get("object_type") or "unknown",
        "object_family": row.get("object_family") or "unknown",

        "raw_sha256": row.get("raw_sha256"),
        "raw_size_bytes": row.get("raw_size_bytes"),

        "collector_raw_bytes_available": False,
        "collector_cas_path": None,
        "raw_fetch_mode": "raw_on_demand",

        "probe_cas_path": row.get("cas_path"),
        "probe_source_path": row.get("source_path"),
        "source_resolver_method": row.get("source_resolver_method"),

        "cas_integrity_status": "not_checked_index_only",
        "recover_status": row.get("recover_status"),

        "warnings": warnings,
        "notes": [
            "M20-C1 imports index-only metadata.",
            "Raw bytes are not copied to collector in this stage.",
            "Use raw-on-demand if semantic diff requires concrete object bytes.",
        ],
    }


def normalize_collector_missing_record(
    row: Dict[str, Any],
    collector_run_id: str,
    source_archive: str,
    summary: Dict[str, Any],
) -> Dict[str, Any]:
    probe_id = row.get("probe_id") or summary.get("probe_id") or "unknown"

    return {
        "schema": "s3.m20c.collector_missing_object_index.v1",
        "created_at_utc": utc_now_iso(),
        "collector_run_id": collector_run_id,
        "source_archive": source_archive,
        "probe_id": probe_id,
        "probe_export_run_id": row.get("export_run_id") or Path(str(summary.get("run_dir", ""))).name,
        "source_path": row.get("source_path"),
        "filename": row.get("filename"),
        "object_type_guess": row.get("object_type_guess"),
        "missing_reason": row.get("missing_reason"),
        "notes": row.get("notes") or [],
    }


def compact_raw_records(rows: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    seen = {}
    duplicate_count = 0

    for row in rows:
        key = (
            row.get("probe_id"),
            row.get("canonical_uri"),
            row.get("raw_sha256"),
        )

        if key in seen:
            duplicate_count += 1
            continue

        seen[key] = row

    compacted = list(seen.values())

    same_probe_uri_hashes = defaultdict(set)
    for row in compacted:
        key = (row.get("probe_id"), row.get("canonical_uri"))
        if row.get("raw_sha256"):
            same_probe_uri_hashes[key].add(row.get("raw_sha256"))

    same_probe_same_uri_multi_hash_count = sum(
        1 for hashes in same_probe_uri_hashes.values()
        if len(hashes) > 1
    )

    stats = {
        "duplicate_exact_probe_uri_hash_count": duplicate_count,
        "same_probe_same_uri_multi_hash_count": same_probe_same_uri_multi_hash_count,
    }

    return compacted, stats


def main() -> int:
    parser = argparse.ArgumentParser(description="M20-C1 collector index-only archive merge")
    parser.add_argument("--index-archive-dir", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--collector-run-id", required=True)
    args = parser.parse_args()

    archive_dir = Path(args.index_archive_dir).expanduser().resolve()
    run_dir = Path(args.run_dir).expanduser().resolve()
    collector_run_id = args.collector_run_id

    imports_dir = run_dir / "imports"
    indexes_dir = run_dir / "indexes"
    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"

    for d in [imports_dir, indexes_dir, outputs_dir, checks_dir]:
        d.mkdir(parents=True, exist_ok=True)

    archives = sorted(archive_dir.glob("*_index_only.tar.gz"))

    sha_checks = []
    imported_probes = set()
    raw_rows = []
    missing_rows = []
    import_errors = []

    for archive in archives:
        sha_status = verify_archive_sha256(archive)
        sha_checks.append(sha_status)

        if sha_status.get("status") != "OK":
            import_errors.append({
                "source_archive": str(archive),
                "error": "sha256_verify_failed",
                "detail": sha_status,
            })
            continue

        probe_hint = detect_probe_id_from_name(archive.name) or "unknown"
        extract_dir = imports_dir / probe_hint

        try:
            safe_extract_tar(archive, extract_dir)
        except Exception as exc:
            import_errors.append({
                "source_archive": str(archive),
                "error": "safe_extract_failed",
                "detail": str(exc),
            })
            continue

        summary = load_summary(extract_dir)
        probe_id = summary.get("probe_id") or probe_hint
        imported_probes.add(probe_id)

        raw_index = extract_dir / "indexes" / "probe_raw_object_index.jsonl"
        missing_index = extract_dir / "indexes" / "probe_missing_object_index.jsonl"

        if not raw_index.exists():
            import_errors.append({
                "source_archive": str(archive),
                "probe_id": probe_id,
                "error": "missing_probe_raw_object_index",
                "path": str(raw_index),
            })
            continue

        for row in read_jsonl(raw_index):
            raw_rows.append(
                normalize_collector_raw_record(
                    row=row,
                    collector_run_id=collector_run_id,
                    source_archive=archive.name,
                    summary=summary,
                )
            )

        if missing_index.exists():
            for row in read_jsonl(missing_index):
                missing_rows.append(
                    normalize_collector_missing_record(
                        row=row,
                        collector_run_id=collector_run_id,
                        source_archive=archive.name,
                        summary=summary,
                    )
                )

    compacted_rows, compact_stats = compact_raw_records(raw_rows)

    raw_index_out = indexes_dir / "collector_raw_object_index.jsonl"
    compacted_index_out = indexes_dir / "collector_raw_object_index_compacted.jsonl"
    missing_index_out = indexes_dir / "collector_missing_object_index.jsonl"
    error_index_out = indexes_dir / "collector_import_error_index.jsonl"

    write_jsonl(raw_index_out, raw_rows)
    write_jsonl(compacted_index_out, compacted_rows)
    write_jsonl(missing_index_out, missing_rows)
    write_jsonl(error_index_out, import_errors)

    by_probe = Counter(row.get("probe_id") for row in compacted_rows)
    by_object_type = Counter(row.get("object_type") for row in compacted_rows)
    by_resolver = Counter(row.get("source_resolver_method") for row in compacted_rows)
    by_missing_reason = Counter(row.get("missing_reason") for row in missing_rows)

    unresolved_uri_count = sum(1 for row in compacted_rows if not row.get("canonical_uri"))
    missing_raw_hash_count = sum(1 for row in compacted_rows if not row.get("raw_sha256"))

    imported_probe_count = len(imported_probes)
    archive_count = len(archives)

    missing_expected_probes = sorted(EXPECTED_PROBES - imported_probes)

    status = "PASS"
    blockers = []

    if archive_count < 3:
        status = "FAIL"
        blockers.append("archive_count_below_3")

    if missing_expected_probes:
        status = "FAIL"
        blockers.append("missing_expected_probes")

    if import_errors:
        status = "FAIL"
        blockers.append("import_errors_observed")

    if not compacted_rows:
        status = "FAIL"
        blockers.append("empty_compacted_index")

    summary = {
        "schema": "s3.m20c.collector_index_only_merge_summary.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "collector_run_id": collector_run_id,
        "run_dir": str(run_dir),
        "index_archive_dir": str(archive_dir),
        "archive_count": archive_count,
        "imported_probe_count": imported_probe_count,
        "imported_probes": sorted(imported_probes),
        "missing_expected_probes": missing_expected_probes,
        "sha256_checks": sha_checks,

        "collector_raw_object_index_count": len(raw_rows),
        "collector_raw_object_index_compacted_count": len(compacted_rows),
        "collector_missing_object_index_count": len(missing_rows),
        "collector_import_error_count": len(import_errors),

        "unresolved_uri_count": unresolved_uri_count,
        "missing_raw_hash_count": missing_raw_hash_count,

        "raw_bytes_merged": False,
        "merge_mode": "index_only_raw_on_demand",

        "by_probe": dict(by_probe),
        "by_object_type": dict(by_object_type),
        "by_source_resolver_method": dict(by_resolver),
        "by_missing_reason": dict(by_missing_reason),

        **compact_stats,

        "collector_raw_object_index": str(raw_index_out),
        "collector_raw_object_index_compacted": str(compacted_index_out),
        "collector_missing_object_index": str(missing_index_out),
        "collector_import_error_index": str(error_index_out),

        "blockers": blockers,
        "important_boundary": [
            "M20-C1 merges metadata indexes only.",
            "Raw bytes are not copied into collector in this stage.",
            "M20-D can identify raw hash divergence from metadata.",
            "M20-F/M21 semantic parsing will require raw-on-demand transfer for selected objects."
        ],
    }

    summary_path = outputs_dir / "M20C1_collector_index_only_merge_summary.json"
    check_path = checks_dir / "M20C1_collector_index_only_merge.txt"

    write_json(summary_path, summary)

    text = "\n".join([
        f"M20C1_COLLECTOR_INDEX_ONLY_MERGE={status}",
        "",
        f"collector_run_id = {collector_run_id}",
        f"run_dir = {run_dir}",
        f"archive_count = {archive_count}",
        f"imported_probe_count = {imported_probe_count}",
        f"imported_probes = {sorted(imported_probes)}",
        f"missing_expected_probes = {missing_expected_probes}",
        f"collector_raw_object_index_count = {len(raw_rows)}",
        f"collector_raw_object_index_compacted_count = {len(compacted_rows)}",
        f"collector_missing_object_index_count = {len(missing_rows)}",
        f"collector_import_error_count = {len(import_errors)}",
        f"unresolved_uri_count = {unresolved_uri_count}",
        f"missing_raw_hash_count = {missing_raw_hash_count}",
        f"raw_bytes_merged = False",
        f"merge_mode = index_only_raw_on_demand",
        f"by_probe = {dict(by_probe)}",
        f"by_object_type = {dict(by_object_type)}",
        f"by_source_resolver_method = {dict(by_resolver)}",
        f"by_missing_reason = {dict(by_missing_reason)}",
        f"duplicate_exact_probe_uri_hash_count = {compact_stats['duplicate_exact_probe_uri_hash_count']}",
        f"same_probe_same_uri_multi_hash_count = {compact_stats['same_probe_same_uri_multi_hash_count']}",
        f"blockers = {blockers}",
        "",
        f"collector_raw_object_index = {raw_index_out}",
        f"collector_raw_object_index_compacted = {compacted_index_out}",
        f"collector_missing_object_index = {missing_index_out}",
        f"summary_path = {summary_path}",
    ]) + "\n"

    check_path.write_text(text, encoding="utf-8")
    print(text)

    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
