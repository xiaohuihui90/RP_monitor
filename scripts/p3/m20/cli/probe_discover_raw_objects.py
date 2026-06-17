#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set


DEFAULT_SUFFIXES = [
    ".mft",
    ".roa",
    ".cer",
    ".crl",
    ".gbr",
    ".aspa",
    ".asa",
    ".sig",
    ".tak",
]

SKIP_DIR_NAMES = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".cache",
}

SKIP_PATH_KEYWORDS = [
    "/data/m20_probe_raw_cas_",
    "/data/p3_collector/e4a_joint_m20/",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def object_type_from_suffix(path: Path) -> str:
    suffix = path.suffix.lower().lstrip(".")
    if suffix in {"mft", "roa", "cer", "crl", "gbr", "aspa", "asa", "sig", "tak"}:
        return suffix
    return "unknown"


def object_family(obj_type: str) -> str:
    if obj_type in {"cer", "crl"}:
        return "resource_control"
    if obj_type in {"mft", "roa", "gbr", "aspa", "asa", "sig", "tak"}:
        return "signed_object"
    return "unknown"


def should_skip_dir(path: Path) -> bool:
    if path.name in SKIP_DIR_NAMES:
        return True

    s = str(path)
    for keyword in SKIP_PATH_KEYWORDS:
        if keyword in s:
            return True

    return False


def expand_scan_roots(raw_roots: List[str]) -> List[Path]:
    roots = []
    seen = set()

    for raw in raw_roots:
        p = Path(os.path.expandvars(os.path.expanduser(raw))).resolve()

        if not p.exists() or not p.is_dir():
            continue

        real = str(p)
        if real in seen:
            continue

        seen.add(real)
        roots.append(p)

    return roots


def iter_candidate_files(
    roots: List[Path],
    suffixes: Set[str],
    max_files: int,
    max_file_size_bytes: int,
) -> tuple[list[Dict[str, Any]], Dict[str, Any]]:
    rows = []
    warnings = []

    scanned_dirs = 0
    scanned_files = 0
    skipped_large_files = 0
    skipped_permission_errors = 0
    skipped_duplicate_paths = 0

    seen_real_paths = set()

    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            current_dir = Path(dirpath)

            if should_skip_dir(current_dir):
                dirnames[:] = []
                continue

            dirnames[:] = [
                d for d in dirnames
                if not should_skip_dir(current_dir / d)
            ]

            scanned_dirs += 1

            for filename in filenames:
                scanned_files += 1

                path = current_dir / filename

                if path.suffix.lower() not in suffixes:
                    continue

                try:
                    st = path.stat()
                except PermissionError:
                    skipped_permission_errors += 1
                    continue
                except Exception as exc:
                    warnings.append(f"stat_failed:{path}:{exc}")
                    continue

                if max_file_size_bytes > 0 and st.st_size > max_file_size_bytes:
                    skipped_large_files += 1
                    continue

                try:
                    real_path = str(path.resolve())
                except Exception:
                    real_path = str(path)

                if real_path in seen_real_paths:
                    skipped_duplicate_paths += 1
                    continue

                seen_real_paths.add(real_path)

                obj_type = object_type_from_suffix(path)

                rows.append({
                    "schema": "s3.m20.probe_raw_candidate_file.v1",
                    "created_at_utc": utc_now_iso(),
                    "source_path": str(path),
                    "real_path": real_path,
                    "filename": path.name,
                    "suffix": path.suffix.lower(),
                    "object_type_guess": obj_type,
                    "object_family_guess": object_family(obj_type),
                    "size_bytes": st.st_size,
                    "mtime": st.st_mtime,
                    "scan_root": str(root),
                    "discovery_method": "filesystem_suffix_scan",
                    "warnings": [],
                })

                if max_files > 0 and len(rows) >= max_files:
                    summary_extra = {
                        "stopped_by_max_files": True,
                        "max_files": max_files,
                    }
                    return rows, {
                        "scanned_dirs": scanned_dirs,
                        "scanned_files": scanned_files,
                        "skipped_large_files": skipped_large_files,
                        "skipped_permission_errors": skipped_permission_errors,
                        "skipped_duplicate_paths": skipped_duplicate_paths,
                        "warnings": warnings,
                        **summary_extra,
                    }

    return rows, {
        "scanned_dirs": scanned_dirs,
        "scanned_files": scanned_files,
        "skipped_large_files": skipped_large_files,
        "skipped_permission_errors": skipped_permission_errors,
        "skipped_duplicate_paths": skipped_duplicate_paths,
        "warnings": warnings,
        "stopped_by_max_files": False,
        "max_files": max_files,
    }


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


def main() -> int:
    parser = argparse.ArgumentParser(description="M20-A probe-side raw object discovery")
    parser.add_argument("--probe-id", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--scan-root", action="append", default=[])
    parser.add_argument("--suffix", action="append", default=[])
    parser.add_argument("--max-files", type=int, default=50000)
    parser.add_argument("--max-file-size-bytes", type=int, default=104857600)
    args = parser.parse_args()

    probe_id = args.probe_id
    run_dir = Path(args.run_dir).expanduser().resolve()

    discovery_dir = run_dir / "discovery"
    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"

    discovery_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)
    checks_dir.mkdir(parents=True, exist_ok=True)

    raw_suffixes = args.suffix or DEFAULT_SUFFIXES
    suffixes = {
        s.lower() if s.startswith(".") else "." + s.lower()
        for s in raw_suffixes
    }

    raw_scan_roots = args.scan_root or [
        "~/.rpki-cache",
        "~/.rpki-cache/repository",
        "~/s3_stage3_v3_code/data",
        "/var/lib/routinator",
        "/var/cache/routinator",
    ]

    roots = expand_scan_roots(raw_scan_roots)

    rows, scan_stats = iter_candidate_files(
        roots=roots,
        suffixes=suffixes,
        max_files=args.max_files,
        max_file_size_bytes=args.max_file_size_bytes,
    )

    for row in rows:
        row["probe_id"] = probe_id

    by_object_type = Counter(row["object_type_guess"] for row in rows)
    by_suffix = Counter(row["suffix"] for row in rows)
    by_scan_root = Counter(row["scan_root"] for row in rows)

    candidate_path = discovery_dir / "probe_raw_candidate_files.jsonl"
    summary_path = outputs_dir / "M20A_probe_raw_discovery_summary.json"
    check_path = checks_dir / "M20A_probe_raw_discovery.txt"

    write_jsonl(candidate_path, rows)

    status = "PASS" if len(rows) > 0 else "FAIL"

    summary = {
        "schema": "s3.m20a.probe_raw_discovery_summary.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "probe_id": probe_id,
        "run_dir": str(run_dir),
        "candidate_path": str(candidate_path),
        "candidate_count": len(rows),
        "scan_roots_requested": raw_scan_roots,
        "scan_roots_existing": [str(p) for p in roots],
        "suffixes": sorted(suffixes),
        "max_files": args.max_files,
        "max_file_size_bytes": args.max_file_size_bytes,
        "by_object_type_guess": dict(by_object_type),
        "by_suffix": dict(by_suffix),
        "by_scan_root": dict(by_scan_root),
        **scan_stats,
    }

    write_json(summary_path, summary)

    text = "\n".join([
        f"M20A_PROBE_RAW_DISCOVERY={status}",
        "",
        f"probe_id = {probe_id}",
        f"run_dir = {run_dir}",
        f"candidate_count = {len(rows)}",
        f"by_object_type_guess = {dict(by_object_type)}",
        f"by_suffix = {dict(by_suffix)}",
        f"scan_roots_existing = {[str(p) for p in roots]}",
        f"scanned_dirs = {scan_stats.get('scanned_dirs')}",
        f"scanned_files = {scan_stats.get('scanned_files')}",
        f"skipped_large_files = {scan_stats.get('skipped_large_files')}",
        f"skipped_permission_errors = {scan_stats.get('skipped_permission_errors')}",
        f"skipped_duplicate_paths = {scan_stats.get('skipped_duplicate_paths')}",
        f"stopped_by_max_files = {scan_stats.get('stopped_by_max_files')}",
        f"warnings = {scan_stats.get('warnings')[:20]}",
        "",
        f"candidate_path = {candidate_path}",
        f"summary_path = {summary_path}",
    ]) + "\n"

    check_path.write_text(text, encoding="utf-8")
    print(text)

    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
