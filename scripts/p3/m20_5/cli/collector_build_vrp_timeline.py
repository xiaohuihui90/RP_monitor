#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


EXPECTED_PROBES = ["probe-bj", "probe-cd", "probe-sg"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return len(rows)


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


def safe_extract_tar(tar_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_root = dest_dir.resolve()

    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar.getmembers():
            name = member.name

            if name.startswith("/"):
                raise RuntimeError(f"unsafe_absolute_path:{name}")

            parts = Path(name).parts
            if ".." in parts:
                raise RuntimeError(f"unsafe_parent_path:{name}")

            if member.issym() or member.islnk():
                raise RuntimeError(f"unsafe_link_member:{name}")

            target = (dest_dir / name).resolve()
            if not str(target).startswith(str(dest_root)):
                raise RuntimeError(f"unsafe_extract_escape:{name}")

        tar.extractall(dest_dir)


def parse_probe_from_archive_name(name: str) -> str:
    for probe_id in EXPECTED_PROBES:
        if probe_id in name:
            return probe_id
    return "unknown"


def parse_iso_utc(value: str | None) -> datetime | None:
    if not value:
        return None

    s = str(value).strip()
    if not s:
        return None

    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    # Python datetime only supports microseconds. Routinator sometimes emits nanoseconds.
    if "." in s:
        left, right = s.split(".", 1)
        if "+" in right:
            frac, tz = right.split("+", 1)
            frac = frac[:6].ljust(6, "0")
            s = f"{left}.{frac}+{tz}"
        elif "-" in right[1:]:
            # very rare; keep best effort
            idx = right[1:].find("-") + 1
            frac = right[:idx]
            tz = right[idx:]
            frac = frac[:6].ljust(6, "0")
            s = f"{left}.{frac}{tz}"
        else:
            frac = right[:6].ljust(6, "0")
            s = f"{left}.{frac}+00:00"

    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def find_summary_file(extract_dir: Path) -> Path | None:
    history_candidates = sorted(extract_dir.glob("history/*/probe_vrp_summary.json"))
    if history_candidates:
        return history_candidates[-1]

    latest = extract_dir / "latest" / "probe_vrp_summary.json"
    if latest.exists():
        return latest

    candidates = sorted(extract_dir.rglob("probe_vrp_summary.json"))
    if candidates:
        return candidates[-1]

    return None


def normalize_summary(summary: Dict[str, Any], source_archive: str) -> Dict[str, Any]:
    probe_id = summary.get("probe_id") or parse_probe_from_archive_name(source_archive)

    status_api = summary.get("status_api") or {}

    return {
        "schema": "s3.m20_5.collector_probe_vrp_summary_record.v1",
        "created_at_utc": utc_now_iso(),
        "source_archive": source_archive,

        "run_id": summary.get("run_id"),
        "probe_id": probe_id,
        "validator_id": summary.get("validator_id"),
        "validator_version": summary.get("validator_version"),
        "validator_backend": summary.get("validator_backend"),

        "collection_started_at_utc": summary.get("collection_started_at_utc"),
        "collection_finished_at_utc": summary.get("collection_finished_at_utc"),
        "latency_ms": summary.get("latency_ms"),
        "command_latency_ms": summary.get("command_latency_ms"),

        "export_status": summary.get("export_status"),
        "vrp_count": summary.get("vrp_count"),
        "vrp_digest": summary.get("vrp_digest"),
        "router_key_count": summary.get("router_key_count"),
        "router_key_digest": summary.get("router_key_digest"),
        "aspa_count": summary.get("aspa_count"),
        "aspa_digest": summary.get("aspa_digest"),

        "last_update_start": summary.get("last_update_start"),
        "last_update_done": summary.get("last_update_done"),
        "last_update_duration": summary.get("last_update_duration"),
        "validator_cycle_status": summary.get("validator_cycle_status"),

        "status_route_origins_final_total": status_api.get("status_route_origins_final_total"),
        "status_route_origins_ipv4_final": status_api.get("status_route_origins_ipv4_final"),
        "status_route_origins_ipv6_final": status_api.get("status_route_origins_ipv6_final"),

        "mode": summary.get("mode"),
        "refresh_before_export": summary.get("refresh_before_export"),
        "cli_export_policy": summary.get("cli_export_policy"),
        "full_snapshot_saved": summary.get("full_snapshot_saved"),
        "full_snapshot_path": summary.get("full_snapshot_path"),
        "full_snapshot_reason": summary.get("full_snapshot_reason"),

        "warnings": summary.get("warnings") or [],
        "errors": summary.get("errors") or [],
    }


def build_single_window(records: List[Dict[str, Any]], window_seconds: int) -> Dict[str, Any]:
    success_records = [
        r for r in records
        if r.get("export_status") == "success"
    ]

    probe_records = {}
    for r in records:
        probe_id = r.get("probe_id") or "unknown"
        probe_records[probe_id] = {
            "run_id": r.get("run_id"),
            "export_status": r.get("export_status"),
            "vrp_count": r.get("vrp_count"),
            "vrp_digest": r.get("vrp_digest"),
            "router_key_count": r.get("router_key_count"),
            "aspa_count": r.get("aspa_count"),
            "validator_version": r.get("validator_version"),
            "collection_finished_at_utc": r.get("collection_finished_at_utc"),
            "last_update_done": r.get("last_update_done"),
            "latency_ms": r.get("latency_ms"),
            "refresh_before_export": r.get("refresh_before_export"),
            "cli_export_policy": r.get("cli_export_policy"),
            "warnings": r.get("warnings") or [],
            "errors": r.get("errors") or [],
        }

    finish_times = [
        parse_iso_utc(r.get("collection_finished_at_utc"))
        for r in success_records
    ]
    finish_times = [x for x in finish_times if x is not None]

    if finish_times:
        start_dt = min(finish_times)
        end_dt = max(finish_times)
        skew_seconds = int((end_dt - start_dt).total_seconds())
        window_started = start_dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        window_finished = end_dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        window_id = "vrpwin_" + start_dt.strftime("%Y%m%dT%H%M%SZ")
    else:
        skew_seconds = None
        window_started = None
        window_finished = None
        window_id = "vrpwin_unknown"

    probe_count = len(set(r.get("probe_id") for r in records))
    success_probe_count = len(set(r.get("probe_id") for r in success_records))

    vrp_counts = {
        r.get("vrp_count")
        for r in success_records
        if r.get("vrp_count") is not None
    }

    vrp_digests = {
        r.get("vrp_digest")
        for r in success_records
        if r.get("vrp_digest")
    }

    validator_versions = {
        r.get("validator_version")
        for r in success_records
        if r.get("validator_version")
    }

    warnings = []

    missing_probes = sorted(set(EXPECTED_PROBES) - set(probe_records))
    if missing_probes:
        warnings.append(f"missing_expected_probes:{missing_probes}")

    failed_probes = sorted([
        r.get("probe_id")
        for r in records
        if r.get("export_status") != "success"
    ])
    if failed_probes:
        warnings.append(f"failed_probe_exports:{failed_probes}")

    if success_probe_count == 3 and skew_seconds is not None:
        if skew_seconds <= window_seconds:
            window_mapping_level = "strong"
        else:
            window_mapping_level = "weak"
    elif success_probe_count > 0:
        window_mapping_level = "partial"
    else:
        window_mapping_level = "invalid"

    if success_probe_count < 3:
        output_diff_status = "insufficient_success_probe"
        candidate_type = "validation_output_incomplete_window"
        full_snapshot_required = False
    elif len(vrp_counts) > 1 or len(vrp_digests) > 1:
        if len(vrp_counts) > 1 and len(vrp_digests) > 1:
            output_diff_status = "vrp_count_and_digest_divergent"
        elif len(vrp_counts) > 1:
            output_diff_status = "vrp_count_divergent"
        else:
            output_diff_status = "vrp_digest_divergent"

        candidate_type = "validation_output_divergence_candidate"
        full_snapshot_required = True
    else:
        output_diff_status = "aligned"
        candidate_type = "no_validation_output_divergence"
        full_snapshot_required = False

    return {
        "schema": "s3.m20_5.collector_vrp_timeline.v1",
        "created_at_utc": utc_now_iso(),

        "window_id": window_id,
        "window_started_at_utc": window_started,
        "window_finished_at_utc": window_finished,
        "window_skew_seconds": skew_seconds,
        "window_mapping_level": window_mapping_level,

        "probe_records": probe_records,
        "probe_count": probe_count,
        "success_probe_count": success_probe_count,
        "expected_probe_count": len(EXPECTED_PROBES),
        "missing_expected_probes": missing_probes,

        "vrp_count_unique_count": len(vrp_counts),
        "vrp_digest_unique_count": len(vrp_digests),
        "validator_version_unique_count": len(validator_versions),

        "vrp_count_values": sorted(vrp_counts),
        "vrp_digest_values": sorted(vrp_digests),
        "validator_version_values": sorted(validator_versions),

        "output_diff_status": output_diff_status,
        "candidate_type": candidate_type,
        "full_snapshot_required": full_snapshot_required,

        "warnings": warnings,
        "notes": [
            "M20.5-B builds validation output timeline from probe-side VRP summaries.",
            "Weak windows are useful for monitoring but should not be used for strong attribution.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="M20.5-B collector-side VRP timeline builder")
    parser.add_argument("--import-dir", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--window-seconds", type=int, default=60)
    args = parser.parse_args()

    import_dir = Path(args.import_dir).expanduser().resolve()
    run_dir = Path(args.run_dir).expanduser().resolve()

    inputs_dir = run_dir / "inputs"
    indexes_dir = run_dir / "indexes"
    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"

    for d in [inputs_dir, indexes_dir, outputs_dir, checks_dir]:
        d.mkdir(parents=True, exist_ok=True)

    archives = sorted(import_dir.glob("m20_5a_vrp_summary_*.tar.gz"))

    sha_checks = []
    records = []
    import_errors = []

    for archive in archives:
        sha = verify_archive_sha256(archive)
        sha_checks.append(sha)

        if sha.get("status") != "OK":
            import_errors.append({
                "source_archive": archive.name,
                "error": "sha256_verify_failed",
                "detail": sha,
            })
            continue

        probe_hint = parse_probe_from_archive_name(archive.name)
        extract_dir = inputs_dir / probe_hint / archive.name.replace(".tar.gz", "")

        try:
            safe_extract_tar(archive, extract_dir)
        except Exception as exc:
            import_errors.append({
                "source_archive": archive.name,
                "error": "safe_extract_failed",
                "detail": str(exc),
            })
            continue

        summary_file = find_summary_file(extract_dir)
        if not summary_file:
            import_errors.append({
                "source_archive": archive.name,
                "error": "probe_vrp_summary_not_found",
                "extract_dir": str(extract_dir),
            })
            continue

        try:
            summary = json.loads(summary_file.read_text(encoding="utf-8"))
            records.append(normalize_summary(summary, archive.name))
        except Exception as exc:
            import_errors.append({
                "source_archive": archive.name,
                "error": "summary_parse_failed",
                "detail": str(exc),
            })

    records = sorted(
        records,
        key=lambda r: (
            str(r.get("probe_id")),
            str(r.get("collection_finished_at_utc") or ""),
        ),
    )

    timeline = []
    if records:
        timeline.append(build_single_window(records, args.window_seconds))

    probe_index_path = indexes_dir / "probe_vrp_summary_index.jsonl"
    timeline_path = indexes_dir / "vrp_output_timeline.jsonl"
    window_index_path = indexes_dir / "vrp_output_window_index.jsonl"
    error_index_path = indexes_dir / "vrp_summary_import_error_index.jsonl"

    write_jsonl(probe_index_path, records)
    write_jsonl(timeline_path, timeline)
    write_jsonl(window_index_path, timeline)
    write_jsonl(error_index_path, import_errors)

    by_probe = Counter(r.get("probe_id") for r in records)
    by_export_status = Counter(r.get("export_status") for r in records)

    by_window_mapping_level = Counter(w.get("window_mapping_level") for w in timeline)
    by_output_diff_status = Counter(w.get("output_diff_status") for w in timeline)

    status = "PASS"
    blockers = []

    if len(records) < 3:
        status = "FAIL"
        blockers.append("summary_record_count_below_3")

    if import_errors:
        status = "FAIL"
        blockers.append("import_errors_observed")

    imported_probes = set(r.get("probe_id") for r in records)
    missing_expected = sorted(set(EXPECTED_PROBES) - imported_probes)
    if missing_expected:
        status = "FAIL"
        blockers.append("missing_expected_probes")

    summary = {
        "schema": "s3.m20_5b.vrp_timeline_summary.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "run_dir": str(run_dir),
        "import_dir": str(import_dir),
        "window_seconds": args.window_seconds,

        "archive_count": len(archives),
        "sha256_checks": sha_checks,
        "input_summary_count": len(records),
        "input_probe_count": len(imported_probes),
        "imported_probes": sorted(imported_probes),
        "missing_expected_probes": missing_expected,
        "import_error_count": len(import_errors),

        "timeline_window_count": len(timeline),
        "strong_window_count": by_window_mapping_level.get("strong", 0),
        "weak_window_count": by_window_mapping_level.get("weak", 0),
        "partial_window_count": by_window_mapping_level.get("partial", 0),
        "invalid_window_count": by_window_mapping_level.get("invalid", 0),

        "by_probe": dict(by_probe),
        "by_export_status": dict(by_export_status),
        "by_window_mapping_level": dict(by_window_mapping_level),
        "by_output_diff_status": dict(by_output_diff_status),

        "probe_vrp_summary_index": str(probe_index_path),
        "vrp_output_timeline": str(timeline_path),
        "vrp_output_window_index": str(window_index_path),
        "import_error_index": str(error_index_path),

        "blockers": blockers,
        "important_boundary": [
            "M20.5-B creates validation-output timeline only.",
            "Weak windows are not strong attribution evidence.",
            "M20.5-C will classify digest/count/cycle candidates from this timeline.",
        ],
    }

    summary_path = outputs_dir / "M20_5B_vrp_timeline_summary.json"
    write_json(summary_path, summary)

    check_text = "\n".join([
        f"M20_5B_COLLECTOR_VRP_TIMELINE={status}",
        "",
        f"run_dir = {run_dir}",
        f"import_dir = {import_dir}",
        f"window_seconds = {args.window_seconds}",
        f"archive_count = {len(archives)}",
        f"input_summary_count = {len(records)}",
        f"input_probe_count = {len(imported_probes)}",
        f"imported_probes = {sorted(imported_probes)}",
        f"missing_expected_probes = {missing_expected}",
        f"import_error_count = {len(import_errors)}",
        "",
        f"timeline_window_count = {len(timeline)}",
        f"strong_window_count = {by_window_mapping_level.get('strong', 0)}",
        f"weak_window_count = {by_window_mapping_level.get('weak', 0)}",
        f"partial_window_count = {by_window_mapping_level.get('partial', 0)}",
        f"invalid_window_count = {by_window_mapping_level.get('invalid', 0)}",
        f"by_window_mapping_level = {dict(by_window_mapping_level)}",
        f"by_output_diff_status = {dict(by_output_diff_status)}",
        "",
        f"by_probe = {dict(by_probe)}",
        f"by_export_status = {dict(by_export_status)}",
        "",
        f"probe_vrp_summary_index = {probe_index_path}",
        f"vrp_output_timeline = {timeline_path}",
        f"summary_path = {summary_path}",
        f"blockers = {blockers}",
    ]) + "\n"

    check_path = checks_dir / "M20_5B_vrp_timeline.txt"
    check_path.write_text(check_text, encoding="utf-8")

    print(check_text)

    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
