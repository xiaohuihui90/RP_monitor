#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


UNKNOWN = "unknown_not_collected_yet"
NA = "not_applicable"


ROOT_CAUSES = [
    "C0_TEMPORAL_OR_MEASUREMENT_ALIGNMENT",
    "C1_ROA_FANOUT_AMPLIFICATION",
    "C2_MANIFEST_PUBLICATION_CLUSTER",
    "C3_MANIFEST_VERSION_OR_FILELIST_EVOLUTION",
    "C4_PP_REACHABILITY_OR_CAPACITY_LIMIT",
    "C5_RRDP_DELTA_SNAPSHOT_OR_FALLBACK_FAILURE",
    "C6_SOURCE_PROVENANCE_GAP",
    "C7_DNS_RESOLUTION_FAILURE",
    "C8_DNS_CDN_ROUTING_INFRASTRUCTURE_EXPOSURE",
    "C9_RP_CACHE_TRAILING_OR_REFRESH_TIMING",
    "C10_VALIDATOR_IMPLEMENTATION_OR_POLICY_DIFFERENCE",
    "E3_LIVE_PP_CENSUS_OBSERVED",
    "NO_CONFIRMED_ROOT_CAUSE_YET",
]

EVIDENCE_LEVELS = [
    "E0_VRP_ONLY",
    "E1_SOURCE_BRIDGE",
    "E2_MANIFEST_BACKFILL",
    "E3_LIVE_PP_CENSUS",
    "E4_REPEATED_SINGLE_NODE_CAPTURE",
    "E5_MULTI_PROBE_L1L2L3_SAME_WINDOW",
    "E6_CROSS_VALIDATOR_REPLAY_OR_CONSENSUS",
]

FIELDS = [
    # L0
    "record_id", "schema", "schema_version", "record_type", "run_id", "capture_id",
    "window_id", "probe_id", "node_id", "collector_id", "capture_time_utc",
    "created_at_utc", "source_stage", "source_file", "semantic_boundary", "evidence_level",

    # Validator metadata
    "validator_name", "validator_version", "validator_binary_path", "validator_config_path",
    "config_hash", "TAL_hash", "refresh_interval_sec", "validation_start_time",
    "validation_end_time", "validation_duration_sec", "validator_exit_code",
    "validator_status", "validator_log_path", "raw_vrp_path", "jsonext_path",

    # L3
    "vrp_key", "tal", "afi", "prefix", "asn", "maxLength", "presence_pattern",
    "presence_count", "present_probes", "absent_probes", "generatedTime",
    "generatedTime_span_sec", "duration_windows", "duration_seconds", "persistence_class",

    # L2
    "repo_host", "repo_base", "repo_uri", "roa_uri", "roa_filename", "roa_sha256",
    "manifest_uri", "manifest_filename", "manifestNumber", "manifest_thisUpdate",
    "manifest_nextUpdate", "manifest_fileList_count", "manifest_fileList_root_sha256",
    "manifest_roa_filelist_match", "manifest_roa_hash_match",
    "manifest_fetch_status", "manifest_parse_status",

    # L2-b
    "repository_status", "repository_fetch_status", "repository_validation_status",
    "failed_repository_count", "failed_repository_list", "discarded_repository_count",
    "discarded_repository_list", "per_pp_fetch_status", "per_pp_manifest_status",
    "per_pp_roa_accept_count", "per_pp_roa_reject_count", "per_pp_object_accept_count",
    "per_pp_object_reject_count", "effective_manifest_uri", "effective_manifestNumber",
    "effective_fileList_root_sha256", "effective_roa_uri", "effective_roa_present",
    "effective_roa_accepted", "effective_roa_rejected_reason", "effective_input_observed",
    "effective_input_source",

    # L1
    "notification_uri", "notification_fetch_status", "rrdp_session_id", "rrdp_serial",
    "notification_digest", "snapshot_uri", "snapshot_hash", "delta_count",
    "delta_apply_status", "fallback_to_rsync", "rsync_fallback_status",

    # Network / infrastructure
    "dns_query_status", "dns_rcode", "resolved_ip_list", "resolved_ip_count",
    "resolved_asn_list", "cname_chain", "tcp_connect_status", "http_status",
    "tls_status", "rsync_return_code", "rsync_stderr_signature", "fetch_failure_type",
    "connection_limit_error", "timeout_error", "cdn_hint", "geo_dependent_ip_hint",
    "infrastructure_exposure_hint",

    # Diagnosis
    "root_cause_primary", "root_cause_secondary", "root_cause_confidence",
    "root_cause_evidence", "diagnosis_stage", "requires_rrdp", "requires_multi_probe",
    "requires_same_input_replay", "next_action",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha1_text(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()


def sha256_file(path: Path) -> str:
    if not path.exists():
        return UNKNOWN
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return 999, "", str(e)


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def g(row: dict, *keys: str, default: str = UNKNOWN) -> str:
    for k in keys:
        v = row.get(k)
        if v not in (None, ""):
            return str(v)
    return default


def safe_float(v: str) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def safe_int(v: str) -> int:
    try:
        return int(float(v))
    except Exception:
        return 0


def collect_validator_metadata(v2: Path) -> dict:
    out = v2 / "validator_metadata"
    out.mkdir(parents=True, exist_ok=True)

    rc, which_out, _ = run_cmd(["bash", "-lc", "command -v routinator || true"])
    binary = which_out if which_out else UNKNOWN

    version = UNKNOWN
    if binary != UNKNOWN:
        for cmd in ([binary, "--version"], [binary, "-V"]):
            rc, so, se = run_cmd(cmd)
            if rc == 0 and (so or se):
                version = (so or se).splitlines()[0]
                break

    config_candidates = [
        Path.home() / ".routinator.conf",
        Path.home() / ".config/routinator/routinator.conf",
        Path("/etc/routinator/routinator.conf"),
    ]
    config_path = next((p for p in config_candidates if p.exists()), None)
    config_hash = sha256_file(config_path) if config_path else "unknown_not_available"

    tal_dirs = [
        Path.home() / ".rpki-cache/tals",
        Path.home() / ".local/share/routinator/tals",
        Path("/etc/routinator/tals"),
        Path("/usr/share/routinator/tals"),
    ]
    tal_files = []
    for d in tal_dirs:
        if d.exists():
            tal_files.extend(sorted(d.glob("*.tal")))
    if tal_files:
        h = hashlib.sha256()
        for p in tal_files:
            h.update(p.name.encode())
            h.update(p.read_bytes())
        tal_hash = h.hexdigest()
    else:
        tal_hash = "unknown_not_available"

    meta = {
        "schema": "s3.m23b.f.validator_metadata.v21",
        "collected_at_utc": utc_now(),
        "validator_name": "routinator" if binary != UNKNOWN else UNKNOWN,
        "validator_version": version,
        "validator_binary_path": binary,
        "validator_config_path": str(config_path) if config_path else "unknown_not_available",
        "config_hash": config_hash,
        "TAL_hash": tal_hash,
        "TAL_file_count": len(tal_files),
        "refresh_interval_sec": UNKNOWN,
        "semantic_boundary": "validator_metadata_snapshot_not_effective_input_proof",
    }

    latest = out / "validator_metadata_latest.json"
    latest.write_text(json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    hist = out / "validator_metadata_history.jsonl"
    with hist.open("a", encoding="utf-8") as f:
        f.write(json.dumps(meta, ensure_ascii=False, sort_keys=True) + "\n")

    if config_path:
        snap = out / "validator_config_snapshot"
        snap.mkdir(exist_ok=True)
        shutil.copy2(config_path, snap / f"routinator_conf_{meta['collected_at_utc'].replace(':','')}.txt")

    return meta


def init_schema(v2: Path) -> None:
    schema_dir = v2 / "schema"
    schema_dir.mkdir(parents=True, exist_ok=True)
    (schema_dir / "m23b_f_schema_v21.json").write_text(
        json.dumps({"schema": "s3.m23b.f.schema.v21", "fields": FIELDS}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (schema_dir / "root_cause_taxonomy_v21.json").write_text(
        json.dumps({"schema": "s3.m23b.f.root_cause_taxonomy.v21", "root_causes": ROOT_CAUSES}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (schema_dir / "evidence_level_v21.json").write_text(
        json.dumps({"schema": "s3.m23b.f.evidence_level.v21", "evidence_levels": EVIDENCE_LEVELS}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def base_record() -> dict:
    return {k: UNKNOWN for k in FIELDS}


def normalize_records(m23b_f_out: Path, m23b_d_out: Path, v2: Path, validator_meta: dict) -> list[dict]:
    records = []

    # F1 hourly census
    seen_paths = set()
    for p in sorted((m23b_f_out / "hourly_census").glob("*/records.csv")):
        seen_paths.add(p)
    for p in sorted((m23b_f_out / "hourly_census").glob("*/*records.csv")):
        seen_paths.add(p)

    for p in sorted(seen_paths):
        run_id = p.parent.name
        for row in read_csv(p):
            r = base_record()
            r.update({
                "schema": "s3.m23b.f.normalized_record.v21",
                "schema_version": "2.1",
                "record_type": "hourly_census",
                "run_id": run_id,
                "capture_id": g(row, "capture_id", default=run_id),
                "probe_id": "probe-cd",
                "node_id": "CD2",
                "collector_id": "CD2",
                "capture_time_utc": g(row, "capture_time_utc", "generated_at_utc", "run_time_utc", default=utc_now()),
                "created_at_utc": utc_now(),
                "source_stage": "F1_hourly_census",
                "source_file": str(p),
                "semantic_boundary": "single_probe_lightweight_census_not_multi_probe_same_window_attribution",
                "evidence_level": "E3_LIVE_PP_CENSUS",

                "target_id": g(row, "target_id"),
                "tal": g(row, "tal", "tal_top"),
                "repo_host": g(row, "repo_host"),
                "repo_base": g(row, "repo_base"),
                "repo_uri": g(row, "repo_base"),
                "manifest_uri": g(row, "manifest_uri", "current_manifest_uri", "selected_manifest_uri"),
                "manifest_filename": g(row, "manifest_filename", "current_manifest_filename", "selected_manifest_name"),
                "manifestNumber": g(row, "manifestNumber", "current_manifestNumber"),
                "manifest_thisUpdate": g(row, "manifest_thisUpdate", "current_manifest_thisUpdate"),
                "manifest_nextUpdate": g(row, "manifest_nextUpdate", "current_manifest_nextUpdate"),
                "manifest_fileList_count": g(row, "manifest_fileList_count", "current_manifest_fileList_count"),
                "manifest_fileList_root_sha256": g(row, "manifest_fileList_root_sha256", "current_manifest_fileList_root_sha256"),
                "manifest_fetch_status": g(row, "manifest_fetch_status", "current_manifest_fetch_status"),
                "manifest_parse_status": g(row, "manifest_parse_status", "current_manifest_parse_status"),
                "rsync_return_code": g(row, "rsync_list_returncode", "rsync_return_code"),
                "fetch_failure_type": g(row, "fetch_failure_type"),
                "connection_limit_error": g(row, "connection_limit_error"),
                "timeout_error": g(row, "timeout_error"),
                "asn": g(row, "asn"),
                "prefix": g(row, "prefix"),
                "maxLength": g(row, "maxLength"),
                "vrp_key": g(row, "vrp_key"),
            })
            r["validator_name"] = validator_meta.get("validator_name", UNKNOWN)
            r["validator_version"] = validator_meta.get("validator_version", UNKNOWN)
            r["validator_binary_path"] = validator_meta.get("validator_binary_path", UNKNOWN)
            r["validator_config_path"] = validator_meta.get("validator_config_path", UNKNOWN)
            r["config_hash"] = validator_meta.get("config_hash", UNKNOWN)
            r["TAL_hash"] = validator_meta.get("TAL_hash", UNKNOWN)
            r["record_id"] = sha1_text("|".join([r["source_stage"], r["capture_id"], r["target_id"], r["repo_base"], r["manifest_uri"], r["capture_time_utc"]]))
            records.append(r)

    # F2 high-impact global capture records
    p = m23b_d_out / "m23b_d_same_window_capture_records.csv"
    for row in read_csv(p):
        r = base_record()
        r.update({
            "schema": "s3.m23b.f.normalized_record.v21",
            "schema_version": "2.1",
            "record_type": "high_impact_capture",
            "run_id": g(row, "capture_id"),
            "capture_id": g(row, "capture_id"),
            "probe_id": "probe-cd",
            "node_id": "CD2",
            "collector_id": "CD2",
            "capture_time_utc": g(row, "capture_time_utc"),
            "created_at_utc": utc_now(),
            "source_stage": "F2_high_impact_capture",
            "source_file": str(p),
            "semantic_boundary": "repeated_single_node_live_capture_not_multi_probe_same_window_attribution",
            "evidence_level": g(row, "evidence_level", default="E4_REPEATED_SINGLE_NODE_CAPTURE"),

            "target_id": g(row, "target_id"),
            "tal": g(row, "tal"),
            "repo_host": g(row, "repo_host"),
            "repo_base": g(row, "repo_base"),
            "repo_uri": g(row, "repo_base"),
            "manifest_uri": g(row, "manifest_uri"),
            "manifest_filename": g(row, "manifest_filename"),
            "manifestNumber": g(row, "manifestNumber"),
            "manifest_thisUpdate": g(row, "manifest_thisUpdate"),
            "manifest_nextUpdate": g(row, "manifest_nextUpdate"),
            "manifest_fileList_count": g(row, "manifest_fileList_count"),
            "manifest_fileList_root_sha256": g(row, "manifest_fileList_root_sha256"),
            "manifest_fetch_status": g(row, "manifest_fetch_status"),
            "manifest_parse_status": g(row, "manifest_parse_status"),
            "rsync_return_code": g(row, "rsync_list_returncode", "rsync_return_code"),
            "rsync_stderr_signature": g(row, "fetch_failure_type"),
            "fetch_failure_type": g(row, "fetch_failure_type"),
            "connection_limit_error": g(row, "connection_limit_error"),
            "timeout_error": g(row, "timeout_error"),
            "asn": g(row, "asn"),
            "prefix": g(row, "prefix"),
            "maxLength": g(row, "maxLength"),
            "vrp_key": g(row, "vrp_key"),
            "raw_vrp_path": g(row, "raw_vrp_path"),
            "jsonext_path": g(row, "jsonext_path"),
            "validator_exit_code": g(row, "validator_exit_code"),
            "validator_status": g(row, "validator_timing_status", default=UNKNOWN),
        })
        r["validator_name"] = validator_meta.get("validator_name", UNKNOWN)
        r["validator_version"] = validator_meta.get("validator_version", UNKNOWN)
        r["validator_binary_path"] = validator_meta.get("validator_binary_path", UNKNOWN)
        r["validator_config_path"] = validator_meta.get("validator_config_path", UNKNOWN)
        r["config_hash"] = validator_meta.get("config_hash", UNKNOWN)
        r["TAL_hash"] = validator_meta.get("TAL_hash", UNKNOWN)
        r["record_id"] = sha1_text("|".join([r["source_stage"], r["capture_id"], r["target_id"], r["repo_base"], r["manifest_uri"], r["capture_time_utc"]]))
        records.append(r)

    out = v2 / "normalized"
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "normalized_records_v21.csv", records, FIELDS)
    write_jsonl(out / "normalized_records_v21.jsonl", records)
    return records


def effective_input(records: list[dict], v2: Path) -> dict[str, dict]:
    rows = []
    by_id = {}
    for r in records:
        row = {
            "record_id": r["record_id"],
            "target_id": r["target_id"],
            "repo_host": r["repo_host"],
            "repo_base": r["repo_base"],
            "manifest_uri": r["manifest_uri"],
            "manifestNumber": r["manifestNumber"],
            "repository_status": UNKNOWN,
            "repository_fetch_status": UNKNOWN,
            "repository_validation_status": UNKNOWN,
            "effective_input_observed": UNKNOWN,
            "effective_input_source": "inferred_from_capture_v21",
            "failed_repository_count": "0",
            "failed_repository_list": "",
            "discarded_repository_count": "0",
            "discarded_repository_list": "",
            "effective_manifestNumber": UNKNOWN,
            "effective_roa_present": UNKNOWN,
            "effective_roa_accepted": UNKNOWN,
            "effective_roa_rejected_reason": UNKNOWN,
        }

        fetch_fail = (
            r.get("fetch_failure_type") not in ("", UNKNOWN, NA)
            or r.get("manifest_fetch_status") == "failed"
            or r.get("rsync_return_code") not in ("", UNKNOWN, "0", "None")
        )
        parsed = r.get("manifest_parse_status") == "parsed" or r.get("manifestNumber") not in ("", UNKNOWN, NA)

        if r.get("repo_base") in ("", UNKNOWN, NA):
            row["repository_status"] = NA
            row["repository_fetch_status"] = NA
            row["repository_validation_status"] = NA
            row["effective_input_observed"] = NA
        elif fetch_fail:
            row["repository_status"] = "fetch_failed"
            row["repository_fetch_status"] = "fetch_failed"
            row["repository_validation_status"] = UNKNOWN
            row["effective_input_observed"] = "unknown_not_available"
            row["failed_repository_count"] = "1"
            row["failed_repository_list"] = r.get("repo_base", "")
        elif parsed:
            row["repository_status"] = "observed_present"
            row["repository_fetch_status"] = "observed_present"
            row["repository_validation_status"] = "observed_present"
            row["effective_input_observed"] = "observed_present"
            row["effective_manifestNumber"] = r.get("manifestNumber", UNKNOWN)
            row["effective_roa_present"] = "unknown_not_collected_yet"
            row["effective_roa_accepted"] = "unknown_not_collected_yet"
        else:
            row["repository_status"] = UNKNOWN
            row["repository_fetch_status"] = UNKNOWN
            row["repository_validation_status"] = UNKNOWN
            row["effective_input_observed"] = UNKNOWN

        rows.append(row)
        by_id[r["record_id"]] = row

    out = v2 / "effective_input"
    out.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0].keys()) if rows else ["record_id"]
    write_csv(out / "effective_input_summary.csv", rows, fields)
    write_csv(out / "failed_repository.csv", [r for r in rows if r.get("failed_repository_count") == "1"], fields)
    write_csv(out / "discarded_repository.csv", [], fields)
    write_csv(out / "per_repository_status.csv", rows, fields)
    return by_id


def classify(records: list[dict], eff_by_id: dict[str, dict], v2: Path) -> list[dict]:
    by_target = defaultdict(list)
    for r in records:
        by_target[r["target_id"]].append(r)

    target_manifest_changed = {}
    for tid, rs in by_target.items():
        nums = {r.get("manifestNumber") for r in rs if r.get("manifestNumber") not in ("", UNKNOWN, NA)}
        roots = {r.get("manifest_fileList_root_sha256") for r in rs if r.get("manifest_fileList_root_sha256") not in ("", UNKNOWN, NA)}
        counts = {r.get("manifest_fileList_count") for r in rs if r.get("manifest_fileList_count") not in ("", UNKNOWN, NA)}
        target_manifest_changed[tid] = (len(nums) > 1 or len(roots) > 1 or len(counts) > 1)

    classified = []
    for r0 in records:
        r = dict(r0)
        eff = eff_by_id.get(r["record_id"], {})
        primary = "NO_CONFIRMED_ROOT_CAUSE_YET"
        secondary = ""
        evidence = []
        confidence = "low"
        requires_rrdp = "False"
        requires_multi = "False"
        requires_replay = "False"
        next_action = "continue_longitudinal_measurement"

        ft = r.get("fetch_failure_type", "")
        stderr = (r.get("rsync_stderr_signature", "") + " " + ft).lower()
        rc = r.get("rsync_return_code", "")
        conn = str(r.get("connection_limit_error", "")).lower() == "true"

        if r.get("repo_base") in ("", UNKNOWN, NA):
            primary = "C6_SOURCE_PROVENANCE_GAP"
            confidence = "probable"
            evidence.append("repo_base_missing_or_unmapped")
            requires_rrdp = "True"
            next_action = "collect_historical_jsonext_or_same_window_source_provenance"

        elif "max connections" in stderr or conn:
            primary = "C4_PP_REACHABILITY_OR_CAPACITY_LIMIT"
            secondary = "C4a_RSYNC_MAX_CONNECTIONS"
            confidence = "confirmed"
            evidence.append("server_side_max_connections_or_connection_limit_error")
            requires_multi = "True"
            next_action = "multi_probe_reachability_and_rrdp_fallback_check"

        elif ft not in ("", UNKNOWN, NA) or (rc not in ("", UNKNOWN, "0", "None")):
            primary = "C4_PP_REACHABILITY_OR_CAPACITY_LIMIT"
            secondary = "C4b_RSYNC_OR_FETCH_ERROR"
            confidence = "probable"
            evidence.append(f"fetch_failure_type={ft};rsync_rc={rc}")
            requires_multi = "True"
            requires_rrdp = "True"
            next_action = "rrdp_notification_discovery_and_multi_probe_fetch"

        elif target_manifest_changed.get(r["target_id"], False):
            primary = "C3_MANIFEST_VERSION_OR_FILELIST_EVOLUTION"
            confidence = "confirmed"
            evidence.append("manifestNumber_or_fileList_changed_across_captures")
            requires_rrdp = "True"
            requires_multi = "True"
            next_action = "rrdp_serial_and_multi_probe_manifest_skew_check"

        elif eff.get("effective_input_observed") == "observed_present":
            primary = "E3_LIVE_PP_CENSUS_OBSERVED"
            confidence = "medium"
            evidence.append("manifest_or_repository_observed_in_live_census")
            next_action = "continue_longitudinal_measurement"

        # structural secondary
        cand = safe_float(g(r, "candidate_count", default="0"))
        uroa = safe_float(g(r, "unique_roa_count", default="0"))
        if uroa > 0 and cand / uroa >= 10:
            secondary = (secondary + "+" if secondary else "") + "C1_ROA_FANOUT_AMPLIFICATION"
            evidence.append("candidate_per_roa_ge_10")

        r["repository_status"] = eff.get("repository_status", UNKNOWN)
        r["repository_fetch_status"] = eff.get("repository_fetch_status", UNKNOWN)
        r["repository_validation_status"] = eff.get("repository_validation_status", UNKNOWN)
        r["failed_repository_count"] = eff.get("failed_repository_count", "0")
        r["failed_repository_list"] = eff.get("failed_repository_list", "")
        r["discarded_repository_count"] = eff.get("discarded_repository_count", "0")
        r["discarded_repository_list"] = eff.get("discarded_repository_list", "")
        r["effective_manifestNumber"] = eff.get("effective_manifestNumber", UNKNOWN)
        r["effective_input_observed"] = eff.get("effective_input_observed", UNKNOWN)
        r["effective_input_source"] = eff.get("effective_input_source", UNKNOWN)
        r["effective_roa_present"] = eff.get("effective_roa_present", UNKNOWN)
        r["effective_roa_accepted"] = eff.get("effective_roa_accepted", UNKNOWN)
        r["effective_roa_rejected_reason"] = eff.get("effective_roa_rejected_reason", UNKNOWN)

        r["root_cause_primary"] = primary
        r["root_cause_secondary"] = secondary
        r["root_cause_confidence"] = confidence
        r["root_cause_evidence"] = ";".join(evidence)
        r["diagnosis_stage"] = "event_centric_root_cause_v21"
        r["requires_rrdp"] = requires_rrdp
        r["requires_multi_probe"] = requires_multi
        r["requires_same_input_replay"] = requires_replay
        r["next_action"] = next_action

        classified.append(r)

    out = v2 / "classified"
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "classified_records_v21.csv", classified, FIELDS)
    write_jsonl(out / "classified_records_v21.jsonl", classified)

    counter = Counter(r["root_cause_primary"] for r in classified)
    md = ["# M23B-F v2.1 Root-cause Classification Summary", ""]
    md.append(f"- generated_at_utc: `{utc_now()}`")
    md.append(f"- classified_record_count: `{len(classified)}`")
    md.append(f"- by_root_cause_primary: `{dict(counter)}`")
    md.append("")
    md.append("Semantic boundary: event-centric classification from single-node longitudinal measurement, not final causal attribution.")
    (out / "root_cause_classification_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return classified


def build_events(classified: list[dict], v2: Path) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    groups = defaultdict(list)
    for r in classified:
        key = (
            r.get("target_id", UNKNOWN),
            r.get("repo_base", UNKNOWN),
            r.get("roa_uri", UNKNOWN),
            r.get("manifest_uri", UNKNOWN),
            r.get("root_cause_primary", UNKNOWN),
        )
        groups[key].append(r)

    events = []
    timeline = []
    confirmations = []
    next_actions = []

    for key, rs in groups.items():
        rs = sorted(rs, key=lambda x: x.get("capture_time_utc", ""))
        tid, repo_base, roa_uri, manifest_uri, cause = key
        event_id = "ev_" + sha1_text("|".join(key))[:16]

        times = [r.get("capture_time_utc", "") for r in rs if r.get("capture_time_utc") not in ("", UNKNOWN)]
        start = times[0] if times else UNKNOWN
        end = times[-1] if times else UNKNOWN

        event_type = {
            "C3_MANIFEST_VERSION_OR_FILELIST_EVOLUTION": "publication_version_change",
            "C4_PP_REACHABILITY_OR_CAPACITY_LIMIT": "fetch_failure_or_reachability_event",
            "C6_SOURCE_PROVENANCE_GAP": "source_provenance_gap_event",
            "E3_LIVE_PP_CENSUS_OBSERVED": "live_pp_census_observation",
        }.get(cause, "divergence_or_observation_event")

        candidates = [safe_float(r.get("candidate_count", "0")) for r in rs]
        event = {
            "event_id": event_id,
            "target_id": tid,
            "vrp_key": rs[0].get("vrp_key", UNKNOWN),
            "tal": rs[0].get("tal", UNKNOWN),
            "repo_host": rs[0].get("repo_host", UNKNOWN),
            "repo_base": repo_base,
            "roa_uri": roa_uri,
            "manifest_uri": manifest_uri,
            "event_type": event_type,
            "event_start_utc": start,
            "event_end_utc": end,
            "observation_count": len(rs),
            "max_candidate_impact": max(candidates) if candidates else 0,
            "root_cause_primary": cause,
            "root_cause_secondary": rs[-1].get("root_cause_secondary", ""),
            "root_cause_confidence": rs[-1].get("root_cause_confidence", "low"),
            "requires_rrdp": rs[-1].get("requires_rrdp", "False"),
            "requires_multi_probe": rs[-1].get("requires_multi_probe", "False"),
            "requires_same_input_replay": rs[-1].get("requires_same_input_replay", "False"),
            "semantic_boundary": "event_constructed_from_single_node_longitudinal_records",
        }
        events.append(event)

        for r in rs:
            timeline.append({
                "event_id": event_id,
                "time_utc": r.get("capture_time_utc", UNKNOWN),
                "window_id": r.get("window_id", UNKNOWN),
                "probe_id": r.get("probe_id", UNKNOWN),
                "L1_serial": r.get("rrdp_serial", UNKNOWN),
                "L1_session_id": r.get("rrdp_session_id", UNKNOWN),
                "L2_manifestNumber": r.get("manifestNumber", UNKNOWN),
                "L2_fileList_root": r.get("manifest_fileList_root_sha256", UNKNOWN),
                "L2b_effective_manifestNumber": r.get("effective_manifestNumber", UNKNOWN),
                "L2b_effective_roa_present": r.get("effective_roa_present", UNKNOWN),
                "L3_presence_pattern": r.get("presence_pattern", UNKNOWN),
                "fetch_status": r.get("fetch_failure_type", "") or r.get("repository_fetch_status", UNKNOWN),
                "dns_status": r.get("dns_query_status", UNKNOWN),
                "validator_status": r.get("validator_status", UNKNOWN),
                "root_cause_evidence": r.get("root_cause_evidence", ""),
            })

        confirmation = "UNKNOWN"
        missing = []
        ruled_out = []

        if cause == "C4_PP_REACHABILITY_OR_CAPACITY_LIMIT":
            confirmation = "CONFIRMED" if any("max_connections" in r.get("root_cause_evidence", "") or "fetch_failure_type" in r.get("root_cause_evidence", "") for r in rs) else "PROBABLE"
            missing.append("multi_probe_fetch_status")
        elif cause == "C3_MANIFEST_VERSION_OR_FILELIST_EVOLUTION":
            confirmation = "CONFIRMED"
            missing.append("rrdp_notification_serial")
        elif cause == "C6_SOURCE_PROVENANCE_GAP":
            confirmation = "PROBABLE"
            missing.append("historical_jsonext_source_sidecar")
        elif cause == "E3_LIVE_PP_CENSUS_OBSERVED":
            confirmation = "PLAUSIBLE"
            missing.append("direct_vrp_diff_binding")
        else:
            confirmation = "PLAUSIBLE"
            missing.append("additional_cross_layer_evidence")

        if all(r.get("repository_fetch_status") == "observed_present" for r in rs):
            ruled_out.append("current_fetch_failure_for_observed_records")

        confirmations.append({
            "event_id": event_id,
            "root_cause": cause,
            "confirmation_level": confirmation,
            "evidence_used": ";".join(sorted(set(r.get("root_cause_evidence", "") for r in rs if r.get("root_cause_evidence", "")))),
            "alternative_causes_ruled_out": ";".join(ruled_out),
            "missing_evidence": ";".join(missing),
            "next_action": rs[-1].get("next_action", "continue_longitudinal_measurement"),
        })

        next_actions.append({
            "event_id": event_id,
            "target_id": tid,
            "repo_host": rs[-1].get("repo_host", UNKNOWN),
            "tal": rs[-1].get("tal", UNKNOWN),
            "root_cause": cause,
            "confirmation_level": confirmation,
            "requires_rrdp": rs[-1].get("requires_rrdp", "False"),
            "requires_multi_probe": rs[-1].get("requires_multi_probe", "False"),
            "requires_same_input_replay": rs[-1].get("requires_same_input_replay", "False"),
            "next_action": rs[-1].get("next_action", "continue_longitudinal_measurement"),
        })

    out = v2 / "events"
    out.mkdir(parents=True, exist_ok=True)
    event_fields = list(events[0].keys()) if events else ["event_id"]
    timeline_fields = list(timeline[0].keys()) if timeline else ["event_id"]
    conf_fields = list(confirmations[0].keys()) if confirmations else ["event_id"]
    next_fields = list(next_actions[0].keys()) if next_actions else ["event_id"]

    write_csv(out / "divergence_event_v21.csv", events, event_fields)
    write_csv(out / "event_timeline_v21.csv", timeline, timeline_fields)
    write_csv(out / "cause_confirmation_v21.csv", confirmations, conf_fields)
    write_csv(out / "next_action_plan_v21.csv", next_actions, next_fields)

    return events, timeline, confirmations, next_actions


def daily_and_tables(v2: Path, classified: list[dict], events: list[dict], confirmations: list[dict], next_actions: list[dict], validator_meta: dict) -> None:
    date = datetime.now(timezone.utc).date().isoformat()
    daily = v2 / "daily_summary" / date
    paper = v2 / "paper_tables" / "latest"
    daily.mkdir(parents=True, exist_ok=True)
    paper.mkdir(parents=True, exist_ok=True)

    # daily root cause
    by_cause = defaultdict(list)
    for r in classified:
        by_cause[r["root_cause_primary"]].append(r)

    root_rows = []
    for cause, rs in sorted(by_cause.items()):
        targets = sorted(set(r.get("target_id", "") for r in rs if r.get("target_id")))
        hosts = sorted(set(r.get("repo_host", "") for r in rs if r.get("repo_host") not in ("", UNKNOWN)))
        tals = sorted(set(r.get("tal", "") for r in rs if r.get("tal") not in ("", UNKNOWN)))
        root_rows.append({
            "date": date,
            "root_cause_primary": cause,
            "record_count": len(rs),
            "target_count": len(targets),
            "affected_tal_count": len(tals),
            "affected_repo_host_count": len(hosts),
            "representative_targets": ";".join(targets[:20]),
            "requires_rrdp_count": sum(1 for r in rs if r.get("requires_rrdp") == "True"),
            "requires_multi_probe_count": sum(1 for r in rs if r.get("requires_multi_probe") == "True"),
            "requires_same_input_replay_count": sum(1 for r in rs if r.get("requires_same_input_replay") == "True"),
        })
    write_csv(daily / "m23b_daily_root_cause_feature_summary_v21.csv", root_rows, list(root_rows[0].keys()) if root_rows else ["date"])

    # effective input summary
    eff_counter = Counter(r.get("effective_input_observed", UNKNOWN) for r in classified)
    eff_rows = [{"date": date, "effective_input_observed": k, "record_count": v} for k, v in sorted(eff_counter.items())]
    write_csv(daily / "m23b_daily_effective_input_summary.csv", eff_rows, ["date", "effective_input_observed", "record_count"])

    # validator summary
    val_row = dict(validator_meta)
    val_row["date"] = date
    write_csv(daily / "m23b_daily_validator_summary.csv", [val_row], list(val_row.keys()))

    # candidates
    rrdp_rows = [r for r in next_actions if r.get("requires_rrdp") == "True"]
    replay_rows = [r for r in next_actions if r.get("requires_same_input_replay") == "True"]
    write_csv(daily / "m23b_daily_rrdp_target_candidates.csv", rrdp_rows, list(rrdp_rows[0].keys()) if rrdp_rows else ["event_id"])
    write_csv(daily / "m23b_daily_replay_target_candidates.csv", replay_rows, list(replay_rows[0].keys()) if replay_rows else ["event_id"])

    # unknown coverage
    unknown_rows = []
    for f in FIELDS:
        total = len(classified)
        u = sum(1 for r in classified if r.get(f, UNKNOWN) in ("", UNKNOWN))
        unknown_rows.append({
            "date": date,
            "field": f,
            "record_count": total,
            "unknown_count": u,
            "unknown_ratio": round(u / total, 4) if total else 0,
        })
    write_csv(daily / "m23b_daily_unknown_coverage_summary.csv", unknown_rows, ["date", "field", "record_count", "unknown_count", "unknown_ratio"])

    md = []
    md.append("# M23B-F v2.1 Daily Summary")
    md.append("")
    md.append(f"- date: `{date}`")
    md.append(f"- generated_at_utc: `{utc_now()}`")
    md.append(f"- classified_record_count: `{len(classified)}`")
    md.append(f"- event_count: `{len(events)}`")
    md.append(f"- confirmation_count: `{len(confirmations)}`")
    md.append(f"- rrdp_target_count: `{len(rrdp_rows)}`")
    md.append(f"- replay_target_count: `{len(replay_rows)}`")
    md.append("")
    md.append("## Root causes")
    for r in root_rows:
        md.append(f"- `{r['root_cause_primary']}` records=`{r['record_count']}` targets=`{r['target_count']}` rrdp=`{r['requires_rrdp_count']}` multi_probe=`{r['requires_multi_probe_count']}` replay=`{r['requires_same_input_replay_count']}`")
    md.append("")
    md.append("Semantic boundary: v2.1 event-centric root-cause determination from single-node longitudinal records; final causal claims require E5/E6 evidence.")
    (daily / "m23b_daily_summary_v21.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    # paper tables
    write_csv(paper / "table_8_effective_input_gap.csv", eff_rows, ["date", "effective_input_observed", "record_count"])
    write_csv(paper / "table_9_rrdp_target_candidates.csv", rrdp_rows, list(rrdp_rows[0].keys()) if rrdp_rows else ["event_id"])
    write_csv(paper / "table_10_replay_target_candidates.csv", replay_rows, list(replay_rows[0].keys()) if replay_rows else ["event_id"])
    write_csv(paper / "table_11_validator_metadata_summary.csv", [val_row], list(val_row.keys()))
    write_csv(paper / "table_12_unknown_coverage_ratio.csv", unknown_rows, ["date", "field", "record_count", "unknown_count", "unknown_ratio"])
    write_csv(paper / "table_13_root_cause_evidence_strength.csv", confirmations, list(confirmations[0].keys()) if confirmations else ["event_id"])

    check = "\n".join([
        "M23B_F21_PIPELINE=PASS" if len(classified) > 0 else "M23B_F21_PIPELINE=WARNING_EMPTY",
        f"generated_at_utc = {utc_now()}",
        f"classified_record_count = {len(classified)}",
        f"event_count = {len(events)}",
        f"rrdp_target_count = {len(rrdp_rows)}",
        f"replay_target_count = {len(replay_rows)}",
        f"daily_summary = {daily / 'm23b_daily_summary_v21.md'}",
        f"paper_tables = {paper}",
        "semantic_boundary = v2.1_event_centric_root_cause_determination_not_final_causal_attribution",
        "next_stage = REVIEW_V21_OUTPUT_AND_ENABLE_V2_DAILY_CRON",
        "",
    ])
    (v2 / "checks" / "M23B_F21_PIPELINE_CHECK.txt").write_text(check, encoding="utf-8")
    (paper / "M23B_F4_PAPER_TABLES_V21_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m23b-f-out", default=os.environ.get("M23B_F_OUT", ""))
    ap.add_argument("--m23b-d-out", default=os.environ.get("M23B_D_OUT", ""))
    args = ap.parse_args()

    m23b_f_out = Path(args.m23b_f_out)
    m23b_d_out = Path(args.m23b_d_out)
    v2 = m23b_f_out / "v2"
    (v2 / "checks").mkdir(parents=True, exist_ok=True)

    init_schema(v2)
    validator_meta = collect_validator_metadata(v2)
    records = normalize_records(m23b_f_out, m23b_d_out, v2, validator_meta)
    eff = effective_input(records, v2)
    classified = classify(records, eff, v2)
    events, timeline, confirmations, next_actions = build_events(classified, v2)
    daily_and_tables(v2, classified, events, confirmations, next_actions, validator_meta)


if __name__ == "__main__":
    main()
