#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROBES = ["probe-cd", "probe-bj", "probe-sg"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def rel_or_none(path: Path, base: Path) -> str | None:
    return str(path.relative_to(base)) if path.exists() else None


def parse_vrp_key(key: str) -> tuple[str, str, str, str]:
    parts = key.strip().split("|")
    tal = parts[0] if len(parts) > 0 else "unknown"
    asn = parts[1] if len(parts) > 1 else "unknown"
    prefix = parts[2] if len(parts) > 2 else "unknown"
    afi = "ipv6" if ":" in prefix else "ipv4"
    return tal, asn, prefix, afi


def collect_affected(paths: list[Path]) -> dict[str, Any]:
    prefixes = set()
    asns = set()
    tals = set()
    afis = set()
    sample_keys = []

    for path in paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                key = line.strip()
                if not key:
                    continue
                tal, asn, prefix, afi = parse_vrp_key(key)
                prefixes.add(prefix)
                asns.add(asn)
                tals.add(tal)
                afis.add(afi)
                if len(sample_keys) < 50:
                    sample_keys.append(key)

    return {
        "affected_prefix_count": len(prefixes),
        "affected_asn_count": len(asns),
        "affected_tal_count": len(tals),
        "affected_afi_count": len(afis),
        "affected_sample_keys": sample_keys,
    }


def build_validator_output_records(run_dir: Path, summary: dict[str, Any], group: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    snapshots = group.get("snapshots", {})

    for probe in PROBES:
        s = summary.get("probe_summaries", {}).get(probe, {})
        snap = snapshots.get(probe, {})
        normalized_path = run_dir / f"normalized_vrps/{probe}_vrp_index.jsonl"

        record = {
            "schema": "s3.stage3.validator_output_record.v2",
            "probe_id": probe,
            "region": {
                "probe-cd": "chengdu",
                "probe-bj": "beijing",
                "probe-sg": "singapore",
            }.get(probe),
            "validator_name": "routinator",
            "validator_version": snap.get("validator_version"),
            "validator_instance_id": f"{probe}:routinator:{snap.get('validator_version')}",
            "validation_start_time": snap.get("export_started_at"),
            "validation_end_time": snap.get("export_finished_at"),
            "last_update_done": s.get("metadata", {}).get("generatedTime") or snap.get("generatedTime"),
            "vrp_count": s.get("raw_vrp_count"),
            "unique_vrp_count": s.get("unique_vrp_count"),
            "vrp_digest": s.get("vrp_root_v1"),
            "vrp_root_v1": s.get("vrp_root_v1"),
            "vrp_set_path": rel_or_none(normalized_path, run_dir),
            "vrp_set_sha256": sha256_file(normalized_path) if normalized_path.exists() else None,
            "vrp_sample_hash": None,
            "router_key_count": None,
            "aspa_count": None,
            "tal_set_hash": None,
            "config_hash": None,
            "stable_config_hash": None,
            "runtime_process_fingerprint": None,
            "fingerprint_status": "partial_version_only",
        }
        records.append(record)

    return records


def build_validator_fingerprint_summary(group: dict[str, Any]) -> dict[str, Any]:
    snapshots = group.get("snapshots", {})

    versions = {
        probe: snapshots.get(probe, {}).get("validator_version")
        for probe in PROBES
    }

    version_values = [v for v in versions.values() if v]
    validator_version_aligned = len(version_values) == 3 and len(set(version_values)) == 1

    return {
        "schema": "s3.stage3.validator_fingerprint_summary.v1",
        "created_at_utc": utc_now(),
        "scope": "m14_e4a_cross_region_same_validator",
        "comparison_type": "cross_region_same_validator",
        "validator_name": "routinator",
        "validator_versions": versions,
        "validator_version_aligned": validator_version_aligned,
        "fingerprint_level": "partial",
        "available_fields": [
            "validator_name",
            "validator_version",
            "validation_start_time",
            "validation_end_time",
            "uploaded_snapshot_sha256",
        ],
        "missing_fields_reserved_for_future": [
            "config_hash",
            "stable_config_hash",
            "tal_set_hash",
            "runtime_process_fingerprint",
            "fallback_policy",
            "local_filter_policy_hash",
            "refresh_interval_seconds",
        ],
        "e4b_cross_validator": {
            "enabled": False,
            "reserved_only": True,
            "validators_reserved": ["routinator", "rpki-client", "fort"],
        },
        "control_plane_impact": {
            "enabled": False,
            "reserved_only": True,
            "control_plane_impact_status": "impact_not_evaluated",
            "impact_level": "not_evaluated",
        },
        "interpretation": (
            "Current stage only uses Routinator version alignment for E4-A baseline. "
            "Full validator fingerprint is reserved and must be completed before E4 confirmed."
        ),
    }


def enrich_diff(run_dir: Path, diff: dict[str, Any]) -> dict[str, Any]:
    work_dir = run_dir / "diffs/_lowmem_work"

    enriched = dict(diff)
    enriched["schema"] = "s3.stage3.m14.vrp_pairwise_diff_enriched.v1"
    enriched["enriched_at_utc"] = utc_now()
    enriched["scope"] = "m14_e4a_cross_region_same_validator"
    enriched["comparison_type_default"] = "cross_region_same_validator"

    for pair_name, s in enriched.get("pair_summary", {}).items():
        common_path = work_dir / f"{pair_name}.common.txt"
        only_left_path = work_dir / f"{pair_name}.only_left.txt"
        only_right_path = work_dir / f"{pair_name}.only_right.txt"
        diff_all_path = work_dir / f"{pair_name}.diff_all.txt"

        affected = collect_affected([only_left_path, only_right_path])

        s["schema"] = "s3.stage3.vrp_set_diff_record.v2"
        s["comparison_id"] = pair_name
        s["comparison_type"] = "cross_region_same_validator"
        s["validator_scope"] = "routinator"
        s["common_vrps_path"] = rel_or_none(common_path, run_dir)
        s["only_left_vrps_path"] = rel_or_none(only_left_path, run_dir)
        s["only_right_vrps_path"] = rel_or_none(only_right_path, run_dir)
        s["diff_all_vrps_path"] = rel_or_none(diff_all_path, run_dir)
        s.update(affected)

    enriched["reserved_interfaces"] = {
        "same_region_cross_validator": {
            "enabled": False,
            "reserved_only": True,
            "expected_future_fields": [
                "left_validator_name",
                "right_validator_name",
                "left_validator_fingerprint",
                "right_validator_fingerprint",
            ],
        },
        "control_plane_impact": {
            "enabled": False,
            "reserved_only": True,
            "control_plane_impact_status": "impact_not_evaluated",
        },
    }

    return enriched


def build_parameter_completeness(
    run_dir: Path,
    enriched_diff: dict[str, Any],
    validator_output_records: list[dict[str, Any]],
    validator_fingerprint_summary: dict[str, Any],
) -> dict[str, Any]:
    pair_values = list(enriched_diff.get("pair_summary", {}).values())

    checks = {
        "vrp_count_exists": all(r.get("vrp_count") is not None for r in validator_output_records),
        "vrp_digest_exists": all(r.get("vrp_digest") for r in validator_output_records),
        "vrp_root_v1_exists": all(r.get("vrp_root_v1") for r in validator_output_records),
        "vrp_set_path_exists": all(r.get("vrp_set_path") for r in validator_output_records),
        "vrp_set_diff_exists": bool(enriched_diff.get("pair_summary")),
        "common_vrps_path_exists": all(p.get("common_vrps_path") for p in pair_values),
        "only_left_vrps_path_exists": all(p.get("only_left_vrps_path") for p in pair_values),
        "only_right_vrps_path_exists": all(p.get("only_right_vrps_path") for p in pair_values),
        "affected_prefix_count_exists": all(p.get("affected_prefix_count") is not None for p in pair_values),
        "affected_asn_count_exists": all(p.get("affected_asn_count") is not None for p in pair_values),
        "validator_fingerprint_summary_exists": bool(validator_fingerprint_summary),
        "e4b_reserved_only": True,
        "control_plane_impact_reserved_only": True,
    }

    return {
        "schema": "s3.stage3.m14.parameter_completeness.v1",
        "created_at_utc": utc_now(),
        "run_id": run_dir.name,
        "scope": "m14_e4a_cross_region_same_validator",
        "checks": checks,
        "all_required_for_p1_ok": all(checks.values()),
        "notes": [
            "E4-B cross-validator fields are reserved only and not executed in current stage.",
            "Control-plane impact fields are reserved only and no BGP data is loaded in current stage.",
            "Full validator fingerprint remains partial and should block E4 confirmed until completed.",
        ],
    }


def write_summary_doc(run_dir: Path, p1_dir: Path, completeness: dict[str, Any], enriched_diff: dict[str, Any]) -> None:
    lines = []
    lines.append("# P1 M14 参数增强与 E4-A enriched diff 总结")
    lines.append("")
    lines.append(f"- run_id：`{run_dir.name}`")
    lines.append("- active_scope：`m14_e4a_cross_region_same_validator`")
    lines.append("- e4b_cross_validator：`reserved_only`")
    lines.append("- control_plane_impact：`reserved_only`")
    lines.append("")
    lines.append("## 1. 已补齐字段")
    lines.append("")
    for k, v in completeness.get("checks", {}).items():
        lines.append(f"- {k}：`{v}`")
    lines.append("")
    lines.append("## 2. Pairwise enriched diff")
    lines.append("")
    for pair, s in enriched_diff.get("pair_summary", {}).items():
        lines.append(f"### {pair}")
        lines.append(f"- entry_level_diff_count：`{s.get('entry_level_diff_count')}`")
        lines.append(f"- jaccard_similarity：`{s.get('jaccard_similarity')}`")
        lines.append(f"- affected_prefix_count：`{s.get('affected_prefix_count')}`")
        lines.append(f"- affected_asn_count：`{s.get('affected_asn_count')}`")
        lines.append(f"- common_vrps_path：`{s.get('common_vrps_path')}`")
        lines.append(f"- only_left_vrps_path：`{s.get('only_left_vrps_path')}`")
        lines.append(f"- only_right_vrps_path：`{s.get('only_right_vrps_path')}`")
        lines.append("")
    lines.append("## 3. 当前解释")
    lines.append("")
    lines.append("本批只增强 E4-A 跨地域同 Routinator 的 VRP set 对比参数，不启动跨 validator 和控制面影响评估。")
    lines.append("当前 final verdict 仍应保持 blocked_object_layer_unverified，不能因为 VRP 差异直接确认 E4。")
    lines.append("")

    out = p1_dir / "docs/P1_m14_parameter_enhancement_summary.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--group-dir", required=True)
    ap.add_argument("--p1-dir", required=True)
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    group_dir = Path(args.group_dir).resolve()
    p1_dir = Path(args.p1_dir).resolve()

    summary = read_json(run_dir / "summaries/m14_vrp_summary.json")
    diff = read_json(run_dir / "diffs/m14_vrp_pairwise_diff.json")
    group = read_json(group_dir / "group_manifest.json")

    enriched_diff = enrich_diff(run_dir, diff)
    validator_output_records = build_validator_output_records(run_dir, summary, group)
    validator_fingerprint_summary = build_validator_fingerprint_summary(group)
    completeness = build_parameter_completeness(
        run_dir,
        enriched_diff,
        validator_output_records,
        validator_fingerprint_summary,
    )

    write_json(run_dir / "diffs/m14_vrp_pairwise_diff_enriched.json", enriched_diff)
    write_json(run_dir / "inputs/validator_output_records_v2.json", validator_output_records)
    write_json(run_dir / "inputs/validator_fingerprint_summary.json", validator_fingerprint_summary)
    write_json(run_dir / "checks/m14_parameter_completeness.json", completeness)

    impact_placeholder = {
        "schema": "s3.stage3.control_plane_impact_placeholder.v1",
        "enabled": False,
        "reserved_only": True,
        "control_plane_impact_status": "impact_not_evaluated",
        "impact_level": "not_evaluated",
        "affected_bgp_route_count": None,
        "rov_state_change_count": None,
        "note": "Control-plane impact is reserved only in current stage; no BGP RIB or updates are loaded.",
    }
    write_json(run_dir / "inputs/control_plane_impact_placeholder.json", impact_placeholder)

    write_summary_doc(run_dir, p1_dir, completeness, enriched_diff)

    acceptance = f"""P1_M14_PARAMETER_ENHANCEMENT_E4A=DONE

run_id = {run_dir.name}
scope = m14_e4a_cross_region_same_validator

outputs:
  {run_dir / "diffs/m14_vrp_pairwise_diff_enriched.json"}
  {run_dir / "inputs/validator_output_records_v2.json"}
  {run_dir / "inputs/validator_fingerprint_summary.json"}
  {run_dir / "inputs/control_plane_impact_placeholder.json"}
  {run_dir / "checks/m14_parameter_completeness.json"}
  {p1_dir / "docs/P1_m14_parameter_enhancement_summary.md"}

checks:
  vrp_count_exists = {completeness["checks"]["vrp_count_exists"]}
  vrp_digest_exists = {completeness["checks"]["vrp_digest_exists"]}
  vrp_root_v1_exists = {completeness["checks"]["vrp_root_v1_exists"]}
  vrp_set_path_exists = {completeness["checks"]["vrp_set_path_exists"]}
  vrp_set_diff_exists = {completeness["checks"]["vrp_set_diff_exists"]}
  common_vrps_path_exists = {completeness["checks"]["common_vrps_path_exists"]}
  only_left_vrps_path_exists = {completeness["checks"]["only_left_vrps_path_exists"]}
  only_right_vrps_path_exists = {completeness["checks"]["only_right_vrps_path_exists"]}
  affected_prefix_count_exists = {completeness["checks"]["affected_prefix_count_exists"]}
  affected_asn_count_exists = {completeness["checks"]["affected_asn_count_exists"]}
  validator_fingerprint_summary_exists = {completeness["checks"]["validator_fingerprint_summary_exists"]}

reserved_interfaces:
  e4b_cross_validator = reserved_only
  control_plane_impact = reserved_only

runtime_service_changed = False
collector_restarted = False
probe_restarted = False
new_validator_installed = False
bgp_data_loaded = False

P1_acceptance = {completeness["all_required_for_p1_ok"]}
"""

    p1_acceptance_path = p1_dir / "checks/P1_m14_parameter_enhancement_acceptance.txt"
    p1_acceptance_path.parent.mkdir(parents=True, exist_ok=True)
    p1_acceptance_path.write_text(acceptance, encoding="utf-8")

    print(acceptance)


if __name__ == "__main__":
    main()
