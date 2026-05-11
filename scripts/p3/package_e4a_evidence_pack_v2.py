#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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


def add_if_exists(tar: tarfile.TarFile, base: Path, rel: str, evidence_files: list[dict[str, Any]]) -> None:
    p = base / rel
    item = {
        "path": rel,
        "exists": p.exists(),
        "size_bytes": p.stat().st_size if p.exists() else None,
        "sha256": sha256_file(p) if p.exists() else None,
    }
    evidence_files.append(item)
    if p.exists():
        tar.add(p, arcname=rel)


def main() -> None:
    ap = argparse.ArgumentParser(description="Package E4-A evidence pack v2 for current M14 run")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--group-dir", required=True)
    ap.add_argument("--p2-dir", required=True)
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    group_dir = Path(args.group_dir).resolve()
    p2_dir = Path(args.p2_dir).resolve()

    evidence_dir = run_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    group = read_json(group_dir / "group_manifest.json")
    summary = read_json(run_dir / "summaries/m14_vrp_summary.json")
    diff = read_json(run_dir / "diffs/m14_vrp_pairwise_diff.json")
    enriched = read_json(run_dir / "diffs/m14_vrp_pairwise_diff_enriched.json")
    final = read_json(run_dir / "verdicts/final_verdict_m14.json")
    completeness = read_json(run_dir / "checks/m14_parameter_completeness.json")
    fingerprint = read_json(run_dir / "inputs/validator_fingerprint_summary.json")
    impact_placeholder = read_json(run_dir / "inputs/control_plane_impact_placeholder.json")

    pack_name = f"{run_dir.name}_e4a_evidence_pack_v2.tar.gz"
    pack_path = evidence_dir / pack_name
    index_path = evidence_dir / "e4a_evidence_index_v2.json"

    important_rels = [
        "inputs/snapshot_group_manifest.json",
        "inputs/m14_auto_run_manifest.json",
        "inputs/validator_output_records_v2.json",
        "inputs/validator_fingerprint_summary.json",
        "inputs/control_plane_impact_placeholder.json",
        "inputs/contexts/object_layer_context.json",
        "inputs/contexts/validator_config_context.json",
        "inputs/contexts/window_mapping_context.json",
        "inputs/contexts/fetch_completeness_context.json",
        "inputs/contexts/infrastructure_context.json",
        "summaries/m14_vrp_summary.json",
        "diffs/m14_vrp_pairwise_diff.json",
        "diffs/m14_vrp_pairwise_diff_enriched.json",
        "diffs/m14_vrp_pairwise_diff_samples.json",
        "verdicts/preliminary_verdict.json",
        "verdicts/final_verdict_m14.json",
        "verdicts/99_m14_p5_preliminary_verdict.txt",
        "verdicts/99_m14_p6_final_verdict.txt",
        "verdicts/99_m14_p6_paper_ready_conclusion_zh.txt",
        "checks/P5_acceptance_check.txt",
        "checks/P6_acceptance_check.txt",
        "checks/m14_parameter_completeness.json",
    ]

    # Pairwise lowmem evidence paths from enriched diff.
    for pair, s in enriched.get("pair_summary", {}).items():
        for key in ["common_vrps_path", "only_left_vrps_path", "only_right_vrps_path", "diff_all_vrps_path"]:
            rel = s.get(key)
            if rel and rel not in important_rels:
                important_rels.append(rel)

    evidence_files: list[dict[str, Any]] = []

    with tarfile.open(pack_path, "w:gz") as tar:
        for rel in important_rels:
            add_if_exists(tar, run_dir, rel, evidence_files)

        group_arc = "inputs/source_snapshot_group_manifest.json"
        tar.add(group_dir / "group_manifest.json", arcname=group_arc)
        evidence_files.append({
            "path": group_arc,
            "exists": True,
            "size_bytes": (group_dir / "group_manifest.json").stat().st_size,
            "sha256": sha256_file(group_dir / "group_manifest.json"),
        })

    pack_sha = sha256_file(pack_path)

    index = {
        "schema": "s3.stage3.e4a.evidence_index_v2",
        "created_at_utc": utc_now(),
        "run_id": run_dir.name,
        "snapshot_group_id": group.get("snapshot_group_id"),
        "scope": "m14_e4a_cross_region_same_validator",
        "comparison_type": "cross_region_same_validator",
        "validator": "routinator",
        "received_probes": group.get("received_probes"),
        "generated_time_skew_seconds": group.get("generated_time_skew_seconds"),
        "final_status": final.get("final_status"),
        "e4_status": final.get("e4_status"),
        "confirmed_allowed": final.get("confirmed_allowed"),
        "blockers": final.get("blockers"),
        "warnings": final.get("warnings"),
        "vrp_metrics": {
            "all_vrp_roots_aligned": summary.get("all_vrp_roots_aligned"),
            "all_pairwise_entry_level_diff_count": diff.get("all_pairwise_entry_level_diff_count"),
            "min_pairwise_jaccard_similarity": diff.get("min_pairwise_jaccard_similarity"),
        },
        "parameter_completeness": completeness.get("checks"),
        "validator_fingerprint_level": fingerprint.get("fingerprint_level"),
        "control_plane_impact_status": impact_placeholder.get("control_plane_impact_status"),
        "reserved_interfaces": {
            "e4b_cross_validator": "reserved_only",
            "control_plane_impact": "reserved_only",
        },
        "evidence_pack": str(pack_path),
        "evidence_pack_sha256": pack_sha,
        "files": evidence_files,
        "all_required_evidence_exists": all(x["exists"] for x in evidence_files),
    }

    write_json(index_path, index)

    # Repack with index included.
    with tarfile.open(pack_path, "w:gz") as tar:
        for rel in important_rels:
            p = run_dir / rel
            if p.exists():
                tar.add(p, arcname=rel)
        tar.add(group_dir / "group_manifest.json", arcname="inputs/source_snapshot_group_manifest.json")
        tar.add(index_path, arcname="evidence/e4a_evidence_index_v2.json")

    pack_sha = sha256_file(pack_path)
    index["evidence_pack_sha256"] = pack_sha
    write_json(index_path, index)

    sha_path = evidence_dir / f"{pack_name}.sha256"
    sha_path.write_text(f"{pack_sha}  {pack_name}\n", encoding="utf-8")

    # Copy key artifacts into P2 directory for closeout.
    p2_evidence_dir = p2_dir / "evidence"
    p2_checks_dir = p2_dir / "checks"
    p2_docs_dir = p2_dir / "docs"
    p2_manifests_dir = p2_dir / "manifests"
    for d in [p2_evidence_dir, p2_checks_dir, p2_docs_dir, p2_manifests_dir]:
        d.mkdir(parents=True, exist_ok=True)

    write_json(p2_manifests_dir / "e4a_evidence_index_v2.json", index)

    summary_doc = f"""# E4-A Evidence Pack v2 Summary

- run_id: `{run_dir.name}`
- snapshot_group_id: `{group.get("snapshot_group_id")}`
- scope: `m14_e4a_cross_region_same_validator`
- comparison_type: `cross_region_same_validator`
- validator: `routinator`
- final_status: `{final.get("final_status")}`
- e4_status: `{final.get("e4_status")}`
- confirmed_allowed: `{final.get("confirmed_allowed")}`
- all_pairwise_entry_level_diff_count: `{diff.get("all_pairwise_entry_level_diff_count")}`
- min_pairwise_jaccard_similarity: `{diff.get("min_pairwise_jaccard_similarity")}`
- generated_time_skew_seconds: `{group.get("generated_time_skew_seconds")}`
- evidence_pack_sha256: `{pack_sha}`

## 当前解释

本 evidence pack v2 固化了当前 E4-A 跨地域同 Routinator 的 VRP set diff、参数增强结果、validator fingerprint summary、control-plane impact placeholder 和 P6 final verdict。

当前不启动 E4-B 跨 validator 开发，也不加载 BGP 数据。最终状态仍为 blocked_object_layer_unverified，原因是缺少同窗 object layer context。
"""
    (p2_docs_dir / "E4A_evidence_pack_v2_summary.md").write_text(summary_doc, encoding="utf-8")

    acceptance = f"""P2_E4A_EVIDENCE_PACK_V2=DONE

run_id = {run_dir.name}
snapshot_group_id = {group.get("snapshot_group_id")}
scope = m14_e4a_cross_region_same_validator

final_status = {final.get("final_status")}
e4_status = {final.get("e4_status")}
confirmed_allowed = {final.get("confirmed_allowed")}

vrp_roots_aligned = {summary.get("all_vrp_roots_aligned")}
all_pairwise_entry_level_diff_count = {diff.get("all_pairwise_entry_level_diff_count")}
min_pairwise_jaccard_similarity = {diff.get("min_pairwise_jaccard_similarity")}

parameter_completeness_ok = {completeness.get("all_required_for_p1_ok")}
all_required_evidence_exists = {index.get("all_required_evidence_exists")}
evidence_pack = {pack_path}
evidence_pack_sha256 = {pack_sha}

reserved_interfaces:
  e4b_cross_validator = reserved_only
  control_plane_impact = reserved_only

runtime_service_changed = False
collector_restarted = False
probe_restarted = False
new_validator_installed = False
bgp_data_loaded = False

P2_acceptance = {completeness.get("all_required_for_p1_ok") and index.get("all_required_evidence_exists")}
"""
    (p2_checks_dir / "P2_e4a_evidence_pack_v2_acceptance.txt").write_text(acceptance, encoding="utf-8")

    print(acceptance)


if __name__ == "__main__":
    main()
