#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import tarfile
import hashlib
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--group-id", required=True)
    ap.add_argument("--object-group-manifest", required=True)
    ap.add_argument("--vrp-group-manifest", required=True)
    ap.add_argument("--object-verdict", required=True)
    ap.add_argument("--object-summary", required=True)
    ap.add_argument("--vrp-diff-manifest", required=True)
    ap.add_argument("--vrp-summary", required=True)
    ap.add_argument("--vrp-pairwise-diff", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    group_id = args.group_id
    out_dir = Path(args.out_dir)

    checks_dir = out_dir / "checks"
    manifests_dir = out_dir / "manifests"
    outputs_dir = out_dir / "outputs"
    verdicts_dir = out_dir / "verdicts"
    evidence_dir = out_dir / "evidence"

    for d in [checks_dir, manifests_dir, outputs_dir, verdicts_dir, evidence_dir]:
        d.mkdir(parents=True, exist_ok=True)

    object_group = read_json(Path(args.object_group_manifest))
    vrp_group = read_json(Path(args.vrp_group_manifest))
    object_verdict = read_json(Path(args.object_verdict))
    object_summary = read_json(Path(args.object_summary))
    vrp_diff_manifest = read_json(Path(args.vrp_diff_manifest))
    vrp_summary = read_json(Path(args.vrp_summary))
    vrp_pairwise = read_json(Path(args.vrp_pairwise_diff))

    object_group_complete = object_group.get("object_group_complete") is True
    vrp_group_complete = vrp_group.get("complete") is True

    object_window_strong = (
        object_group.get("window_mapping_level") == "strong"
        and isinstance(object_group.get("generated_time_skew_seconds"), int)
        and object_group.get("generated_time_skew_seconds") <= 600
    )

    vrp_window_strong = (
        isinstance(vrp_group.get("generated_time_skew_seconds"), int)
        and vrp_group.get("generated_time_skew_seconds") <= 600
    )

    object_layer_diverged = (
        object_verdict.get("final_status") == "object_layer_divergence_observed"
        or object_verdict.get("e4_gate_recommendation") == "do_not_confirm_e4"
        or object_verdict.get("object_roots_aligned") is False
        or object_verdict.get("effective_object_roots_aligned") is False
    )

    vrp_roots_aligned = vrp_summary.get("all_vrp_roots_aligned")
    vrp_diff_count = vrp_pairwise.get("all_pairwise_entry_level_diff_count")
    vrp_min_jaccard = vrp_pairwise.get("min_pairwise_jaccard_similarity")

    blockers = []
    warnings = []

    if not object_group_complete:
        blockers.append("object_group_incomplete")
    if not vrp_group_complete:
        blockers.append("vrp_group_incomplete")
    if not object_window_strong:
        blockers.append("object_window_not_strong")
    if not vrp_window_strong:
        blockers.append("vrp_window_not_strong")

    if object_layer_diverged:
        blockers.append("object_layer_divergence_observed")
        final_status = "not_e4_object_layer_divergence"
        e4_status = "blocked"
        confirmed_allowed = False
        blocking_layer = "object_layer"
        confidence = "high" if object_window_strong and vrp_window_strong else "medium"
        interpretation = (
            "Object-layer divergence is observed under a strong same-group collection window. "
            "Therefore VRP differences must not be attributed to validator output-layer E4-A."
        )
    elif blockers:
        final_status = "blocked_preconditions_not_satisfied"
        e4_status = "blocked"
        confirmed_allowed = False
        blocking_layer = "precondition"
        confidence = "medium"
        interpretation = (
            "Final E4-A gate is blocked because one or more collection or timing preconditions are not satisfied."
        )
    elif vrp_roots_aligned is False and (vrp_diff_count or 0) > 0:
        final_status = "e4a_candidate_output_layer_divergence"
        e4_status = "candidate"
        confirmed_allowed = True
        blocking_layer = None
        confidence = "medium-high"
        warnings.append("object_layer_aligned_but_vrp_layer_diverged")
        interpretation = (
            "Object layer is aligned and VRP output layer diverges under strong same-group collection. "
            "This is an E4-A candidate and requires deeper validator/config/context review before confirmation."
        )
    else:
        final_status = "no_e4a_vrp_outputs_aligned"
        e4_status = "not_e4"
        confirmed_allowed = False
        blocking_layer = None
        confidence = "high"
        interpretation = (
            "Object and VRP layers do not show output-layer divergence requiring E4-A confirmation."
        )

    final_verdict = {
        "schema": "s3.stage3.e4a_joint.p10_final_gate.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "final_status": final_status,
        "e4_status": e4_status,
        "confirmed_allowed": confirmed_allowed,
        "blocking_layer": blocking_layer,
        "confidence": confidence,
        "object_group_complete": object_group_complete,
        "vrp_group_complete": vrp_group_complete,
        "object_window_strong": object_window_strong,
        "vrp_window_strong": vrp_window_strong,
        "object_generated_time_skew_seconds": object_group.get("generated_time_skew_seconds"),
        "vrp_generated_time_skew_seconds": vrp_group.get("generated_time_skew_seconds"),
        "object_roots_aligned": object_verdict.get("object_roots_aligned"),
        "effective_object_roots_aligned": object_verdict.get("effective_object_roots_aligned"),
        "object_layer_final_status": object_verdict.get("final_status"),
        "object_layer_e4_gate_recommendation": object_verdict.get("e4_gate_recommendation"),
        "object_inventory_diff_count": object_verdict.get("all_pairwise_inventory_diff_count"),
        "active_manifest_diff_count": object_verdict.get("all_pairwise_active_manifest_diff_count"),
        "min_inventory_jaccard_similarity": object_verdict.get("min_inventory_jaccard_similarity"),
        "min_active_manifest_jaccard_similarity": object_verdict.get("min_active_manifest_jaccard_similarity"),
        "all_vrp_roots_aligned": vrp_roots_aligned,
        "vrp_pairwise_entry_level_diff_count": vrp_diff_count,
        "vrp_min_pairwise_jaccard_similarity": vrp_min_jaccard,
        "blockers": blockers,
        "warnings": warnings,
        "interpretation": interpretation,
        "inputs": {
            "object_group_manifest": args.object_group_manifest,
            "vrp_group_manifest": args.vrp_group_manifest,
            "object_verdict": args.object_verdict,
            "object_summary": args.object_summary,
            "vrp_diff_manifest": args.vrp_diff_manifest,
            "vrp_summary": args.vrp_summary,
            "vrp_pairwise_diff": args.vrp_pairwise_diff,
        },
        "reserved_interfaces": {
            "e4b_cross_validator": "reserved_only",
            "control_plane_impact": "reserved_only",
        },
    }

    write_json(verdicts_dir / "final_joint_e4a_gate.json", final_verdict)

    write_json(outputs_dir / "object_group_manifest.json", object_group)
    write_json(outputs_dir / "vrp_group_manifest.json", vrp_group)
    write_json(outputs_dir / "object_layer_verdict.json", object_verdict)
    write_json(outputs_dir / "object_layer_compare_summary.json", object_summary)
    write_json(outputs_dir / "vrp_layer_diff_manifest.json", vrp_diff_manifest)
    write_json(outputs_dir / "vrp_summary.json", vrp_summary)
    write_json(outputs_dir / "vrp_pairwise_diff.json", vrp_pairwise)

    evidence_pack = evidence_dir / f"{group_id}_p10_final_joint_e4a_gate_evidence.tar.gz"
    with tarfile.open(evidence_pack, "w:gz") as tar:
        for p in [
            verdicts_dir / "final_joint_e4a_gate.json",
            outputs_dir / "object_group_manifest.json",
            outputs_dir / "vrp_group_manifest.json",
            outputs_dir / "object_layer_verdict.json",
            outputs_dir / "object_layer_compare_summary.json",
            outputs_dir / "vrp_layer_diff_manifest.json",
            outputs_dir / "vrp_summary.json",
            outputs_dir / "vrp_pairwise_diff.json",
        ]:
            tar.add(p, arcname=p.name)

    evidence_sha = sha256_file(evidence_pack)
    (evidence_pack.with_suffix(evidence_pack.suffix + ".sha256")).write_text(
        f"{evidence_sha}  {evidence_pack.name}\n",
        encoding="utf-8",
    )

    acceptance = f"""P10_FINAL_JOINT_E4A_GATE=DONE

created_at_utc = {utc_now()}

snapshot_group_id = {group_id}

final_status = {final_status}
e4_status = {e4_status}
confirmed_allowed = {confirmed_allowed}
blocking_layer = {blocking_layer}
confidence = {confidence}

object_group_complete = {object_group_complete}
vrp_group_complete = {vrp_group_complete}
object_window_strong = {object_window_strong}
vrp_window_strong = {vrp_window_strong}

object_generated_time_skew_seconds = {object_group.get("generated_time_skew_seconds")}
vrp_generated_time_skew_seconds = {vrp_group.get("generated_time_skew_seconds")}

object_roots_aligned = {object_verdict.get("object_roots_aligned")}
effective_object_roots_aligned = {object_verdict.get("effective_object_roots_aligned")}
object_inventory_diff_count = {object_verdict.get("all_pairwise_inventory_diff_count")}
active_manifest_diff_count = {object_verdict.get("all_pairwise_active_manifest_diff_count")}

all_vrp_roots_aligned = {vrp_roots_aligned}
vrp_pairwise_entry_level_diff_count = {vrp_diff_count}
vrp_min_pairwise_jaccard_similarity = {vrp_min_jaccard}

blockers = {blockers}
warnings = {warnings}

interpretation:
  {interpretation}

evidence_pack = {evidence_pack}
evidence_pack_sha256 = {evidence_sha}

runtime_changes:
  collector_main_service_restarted = False
  probe_restarted = False
  new_validator_installed = False
  bgp_data_loaded = False
  cron_enabled = False

reserved_interfaces:
  e4b_cross_validator = reserved_only
  control_plane_impact = reserved_only

P10_acceptance = True
"""

    (checks_dir / "P10_final_joint_e4a_gate_acceptance.txt").write_text(acceptance, encoding="utf-8")

    manifest = {
        "schema": "s3.stage3.e4a_joint.p10_final_gate_manifest.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "final_status": final_status,
        "e4_status": e4_status,
        "confirmed_allowed": confirmed_allowed,
        "blocking_layer": blocking_layer,
        "confidence": confidence,
        "final_verdict": str(verdicts_dir / "final_joint_e4a_gate.json"),
        "evidence_pack": str(evidence_pack),
        "evidence_pack_sha256": evidence_sha,
        "P10_acceptance": True,
    }

    write_json(manifests_dir / "P10_final_joint_e4a_gate_manifest.json", manifest)

    print(acceptance)


if __name__ == "__main__":
    main()
