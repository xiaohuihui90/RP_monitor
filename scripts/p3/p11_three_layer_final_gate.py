#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
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
    ap = argparse.ArgumentParser(description="P11-D three-layer final E4-A gate")

    ap.add_argument("--group-id", required=True)

    ap.add_argument("--announced-view-group-manifest", required=True)
    ap.add_argument("--announced-view-pairwise-diff", required=True)

    ap.add_argument("--object-joint-group-manifest", required=True)
    ap.add_argument("--object-layer-verdict", required=True)
    ap.add_argument("--object-layer-summary", required=True)

    ap.add_argument("--vrp-group-manifest", required=True)
    ap.add_argument("--vrp-layer-diff-manifest", required=True)
    ap.add_argument("--vrp-summary", required=True)
    ap.add_argument("--vrp-pairwise-diff", required=True)

    ap.add_argument("--p10-final-verdict", required=True)
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

    input_paths = {
        "announced_view_group_manifest": Path(args.announced_view_group_manifest),
        "announced_view_pairwise_diff": Path(args.announced_view_pairwise_diff),
        "object_joint_group_manifest": Path(args.object_joint_group_manifest),
        "object_layer_verdict": Path(args.object_layer_verdict),
        "object_layer_summary": Path(args.object_layer_summary),
        "vrp_group_manifest": Path(args.vrp_group_manifest),
        "vrp_layer_diff_manifest": Path(args.vrp_layer_diff_manifest),
        "vrp_summary": Path(args.vrp_summary),
        "vrp_pairwise_diff": Path(args.vrp_pairwise_diff),
        "p10_final_verdict": Path(args.p10_final_verdict),
    }

    blockers = []
    warnings = []

    for name, path in input_paths.items():
        if not path.exists() or not path.is_file():
            blockers.append(f"missing_input:{name}:{path}")

    if blockers:
        verdict = {
            "schema": "s3.stage3.m15.three_layer_final_verdict.v1",
            "created_at_utc": utc_now(),
            "snapshot_group_id": group_id,
            "final_status": "blocked_preconditions_not_satisfied",
            "e4_status": "blocked",
            "confirmed_allowed": False,
            "blocking_layer": "precondition",
            "attribution_layer": "precondition",
            "confidence": "low",
            "warnings": warnings,
            "blockers": blockers,
        }
        write_json(verdicts_dir / "three_layer_final_verdict.json", verdict)
        raise SystemExit("[BLOCKED] missing inputs")

    av_group = read_json(input_paths["announced_view_group_manifest"])
    av_diff = read_json(input_paths["announced_view_pairwise_diff"])
    obj_group = read_json(input_paths["object_joint_group_manifest"])
    obj_verdict = read_json(input_paths["object_layer_verdict"])
    obj_summary = read_json(input_paths["object_layer_summary"])
    vrp_group = read_json(input_paths["vrp_group_manifest"])
    vrp_diff_manifest = read_json(input_paths["vrp_layer_diff_manifest"])
    vrp_summary = read_json(input_paths["vrp_summary"])
    vrp_pairwise = read_json(input_paths["vrp_pairwise_diff"])
    p10_final = read_json(input_paths["p10_final_verdict"])

    group_sources = {
        "announced_view_group_manifest": av_group.get("snapshot_group_id"),
        "announced_view_pairwise_diff": av_diff.get("snapshot_group_id"),
        "object_joint_group_manifest": obj_group.get("snapshot_group_id"),
        "object_layer_verdict": obj_verdict.get("snapshot_group_id"),
        "vrp_group_manifest": vrp_group.get("snapshot_group_id"),
        "vrp_layer_diff_manifest": vrp_diff_manifest.get("snapshot_group_id"),
        "p10_final_verdict": p10_final.get("snapshot_group_id"),
    }

    for name, gid in group_sources.items():
        if gid != group_id:
            blockers.append(f"group_id_mismatch:{name}:{gid}")

    av_complete = av_group.get("announced_view_group_complete") is True
    av_collection_mode = av_group.get("collection_mode")
    av_window = av_group.get("window_mapping_level")
    av_time_skew = av_group.get("generated_time_skew_seconds")
    av_strict = av_group.get("strict_announced_view_aligned") is True
    av_semantic = av_group.get("semantic_announced_view_aligned") is True
    av_pairwise_diff_count = av_diff.get("all_pairwise_diff_count")

    object_group_complete = obj_group.get("object_group_complete") is True
    object_roots_aligned = obj_verdict.get("object_roots_aligned") is True
    effective_object_roots_aligned = obj_verdict.get("effective_object_roots_aligned") is True
    object_layer_aligned = object_roots_aligned and effective_object_roots_aligned
    object_inventory_diff_count = obj_verdict.get("all_pairwise_inventory_diff_count")
    active_manifest_diff_count = obj_verdict.get("all_pairwise_active_manifest_diff_count")
    object_window = obj_verdict.get("window_mapping_level", obj_group.get("window_mapping_level"))
    object_time_skew = obj_verdict.get("generated_time_skew_seconds", obj_group.get("generated_time_skew_seconds"))

    vrp_group_complete = vrp_group.get("complete") is True
    all_vrp_roots_aligned = vrp_summary.get("all_vrp_roots_aligned") is True
    vrp_layer_aligned = all_vrp_roots_aligned
    vrp_pairwise_entry_level_diff_count = vrp_pairwise.get(
        "all_pairwise_entry_level_diff_count",
        vrp_diff_manifest.get("all_pairwise_entry_level_diff_count"),
    )
    vrp_min_pairwise_jaccard_similarity = vrp_pairwise.get(
        "min_pairwise_jaccard_similarity",
        vrp_diff_manifest.get("min_pairwise_jaccard_similarity"),
    )
    vrp_time_skew = vrp_group.get("generated_time_skew_seconds")

    p10_final_status = p10_final.get("final_status")
    p10_e4_status = p10_final.get("e4_status")
    p10_confirmed_allowed = p10_final.get("confirmed_allowed")
    p10_blocking_layer = p10_final.get("blocking_layer")

    if not av_complete:
        blockers.append("announced_view_group_not_complete")
    if not object_group_complete:
        blockers.append("object_group_not_complete")
    if not vrp_group_complete:
        blockers.append("vrp_group_not_complete")

    if av_collection_mode == "retrofit_or_diagnostic":
        warnings.append("announced_view_collection_mode_retrofit_or_diagnostic")

    if av_window != "strong":
        warnings.append("announced_view_window_mapping_not_strong")

    confirmed_blockers = []
    if not object_layer_aligned:
        confirmed_blockers.append("object_layer_divergence_observed")

    if p10_final_status != "not_e4_object_layer_divergence":
        warnings.append(f"p10_final_status_unexpected:{p10_final_status}")

    if blockers:
        final_status = "blocked_preconditions_not_satisfied"
        e4_status = "blocked"
        confirmed_allowed = False
        blocking_layer = "precondition"
        attribution_layer = "precondition"
        confidence = "low"
        strict_three_layer_status = "blocked_preconditions_not_satisfied"

    elif av_window != "strong" and av_collection_mode == "retrofit_or_diagnostic":
        if not object_layer_aligned and p10_blocking_layer == "object_layer":
            final_status = "not_e4_object_layer_divergence_with_l1_retrofit_context"
            e4_status = "blocked"
            confirmed_allowed = False
            blocking_layer = "object_layer"
            attribution_layer = "object_view"
            confidence = "medium-high"
            strict_three_layer_status = "blocked_l1_window_mapping_not_strong"
        else:
            final_status = "blocked_l1_window_mapping_not_strong"
            e4_status = "blocked"
            confirmed_allowed = False
            blocking_layer = "window_mapping"
            attribution_layer = "precondition"
            confidence = "medium"
            strict_three_layer_status = "blocked_l1_window_mapping_not_strong"

    elif not av_strict:
        final_status = "not_e4_announced_view_divergence"
        e4_status = "blocked"
        confirmed_allowed = False
        blocking_layer = "announced_view"
        attribution_layer = "advertised_view"
        confidence = "high" if av_complete else "medium"
        strict_three_layer_status = final_status

    elif not object_layer_aligned:
        final_status = "not_e4_object_layer_divergence"
        e4_status = "blocked"
        confirmed_allowed = False
        blocking_layer = "object_layer"
        attribution_layer = "object_view"
        confidence = "high"
        strict_three_layer_status = final_status

    elif not vrp_layer_aligned:
        final_status = "e4a_candidate_output_layer_divergence"
        e4_status = "candidate"
        confirmed_allowed = True
        blocking_layer = None
        attribution_layer = "validated_output"
        confidence = "medium-high"
        strict_three_layer_status = final_status

    else:
        final_status = "no_cross_layer_divergence"
        e4_status = "not_e4"
        confirmed_allowed = False
        blocking_layer = None
        attribution_layer = "none"
        confidence = "high"
        strict_three_layer_status = final_status

    gating_result = {
        "G0_input_integrity": "pass" if not blockers else "blocked",
        "G1_window_mapping": "pass" if av_window == "strong" else "warning_or_blocked_for_strict_three_layer",
        "G2_advertised_view": "pass" if av_strict else "diagnostic_divergence_or_version_skew",
        "G3_object_view": "pass" if object_layer_aligned else "blocked",
        "G4_validator_version": "reserved_or_inherited",
        "G5_validator_config": "reserved_or_warning",
        "G6_validator_cycle": "reserved_or_warning",
        "G8_fetch_completeness": "reserved_or_warning",
        "G9_infrastructure_context": "reserved_or_warning",
        "G10_vrp_output": "pass" if vrp_group_complete else "blocked",
        "G12_final": "blocked" if e4_status == "blocked" else e4_status,
    }

    if final_status == "not_e4_object_layer_divergence_with_l1_retrofit_context":
        interpretation = (
            "L1 announced-view context was added as retrofit/diagnostic evidence. "
            "Because the L1 window is not strong, it must not override the existing P10 strong-window "
            "object+VRP gate. The current conservative conclusion remains that E4-A must not be confirmed, "
            "because object-layer divergence has already been observed under the P9/P10 strong same-group evidence."
        )
    else:
        interpretation = "Three-layer final gate completed under conservative ordering."

    verdict = {
        "schema": "s3.stage3.m15.three_layer_final_verdict.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "final_status": final_status,
        "strict_three_layer_status": strict_three_layer_status,
        "e4_status": e4_status,
        "confirmed_allowed": confirmed_allowed,
        "blocking_layer": blocking_layer,
        "attribution_layer": attribution_layer,
        "confidence": confidence,
        "announced_view": {
            "group_complete": av_complete,
            "collection_mode": av_collection_mode,
            "window_mapping_level": av_window,
            "generated_time_skew_seconds": av_time_skew,
            "strict_announced_view_aligned": av_strict,
            "semantic_announced_view_aligned": av_semantic,
            "all_pairwise_diff_count": av_pairwise_diff_count,
        },
        "object_layer": {
            "group_complete": object_group_complete,
            "window_mapping_level": object_window,
            "generated_time_skew_seconds": object_time_skew,
            "object_layer_aligned": object_layer_aligned,
            "object_roots_aligned": object_roots_aligned,
            "effective_object_roots_aligned": effective_object_roots_aligned,
            "all_pairwise_inventory_diff_count": object_inventory_diff_count,
            "all_pairwise_active_manifest_diff_count": active_manifest_diff_count,
        },
        "vrp_layer": {
            "group_complete": vrp_group_complete,
            "generated_time_skew_seconds": vrp_time_skew,
            "vrp_layer_aligned": vrp_layer_aligned,
            "all_vrp_roots_aligned": all_vrp_roots_aligned,
            "all_pairwise_entry_level_diff_count": vrp_pairwise_entry_level_diff_count,
            "min_pairwise_jaccard_similarity": vrp_min_pairwise_jaccard_similarity,
        },
        "p10_baseline": {
            "final_status": p10_final_status,
            "e4_status": p10_e4_status,
            "confirmed_allowed": p10_confirmed_allowed,
            "blocking_layer": p10_blocking_layer,
        },
        "gating_result": gating_result,
        "confirmed_blockers": confirmed_blockers,
        "warnings": warnings,
        "blockers": blockers,
        "interpretation": interpretation,
        "reserved_interfaces": {
            "e4b_cross_validator": "reserved_only",
            "control_plane_impact": "reserved_only",
        },
        "input_paths": {k: str(v) for k, v in input_paths.items()},
    }

    write_json(verdicts_dir / "three_layer_final_verdict.json", verdict)

    summary = {
        "schema": "s3.stage3.m15.p11_d_three_layer_summary.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "final_status": final_status,
        "strict_three_layer_status": strict_three_layer_status,
        "e4_status": e4_status,
        "confirmed_allowed": confirmed_allowed,
        "blocking_layer": blocking_layer,
        "attribution_layer": attribution_layer,
        "confidence": confidence,
        "announced_view_window_mapping_level": av_window,
        "announced_view_strict_aligned": av_strict,
        "object_layer_aligned": object_layer_aligned,
        "vrp_layer_aligned": vrp_layer_aligned,
    }

    write_json(outputs_dir / "three_layer_summary.json", summary)

    snapshot_dir = outputs_dir / "input_snapshot"
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    for name, src in input_paths.items():
        shutil.copy2(src, snapshot_dir / f"{name}.json")

    sha_lines = []
    for p in sorted(snapshot_dir.glob("*.json")) + [
        verdicts_dir / "three_layer_final_verdict.json",
        outputs_dir / "three_layer_summary.json",
    ]:
        sha_lines.append(f"{sha256_file(p)}  {p.relative_to(out_dir)}")

    (outputs_dir / "SHA256SUMS.txt").write_text(
        "\n".join(sha_lines) + "\n",
        encoding="utf-8",
    )

    acceptance = len(blockers) == 0 and bool(final_status)

    acceptance_text = f"""P11_D_THREE_LAYER_FINAL_GATE=DONE

created_at_utc = {utc_now()}

snapshot_group_id = {group_id}

final_status = {final_status}
strict_three_layer_status = {strict_three_layer_status}
e4_status = {e4_status}
confirmed_allowed = {confirmed_allowed}
blocking_layer = {blocking_layer}
attribution_layer = {attribution_layer}
confidence = {confidence}

announced_view:
  collection_mode = {av_collection_mode}
  group_complete = {av_complete}
  window_mapping_level = {av_window}
  generated_time_skew_seconds = {av_time_skew}
  strict_announced_view_aligned = {av_strict}
  semantic_announced_view_aligned = {av_semantic}
  all_pairwise_diff_count = {av_pairwise_diff_count}

object_layer:
  group_complete = {object_group_complete}
  object_layer_aligned = {object_layer_aligned}
  object_roots_aligned = {object_roots_aligned}
  effective_object_roots_aligned = {effective_object_roots_aligned}
  all_pairwise_inventory_diff_count = {object_inventory_diff_count}
  all_pairwise_active_manifest_diff_count = {active_manifest_diff_count}

vrp_layer:
  group_complete = {vrp_group_complete}
  vrp_layer_aligned = {vrp_layer_aligned}
  all_vrp_roots_aligned = {all_vrp_roots_aligned}
  all_pairwise_entry_level_diff_count = {vrp_pairwise_entry_level_diff_count}
  min_pairwise_jaccard_similarity = {vrp_min_pairwise_jaccard_similarity}

p10_baseline:
  final_status = {p10_final_status}
  e4_status = {p10_e4_status}
  confirmed_allowed = {p10_confirmed_allowed}
  blocking_layer = {p10_blocking_layer}

warnings = {warnings}
blockers = {blockers}

interpretation:
  {interpretation}

runtime_changes:
  collector_main_service_restarted = False
  probe_restarted = False
  new_validator_installed = False
  bgp_data_loaded = False
  cron_enabled = False

outputs:
  {verdicts_dir / "three_layer_final_verdict.json"}
  {outputs_dir / "three_layer_summary.json"}
  {outputs_dir / "SHA256SUMS.txt"}

next_batch:
  Batch 4 / A4 / P11 evidence pack

P11_D_acceptance = {acceptance}
"""

    (checks_dir / "P11_D_three_layer_final_gate_acceptance.txt").write_text(
        acceptance_text,
        encoding="utf-8",
    )

    run_manifest = {
        "schema": "s3.stage3.m15.p11_d_three_layer_final_gate_manifest.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "p11_d_id": out_dir.name,
        "p11_d_dir": str(out_dir),
        "final_status": final_status,
        "strict_three_layer_status": strict_three_layer_status,
        "e4_status": e4_status,
        "confirmed_allowed": confirmed_allowed,
        "blocking_layer": blocking_layer,
        "attribution_layer": attribution_layer,
        "confidence": confidence,
        "final_verdict": str(verdicts_dir / "three_layer_final_verdict.json"),
        "summary": str(outputs_dir / "three_layer_summary.json"),
        "sha256sums": str(outputs_dir / "SHA256SUMS.txt"),
        "warnings": warnings,
        "blockers": blockers,
        "P11_D_acceptance": acceptance,
    }

    write_json(
        manifests_dir / "P11_D_three_layer_final_gate_manifest.json",
        run_manifest,
    )

    print(acceptance_text)

    if not acceptance:
        raise SystemExit("[BLOCKED] P11-D acceptance is False")


if __name__ == "__main__":
    main()
