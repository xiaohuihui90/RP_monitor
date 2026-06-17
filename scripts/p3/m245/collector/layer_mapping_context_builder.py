from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def infer_mapping_strength(run_dir: Path, loop_summary: dict[str, Any]) -> tuple[str, str, list[str]]:
    blockers = [
        "delegated_pp_advertised_view_missing",
        "validator_cache_snapshot_missing",
        "validator_effective_input_missing",
        "accepted_object_set_not_available",
    ]

    # 后续 H7 接入 validator_cache_view 后，这里可升级为 medium。
    cache_view_candidates = [
        run_dir / "indexes" / "validator_cache_view_records.jsonl",
        run_dir / "outputs" / "validator_cache_view_summary.json",
    ]

    cache_view_available = any(p.exists() and p.stat().st_size > 0 for p in cache_view_candidates)

    if cache_view_available:
        blockers = [
            b for b in blockers
            if b != "validator_cache_snapshot_missing"
        ]
        return "medium", "validator_cache_associated_output", blockers

    return "weak", "same_window_association", blockers


def build_context(project_dir: Path, collector_run_dir: Path, window_id: str) -> dict[str, Any]:
    outputs = collector_run_dir / "outputs"

    loop_summary = read_json(outputs / "THREE_LAYER_BASELINE_LOOP_SUMMARY.json")
    matrix = read_json(outputs / "M245_three_layer_status_matrix.json")
    m25 = read_json(outputs / "M25_basic_attribution_summary.json")

    mapping_strength, mapping_type, blockers = infer_mapping_strength(collector_run_dir, loop_summary)

    layer_status = loop_summary.get("layer_status") or {}
    probe_count = loop_summary.get("probe_count")
    probe_health_ok_count = loop_summary.get("probe_health_ok_count")

    advertised_layer_status = layer_status.get("advertised_view")
    object_layer_status = layer_status.get("object_view")
    validation_layer_status = layer_status.get("validation_output")

    context = {
        "schema": "s3.m245.layer_mapping_context.v1",
        "created_at_utc": utc_now(),
        "window_id": window_id,
        "collector_run_dir": str(collector_run_dir),

        "scope_alignment": "partial",
        "mapping_strength": mapping_strength,
        "mapping_type": mapping_type,

        "advertised_view_scope": {
            "scope_type": "top_level_rir_pp_only",
            "covered_pp": ["arin", "ripe", "apnic"],
            "delegated_pp_covered": False,
            "notes": [
                "current_advertised_view_does_not_cover_all_delegated_pp",
                "rir_parent_pp_reachability_does_not_imply_child_pp_reachability",
            ],
        },

        "object_view_scope": {
            "scope_type": "observer_or_local_cache_inventory",
            "is_validator_effective_input": False,
            "object_root_available": bool(matrix.get("object_view")),
            "notes": [
                "s3_observer_object_view_is_not_equal_to_routinator_accepted_input",
                "object_inventory_may_include_cache_or_observer_artifacts",
            ],
        },

        "validation_output_scope": {
            "scope_type": "global_validator_vrp_output",
            "validator": "routinator",
            "covers_delegated_pp_indirectly": True,
            "notes": [
                "routinator_validation_output_depends_on_global_rpki_repository_graph",
                "validation_output_may_be_affected_by_child_ca_and_delegated_pp",
            ],
        },

        "layer_status": {
            "advertised_view": advertised_layer_status,
            "object_view": object_layer_status,
            "validation_output": validation_layer_status,
        },

        "probe_context": {
            "probe_count": probe_count,
            "probe_health_ok_count": probe_health_ok_count,
        },

        "blockers": blockers,

        "allowed_claims": [
            "same_window_multilayer_divergence_observed",
            "diagnostic_only_attribution",
            "anomaly_radar_trigger",
        ],

        "disallowed_claims": [
            "top_level_rir_pp_caused_global_vrp_divergence",
            "observer_object_view_equals_validator_input",
            "object_root_caused_vrp_root",
            "validator_cache_root_equals_accepted_object_set",
        ],

        "recommended_next_steps": [
            "add_validator_refresh_policy",
            "add_validator_cache_view",
            "add_passive_delegated_pp_inventory",
            "add_anomaly_evidence_pack",
        ],

        "source_files": {
            "THREE_LAYER_BASELINE_LOOP_SUMMARY": str(outputs / "THREE_LAYER_BASELINE_LOOP_SUMMARY.json"),
            "M245_three_layer_status_matrix": str(outputs / "M245_three_layer_status_matrix.json"),
            "M25_basic_attribution_summary": str(outputs / "M25_basic_attribution_summary.json"),
        },
    }

    return context


def update_json_with_mapping(path: Path, context: dict[str, Any]) -> bool:
    if not path.exists():
        return False

    obj = read_json(path)

    obj["scope_alignment"] = context["scope_alignment"]
    obj["mapping_strength"] = context["mapping_strength"]
    obj["mapping_type"] = context["mapping_type"]
    obj["mapping_blockers"] = context["blockers"]
    obj["mapping_allowed_claims"] = context["allowed_claims"]
    obj["mapping_disallowed_claims"] = context["disallowed_claims"]

    write_json(path, obj)
    return True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--collector-run-dir", required=True)
    ap.add_argument("--window-id", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--update-existing-summaries", action="store_true")
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    collector_run_dir = Path(args.collector_run_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    hard_fail: list[str] = []

    if not collector_run_dir.exists():
        hard_fail.append("collector_run_dir_missing")

    outputs = collector_run_dir / "outputs"
    if not (outputs / "THREE_LAYER_BASELINE_LOOP_SUMMARY.json").exists():
        hard_fail.append("loop_summary_missing")
    if not (outputs / "M245_three_layer_status_matrix.json").exists():
        hard_fail.append("status_matrix_missing")
    if not (outputs / "M25_basic_attribution_summary.json").exists():
        hard_fail.append("m25_summary_missing")

    context = {}
    if not hard_fail:
        context = build_context(project_dir, collector_run_dir, args.window_id)
        write_json(outputs / "M245_layer_mapping_context.json", context)
        write_json(out_dir / "M245_layer_mapping_context.json", context)

        updated = {}
        if args.update_existing_summaries:
            updated["THREE_LAYER_BASELINE_LOOP_SUMMARY"] = update_json_with_mapping(
                outputs / "THREE_LAYER_BASELINE_LOOP_SUMMARY.json",
                context,
            )
            updated["M25_basic_attribution_summary"] = update_json_with_mapping(
                outputs / "M25_basic_attribution_summary.json",
                context,
            )
        context["updated_existing_summaries"] = updated

    status = "PASS" if not hard_fail else "FAIL"

    summary = {
        "schema": "s3.m245.h3a.layer_mapping_context_check.v1",
        "status": status,
        "created_at_utc": utc_now(),
        "window_id": args.window_id,
        "collector_run_dir": str(collector_run_dir),
        "mapping_context_path": str(outputs / "M245_layer_mapping_context.json"),
        "scope_alignment": context.get("scope_alignment"),
        "mapping_strength": context.get("mapping_strength"),
        "mapping_type": context.get("mapping_type"),
        "blockers": context.get("blockers"),
        "hard_fail": hard_fail,
    }

    write_json(out_dir / "H3A_layer_mapping_context_summary.json", summary)

    check_path = out_dir / "H3A_LAYER_MAPPING_CONTEXT_CHECK.txt"
    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"H3A_LAYER_MAPPING_CONTEXT={status}\n\n")
        f.write(f"created_at_utc = {summary['created_at_utc']}\n")
        f.write(f"window_id = {args.window_id}\n")
        f.write(f"collector_run_dir = {collector_run_dir}\n")
        f.write(f"mapping_context_path = {summary['mapping_context_path']}\n")
        f.write(f"scope_alignment = {summary['scope_alignment']}\n")
        f.write(f"mapping_strength = {summary['mapping_strength']}\n")
        f.write(f"mapping_type = {summary['mapping_type']}\n")
        f.write(f"blockers = {summary['blockers']}\n")
        f.write(f"hard_fail = {hard_fail}\n")

    print(f"H3A_CHECK={check_path}")
    print(f"H3A_STATUS={status}")
    print(f"H3A_MAPPING_CONTEXT={outputs / 'M245_layer_mapping_context.json'}")


if __name__ == "__main__":
    main()
