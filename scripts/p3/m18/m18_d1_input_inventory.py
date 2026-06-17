#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return default


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    n = 0
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def file_exists(path: Path) -> bool:
    return path.exists() and path.is_file() and path.stat().st_size >= 0


def nonempty_file(path: Path) -> bool:
    return path.exists() and path.is_file() and path.stat().st_size > 0


def main() -> None:
    selected_path = Path("data/p3_collector/m245_three_layer_baseline/m17_vrp_entry_diff_inputs/selected_windows.json")
    m245_history_root = Path("data/p3_collector/m245_three_layer_baseline/history")
    m17_root = Path("data/p3_collector/m17_vrp_entry_diff/history")
    m18_root = Path("data/p3_collector/m18_diff_lifetime/history")

    run_id = "m18_d1_input_inventory_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = Path("data/p3_collector/m18_deep_analysis/history") / run_id
    out_dir = run_dir / "outputs"
    check_dir = run_dir / "checks"
    out_dir.mkdir(parents=True, exist_ok=True)
    check_dir.mkdir(parents=True, exist_ok=True)

    selected_obj = read_json(selected_path, {})
    selected_windows = selected_obj.get("selected_windows", []) if isinstance(selected_obj, dict) else []

    records = []
    counters = Counter()

    for item in selected_windows:
        if not isinstance(item, dict):
            continue

        window_id = item.get("window_id")
        if not window_id:
            continue

        m245_dir = m245_history_root / f"m245_window_{window_id}"
        m245_out = m245_dir / "outputs"
        m245_idx = m245_dir / "indexes"

        m17_dir = m17_root / f"m17_window_{window_id}"
        m17_out = m17_dir / "outputs"

        raw_vrp_root = m245_out / "raw_vrp"
        raw_vrp_import_manifest = m245_out / "raw_vrp_import_manifest.json"
        raw_manifest = read_json(raw_vrp_import_manifest, {})

        canonical_files = sorted(m17_out.glob("canonical_vrp_records_probe-*.jsonl")) if m17_out.exists() else []
        failed_canonical_files = sorted(m17_out.glob("canonical_vrp_failed_records_probe-*.jsonl")) if m17_out.exists() else []

        rec = {
            "schema": "s3.m18.deep_input_inventory.window.v1",
            "window_id": window_id,

            "selected_window_record_available": True,
            "selected_mapping_strength": item.get("mapping_strength"),
            "selected_validation_output_status": item.get("validation_output_status"),
            "selected_raw_vrp_file_count": item.get("raw_vrp_file_count"),

            "m245_window_dir": str(m245_dir),
            "m245_window_exists": m245_dir.exists(),
            "m245_status_matrix_available": nonempty_file(m245_out / "M245_three_layer_status_matrix.json"),
            "m245_mapping_context_available": nonempty_file(m245_out / "M245_layer_mapping_context.json"),
            "m245_window_summary_available": nonempty_file(m245_out / "M245_window_summary.json"),
            "m245_loop_summary_available": nonempty_file(m245_out / "THREE_LAYER_BASELINE_LOOP_SUMMARY.json"),
            "m245_validator_runtime_metadata_available": nonempty_file(m245_out / "validator_runtime_metadata.json"),

            "m245_raw_vrp_root": str(raw_vrp_root),
            "m245_raw_vrp_root_exists": raw_vrp_root.exists(),
            "m245_raw_vrp_import_manifest_available": nonempty_file(raw_vrp_import_manifest),
            "m245_raw_vrp_installed_probe_count": raw_manifest.get("installed_probe_count") if isinstance(raw_manifest, dict) else None,
            "m245_raw_vrp_installed_probes": raw_manifest.get("installed_probes") if isinstance(raw_manifest, dict) else None,

            "m245_merged_validator_context_available": nonempty_file(m245_idx / "merged_validator_context_records.jsonl"),
            "m245_merged_validation_output_light_available": nonempty_file(m245_idx / "merged_validation_output_light_records.jsonl"),

            "m17_window_dir": str(m17_dir),
            "m17_window_exists": m17_dir.exists(),
            "m17_acceptance_available": nonempty_file(m17_out / "M17_ACCEPTANCE.txt"),
            "m17_quality_annotation_available": nonempty_file(m17_out / "M17_quality_annotation.json"),
            "m17_vrp_entry_diff_records_available": nonempty_file(m17_out / "vrp_entry_diff_records.jsonl"),
            "m17_vrp_entry_diff_records_count": count_jsonl(m17_out / "vrp_entry_diff_records.jsonl"),
            "m17_vrp_entry_diff_summary_available": nonempty_file(m17_out / "vrp_entry_diff_summary.json"),
            "m17_pairwise_diff_summary_available": nonempty_file(m17_out / "pairwise_diff_summary.json"),
            "m17_vote_profile_records_available": nonempty_file(m17_out / "vrp_vote_profile_records.jsonl"),
            "m17_vote_profile_records_count": count_jsonl(m17_out / "vrp_vote_profile_records.jsonl"),
            "m17_canonical_probe_file_count": len(canonical_files),
            "m17_failed_canonical_probe_file_count": len(failed_canonical_files),
            "m17_validator_cycle_records_available": nonempty_file(m17_out / "validator_cycle_records.jsonl"),
            "m17_validator_cycle_records_count": count_jsonl(m17_out / "validator_cycle_records.jsonl"),
            "m17_validator_cycle_summary_available": nonempty_file(m17_out / "validator_cycle_summary.json"),
            "m17_validator_effective_input_summary_available": nonempty_file(m17_out / "validator_effective_input_summary.json"),
            "m17_m18_lifetime_seed_available": nonempty_file(m17_out / "m18_lifetime_seed_records.jsonl"),
            "m17_m18_lifetime_seed_count": count_jsonl(m17_out / "m18_lifetime_seed_records.jsonl"),

            "jsonext_source_uri_available": False,
            "repository_metrics_available": False,
            "cache_index_available": False,
            "same_window_cache_snapshot_available": False,
        }

        rec["m18_d2_probewise_lifetime_ready"] = bool(
            rec["m17_vrp_entry_diff_records_available"]
            and rec["m17_vrp_entry_diff_summary_available"]
            and rec["m17_canonical_probe_file_count"] >= 3
        )

        rec["m18_d3_probe_lag_ready"] = bool(
            rec["m18_d2_probewise_lifetime_ready"]
            and rec["m17_validator_cycle_records_available"]
        )

        rec["m18_d4_trailing_cache_v1_ready"] = bool(
            rec["m17_vrp_entry_diff_records_available"]
            and rec["m17_m18_lifetime_seed_available"]
        )

        rec["m18_d4_trailing_cache_supported_ready"] = bool(
            rec["jsonext_source_uri_available"]
            or rec["repository_metrics_available"]
            or rec["cache_index_available"]
        )

        rec["m19_priority_candidate_input_ready"] = bool(
            rec["m17_vrp_entry_diff_records_available"]
            and rec["m17_quality_annotation_available"]
        )

        for k, v in rec.items():
            if isinstance(v, bool) and v:
                counters[k] += 1

        counters["selected_window_count"] += 1
        counters["total_vrp_diff_records"] += rec["m17_vrp_entry_diff_records_count"]
        counters["total_lifetime_seed_records"] += rec["m17_m18_lifetime_seed_count"]

        records.append(rec)

    inventory_json = out_dir / "m18_d1_input_inventory.json"
    inventory_json.write_text(json.dumps({
        "schema": "s3.m18.deep_input_inventory.v1",
        "generated_at_utc": utc_now(),
        "run_id": run_id,
        "selected_windows_path": str(selected_path),
        "window_count": len(records),
        "counters": dict(counters),
        "records": records,
        "semantic_boundary": "weak_mapping_only_no_strong_causal_claim",
        "strong_causal_claim_allowed": False,
        "next_stage": "M18_D2_PROBEWISE_LIFETIME",
    }, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    inventory_jsonl = out_dir / "m18_d1_window_inventory.jsonl"
    with inventory_jsonl.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")

    check_txt = check_dir / "M18_D1_INPUT_INVENTORY_CHECK.txt"
    lines = [
        "M18_D1_INPUT_INVENTORY=PASS",
        f"generated_at_utc = {utc_now()}",
        f"run_id = {run_id}",
        f"selected_window_count = {counters['selected_window_count']}",
        f"m17_window_exists_count = {counters['m17_window_exists']}",
        f"m17_vrp_entry_diff_records_available_count = {counters['m17_vrp_entry_diff_records_available']}",
        f"m17_quality_annotation_available_count = {counters['m17_quality_annotation_available']}",
        f"m17_validator_cycle_records_available_count = {counters['m17_validator_cycle_records_available']}",
        f"m17_validator_effective_input_summary_available_count = {counters['m17_validator_effective_input_summary_available']}",
        f"m18_d2_probewise_lifetime_ready_count = {counters['m18_d2_probewise_lifetime_ready']}",
        f"m18_d3_probe_lag_ready_count = {counters['m18_d3_probe_lag_ready']}",
        f"m18_d4_trailing_cache_v1_ready_count = {counters['m18_d4_trailing_cache_v1_ready']}",
        f"m18_d4_trailing_cache_supported_ready_count = {counters['m18_d4_trailing_cache_supported_ready']}",
        f"m19_priority_candidate_input_ready_count = {counters['m19_priority_candidate_input_ready']}",
        f"total_vrp_diff_records = {counters['total_vrp_diff_records']}",
        f"total_lifetime_seed_records = {counters['total_lifetime_seed_records']}",
        f"inventory_json = {inventory_json}",
        f"inventory_jsonl = {inventory_jsonl}",
        "semantic_boundary = weak_mapping_only_no_strong_causal_claim",
        "strong_causal_claim_allowed = False",
        "next_stage = M18_D2_PROBEWISE_LIFETIME",
    ]

    check_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state = Path("data/p3_collector/m18_deep_analysis/state/current_m18_d1_run.env")
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(
        "\n".join([
            f'export M18_D1_RUN_ID="{run_id}"',
            f'export M18_D1_RUN_DIR="{run_dir}"',
            f'export M18_D1_OUT_DIR="{out_dir}"',
            f'export M18_D1_CHECK_DIR="{check_dir}"',
            f'export M18_D1_INVENTORY_JSON="{inventory_json}"',
            f'export M18_D1_INVENTORY_JSONL="{inventory_jsonl}"',
            "",
        ]),
        encoding="utf-8",
    )

    print(check_txt.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
