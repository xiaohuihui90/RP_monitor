#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from s3lib.p0.jsonio import read_json, read_jsonl, sha256_file, write_json
from s3lib.p0.scanner import scan_window_dirs, window_id_from_dir
from s3lib.p0.timeutil import utc_now


DISALLOWED_CLAIMS = [
    "observer_object_view_equals_validator_input",
    "object_root_caused_vrp_root",
    "validator_cache_root_equals_accepted_object_set",
    "validator_logical_cache_index_root_equals_accepted_object_set",
    "validator_cache_view_caused_vrp_output",
    "validator_implementation_divergence",
    "high_confidence_attribution",
    "high_confidence_e4_attribution",
]

ALLOWED_CLAIMS = [
    "same_window_multilayer_divergence_observed",
    "diagnostic_only_attribution",
    "anomaly_radar_trigger",
    "validator_cache_view_observed",
    "raw_vrp_retained_for_entry_level_diff",
]


def read_text(path: Path) -> str | None:
    if not path.exists():
        return None
    return path.read_text(encoding="utf-8", errors="ignore")


def compact_json(obj: Any, max_chars: int = 8000) -> str:
    try:
        text = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
    except Exception:
        text = str(obj)
    if len(text) > max_chars:
        return text[:max_chars] + "\n...<truncated>..."
    return text


def layer_status_from_matrix(status_matrix: dict[str, Any]) -> dict[str, str]:
    out = {}

    for layer in ["advertised_view", "object_view", "validation_output", "validator_cache_view"]:
        section = status_matrix.get(layer)
        status = "unknown"

        if isinstance(section, dict):
            for key in ["layer_status", "status", "view_status"]:
                if isinstance(section.get(key), str):
                    status = section[key]
                    break

            if status == "unknown":
                text = json.dumps(section, ensure_ascii=False).lower()
                if "divergent" in text:
                    status = "divergent"
                elif "consistent" in text:
                    status = "consistent"

        out[layer] = status

    return out


def get_probe_ids(status_matrix: dict[str, Any]) -> list[str]:
    probes = set()

    for key in ["probe_status", "probe_health", "probes"]:
        value = status_matrix.get(key)
        if isinstance(value, dict):
            for k in value:
                if isinstance(k, str) and k.startswith("probe-"):
                    probes.add(k)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item.startswith("probe-"):
                    probes.add(item)

    for section in status_matrix.values():
        if isinstance(section, dict):
            for k in section:
                if isinstance(k, str) and k.startswith("probe-"):
                    probes.add(k)

    return sorted(probes)


def source_manifest_for_window(window_dir: Path) -> dict[str, Any]:
    files = []

    candidate_files = [
        window_dir / "checks" / "THREE_LAYER_BASELINE_LOOP_CHECK.txt",
        window_dir / "outputs" / "THREE_LAYER_BASELINE_LOOP_SUMMARY.json",
        window_dir / "outputs" / "M245_three_layer_status_matrix.json",
        window_dir / "outputs" / "M245_layer_mapping_context.json",
        window_dir / "outputs" / "M245_layer_mapping_context_h7_overlay.json",
        window_dir / "outputs" / "validator_runtime_metadata.json",
        window_dir / "outputs" / "raw_vrp_import_manifest.json",
        window_dir / "indexes" / "m245_baseline_diff_records.jsonl",
        window_dir / "indexes" / "m25_trigger_candidate_records.jsonl",
        window_dir / "indexes" / "merged_validation_output_light_records.jsonl",
        window_dir / "indexes" / "merged_validator_context_records.jsonl",
    ]

    for path in candidate_files:
        if path.exists():
            files.append({
                "path": str(path),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            })

    raw_root = window_dir / "outputs" / "raw_vrp"
    if raw_root.exists():
        for path in sorted(raw_root.glob("probe-*/*")):
            if path.is_file():
                files.append({
                    "path": str(path),
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                })

    return {
        "schema": "s3.p0.evidence_source_file_manifest.v1",
        "generated_at_utc": utc_now(),
        "window_id": window_id_from_dir(window_dir),
        "file_count": len(files),
        "files": files,
    }


def build_pack(window_dir: Path) -> dict[str, Any]:
    window_id = window_id_from_dir(window_dir)

    status_matrix = read_json(window_dir / "outputs" / "M245_three_layer_status_matrix.json")
    if not isinstance(status_matrix, dict):
        status_matrix = {}

    mapping_context = read_json(window_dir / "outputs" / "M245_layer_mapping_context_h7_overlay.json")
    if not isinstance(mapping_context, dict):
        mapping_context = read_json(window_dir / "outputs" / "M245_layer_mapping_context.json")
    if not isinstance(mapping_context, dict):
        mapping_context = {}

    validator_metadata = read_json(window_dir / "outputs" / "validator_runtime_metadata.json")
    if not isinstance(validator_metadata, dict):
        validator_metadata = {}

    raw_import_manifest = read_json(window_dir / "outputs" / "raw_vrp_import_manifest.json")
    if not isinstance(raw_import_manifest, dict):
        raw_import_manifest = {}

    diff_records = read_jsonl(window_dir / "indexes" / "m245_baseline_diff_records.jsonl")
    trigger_records = read_jsonl(window_dir / "indexes" / "m25_trigger_candidate_records.jsonl")

    layer_status = layer_status_from_matrix(status_matrix)
    probes = get_probe_ids(status_matrix)

    validation_output_divergent = layer_status.get("validation_output") == "divergent"
    object_view_divergent = layer_status.get("object_view") == "divergent"
    advertised_view_divergent = layer_status.get("advertised_view") == "divergent"

    raw_vrp_ready = validator_metadata.get("raw_vrp_ready") is True

    candidate_causes = []
    if advertised_view_divergent:
        candidate_causes.append("advertised_view_divergence_observed")
    if object_view_divergent:
        candidate_causes.append("object_view_divergence_observed")
    if validation_output_divergent:
        candidate_causes.append("validation_output_divergence_observed")
    if object_view_divergent and validation_output_divergent:
        candidate_causes.append("same_window_object_and_validation_output_divergence_observed")
    if raw_vrp_ready:
        candidate_causes.append("raw_vrp_available_for_m17_entry_diff")

    blockers = sorted(set(
        mapping_context.get("blockers", [])
        if isinstance(mapping_context.get("blockers"), list)
        else []
    ) | {
        "validator_effective_input_missing",
        "accepted_object_set_not_available",
        "manifest_effective_object_set_missing",
        "same_input_replay_missing",
    })

    recommended_next_actions = [
        "run_m17_vrp_entry_level_diff",
        "run_m18_diff_lifetime_tracker",
        "run_m19_roa_to_vrp_mapping_for_persistent_or_high_impact_diffs",
        "run_m20_targeted_l1_l2_l0_backfill_if_diff_scope_out_of_scope",
    ]

    pack = {
        "schema": "s3.p0.basic_evidence_pack.v1",
        "generated_at_utc": utc_now(),
        "window_id": window_id,
        "window_dir": str(window_dir),
        "evidence_pack_type": "diagnostic_only",
        "complete_3probe_window": len(probes) >= 3,
        "probes_observed": probes,

        "layer_status": layer_status,
        "raw_vrp_ready": raw_vrp_ready,
        "raw_vrp_import_manifest_available": bool(raw_import_manifest),
        "validator_metadata_available": bool(validator_metadata),

        "mapping_context": {
            "scope_alignment": mapping_context.get("scope_alignment", "partial"),
            "mapping_strength": mapping_context.get("mapping_strength", "weak"),
            "mapping_type": mapping_context.get("mapping_type"),
            "strong_causal_claim_allowed": False,
            "validator_cache_view_status": mapping_context.get(
                "validator_cache_view_status",
                "observed_but_unstable",
            ),
            "validator_cache_view_medium_eligible": False,
            "accepted_object_set_available": False,
        },

        "detection_confidence": "medium-high",
        "attribution_confidence": "weak",
        "candidate_causes": candidate_causes,
        "blockers": blockers,
        "allowed_claims": ALLOWED_CLAIMS,
        "disallowed_claims": DISALLOWED_CLAIMS,

        "diff_record_count": len(diff_records),
        "trigger_record_count": len(trigger_records),

        "m17_readiness": {
            "m17_candidate": bool(validation_output_divergent and raw_vrp_ready),
            "validation_output_divergent": validation_output_divergent,
            "raw_vrp_ready": raw_vrp_ready,
            "expected_next_input": "raw VRP files under outputs/raw_vrp/probe-*",
        },

        "recommended_next_actions": recommended_next_actions,

        "semantic_note": (
            "This evidence pack is diagnostic-only. It supports same-window multilayer "
            "divergence observation and M17 entry-level diff readiness. It does not claim "
            "that observer object view equals validator input, object root caused VRP root, "
            "validator cache equals accepted object set, or validator implementation divergence."
        ),
    }

    return pack


def build_markdown(pack: dict[str, Any]) -> str:
    lines = []
    lines.append(f"# P0 Basic Evidence Pack: {pack['window_id']}")
    lines.append("")
    lines.append(f"- generated_at_utc: `{pack['generated_at_utc']}`")
    lines.append(f"- evidence_pack_type: `{pack['evidence_pack_type']}`")
    lines.append(f"- complete_3probe_window: `{pack['complete_3probe_window']}`")
    lines.append(f"- probes_observed: `{', '.join(pack['probes_observed'])}`")
    lines.append("")
    lines.append("## Layer status")
    lines.append("")
    for k, v in pack["layer_status"].items():
        lines.append(f"- {k}: `{v}`")
    lines.append("")
    lines.append("## Mapping context")
    lines.append("")
    for k, v in pack["mapping_context"].items():
        lines.append(f"- {k}: `{v}`")
    lines.append("")
    lines.append("## M17 readiness")
    lines.append("")
    for k, v in pack["m17_readiness"].items():
        lines.append(f"- {k}: `{v}`")
    lines.append("")
    lines.append("## Candidate causes")
    lines.append("")
    for x in pack["candidate_causes"]:
        lines.append(f"- {x}")
    lines.append("")
    lines.append("## Blockers")
    lines.append("")
    for x in pack["blockers"]:
        lines.append(f"- {x}")
    lines.append("")
    lines.append("## Allowed claims")
    lines.append("")
    for x in pack["allowed_claims"]:
        lines.append(f"- {x}")
    lines.append("")
    lines.append("## Disallowed claims")
    lines.append("")
    for x in pack["disallowed_claims"]:
        lines.append(f"- {x}")
    lines.append("")
    lines.append("## Recommended next actions")
    lines.append("")
    for x in pack["recommended_next_actions"]:
        lines.append(f"- {x}")
    lines.append("")
    lines.append("## Semantic note")
    lines.append("")
    lines.append(pack["semantic_note"])
    lines.append("")
    return "\n".join(lines)


def is_anomaly_window(window_dir: Path) -> bool:
    status_matrix = read_json(window_dir / "outputs" / "M245_three_layer_status_matrix.json")
    if not isinstance(status_matrix, dict):
        return False

    statuses = layer_status_from_matrix(status_matrix)
    return any(
        statuses.get(layer) == "divergent"
        for layer in ["advertised_view", "object_view", "validation_output"]
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--history-root", default="data/p3_collector/m245_three_layer_baseline/history")
    ap.add_argument("--report-dir", default="data/p3_collector/m245_three_layer_baseline/reports")
    ap.add_argument("--out-dir", default="data/p3_collector/m245_three_layer_baseline/evidence_packs")
    ap.add_argument("--window-id", default="")
    args = ap.parse_args()

    history_root = Path(args.history_root)
    out_root = Path(args.out_dir)
    report_dir = Path(args.report_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    if args.window_id:
        windows = [history_root / f"m245_window_{args.window_id}"]
    else:
        windows = [w for w in scan_window_dirs(history_root) if is_anomaly_window(w)]

    records = []
    failures = []

    for window_dir in windows:
        if not window_dir.exists():
            failures.append({
                "window_dir": str(window_dir),
                "reason": "window_dir_missing",
            })
            continue

        window_id = window_id_from_dir(window_dir)
        pack = build_pack(window_dir)
        source_manifest = source_manifest_for_window(window_dir)

        out_dir = out_root / window_id
        out_dir.mkdir(parents=True, exist_ok=True)

        write_json(out_dir / "evidence_pack.json", pack)
        write_json(out_dir / "source_file_manifest.json", source_manifest)
        (out_dir / "evidence_pack.md").write_text(build_markdown(pack), encoding="utf-8")

        records.append({
            "window_id": window_id,
            "window_dir": str(window_dir),
            "evidence_pack_dir": str(out_dir),
            "m17_candidate": pack["m17_readiness"]["m17_candidate"],
            "raw_vrp_ready": pack["raw_vrp_ready"],
            "mapping_strength": pack["mapping_context"]["mapping_strength"],
        })

    status = "PASS" if records else "FAIL"

    summary = {
        "schema": "s3.p0.basic_evidence_pack_summary.v1",
        "generated_at_utc": utc_now(),
        "status": status,
        "history_root": str(history_root),
        "out_root": str(out_root),
        "evidence_pack_count": len(records),
        "failure_count": len(failures),
        "m17_candidate_evidence_pack_count": sum(1 for r in records if r["m17_candidate"]),
        "records": records,
        "failures": failures,
    }

    write_json(report_dir / "P0_basic_evidence_pack_summary.json", summary)

    txt = [
        f"P0_BASIC_EVIDENCE_PACK={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"history_root = {summary['history_root']}",
        f"out_root = {summary['out_root']}",
        f"evidence_pack_count = {summary['evidence_pack_count']}",
        f"m17_candidate_evidence_pack_count = {summary['m17_candidate_evidence_pack_count']}",
        f"failure_count = {summary['failure_count']}",
    ]

    (report_dir / "P0_basic_evidence_pack_summary.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")
    print("\n".join(txt))


if __name__ == "__main__":
    main()
