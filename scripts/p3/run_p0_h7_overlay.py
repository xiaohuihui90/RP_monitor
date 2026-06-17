#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
from pathlib import Path
from typing import Any

from s3lib.p0.jsonio import read_json, write_json
from s3lib.p0.scanner import scan_window_dirs, window_id_from_dir
from s3lib.p0.timeutil import utc_now


OLD_CACHE_BLOCKERS = {
    "validator_cache_snapshot_missing",
    "validator_cache_snapshot_absent",
}

NEW_CACHE_BLOCKER = "validator_cache_view_observed_but_unstable"

REQUIRED_BLOCKERS = {
    "delegated_pp_advertised_view_missing",
    "validator_effective_input_missing",
    "accepted_object_set_not_available",
    "validator_cache_view_observed_but_unstable",
    "content_hash_not_computed",
    "manifest_effective_object_set_missing",
}

REQUIRED_ALLOWED_CLAIMS = {
    "same_window_multilayer_divergence_observed",
    "diagnostic_only_attribution",
    "anomaly_radar_trigger",
    "validator_cache_view_observed",
}

REQUIRED_DISALLOWED_CLAIMS = {
    "observer_object_view_equals_validator_input",
    "object_root_caused_vrp_root",
    "validator_logical_cache_index_root_equals_accepted_object_set",
    "validator_cache_view_caused_vrp_output",
    "validator_implementation_divergence",
    "high_confidence_e4_attribution",
    "high_confidence_attribution",
}


def normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if item is None:
                continue
            out.append(str(item))
        return out
    return [str(value)]


def merge_str_list(existing: Any, required: set[str]) -> list[str]:
    values = normalize_list(existing)
    cleaned: list[str] = []

    for item in values:
        if item in OLD_CACHE_BLOCKERS:
            item = NEW_CACHE_BLOCKER
        if item not in cleaned:
            cleaned.append(item)

    for item in sorted(required):
        if item not in cleaned:
            cleaned.append(item)

    return sorted(cleaned)


def recursive_replace_old_cache_blockers(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: recursive_replace_old_cache_blockers(v) for k, v in obj.items()}

    if isinstance(obj, list):
        return [recursive_replace_old_cache_blockers(v) for v in obj]

    if isinstance(obj, str) and obj in OLD_CACHE_BLOCKERS:
        return NEW_CACHE_BLOCKER

    return obj


def update_mapping_target(target: dict[str, Any]) -> dict[str, Any]:
    target["mapping_strength"] = "weak"
    target["mapping_type"] = "validator_cache_view_observed_but_unstable"

    target["validator_cache_view_status"] = "observed_but_unstable"
    target["validator_cache_view_medium_eligible"] = False
    target["validator_cache_view_accepted_object_set_available"] = False
    target["strong_causal_claim_allowed"] = False

    target["attribution_confidence"] = "weak"
    target.setdefault("detection_confidence", "medium-high")

    target["blockers"] = merge_str_list(target.get("blockers"), REQUIRED_BLOCKERS)
    target["allowed_claims"] = merge_str_list(target.get("allowed_claims"), REQUIRED_ALLOWED_CLAIMS)
    target["disallowed_claims"] = merge_str_list(target.get("disallowed_claims"), REQUIRED_DISALLOWED_CLAIMS)

    return target


def build_h7_overlay(base: dict[str, Any], window_id: str, base_path: Path) -> dict[str, Any]:
    base_replaced = recursive_replace_old_cache_blockers(copy.deepcopy(base))

    overlay: dict[str, Any] = copy.deepcopy(base_replaced)

    previous_mapping_strength = None
    previous_mapping_type = None

    if isinstance(base, dict):
        previous_mapping_strength = base.get("mapping_strength")
        previous_mapping_type = base.get("mapping_type")

    overlay["schema"] = "s3.p0.layer_mapping_context_h7_overlay.v1"
    overlay["window_id"] = window_id
    overlay["generated_at_utc"] = utc_now()

    overlay["h7_overlay"] = {
        "applied": True,
        "non_destructive": True,
        "base_mapping_context_path": str(base_path),
        "reason": (
            "Routinator validator cache view is observed but unstable; "
            "do not treat validator cache wrapper or logical cache index as accepted object set."
        ),
        "previous_mapping_strength": previous_mapping_strength,
        "previous_mapping_type": previous_mapping_type,
        "new_mapping_strength": "weak",
        "new_mapping_type": "validator_cache_view_observed_but_unstable",
    }

    overlay["h7_overlay_applied"] = True
    overlay["h7_overlay_non_destructive"] = True
    overlay["base_mapping_context_path"] = str(base_path)

    update_mapping_target(overlay)

    # Some older contexts may nest the real mapping object under mapping_context.
    # Keep root-level fields for P0 consumers, and also patch nested context if it exists.
    nested = overlay.get("mapping_context")
    if isinstance(nested, dict):
        update_mapping_target(nested)

    return overlay


def locate_mapping_context(window_dir: Path) -> Path | None:
    preferred = window_dir / "outputs" / "M245_layer_mapping_context.json"
    if preferred.exists():
        return preferred

    candidates = sorted(window_dir.rglob("M245_layer_mapping_context.json"))
    if candidates:
        return candidates[0]

    return None


def overlay_path_for(mapping_path: Path) -> Path:
    return mapping_path.with_name("M245_layer_mapping_context_h7_overlay.json")


def validate_overlay(overlay: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if overlay.get("mapping_strength") != "weak":
        errors.append("mapping_strength_not_weak")

    if overlay.get("mapping_type") != "validator_cache_view_observed_but_unstable":
        errors.append("mapping_type_not_h7_observed_but_unstable")

    if overlay.get("validator_cache_view_status") != "observed_but_unstable":
        errors.append("validator_cache_view_status_not_observed_but_unstable")

    if overlay.get("validator_cache_view_medium_eligible") is not False:
        errors.append("medium_eligible_not_false")

    if overlay.get("validator_cache_view_accepted_object_set_available") is not False:
        errors.append("accepted_object_set_available_not_false")

    if overlay.get("strong_causal_claim_allowed") is not False:
        errors.append("strong_causal_claim_allowed_not_false")

    blockers = set(normalize_list(overlay.get("blockers")))
    if NEW_CACHE_BLOCKER not in blockers:
        errors.append("missing_h7_blocker")

    disallowed = set(normalize_list(overlay.get("disallowed_claims")))
    missing_disallowed = REQUIRED_DISALLOWED_CLAIMS - disallowed
    if missing_disallowed:
        errors.append("missing_disallowed_claims:" + ",".join(sorted(missing_disallowed)))

    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--history-root",
        default="data/p3_collector/m245_three_layer_baseline/history",
    )
    parser.add_argument(
        "--out-dir",
        default="data/p3_collector/m245_three_layer_baseline/p0_acceptance",
    )
    args = parser.parse_args()

    history_root = Path(args.history_root)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    window_dirs = scan_window_dirs(history_root)

    records: list[dict[str, Any]] = []
    missing_mapping_context: list[str] = []
    bad_json: list[str] = []
    validation_errors: list[dict[str, Any]] = []

    overlay_written = 0

    for window_dir in window_dirs:
        window_id = window_id_from_dir(window_dir)
        mapping_path = locate_mapping_context(window_dir)

        if mapping_path is None:
            missing_mapping_context.append(str(window_dir))
            records.append({
                "window_id": window_id,
                "window_dir": str(window_dir),
                "status": "mapping_context_missing",
            })
            continue

        base = read_json(mapping_path)
        if not isinstance(base, dict):
            bad_json.append(str(mapping_path))
            records.append({
                "window_id": window_id,
                "window_dir": str(window_dir),
                "mapping_context_path": str(mapping_path),
                "status": "mapping_context_json_invalid",
            })
            continue

        overlay = build_h7_overlay(base, window_id, mapping_path)
        errors = validate_overlay(overlay)

        out_path = overlay_path_for(mapping_path)
        write_json(out_path, overlay)
        overlay_written += 1

        if errors:
            validation_errors.append({
                "window_id": window_id,
                "overlay_path": str(out_path),
                "errors": errors,
            })

        records.append({
            "window_id": window_id,
            "window_dir": str(window_dir),
            "mapping_context_path": str(mapping_path),
            "overlay_path": str(out_path),
            "status": "overlay_written" if not errors else "overlay_written_with_validation_errors",
            "validation_errors": errors,
        })

    mapping_strength_always_weak = not validation_errors
    medium_eligible_always_false = not any(
        "medium_eligible_not_false" in err
        for rec in validation_errors
        for err in rec.get("errors", [])
    )

    status = "PASS"
    if overlay_written == 0:
        status = "FAIL"
    if validation_errors:
        status = "FAIL"

    summary = {
        "schema": "s3.p0.h7_overlay_summary.v1",
        "generated_at_utc": utc_now(),
        "status": status,
        "history_root": str(history_root),
        "out_dir": str(out_dir),
        "windows_scanned": len(window_dirs),
        "mapping_context_found_windows": len(window_dirs) - len(missing_mapping_context) - len(bad_json),
        "overlay_written_windows": overlay_written,
        "missing_mapping_context_count": len(missing_mapping_context),
        "bad_json_count": len(bad_json),
        "validation_error_count": len(validation_errors),
        "mapping_strength_always_weak": mapping_strength_always_weak,
        "validator_cache_view_medium_eligible_always_false": medium_eligible_always_false,
        "validator_cache_view_accepted_object_set_available_always_false": not validation_errors,
        "non_destructive": True,
        "records": records,
        "missing_mapping_context": missing_mapping_context,
        "bad_json": bad_json,
        "validation_errors": validation_errors,
    }

    write_json(out_dir / "p0_h7_overlay_summary.json", summary)

    txt_lines = [
        f"P0_H7_OVERLAY={status}",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"history_root = {summary['history_root']}",
        f"windows_scanned = {summary['windows_scanned']}",
        f"mapping_context_found_windows = {summary['mapping_context_found_windows']}",
        f"overlay_written_windows = {summary['overlay_written_windows']}",
        f"missing_mapping_context_count = {summary['missing_mapping_context_count']}",
        f"bad_json_count = {summary['bad_json_count']}",
        f"validation_error_count = {summary['validation_error_count']}",
        f"mapping_strength_always_weak = {summary['mapping_strength_always_weak']}",
        f"validator_cache_view_medium_eligible_always_false = {summary['validator_cache_view_medium_eligible_always_false']}",
        f"non_destructive = {summary['non_destructive']}",
    ]

    (out_dir / "p0_h7_overlay_summary.txt").write_text(
        "\n".join(txt_lines) + "\n",
        encoding="utf-8",
    )

    print("\n".join(txt_lines))


if __name__ == "__main__":
    main()
