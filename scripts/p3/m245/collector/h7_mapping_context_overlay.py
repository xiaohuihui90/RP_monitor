from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def uniq(xs: list[str]) -> list[str]:
    out = []
    seen = set()
    for x in xs:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def build_overlay(base: dict[str, Any], h7_ingest: dict[str, Any]) -> dict[str, Any]:
    h7 = h7_ingest.get("h7_context", {}) or {}

    base_blockers = list(base.get("blockers") or [])
    base_allowed = list(base.get("allowed_claims") or [])
    base_disallowed = list(base.get("disallowed_claims") or [])

    h7_status = h7.get("validator_cache_view_status")
    mapping_effect = h7.get("mapping_effect")

    blockers = [b for b in base_blockers if b != "validator_cache_snapshot_missing"]
    allowed_claims = list(base_allowed)
    disallowed_claims = list(base_disallowed)

    mapping_strength = base.get("mapping_strength") or "weak"
    mapping_type = base.get("mapping_type") or "same_window_association"

    if h7_status == "observed_but_unstable":
        blockers.extend([
            "validator_cache_view_observed_but_unstable",
            "accepted_object_set_not_available",
            "content_hash_not_computed",
            "manifest_effective_object_set_missing",
        ])
        allowed_claims.append("validator_cache_view_observed")
        mapping_strength = "weak"
        mapping_type = "validator_cache_view_observed_but_unstable"

    elif h7_status == "stable_medium_candidate" and mapping_effect == "medium_candidate_index_only":
        blockers.extend([
            "accepted_object_set_not_available",
            "content_hash_not_computed",
            "manifest_effective_object_set_missing",
        ])
        allowed_claims.append("validator_cache_index_associated_with_output")
        mapping_strength = "medium_candidate"
        mapping_type = "validator_cache_index_associated_output"

    elif h7_status == "missing":
        blockers.append("validator_cache_snapshot_missing")
        mapping_strength = "weak"
        mapping_type = "same_window_association"

    else:
        blockers.append("validator_cache_view_status_unknown")
        mapping_strength = "weak"
        mapping_type = "same_window_association"

    disallowed_claims.extend([
        "validator_logical_cache_index_root_equals_accepted_object_set",
        "validator_cache_view_caused_vrp_output",
        "observer_object_view_equals_validator_input",
        "high_confidence_e4_attribution",
    ])

    overlay = dict(base)
    overlay.update({
        "schema": "s3.m245.layer_mapping_context.h7_overlay.v1",
        "created_at_utc": utc_now(),
        "h7_overlay_applied": True,
        "h7_validator_cache_view_status": h7_status,
        "h7_mapping_effect": mapping_effect,
        "validator_cache_view_available": h7.get("validator_cache_view_available"),
        "validator_logical_cache_index_stable": h7.get("validator_logical_cache_index_stable"),
        "validator_cache_view_medium_eligible": h7.get("validator_cache_view_medium_eligible"),
        "validator_logical_cache_index_root": h7.get("validator_logical_cache_index_root"),
        "validator_logical_cache_index_root_method": h7.get("validator_logical_cache_index_root_method"),
        "mapping_strength": mapping_strength,
        "mapping_type": mapping_type,
        "blockers": uniq(blockers),
        "allowed_claims": uniq(allowed_claims),
        "disallowed_claims": uniq(disallowed_claims),
        "notes": uniq(list(base.get("notes") or []) + [
            "h7_overlay_does_not_prove_accepted_object_set",
            "h7_overlay_does_not_enable_high_causality",
        ]),
    })

    return overlay


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-context", required=False)
    ap.add_argument("--h7-ingest-summary", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    out_dir = Path(args.out_dir).resolve()
    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)

    h7_ingest = load_json(Path(args.h7_ingest_summary).resolve())

    if args.base_context and Path(args.base_context).exists():
        base = load_json(Path(args.base_context).resolve())
    else:
        base = {
            "schema": "s3.m245.layer_mapping_context.synthetic_base.v1",
            "scope_alignment": "partial",
            "mapping_strength": "weak",
            "mapping_type": "same_window_association",
            "blockers": [
                "delegated_pp_advertised_view_missing",
                "validator_cache_snapshot_missing",
                "validator_effective_input_missing",
                "accepted_object_set_not_available",
            ],
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
        }

    overlay = build_overlay(base, h7_ingest)

    hard_fail = []

    blockers = overlay.get("blockers") or []
    if overlay.get("h7_validator_cache_view_status") == "observed_but_unstable":
        if "validator_cache_snapshot_missing" in blockers:
            hard_fail.append("snapshot_missing_not_removed")
        if "validator_cache_view_observed_but_unstable" not in blockers:
            hard_fail.append("unstable_cache_blocker_missing")
        if overlay.get("mapping_strength") != "weak":
            hard_fail.append("mapping_strength_should_remain_weak")

    status = "PASS" if not hard_fail else "FAIL"

    overlay_path = outputs / "M245_layer_mapping_context_h7_overlay.json"
    write_json(overlay_path, overlay)

    check_path = checks / "H7_MAPPING_CONTEXT_OVERLAY_CHECK.txt"
    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"H7_MAPPING_CONTEXT_OVERLAY={status}\n\n")
        f.write(f"created_at_utc = {utc_now()}\n")
        f.write(f"h7_validator_cache_view_status = {overlay.get('h7_validator_cache_view_status')}\n")
        f.write(f"h7_mapping_effect = {overlay.get('h7_mapping_effect')}\n")
        f.write(f"validator_cache_view_available = {overlay.get('validator_cache_view_available')}\n")
        f.write(f"validator_logical_cache_index_stable = {overlay.get('validator_logical_cache_index_stable')}\n")
        f.write(f"validator_cache_view_medium_eligible = {overlay.get('validator_cache_view_medium_eligible')}\n")
        f.write(f"mapping_strength = {overlay.get('mapping_strength')}\n")
        f.write(f"mapping_type = {overlay.get('mapping_type')}\n")
        f.write(f"blockers = {overlay.get('blockers')}\n")
        f.write(f"allowed_claims = {overlay.get('allowed_claims')}\n")
        f.write(f"disallowed_claims = {overlay.get('disallowed_claims')}\n")
        f.write(f"hard_fail = {hard_fail}\n")
        f.write(f"overlay_path = {overlay_path}\n")

    print(f"H7_MAPPING_CONTEXT_OVERLAY_CHECK={check_path}")
    print(f"H7_MAPPING_CONTEXT_OVERLAY_STATUS={status}")

    if status != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
