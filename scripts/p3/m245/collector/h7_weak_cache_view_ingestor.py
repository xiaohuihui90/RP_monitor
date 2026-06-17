from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def classify_h7(summary: dict[str, Any]) -> dict[str, Any]:
    available = summary.get("validator_cache_view_available") is True
    stable = summary.get("validator_logical_cache_index_stable") is True
    candidate = summary.get("validator_cache_view_mapping_strength_candidate")
    medium_eligible = summary.get("validator_cache_view_medium_eligible") is True
    accepted_available = summary.get("validator_cache_view_accepted_object_set_available") is True

    blockers = []
    allowed_claims = []
    disallowed_claims = []

    if not available:
        status = "missing"
        mapping_effect = "keep_weak"
        blockers.append("validator_cache_snapshot_missing")
    elif stable and candidate in ["medium_candidate_index_only", "medium_candidate"] and medium_eligible:
        status = "stable_medium_candidate"
        mapping_effect = "medium_candidate_index_only"
        allowed_claims.append("validator_cache_index_associated_with_output")
        blockers.extend([
            "accepted_object_set_not_available",
            "content_hash_not_computed",
            "manifest_effective_object_set_missing",
        ])
    else:
        status = "observed_but_unstable"
        mapping_effect = "keep_weak"
        allowed_claims.append("validator_cache_view_observed")
        blockers.extend([
            "validator_cache_view_observed_but_unstable",
            "accepted_object_set_not_available",
            "content_hash_not_computed",
            "manifest_effective_object_set_missing",
        ])

    disallowed_claims.extend([
        "validator_logical_cache_index_root_equals_accepted_object_set",
        "validator_cache_view_caused_vrp_output",
        "observer_object_view_equals_validator_input",
        "high_confidence_e4_attribution",
    ])

    return {
        "validator_cache_view_status": status,
        "mapping_effect": mapping_effect,
        "validator_cache_view_available": available,
        "validator_logical_cache_index_stable": stable,
        "validator_cache_view_mapping_strength_candidate": candidate,
        "validator_cache_view_medium_eligible": medium_eligible,
        "accepted_object_set_available": accepted_available,
        "validator_logical_cache_index_root": summary.get("validator_logical_cache_index_root"),
        "validator_logical_cache_index_root_method": summary.get("validator_logical_cache_index_root_method"),
        "blockers": blockers,
        "allowed_claims": allowed_claims,
        "disallowed_claims": disallowed_claims,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project-dir", default=".")
    ap.add_argument("--probe-run-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    project_dir = Path(args.project_dir).resolve()
    probe_run_dir = Path(args.probe_run_dir).resolve()
    out_dir = Path(args.out_dir).resolve()

    checks_dir = out_dir / "checks"
    outputs_dir = out_dir / "outputs"
    checks_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    summary_path = probe_run_dir / "outputs" / "m245_probe_window_summary.json"
    cache_view_path = probe_run_dir / "outputs" / "validator_cache_view_summary.json"

    hard_fail = []

    if not summary_path.exists():
        hard_fail.append("probe_summary_missing")
        summary = {}
    else:
        summary = load_json(summary_path)

    if not cache_view_path.exists():
        cache_view = {}
    else:
        cache_view = load_json(cache_view_path)

    h7 = classify_h7(summary)

    probe_status = summary.get("probe_status") or summary.get("status")
    if probe_status != "PASS":
        hard_fail.append("probe_window_not_pass")

    if h7["validator_cache_view_status"] == "missing":
        hard_fail.append("validator_cache_view_missing")

    status = "PASS" if not hard_fail else "FAIL"
    created = utc_now()

    result = {
        "schema": "s3.m245.h7.collector_weak_cache_view_ingest.v1",
        "status": status,
        "created_at_utc": created,
        "project_dir": str(project_dir),
        "probe_run_dir": str(probe_run_dir),
        "summary_path": str(summary_path),
        "cache_view_path": str(cache_view_path),
        "probe_id": summary.get("probe_id"),
        "window_id": summary.get("window_id"),
        "probe_status": probe_status,
        "window_quality": summary.get("window_quality"),
        "validation_output_quality": summary.get("validation_output_quality"),
        "vrp_count": summary.get("vrp_count"),
        "h7_context": h7,
        "cache_view_medium_blockers": cache_view.get("medium_blockers"),
        "hard_fail": hard_fail,
    }

    write_json(outputs_dir / "H7_collector_weak_cache_view_ingest_summary.json", result)

    check_path = checks_dir / "H7_COLLECTOR_WEAK_CACHE_VIEW_INGEST_CHECK.txt"
    with check_path.open("w", encoding="utf-8") as f:
        f.write(f"H7_COLLECTOR_WEAK_CACHE_VIEW_INGEST={status}\n\n")
        f.write(f"created_at_utc = {created}\n")
        f.write(f"probe_id = {result['probe_id']}\n")
        f.write(f"window_id = {result['window_id']}\n")
        f.write(f"probe_status = {result['probe_status']}\n")
        f.write(f"window_quality = {result['window_quality']}\n")
        f.write(f"validation_output_quality = {result['validation_output_quality']}\n")
        f.write(f"vrp_count = {result['vrp_count']}\n")
        f.write(f"validator_cache_view_status = {h7['validator_cache_view_status']}\n")
        f.write(f"mapping_effect = {h7['mapping_effect']}\n")
        f.write(f"validator_cache_view_available = {h7['validator_cache_view_available']}\n")
        f.write(f"validator_logical_cache_index_stable = {h7['validator_logical_cache_index_stable']}\n")
        f.write(f"validator_cache_view_medium_eligible = {h7['validator_cache_view_medium_eligible']}\n")
        f.write(f"validator_logical_cache_index_root = {h7['validator_logical_cache_index_root']}\n")
        f.write(f"blockers = {h7['blockers']}\n")
        f.write(f"allowed_claims = {h7['allowed_claims']}\n")
        f.write(f"disallowed_claims = {h7['disallowed_claims']}\n")
        f.write(f"hard_fail = {hard_fail}\n")
        f.write(f"summary_path = {outputs_dir / 'H7_collector_weak_cache_view_ingest_summary.json'}\n")

    print(f"H7_COLLECTOR_WEAK_CACHE_VIEW_INGEST_CHECK={check_path}")
    print(f"H7_COLLECTOR_WEAK_CACHE_VIEW_INGEST_STATUS={status}")


if __name__ == "__main__":
    main()
