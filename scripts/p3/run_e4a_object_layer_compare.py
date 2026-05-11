#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import hashlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_PROBES = ["probe-cd", "probe-bj", "probe-sg"]
PAIRS = [
    ("probe-cd", "probe-bj"),
    ("probe-cd", "probe-sg"),
    ("probe-bj", "probe-sg"),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_jsonl_keys(path: Path) -> tuple[set[str], Counter, list[dict[str, Any]]]:
    keys: set[str] = set()
    type_counter: Counter = Counter()
    sample_rows: list[dict[str, Any]] = []

    if not path.exists():
        return keys, type_counter, sample_rows

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
            except Exception:
                continue

            uri = str(obj.get("uri") or obj.get("relative_path") or "")
            h = str(obj.get("sha256") or obj.get("hash") or "")
            typ = str(obj.get("object_type") or "unknown")

            if not uri or not h:
                continue

            key = f"{uri}|{h}|{typ}"
            keys.add(key)
            type_counter[typ] += 1

            if len(sample_rows) < 20:
                sample_rows.append({
                    "uri": uri,
                    "sha256": h,
                    "object_type": typ,
                    "size_bytes": obj.get("size_bytes"),
                    "source_root": obj.get("source_root"),
                    "evidence_level": obj.get("evidence_level"),
                })

    return keys, type_counter, sample_rows


def key_to_sample(key: str) -> dict[str, str]:
    parts = key.split("|", 2)
    while len(parts) < 3:
        parts.append("")
    return {
        "uri": parts[0],
        "sha256": parts[1],
        "object_type": parts[2],
    }


def pair_diff(left: str, right: str, left_keys: set[str], right_keys: set[str], sample_limit: int) -> dict[str, Any]:
    common = left_keys & right_keys
    only_left = left_keys - right_keys
    only_right = right_keys - left_keys
    union = left_keys | right_keys

    jaccard = len(common) / len(union) if union else 1.0

    type_counter = Counter()
    for k in list(only_left)[:100000]:
        type_counter[key_to_sample(k)["object_type"]] += 1
    for k in list(only_right)[:100000]:
        type_counter[key_to_sample(k)["object_type"]] += 1

    return {
        "pair": f"{left}_vs_{right}",
        "left_probe": left,
        "right_probe": right,
        "left_count": len(left_keys),
        "right_count": len(right_keys),
        "common_count": len(common),
        "only_left_count": len(only_left),
        "only_right_count": len(only_right),
        "entry_level_diff_count": len(only_left) + len(only_right),
        "jaccard_similarity": jaccard,
        "top_diff_object_type": type_counter.most_common(1)[0][0] if type_counter else None,
        "diff_object_type_breakdown_sampled": dict(type_counter),
        "only_left_samples": [key_to_sample(k) for k in sorted(only_left)[:sample_limit]],
        "only_right_samples": [key_to_sample(k) for k in sorted(only_right)[:sample_limit]],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--group-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--sample-limit", type=int, default=50)
    args = ap.parse_args()

    group_dir = Path(args.group_dir)
    out_dir = Path(args.out_dir)

    joint_manifest_path = group_dir / "joint_group_manifest.json"
    if not joint_manifest_path.exists():
        raise SystemExit(f"missing joint_group_manifest: {joint_manifest_path}")

    joint_manifest = read_json(joint_manifest_path)

    outputs_dir = out_dir / "outputs"
    diffs_dir = out_dir / "diffs"
    verdicts_dir = out_dir / "verdicts"
    checks_dir = out_dir / "checks"
    manifests_dir = out_dir / "manifests"

    for d in [outputs_dir, diffs_dir, verdicts_dir, checks_dir, manifests_dir]:
        d.mkdir(parents=True, exist_ok=True)

    probe_records = {}
    inventory_keys = {}
    active_manifest_keys = {}
    inventory_type_breakdown = {}
    active_type_breakdown = {}

    blockers = []
    warnings = []

    for probe in REQUIRED_PROBES:
        object_dir = group_dir / probe / "object"
        upload_record_path = object_dir / "object_upload_record.json"
        inventory_path = object_dir / "object_inventory.jsonl"
        active_path = object_dir / "active_manifest_records.jsonl"

        if not upload_record_path.exists():
            blockers.append(f"{probe}:object_upload_record_missing")
            continue

        rec = read_json(upload_record_path)
        probe_records[probe] = rec

        inv_keys, inv_types, inv_samples = load_jsonl_keys(inventory_path)
        act_keys, act_types, act_samples = load_jsonl_keys(active_path)

        inventory_keys[probe] = inv_keys
        active_manifest_keys[probe] = act_keys
        inventory_type_breakdown[probe] = dict(inv_types)
        active_type_breakdown[probe] = dict(act_types)

        if not inv_keys:
            blockers.append(f"{probe}:object_inventory_empty")
        if not rec.get("object_set_root"):
            blockers.append(f"{probe}:object_set_root_missing")
        if not rec.get("effective_object_root"):
            blockers.append(f"{probe}:effective_object_root_missing")
        if not act_keys:
            warnings.append(f"{probe}:active_manifest_records_empty")

        write_json(outputs_dir / f"{probe}_inventory_sample.json", inv_samples)
        write_json(outputs_dir / f"{probe}_active_manifest_sample.json", act_samples)

    pair_inventory = {}
    pair_active = {}

    for left, right in PAIRS:
        if left in inventory_keys and right in inventory_keys:
            pair_inventory[f"{left}_vs_{right}"] = pair_diff(
                left, right, inventory_keys[left], inventory_keys[right], args.sample_limit
            )

        if left in active_manifest_keys and right in active_manifest_keys:
            pair_active[f"{left}_vs_{right}"] = pair_diff(
                left, right, active_manifest_keys[left], active_manifest_keys[right], args.sample_limit
            )

    object_roots_aligned = False
    effective_roots_aligned = False

    if len(probe_records) == 3:
        object_roots = [probe_records[p].get("object_set_root") for p in REQUIRED_PROBES]
        effective_roots = [probe_records[p].get("effective_object_root") for p in REQUIRED_PROBES]
        object_roots_aligned = len(set(object_roots)) == 1
        effective_roots_aligned = len(set(effective_roots)) == 1

    all_inventory_diff = sum(x["entry_level_diff_count"] for x in pair_inventory.values())
    all_active_diff = sum(x["entry_level_diff_count"] for x in pair_active.values())

    min_inventory_jaccard = min(
        [x["jaccard_similarity"] for x in pair_inventory.values()],
        default=None,
    )
    min_active_jaccard = min(
        [x["jaccard_similarity"] for x in pair_active.values()],
        default=None,
    )

    window_level = joint_manifest.get("window_mapping_level")
    generated_time_skew_seconds = joint_manifest.get("generated_time_skew_seconds")

    if not object_roots_aligned:
        warnings.append("object_set_roots_not_aligned")
    if not effective_roots_aligned:
        warnings.append("effective_object_roots_not_aligned")
    if window_level == "weak":
        warnings.append("object_snapshot_window_mapping_weak")

    if blockers:
        final_status = "blocked_object_layer_compare_incomplete"
        e4_gate_recommendation = "blocked"
        explanation = "Object layer compare is incomplete because required probe evidence is missing."
    elif not object_roots_aligned or not effective_roots_aligned:
        final_status = "object_layer_divergence_observed"
        e4_gate_recommendation = "do_not_confirm_e4"
        explanation = (
            "Object-layer roots and inventories diverge across probes. "
            "Therefore current VRP output difference cannot be attributed to validator output logic alone."
        )
    else:
        final_status = "object_layer_aligned"
        e4_gate_recommendation = "object_layer_not_blocking_e4_candidate"
        explanation = (
            "Object-layer roots align across probes. If VRP roots differ under aligned validator context, "
            "this may support an E4-A candidate."
        )

    if window_level == "weak":
        final_status = final_status + "_weak_window"
        explanation += " However, this batch has weak time-window mapping, so the result is diagnostic rather than strict same-window evidence."

    summary = {
        "schema": "s3.stage3.e4a.object_layer_compare_summary.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": joint_manifest.get("snapshot_group_id"),
        "group_dir": str(group_dir),
        "required_probes": REQUIRED_PROBES,
        "received_object_probes": joint_manifest.get("received_object_probes"),
        "object_group_complete": joint_manifest.get("object_group_complete"),
        "vrp_group_complete": joint_manifest.get("vrp_group_complete"),
        "joint_group_complete": joint_manifest.get("joint_group_complete"),
        "generated_time_skew_seconds": generated_time_skew_seconds,
        "window_mapping_level": window_level,
        "probe_summary": {
            probe: {
                "object_inventory_count_recorded": probe_records.get(probe, {}).get("object_inventory_count"),
                "object_inventory_count_loaded": len(inventory_keys.get(probe, set())),
                "active_manifest_count_recorded": probe_records.get(probe, {}).get("active_manifest_count"),
                "active_manifest_count_loaded": len(active_manifest_keys.get(probe, set())),
                "object_set_root": probe_records.get(probe, {}).get("object_set_root"),
                "effective_object_root": probe_records.get(probe, {}).get("effective_object_root"),
                "object_source_mode": probe_records.get(probe, {}).get("object_source_mode"),
                "inventory_type_breakdown": inventory_type_breakdown.get(probe, {}),
                "active_type_breakdown": active_type_breakdown.get(probe, {}),
            }
            for probe in REQUIRED_PROBES
        },
        "object_roots_aligned": object_roots_aligned,
        "effective_object_roots_aligned": effective_roots_aligned,
        "all_pairwise_inventory_diff_count": all_inventory_diff,
        "all_pairwise_active_manifest_diff_count": all_active_diff,
        "min_inventory_jaccard_similarity": min_inventory_jaccard,
        "min_active_manifest_jaccard_similarity": min_active_jaccard,
        "final_status": final_status,
        "e4_gate_recommendation": e4_gate_recommendation,
        "warnings": warnings,
        "blockers": blockers,
        "explanation": explanation,
    }

    write_json(diffs_dir / "object_inventory_pairwise_diff.json", pair_inventory)
    write_json(diffs_dir / "active_manifest_pairwise_diff.json", pair_active)
    write_json(outputs_dir / "object_layer_compare_summary.json", summary)

    verdict = {
        "schema": "s3.stage3.e4a.object_layer_verdict.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": joint_manifest.get("snapshot_group_id"),
        "final_status": final_status,
        "e4_gate_recommendation": e4_gate_recommendation,
        "object_roots_aligned": object_roots_aligned,
        "effective_object_roots_aligned": effective_roots_aligned,
        "all_pairwise_inventory_diff_count": all_inventory_diff,
        "all_pairwise_active_manifest_diff_count": all_active_diff,
        "min_inventory_jaccard_similarity": min_inventory_jaccard,
        "min_active_manifest_jaccard_similarity": min_active_jaccard,
        "window_mapping_level": window_level,
        "generated_time_skew_seconds": generated_time_skew_seconds,
        "warnings": warnings,
        "blockers": blockers,
        "interpretation": explanation,
        "reserved_interfaces": {
            "e4b_cross_validator": "reserved_only",
            "control_plane_impact": "reserved_only",
        },
    }

    write_json(verdicts_dir / "object_layer_verdict.json", verdict)

    acceptance = not blockers and bool(pair_inventory) and bool(pair_active)

    text = f"""P6_OBJECT_LAYER_COMPARE=DONE

created_at_utc = {utc_now()}

snapshot_group_id = {joint_manifest.get("snapshot_group_id")}

object_group_complete = {joint_manifest.get("object_group_complete")}
vrp_group_complete = {joint_manifest.get("vrp_group_complete")}
joint_group_complete = {joint_manifest.get("joint_group_complete")}

window_mapping_level = {window_level}
generated_time_skew_seconds = {generated_time_skew_seconds}

object_roots_aligned = {object_roots_aligned}
effective_object_roots_aligned = {effective_roots_aligned}

all_pairwise_inventory_diff_count = {all_inventory_diff}
all_pairwise_active_manifest_diff_count = {all_active_diff}

min_inventory_jaccard_similarity = {min_inventory_jaccard}
min_active_manifest_jaccard_similarity = {min_active_jaccard}

final_status = {final_status}
e4_gate_recommendation = {e4_gate_recommendation}

warnings = {warnings}
blockers = {blockers}

interpretation:
  {explanation}

outputs:
  {outputs_dir / "object_layer_compare_summary.json"}
  {diffs_dir / "object_inventory_pairwise_diff.json"}
  {diffs_dir / "active_manifest_pairwise_diff.json"}
  {verdicts_dir / "object_layer_verdict.json"}

P6_acceptance = {acceptance}
"""

    (checks_dir / "P6_object_layer_compare_acceptance.txt").write_text(text, encoding="utf-8")

    manifest = {
        "schema": "s3.stage3.e4a_joint.p6_manifest.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": joint_manifest.get("snapshot_group_id"),
        "group_dir": str(group_dir),
        "summary": str(outputs_dir / "object_layer_compare_summary.json"),
        "inventory_pairwise_diff": str(diffs_dir / "object_inventory_pairwise_diff.json"),
        "active_manifest_pairwise_diff": str(diffs_dir / "active_manifest_pairwise_diff.json"),
        "verdict": str(verdicts_dir / "object_layer_verdict.json"),
        "P6_acceptance": acceptance,
    }

    write_json(manifests_dir / "P6_object_layer_compare_manifest.json", manifest)

    print(text)


if __name__ == "__main__":
    main()
