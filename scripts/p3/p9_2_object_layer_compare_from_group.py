#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROBES = ["probe-cd", "probe-bj", "probe-sg"]
PAIRS = [
    ("probe-cd", "probe-bj"),
    ("probe-cd", "probe-sg"),
    ("probe-bj", "probe-sg"),
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def make_record_key(obj: Any) -> str:
    if isinstance(obj, str):
        return obj

    if isinstance(obj, dict):
        for k in ["key", "object_key", "canonical_key", "record_key"]:
            v = obj.get(k)
            if v not in (None, ""):
                return str(v)

        uri = (
            obj.get("uri")
            or obj.get("url")
            or obj.get("path")
            or obj.get("relative_path")
            or obj.get("filename")
            or obj.get("name")
        )
        h = (
            obj.get("sha256")
            or obj.get("hash")
            or obj.get("object_hash")
            or obj.get("file_hash")
            or obj.get("hash_hex")
            or obj.get("digest")
        )
        obj_type = obj.get("object_type") or obj.get("type") or obj.get("ext")

        if uri is not None and h is not None:
            return json.dumps(
                {"uri": str(uri), "sha256": str(h), "object_type": obj_type},
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            )

        if uri is not None:
            return json.dumps(
                {"uri": str(uri), "object_type": obj_type},
                sort_keys=True,
                ensure_ascii=False,
                separators=(",", ":"),
            )

    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def extract_type_from_key_or_obj(obj: Any, key: str) -> str | None:
    if isinstance(obj, dict):
        for k in ["object_type", "type", "ext", "file_type"]:
            v = obj.get(k)
            if v not in (None, ""):
                return str(v).lower()

        uri = (
            obj.get("uri")
            or obj.get("url")
            or obj.get("path")
            or obj.get("relative_path")
            or obj.get("filename")
            or obj.get("name")
        )
        if uri:
            suffix = str(uri).rsplit(".", 1)[-1].lower()
            if suffix in {"cer", "roa", "mft", "crl", "asa", "gbr"}:
                return suffix

    lowered = key.lower()
    for t in ["mft", "roa", "cer", "crl", "asa", "gbr"]:
        if f".{t}" in lowered or f'"{t}"' in lowered:
            return t
    return None


def load_jsonl_set(path: Path) -> tuple[set[str], dict[str, str]]:
    keys: set[str] = set()
    type_by_key: dict[str, str] = {}

    if not path.exists():
        return keys, type_by_key

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
            except Exception:
                obj = line

            key = make_record_key(obj)
            keys.add(key)

            typ = extract_type_from_key_or_obj(obj, key)
            if typ:
                type_by_key[key] = typ

    return keys, type_by_key


def top_type(keys: set[str], *maps: dict[str, str]) -> str | None:
    counts: dict[str, int] = {}
    for k in keys:
        for m in maps:
            t = m.get(k)
            if t:
                counts[t] = counts.get(t, 0) + 1
                break
    if not counts:
        return None
    return sorted(counts.items(), key=lambda x: (-x[1], x[0]))[0][0]


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def write_samples(path: Path, values: set[str], limit: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for x in sorted(values)[:limit]:
            f.write(x + "\n")


def pairwise_compare(
    key_sets: dict[str, set[str]],
    type_maps: dict[str, dict[str, str]],
    out_dir: Path,
    label: str,
    sample_limit: int,
) -> dict[str, Any]:
    pair_summary: dict[str, Any] = {}
    total_diff = 0
    min_jaccard: float | None = None

    for left, right in PAIRS:
        pair = f"{left}_vs_{right}"
        a = key_sets[left]
        b = key_sets[right]

        only_left = a - b
        only_right = b - a
        common = a & b
        union = a | b

        diff_count = len(only_left) + len(only_right)
        jaccard = len(common) / len(union) if union else 1.0

        total_diff += diff_count
        min_jaccard = jaccard if min_jaccard is None else min(min_jaccard, jaccard)

        sample_base = out_dir / f"{label}_{pair}"
        write_samples(sample_base.with_name(sample_base.name + "_only_left.txt"), only_left, sample_limit)
        write_samples(sample_base.with_name(sample_base.name + "_only_right.txt"), only_right, sample_limit)

        pair_summary[pair] = {
            "left_probe": left,
            "right_probe": right,
            "left_count": len(a),
            "right_count": len(b),
            "common_count": len(common),
            "union_count": len(union),
            "only_left_count": len(only_left),
            "only_right_count": len(only_right),
            "entry_level_diff_count": diff_count,
            "jaccard_similarity": jaccard,
            "top_diff_object_type": top_type(only_left | only_right, type_maps[left], type_maps[right]),
        }

    return {
        "all_pairwise_entry_level_diff_count": total_diff,
        "min_pairwise_jaccard_similarity": min_jaccard,
        "pair_summary": pair_summary,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--group-id", required=True)
    ap.add_argument("--group-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--sample-limit", type=int, default=50)
    args = ap.parse_args()

    group_id = args.group_id
    group_dir = Path(args.group_dir)
    out_dir = Path(args.out_dir)

    checks_dir = out_dir / "checks"
    outputs_dir = out_dir / "outputs"
    diffs_dir = out_dir / "diffs"
    verdicts_dir = out_dir / "verdicts"
    manifests_dir = out_dir / "manifests"

    for d in [checks_dir, outputs_dir, diffs_dir, verdicts_dir, manifests_dir]:
        d.mkdir(parents=True, exist_ok=True)

    manifest_path = group_dir / "joint_group_manifest.json"
    manifest = read_json(manifest_path)

    inventory_sets: dict[str, set[str]] = {}
    inventory_type_maps: dict[str, dict[str, str]] = {}
    active_sets: dict[str, set[str]] = {}
    active_type_maps: dict[str, dict[str, str]] = {}

    for probe in PROBES:
        obj_dir = group_dir / probe / "object"
        inventory_path = obj_dir / "object_inventory.jsonl"
        active_path = obj_dir / "active_manifest_records.jsonl"

        inv_set, inv_types = load_jsonl_set(inventory_path)
        act_set, act_types = load_jsonl_set(active_path)

        inventory_sets[probe] = inv_set
        inventory_type_maps[probe] = inv_types
        active_sets[probe] = act_set
        active_type_maps[probe] = act_types

    object_roots = {
        p: manifest.get("snapshots", {}).get(p, {}).get("object_set_root")
        for p in PROBES
    }
    effective_roots = {
        p: manifest.get("snapshots", {}).get(p, {}).get("effective_object_root")
        for p in PROBES
    }

    object_roots_aligned = len(set(v for v in object_roots.values() if v)) == 1
    effective_object_roots_aligned = len(set(v for v in effective_roots.values() if v)) == 1

    inventory_diff = pairwise_compare(
        inventory_sets,
        inventory_type_maps,
        diffs_dir,
        "object_inventory",
        args.sample_limit,
    )
    active_diff = pairwise_compare(
        active_sets,
        active_type_maps,
        diffs_dir,
        "active_manifest",
        args.sample_limit,
    )

    final_status = (
        "object_layer_aligned"
        if object_roots_aligned and effective_object_roots_aligned
        else "object_layer_divergence_observed"
    )

    e4_gate_recommendation = (
        "object_layer_allows_e4_check"
        if final_status == "object_layer_aligned"
        else "do_not_confirm_e4"
    )

    summary = {
        "schema": "s3.stage3.e4a_joint.p9_2_object_layer_compare_summary.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "object_group_complete": manifest.get("object_group_complete"),
        "window_mapping_level": manifest.get("window_mapping_level"),
        "generated_time_skew_seconds": manifest.get("generated_time_skew_seconds"),
        "object_roots": object_roots,
        "effective_object_roots": effective_roots,
        "object_roots_aligned": object_roots_aligned,
        "effective_object_roots_aligned": effective_object_roots_aligned,
        "inventory_counts": {p: len(inventory_sets[p]) for p in PROBES},
        "active_manifest_counts": {p: len(active_sets[p]) for p in PROBES},
        "inventory_diff": inventory_diff,
        "active_manifest_diff": active_diff,
    }

    verdict = {
        "schema": "s3.stage3.e4a_joint.p9_2_object_layer_verdict.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "final_status": final_status,
        "e4_gate_recommendation": e4_gate_recommendation,
        "object_roots_aligned": object_roots_aligned,
        "effective_object_roots_aligned": effective_object_roots_aligned,
        "all_pairwise_inventory_diff_count": inventory_diff["all_pairwise_entry_level_diff_count"],
        "all_pairwise_active_manifest_diff_count": active_diff["all_pairwise_entry_level_diff_count"],
        "min_inventory_jaccard_similarity": inventory_diff["min_pairwise_jaccard_similarity"],
        "min_active_manifest_jaccard_similarity": active_diff["min_pairwise_jaccard_similarity"],
        "window_mapping_level": manifest.get("window_mapping_level"),
        "generated_time_skew_seconds": manifest.get("generated_time_skew_seconds"),
        "interpretation": (
            "Object layer is aligned; E4-A check may proceed to VRP/output layer."
            if final_status == "object_layer_aligned"
            else "Object-layer roots or inventories diverge across probes; do not attribute VRP differences to validator output logic alone."
        ),
        "reserved_interfaces": {
            "e4b_cross_validator": "reserved_only",
            "control_plane_impact": "reserved_only",
        },
    }

    write_json(outputs_dir / "object_layer_compare_summary.json", summary)
    write_json(diffs_dir / "object_inventory_pairwise_diff.json", inventory_diff)
    write_json(diffs_dir / "active_manifest_pairwise_diff.json", active_diff)
    write_json(verdicts_dir / "object_layer_verdict.json", verdict)

    acceptance = f"""P9_2_OBJECT_LAYER_COMPARE=DONE

created_at_utc = {utc_now()}

snapshot_group_id = {group_id}

object_group_complete = {manifest.get("object_group_complete")}
window_mapping_level = {manifest.get("window_mapping_level")}
generated_time_skew_seconds = {manifest.get("generated_time_skew_seconds")}

object_roots_aligned = {object_roots_aligned}
effective_object_roots_aligned = {effective_object_roots_aligned}

all_pairwise_inventory_diff_count = {inventory_diff["all_pairwise_entry_level_diff_count"]}
all_pairwise_active_manifest_diff_count = {active_diff["all_pairwise_entry_level_diff_count"]}

min_inventory_jaccard_similarity = {inventory_diff["min_pairwise_jaccard_similarity"]}
min_active_manifest_jaccard_similarity = {active_diff["min_pairwise_jaccard_similarity"]}

final_status = {final_status}
e4_gate_recommendation = {e4_gate_recommendation}

interpretation:
  {verdict["interpretation"]}

P9_2_acceptance = True
"""

    (checks_dir / "P9_2_object_layer_compare_acceptance.txt").write_text(acceptance, encoding="utf-8")

    run_manifest = {
        "schema": "s3.stage3.e4a_joint.p9_2_object_compare_manifest.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "object_group_manifest": str(manifest_path),
        "summary": str(outputs_dir / "object_layer_compare_summary.json"),
        "verdict": str(verdicts_dir / "object_layer_verdict.json"),
        "P9_2_acceptance": True,
    }

    write_json(manifests_dir / "P9_2_object_layer_compare_manifest.json", run_manifest)

    print(acceptance)


if __name__ == "__main__":
    main()
