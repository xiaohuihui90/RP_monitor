#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
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


def safe_json_load(path: Path) -> dict[str, Any] | None:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore").strip()
        if not text:
            return None
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def classify_candidate(path: Path, obj: dict[str, Any], group: dict[str, Any]) -> dict[str, Any]:
    snapshot_group_id = group.get("snapshot_group_id")
    text = json.dumps(obj, ensure_ascii=False)

    final_status = obj.get("final_status") or obj.get("status")
    final_attribution = obj.get("final_attribution") or obj.get("attribution")
    e4_status = obj.get("e4_status")
    run_id = obj.get("run_id") or obj.get("source_run_id") or obj.get("gate_id")

    has_object_signal = any(x in text for x in [
        "object_layer",
        "object_set_root",
        "effective_object_root",
        "manifest_version_skew",
        "object_layer_temporal_version_divergence",
        "active_manifest",
    ])

    same_snapshot_group = obj.get("snapshot_group_id") == snapshot_group_id

    # 当前真实 M14 snapshot group 是 VRP 上传分组。历史 M12/M13 object verdict
    # 通常没有相同 snapshot_group_id，因此不能直接复用为同窗 object context。
    reusable_same_window = bool(same_snapshot_group and has_object_signal)

    if reusable_same_window:
        mapping_level = "same_snapshot_group"
    elif has_object_signal:
        mapping_level = "historical_or_unmapped_object_evidence"
    else:
        mapping_level = "not_object_context"

    return {
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "run_id": run_id,
        "snapshot_group_id": obj.get("snapshot_group_id"),
        "final_status": final_status,
        "final_attribution": final_attribution,
        "e4_status": e4_status,
        "has_object_signal": has_object_signal,
        "same_snapshot_group": same_snapshot_group,
        "reusable_same_window": reusable_same_window,
        "mapping_level": mapping_level,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Discover same-window object layer context for M14 E4-A run")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--group-dir", required=True)
    ap.add_argument("--p3-dir", required=True)
    ap.add_argument("--collector-root", default="data/p3_collector")
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    group_dir = Path(args.group_dir).resolve()
    p3_dir = Path(args.p3_dir).resolve()
    collector_root = Path(args.collector_root).resolve()

    group = read_json(group_dir / "group_manifest.json")
    final_verdict = read_json(run_dir / "verdicts/final_verdict_m14.json")

    out_dir = run_dir / "inputs/object_context_discovery"
    out_dir.mkdir(parents=True, exist_ok=True)

    request = {
        "schema": "s3.stage3.m14.same_window_object_context_request.v1",
        "created_at_utc": utc_now(),
        "m14_run_id": run_dir.name,
        "snapshot_group_id": group.get("snapshot_group_id"),
        "generated_time_min": group.get("generated_time_min"),
        "generated_time_max": group.get("generated_time_max"),
        "generated_time_skew_seconds": group.get("generated_time_skew_seconds"),
        "required_probes": group.get("required_probes"),
        "received_probes": group.get("received_probes"),
        "required_context": {
            "object_set_root_per_probe": True,
            "effective_object_root_per_probe": True,
            "active_manifest_records_per_probe": True,
            "object_layer_verdict": True,
            "same_window_mapping": True,
        },
        "matching_rule": {
            "must_match_snapshot_group": True,
            "must_overlap_generated_time_window": True,
            "do_not_reuse_m13_historical_object_verdict_as_same_window": True,
        },
        "current_final_status_before_discovery": final_verdict.get("final_status"),
        "current_blockers": final_verdict.get("blockers"),
    }

    candidate_paths = []
    for pattern in [
        "object_gate_v5_runs/**/*.json",
        "stage3_final_archive/**/*.json",
        "m14_vrp_runs/**/*.json",
    ]:
        candidate_paths.extend(collector_root.glob(pattern))

    candidates = []
    for path in sorted(set(candidate_paths)):
        obj = safe_json_load(path)
        if obj is None:
            continue
        cand = classify_candidate(path, obj, group)
        if cand["has_object_signal"]:
            candidates.append(cand)

    same_window_candidates = [c for c in candidates if c["reusable_same_window"]]
    historical_candidates = [
        c for c in candidates
        if c["has_object_signal"] and not c["reusable_same_window"]
    ]

    available = bool(same_window_candidates)

    object_context = {
        "schema": "s3.stage3.m14.object_layer_context_discovery_result.v1",
        "created_at_utc": utc_now(),
        "m14_run_id": run_dir.name,
        "snapshot_group_id": group.get("snapshot_group_id"),
        "available": available,
        "mapping_level": "same_snapshot_group" if available else "missing",
        "object_roots_aligned": None,
        "object_layer_temporal_version_divergence": None,
        "final_attribution": None,
        "confidence": None,
        "hard_blockers": [] if available else ["same_window_object_layer_context_missing"],
        "same_window_candidate_count": len(same_window_candidates),
        "historical_or_unmapped_candidate_count": len(historical_candidates),
        "same_window_candidates": same_window_candidates,
        "historical_or_unmapped_candidates_sample": historical_candidates[:20],
        "interpretation": (
            "Same-window object-layer context was found for this snapshot group."
            if available else
            "No same-window object-layer context was found for this VRP snapshot group. "
            "Historical M12/M13 object verdicts may be useful as background but must not be reused "
            "as same-window E4 evidence."
        ),
    }

    report = {
        "schema": "s3.stage3.m14.object_context_discovery_report.v1",
        "created_at_utc": utc_now(),
        "m14_run_id": run_dir.name,
        "snapshot_group_id": group.get("snapshot_group_id"),
        "collector_root": str(collector_root),
        "searched_json_file_count": len(set(candidate_paths)),
        "object_signal_candidate_count": len(candidates),
        "same_window_candidate_count": len(same_window_candidates),
        "historical_or_unmapped_candidate_count": len(historical_candidates),
        "available": available,
        "next_action": (
            "join_same_window_object_context_and_rerun_p6"
            if available else
            "trigger_or_collect_object_layer_context_in_next_same_window_run"
        ),
    }

    write_json(out_dir / "object_context_request.json", request)
    write_json(out_dir / "object_layer_context_discovered.json", object_context)
    write_json(out_dir / "object_context_discovery_report.json", report)

    write_json(p3_dir / "outputs/object_context_request.json", request)
    write_json(p3_dir / "outputs/object_layer_context_discovered.json", object_context)
    write_json(p3_dir / "outputs/object_context_discovery_report.json", report)

    summary_doc = f"""# P3 同窗 Object Layer Context Discovery 总结

- m14_run_id：`{run_dir.name}`
- snapshot_group_id：`{group.get("snapshot_group_id")}`
- generated_time_min：`{group.get("generated_time_min")}`
- generated_time_max：`{group.get("generated_time_max")}`
- searched_json_file_count：`{report["searched_json_file_count"]}`
- object_signal_candidate_count：`{report["object_signal_candidate_count"]}`
- same_window_candidate_count：`{report["same_window_candidate_count"]}`
- available：`{available}`

## 结论

当前阶段只做 E4-A 三地 Routinator 基线。P3 的目标是寻找与 VRP snapshot group 同窗的对象层上下文。

若 `available=False`，说明当前没有找到可直接用于 E4 判定的同窗对象层证据，P6 final verdict 应继续保持 `blocked_object_layer_unverified`，不能将 VRP 差异提升为 E4 confirmed。

历史 M12/M13 object verdict 可作为背景证据，但不能作为该 snapshot group 的同窗 object context 直接复用。
"""
    (p3_dir / "docs/P3_object_context_discovery_summary.md").write_text(summary_doc, encoding="utf-8")

    acceptance = f"""P3_SAME_WINDOW_OBJECT_CONTEXT_DISCOVERY=DONE

run_id = {run_dir.name}
snapshot_group_id = {group.get("snapshot_group_id")}

searched_json_file_count = {report["searched_json_file_count"]}
object_signal_candidate_count = {report["object_signal_candidate_count"]}
same_window_candidate_count = {report["same_window_candidate_count"]}
historical_or_unmapped_candidate_count = {report["historical_or_unmapped_candidate_count"]}

object_context_available = {available}
mapping_level = {object_context["mapping_level"]}
hard_blockers = {object_context["hard_blockers"]}

expected_behavior:
  if object_context_available = False, keep final_status blocked_object_layer_unverified
  do_not_reuse_historical_m13_object_verdict_as_same_window = True

reserved_interfaces:
  e4b_cross_validator = reserved_only
  control_plane_impact = reserved_only

runtime_service_changed = False
collector_restarted = False
probe_restarted = False
new_validator_installed = False
bgp_data_loaded = False

P3_acceptance = True
"""
    (p3_dir / "checks/P3_same_window_object_context_discovery_acceptance.txt").write_text(acceptance, encoding="utf-8")

    # Small archive for P3 outputs.
    pack_path = p3_dir / "e4a_object_context_discovery_outputs.tar.gz"
    with tarfile.open(pack_path, "w:gz") as tar:
        for rel in [
            "outputs/object_context_request.json",
            "outputs/object_layer_context_discovered.json",
            "outputs/object_context_discovery_report.json",
            "docs/P3_object_context_discovery_summary.md",
            "checks/P3_same_window_object_context_discovery_acceptance.txt",
        ]:
            p = p3_dir / rel
            if p.exists():
                tar.add(p, arcname=rel)

    (p3_dir / "manifests/P3_object_context_discovery_manifest.json").write_text(
        json.dumps({
            "schema": "s3.stage3.e4a.p3_manifest.v1",
            "created_at_utc": utc_now(),
            "run_id": run_dir.name,
            "snapshot_group_id": group.get("snapshot_group_id"),
            "object_context_available": available,
            "same_window_candidate_count": len(same_window_candidates),
            "archive": str(pack_path),
            "archive_sha256": sha256_file(pack_path),
        }, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(acceptance)


if __name__ == "__main__":
    main()
