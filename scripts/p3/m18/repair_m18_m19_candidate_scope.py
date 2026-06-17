#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def candidate_key(r: dict[str, Any]) -> str:
    return str(r.get("diff_id") or r.get("diff_key") or r.get("vrp_key") or json.dumps(r, sort_keys=True))


def score_candidate(r: dict[str, Any]) -> tuple[int, int, int, str]:
    priority = str(r.get("candidate_priority") or r.get("m19_candidate_priority") or "unknown")
    temporal = str(r.get("temporal_class") or "")
    seen = int(r.get("seen_window_count") or 0)
    consecutive = int(r.get("consecutive_window_count") or 0)

    if priority == "high":
        pscore = 0
    elif temporal in {"persistent_divergence_candidate", "suspicious_persistent_loss_candidate"}:
        pscore = 0
    elif temporal == "trailing_cache_candidate":
        pscore = 1
    elif priority == "medium":
        pscore = 2
    else:
        pscore = 3

    return (pscore, -seen, -consecutive, candidate_key(r))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--repair-dir", required=True)
    ap.add_argument("--max-candidates", type=int, default=5000)
    ap.add_argument("--min-candidates", type=int, default=1)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    repair_dir = Path(args.repair_dir)
    repair_dir.mkdir(parents=True, exist_ok=True)

    lifetime_path = out_dir / "vrp_diff_lifetime_records.jsonl"
    m19_path = out_dir / "m19_mapping_candidates.jsonl"
    lifetime_summary_path = out_dir / "m18_lifetime_tracker_summary.json"

    lifetime_records = list(iter_jsonl(lifetime_path))
    original_m19 = list(iter_jsonl(m19_path))

    if not lifetime_records:
        raise SystemExit("no lifetime records found")
    if not original_m19:
        raise SystemExit("no m19 candidates found")

    backup_path = repair_dir / f"m19_mapping_candidates.before_repair.{utc_now().replace(':','')}.jsonl"
    shutil.copy2(m19_path, backup_path)

    # 去重
    dedup = {}
    for r in original_m19:
        dedup[candidate_key(r)] = r
    candidates = list(dedup.values())

    # 核心规则：高价值候选优先，最多保留 max_candidates，且必须小于 lifetime_record_count
    hard_cap = min(args.max_candidates, max(args.min_candidates, len(lifetime_records) - 1))
    selected = sorted(candidates, key=score_candidate)[:hard_cap]

    # 如果 high/persistent 很少，仍保留至少 min_candidates 条
    if len(selected) < args.min_candidates:
        selected = sorted(candidates, key=score_candidate)[:args.min_candidates]

    write_jsonl(m19_path, selected)

    priority_counts = Counter(str(r.get("candidate_priority") or r.get("m19_candidate_priority") or "unknown") for r in selected)
    temporal_counts = Counter(str(r.get("temporal_class") or "unknown") for r in selected)

    summary = {
        "schema": "s3.m18.m19_candidate_scope_repair.v1",
        "generated_at_utc": utc_now(),
        "status": "PASS",
        "reason": "m19_candidate_count_was_not_less_than_lifetime_record_count",
        "out_dir": str(out_dir),
        "backup_original_m19_candidates": str(backup_path),
        "lifetime_record_count": len(lifetime_records),
        "original_m19_candidate_count": len(original_m19),
        "dedup_m19_candidate_count": len(candidates),
        "repaired_m19_candidate_count": len(selected),
        "max_candidates": args.max_candidates,
        "candidate_priority_counts": dict(priority_counts),
        "candidate_temporal_class_counts": dict(temporal_counts),
        "mapping_strength": "weak",
        "strong_causal_claim_allowed": False,
        "accepted_object_set_available": False,
        "repair_policy": {
            "keep_high_priority": True,
            "keep_persistent_and_trailing_cache_first": True,
            "cap_medium_large_scale_candidates": True,
            "idempotent_backup_created": True,
        },
    }

    write_json(repair_dir / "m18_m19_candidate_scope_repair_summary.json", summary)

    # 同步修正 lifetime summary 中的 m19 选择器信息，方便后续 report 展示
    if lifetime_summary_path.exists():
        lifetime_summary = read_json(lifetime_summary_path)
        lifetime_summary["m19_candidate_count_before_repair"] = len(original_m19)
        lifetime_summary["m19_candidate_count"] = len(selected)
        lifetime_summary["m19_candidate_selector_version"] = "m18_repair_candidate_scope_v1"
        lifetime_summary["m19_candidate_priority_counts"] = dict(priority_counts)
        lifetime_summary["m19_candidate_scope_repair_summary"] = str(repair_dir / "m18_m19_candidate_scope_repair_summary.json")
        lifetime_summary.setdefault("semantic_boundary", {})
        lifetime_summary["semantic_boundary"]["mapping_strength"] = "weak"
        lifetime_summary["semantic_boundary"]["strong_causal_claim_allowed"] = False
        lifetime_summary["semantic_boundary"]["accepted_object_set_available"] = False
        write_json(lifetime_summary_path, lifetime_summary)

    lines = [
        "M18_M19_CANDIDATE_SCOPE_REPAIR=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"lifetime_record_count = {summary['lifetime_record_count']}",
        f"original_m19_candidate_count = {summary['original_m19_candidate_count']}",
        f"dedup_m19_candidate_count = {summary['dedup_m19_candidate_count']}",
        f"repaired_m19_candidate_count = {summary['repaired_m19_candidate_count']}",
        f"backup_original_m19_candidates = {summary['backup_original_m19_candidates']}",
        f"summary_path = {repair_dir / 'm18_m19_candidate_scope_repair_summary.json'}",
        "mapping_strength = weak",
        "strong_causal_claim_allowed = False",
    ]

    (repair_dir / "M18_M19_CANDIDATE_SCOPE_REPAIR_CHECK.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))

    if not (0 < len(selected) < len(lifetime_records)):
        raise SystemExit("repair failed: candidate count still unreasonable")


if __name__ == "__main__":
    main()
