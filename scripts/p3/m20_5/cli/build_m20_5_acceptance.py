#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def count_jsonl(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return sum(1 for line in f if line.strip())


def create_archive(run_dir: Path, archive_path: Path) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)

    include_dirs = [
        "inputs",
        "indexes",
        "outputs",
        "checks",
        "logs",
        "docs",
        "configs",
    ]

    with tarfile.open(archive_path, "w:gz") as tar:
        for dirname in include_dirs:
            d = run_dir / dirname
            if d.exists():
                tar.add(d, arcname=dirname)


def main() -> int:
    parser = argparse.ArgumentParser(description="M20.5-E acceptance/archive builder")
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir).expanduser().resolve()

    outputs_dir = run_dir / "outputs"
    checks_dir = run_dir / "checks"
    docs_dir = run_dir / "docs"
    archive_dir = run_dir / "archive"

    for d in [outputs_dir, checks_dir, docs_dir, archive_dir]:
        d.mkdir(parents=True, exist_ok=True)

    b_path = outputs_dir / "M20_5B_vrp_timeline_summary.json"
    c_path = outputs_dir / "M20_5C_vrp_output_candidate_summary.json"
    d_path = outputs_dir / "M20_5D_full_snapshot_trigger_summary.json"

    missing = [str(p) for p in [b_path, c_path, d_path] if not p.exists()]

    b = load_json(b_path) if b_path.exists() else {}
    c = load_json(c_path) if c_path.exists() else {}
    d = load_json(d_path) if d_path.exists() else {}

    timeline_index = run_dir / "indexes" / "vrp_output_timeline.jsonl"
    candidate_index = run_dir / "indexes" / "validation_output_candidate_index.jsonl"
    trigger_index = run_dir / "indexes" / "full_snapshot_trigger_decision_index.jsonl"
    policy_path = run_dir / "configs" / "m20_5_full_snapshot_trigger_policy.json"

    blockers = []

    if missing:
        blockers.append("missing_required_summary_files")

    if b.get("status") != "PASS":
        blockers.append("m20_5b_not_pass")

    if c.get("status") != "PASS":
        blockers.append("m20_5c_not_pass")

    if d.get("status") != "PASS":
        blockers.append("m20_5d_not_pass")

    if b.get("input_probe_count") != 3:
        blockers.append("input_probe_count_not_3")

    if b.get("timeline_window_count", 0) < 1:
        blockers.append("timeline_window_count_below_1")

    if not timeline_index.exists():
        blockers.append("timeline_index_missing")

    if not candidate_index.exists():
        blockers.append("candidate_index_missing")

    if not trigger_index.exists():
        blockers.append("trigger_decision_index_missing")

    if not policy_path.exists():
        blockers.append("trigger_policy_missing")

    status = "PASS" if not blockers else "FAIL"

    acceptance = {
        "schema": "s3.m20_5e.acceptance.v1",
        "status": status,
        "created_at_utc": utc_now_iso(),
        "run_dir": str(run_dir),
        "scope": "validation_output_continuous_collection_baseline",

        "m20_5a_status": "PASS" if b.get("input_probe_count") == 3 else "UNKNOWN",
        "m20_5b_status": b.get("status"),
        "m20_5c_status": c.get("status"),
        "m20_5d_status": d.get("status"),

        "probe_summary_count": b.get("input_summary_count"),
        "probe_count": b.get("input_probe_count"),
        "imported_probes": b.get("imported_probes"),
        "timeline_window_count": b.get("timeline_window_count"),
        "strong_window_count": b.get("strong_window_count"),
        "weak_window_count": b.get("weak_window_count"),
        "partial_window_count": b.get("partial_window_count"),
        "invalid_window_count": b.get("invalid_window_count"),

        "validation_output_candidate_count": c.get("candidate_count"),
        "by_anomaly_type": c.get("by_anomaly_type"),
        "by_confidence": c.get("by_confidence"),
        "strong_attribution_candidate_count": c.get("strong_attribution_candidate_count"),
        "weak_or_partial_candidate_count": c.get("weak_or_partial_candidate_count"),

        "trigger_decision_count": d.get("trigger_decision_count"),
        "immediate_trigger_count": d.get("immediate_trigger_count"),
        "deferred_trigger_count": d.get("deferred_trigger_count"),
        "disk_blocked_count": d.get("disk_blocked_count"),
        "by_trigger_decision_status": d.get("by_decision_status"),
        "by_effective_snapshot_mode": d.get("by_effective_snapshot_mode"),
        "free_gb": d.get("free_gb"),
        "min_free_gb": d.get("min_free_gb"),

        "timeline_index": str(timeline_index),
        "candidate_index": str(candidate_index),
        "trigger_decision_index": str(trigger_index),
        "trigger_policy": str(policy_path),

        "timeline_jsonl_count": count_jsonl(timeline_index),
        "candidate_jsonl_count": count_jsonl(candidate_index),
        "trigger_decision_jsonl_count": count_jsonl(trigger_index),

        "continuous_collection_ready": status == "PASS",
        "next_step": "M20.5-F continuous low-frequency run, then M20-F extended M19 rerun",
        "blockers": blockers,

        "important_boundary": [
            "M20.5 current acceptance means single-round validation-output summary collection, timeline construction, candidate detection, and trigger decision are complete.",
            "Current window is weak if weak_window_count > 0; weak-window candidates are monitoring evidence, not strong attribution evidence.",
            "No full VRP snapshot was executed by M20.5-D/E.",
            "For strong attribution, use a strong window or scheduled low-frequency repeated collection."
        ],
    }

    acceptance_path = outputs_dir / "M20_5E_acceptance_summary.json"
    write_json(acceptance_path, acceptance)

    md_path = docs_dir / "M20_5_summary_zh.md"
    md = f"""# M20.5 验收总结

## 1. 阶段状态

- M20.5-A：{acceptance['m20_5a_status']}
- M20.5-B：{acceptance['m20_5b_status']}
- M20.5-C：{acceptance['m20_5c_status']}
- M20.5-D：{acceptance['m20_5d_status']}
- M20.5-E：{status}

## 2. 关键结果

- 三地 summary 数量：{acceptance['probe_summary_count']}
- probe 数量：{acceptance['probe_count']}
- timeline window 数量：{acceptance['timeline_window_count']}
- strong window 数量：{acceptance['strong_window_count']}
- weak window 数量：{acceptance['weak_window_count']}
- validation output candidate 数量：{acceptance['validation_output_candidate_count']}
- trigger decision 数量：{acceptance['trigger_decision_count']}
- immediate trigger 数量：{acceptance['immediate_trigger_count']}
- deferred trigger 数量：{acceptance['deferred_trigger_count']}

## 3. 边界说明

本轮已经打通验证输出层持续采集的单轮闭环，但当前窗口如果为 weak window，则只能作为监测证据，不能作为强归因证据。full snapshot 默认未触发，后续应通过低频连续采集获得更好的同窗窗口。

## 4. 下一步

建议先进入 M20.5-F：低频连续运行 2～3 小时，再进入 M20-F：使用 extended coverage 重跑 M19。
"""
    md_path.write_text(md, encoding="utf-8")

    check_text = "\n".join([
        f"M20_5E_ACCEPTANCE={status}",
        "",
        f"run_dir = {run_dir}",
        f"m20_5a_status = {acceptance['m20_5a_status']}",
        f"m20_5b_status = {acceptance['m20_5b_status']}",
        f"m20_5c_status = {acceptance['m20_5c_status']}",
        f"m20_5d_status = {acceptance['m20_5d_status']}",
        "",
        f"probe_summary_count = {acceptance['probe_summary_count']}",
        f"probe_count = {acceptance['probe_count']}",
        f"timeline_window_count = {acceptance['timeline_window_count']}",
        f"strong_window_count = {acceptance['strong_window_count']}",
        f"weak_window_count = {acceptance['weak_window_count']}",
        f"validation_output_candidate_count = {acceptance['validation_output_candidate_count']}",
        f"trigger_decision_count = {acceptance['trigger_decision_count']}",
        f"immediate_trigger_count = {acceptance['immediate_trigger_count']}",
        f"deferred_trigger_count = {acceptance['deferred_trigger_count']}",
        f"continuous_collection_ready = {acceptance['continuous_collection_ready']}",
        f"blockers = {blockers}",
        "",
        f"acceptance_summary = {acceptance_path}",
        f"summary_doc = {md_path}",
    ]) + "\n"

    check_path = checks_dir / "M20_5E_acceptance.txt"
    check_path.write_text(check_text, encoding="utf-8")
    print(check_text)

    archive_name = f"m20_5_acceptance_{utc_id()}.tar.gz"
    archive_path = archive_dir / archive_name
    create_archive(run_dir, archive_path)

    sha_path = archive_path.with_suffix(archive_path.suffix + ".sha256")
    sha_path.write_text(f"{sha256_file(archive_path)}  {archive_path}\n", encoding="utf-8")

    print("========== M20.5-E ARCHIVE ==========")
    print(f"archive_path = {archive_path}")
    print(f"archive_sha256 = {sha_path}")
    print(f"archive_size_bytes = {archive_path.stat().st_size}")

    return 0 if status == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
