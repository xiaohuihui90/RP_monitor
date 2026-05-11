#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
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


def copy_if_exists(src: Path, dst: Path, blockers: list[str], required: bool = True) -> bool:
    if not src.exists() or not src.is_file():
        if required:
            blockers.append(f"missing_required:{src}")
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description="P11 three-layer closeout")
    ap.add_argument("--group-id", required=True)
    ap.add_argument("--out-dir", required=True)

    ap.add_argument("--a1-acceptance", required=True)
    ap.add_argument("--a1-manifest", required=True)

    ap.add_argument("--p11-c-acceptance", required=True)
    ap.add_argument("--announced-view-group-manifest", required=True)
    ap.add_argument("--announced-view-pairwise-diff", required=True)

    ap.add_argument("--p11-d-acceptance", required=True)
    ap.add_argument("--three-layer-final-verdict", required=True)
    ap.add_argument("--p11-d-manifest", required=True)

    ap.add_argument("--p11-a4-acceptance", required=True)
    ap.add_argument("--p11-a4-manifest", required=True)
    ap.add_argument("--evidence-pack", required=True)
    ap.add_argument("--evidence-pack-sha256", required=True)

    args = ap.parse_args()

    group_id = args.group_id
    out_dir = Path(args.out_dir)

    checks_dir = out_dir / "checks"
    docs_dir = out_dir / "docs"
    manifests_dir = out_dir / "manifests"
    outputs_dir = out_dir / "outputs"
    evidence_dir = out_dir / "evidence"
    snapshot_dir = out_dir / "input_snapshot"

    for d in [checks_dir, docs_dir, manifests_dir, outputs_dir, evidence_dir, snapshot_dir]:
        d.mkdir(parents=True, exist_ok=True)

    blockers: list[str] = []
    warnings: list[str] = []

    inputs = {
        "a1_acceptance.txt": Path(args.a1_acceptance),
        "a1_manifest.json": Path(args.a1_manifest),

        "p11_c_acceptance.txt": Path(args.p11_c_acceptance),
        "announced_view_group_manifest.json": Path(args.announced_view_group_manifest),
        "announced_view_pairwise_diff.json": Path(args.announced_view_pairwise_diff),

        "p11_d_acceptance.txt": Path(args.p11_d_acceptance),
        "three_layer_final_verdict.json": Path(args.three_layer_final_verdict),
        "p11_d_manifest.json": Path(args.p11_d_manifest),

        "p11_a4_acceptance.txt": Path(args.p11_a4_acceptance),
        "p11_a4_manifest.json": Path(args.p11_a4_manifest),
        "evidence_pack.tar.gz": Path(args.evidence_pack),
        "evidence_pack.tar.gz.sha256": Path(args.evidence_pack_sha256),
    }

    for name, src in inputs.items():
        copy_if_exists(src, snapshot_dir / name, blockers, required=True)

    if blockers:
        raise SystemExit("[BLOCKED] missing required closeout inputs: " + repr(blockers))

    verdict = read_json(Path(args.three_layer_final_verdict))
    a4_manifest = read_json(Path(args.p11_a4_manifest))
    c_manifest = read_json(Path(args.announced_view_group_manifest))

    if verdict.get("snapshot_group_id") != group_id:
        blockers.append("three_layer_verdict_group_id_mismatch")
    if c_manifest.get("snapshot_group_id") != group_id:
        blockers.append("announced_view_group_id_mismatch")
    if a4_manifest.get("snapshot_group_id") != group_id:
        blockers.append("a4_manifest_group_id_mismatch")

    final_status = verdict.get("final_status")
    strict_three_layer_status = verdict.get("strict_three_layer_status")
    e4_status = verdict.get("e4_status")
    confirmed_allowed = verdict.get("confirmed_allowed")
    blocking_layer = verdict.get("blocking_layer")
    attribution_layer = verdict.get("attribution_layer")
    confidence = verdict.get("confidence")

    evidence_pack = Path(args.evidence_pack)
    evidence_pack_sha256_file = Path(args.evidence_pack_sha256)

    copied_evidence_pack = evidence_dir / evidence_pack.name
    copied_evidence_sha = evidence_dir / evidence_pack_sha256_file.name

    shutil.copy2(evidence_pack, copied_evidence_pack)
    shutil.copy2(evidence_pack_sha256_file, copied_evidence_sha)

    # Build closeout SHA256SUMS.
    sha_lines = []
    for p in sorted(snapshot_dir.iterdir()):
        if p.is_file():
            sha_lines.append(f"{sha256_file(p)}  input_snapshot/{p.name}")
    for p in sorted(evidence_dir.iterdir()):
        if p.is_file():
            sha_lines.append(f"{sha256_file(p)}  evidence/{p.name}")

    (outputs_dir / "SHA256SUMS.txt").write_text(
        "\n".join(sha_lines) + "\n",
        encoding="utf-8",
    )

    closeout_summary = f"""# M15 / P11 三层视图联合归因闭环工程收口报告

## 1. 基本信息

snapshot_group_id: {group_id}

closeout_time_utc: {utc_now()}

## 2. 最终结论

final_status: {final_status}
strict_three_layer_status: {strict_three_layer_status}
e4_status: {e4_status}
confirmed_allowed: {confirmed_allowed}
blocking_layer: {blocking_layer}
attribution_layer: {attribution_layer}
confidence: {confidence}

## 3. 三层状态摘要

### L1 宣告视图层

collection_mode: {verdict.get("announced_view", {}).get("collection_mode")}
window_mapping_level: {verdict.get("announced_view", {}).get("window_mapping_level")}
generated_time_skew_seconds: {verdict.get("announced_view", {}).get("generated_time_skew_seconds")}
strict_announced_view_aligned: {verdict.get("announced_view", {}).get("strict_announced_view_aligned")}
semantic_announced_view_aligned: {verdict.get("announced_view", {}).get("semantic_announced_view_aligned")}
all_pairwise_diff_count: {verdict.get("announced_view", {}).get("all_pairwise_diff_count")}

### L2 对象视图层

object_layer_aligned: {verdict.get("object_layer", {}).get("object_layer_aligned")}
object_roots_aligned: {verdict.get("object_layer", {}).get("object_roots_aligned")}
effective_object_roots_aligned: {verdict.get("object_layer", {}).get("effective_object_roots_aligned")}
all_pairwise_inventory_diff_count: {verdict.get("object_layer", {}).get("all_pairwise_inventory_diff_count")}
all_pairwise_active_manifest_diff_count: {verdict.get("object_layer", {}).get("all_pairwise_active_manifest_diff_count")}

### L3 验证输出层

vrp_layer_aligned: {verdict.get("vrp_layer", {}).get("vrp_layer_aligned")}
all_vrp_roots_aligned: {verdict.get("vrp_layer", {}).get("all_vrp_roots_aligned")}
all_pairwise_entry_level_diff_count: {verdict.get("vrp_layer", {}).get("all_pairwise_entry_level_diff_count")}
min_pairwise_jaccard_similarity: {verdict.get("vrp_layer", {}).get("min_pairwise_jaccard_similarity")}

## 4. 工程解释

本轮 P11 完成了 L1 宣告视图、L2 对象视图、L3 验证输出视图的联合门控与证据封装。

由于本轮 L1 是 retrofit_or_diagnostic 补采，L1 window_mapping_level 不是 strong，因此 strict_three_layer_status 被标记为 blocked_l1_window_mapping_not_strong。

同时，P9/P10 已经在强同窗对象层和 VRP 层证据下确认 object_layer_divergence_observed，因此最终保守结论仍然是：不允许确认 E4-A，当前阻断层为 object_layer。

## 5. 当前限制

1. L1 宣告视图为 retrofit_or_diagnostic 补采，不是严格三层同窗采集。
2. object_source_mode 仍是 cache_file_inventory，不完全等价于 validator active-object decision。
3. E4-B cross-validator 仍为 reserved_only。
4. control-plane impact 仍为 reserved_only。
5. 后续需要重新跑 group_m15_* strict strong group 作为最终三层强同窗样例。

## 6. 证据包

evidence_pack: {copied_evidence_pack}
evidence_pack_sha256_file: {copied_evidence_sha}

## 7. 下一步

建议进入 Batch 6，重新构造一个 group_m15_*，三地尽量同步采集 L1/L2/L3，形成严格三层 strong-window 工程验收样例。
"""

    (docs_dir / "M15_P11_three_layer_closeout_summary_zh.md").write_text(
        closeout_summary,
        encoding="utf-8",
    )

    acceptance = (
        len(blockers) == 0
        and final_status is not None
        and evidence_pack.exists()
        and evidence_pack_sha256_file.exists()
        and (outputs_dir / "SHA256SUMS.txt").exists()
    )

    closeout_manifest = {
        "schema": "s3.stage3.m15.p11_e_closeout_manifest.v1",
        "created_at_utc": utc_now(),
        "snapshot_group_id": group_id,
        "p11_closeout_id": out_dir.name,
        "p11_closeout_dir": str(out_dir),

        "final_status": final_status,
        "strict_three_layer_status": strict_three_layer_status,
        "e4_status": e4_status,
        "confirmed_allowed": confirmed_allowed,
        "blocking_layer": blocking_layer,
        "attribution_layer": attribution_layer,
        "confidence": confidence,

        "evidence_pack": str(copied_evidence_pack),
        "evidence_pack_sha256_file": str(copied_evidence_sha),
        "summary_doc": str(docs_dir / "M15_P11_three_layer_closeout_summary_zh.md"),
        "sha256sums": str(outputs_dir / "SHA256SUMS.txt"),

        "warnings": warnings,
        "blockers": blockers,
        "P11_closeout_acceptance": acceptance,
    }

    write_json(manifests_dir / "P11_E_three_layer_closeout_manifest.json", closeout_manifest)
    write_json(outputs_dir / "P11_E_three_layer_closeout_summary.json", closeout_manifest)

    acceptance_text = f"""P11_E_THREE_LAYER_CLOSEOUT=DONE

created_at_utc = {utc_now()}

snapshot_group_id = {group_id}

final_status = {final_status}
strict_three_layer_status = {strict_three_layer_status}
e4_status = {e4_status}
confirmed_allowed = {confirmed_allowed}
blocking_layer = {blocking_layer}
attribution_layer = {attribution_layer}
confidence = {confidence}

evidence_pack_exists = {copied_evidence_pack.exists()}
evidence_pack_sha256_exists = {copied_evidence_sha.exists()}
summary_doc_exists = {(docs_dir / "M15_P11_three_layer_closeout_summary_zh.md").exists()}
sha256sums_exists = {(outputs_dir / "SHA256SUMS.txt").exists()}

warnings = {warnings}
blockers = {blockers}

runtime_changes:
  collector_main_service_restarted = False
  probe_restarted = False
  new_validator_installed = False
  bgp_data_loaded = False
  cron_enabled = False

outputs:
  {manifests_dir / "P11_E_three_layer_closeout_manifest.json"}
  {docs_dir / "M15_P11_three_layer_closeout_summary_zh.md"}
  {outputs_dir / "SHA256SUMS.txt"}
  {copied_evidence_pack}
  {copied_evidence_sha}

next_batch:
  Batch 6 / M15 strict strong group rerun

P11_closeout_acceptance = {acceptance}
"""

    (checks_dir / "P11_E_three_layer_closeout_acceptance.txt").write_text(
        acceptance_text,
        encoding="utf-8",
    )

    print(acceptance_text)

    if not acceptance:
        raise SystemExit("[BLOCKED] P11 closeout acceptance is False")


if __name__ == "__main__":
    main()
