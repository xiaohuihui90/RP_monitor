#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import csv
import json
import os
import tarfile
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text(encoding="utf-8"))


def read_tsv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    with path.open("rt", encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_archive(run_dir: Path) -> Dict[str, str]:
    archive_dir = run_dir / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)

    archive_path = archive_dir / f"{run_dir.name}.tar.gz"
    sha_path = archive_dir / f"{run_dir.name}.tar.gz.sha256"

    with tarfile.open(archive_path, "w:gz") as tf:
        for sub in ["outputs", "checks", "inputs"]:
            p = run_dir / sub
            if p.exists():
                tf.add(p, arcname=f"{run_dir.name}/{sub}")

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    sha_path.write_text(f"{digest}  {archive_path.name}\n", encoding="utf-8")

    return {
        "archive_path": str(archive_path),
        "archive_sha256": str(sha_path),
        "archive_digest": "sha256:" + digest,
    }


def pct(num: int, den: int) -> str:
    if not den:
        return "0.00%"
    return f"{num / den * 100:.2f}%"


def main() -> int:
    final_dir = Path(os.environ["M21_FINAL_DIR"])
    outputs = final_dir / "outputs"
    checks = final_dir / "checks"
    inputs = final_dir / "inputs"

    for d in [outputs, checks, inputs]:
        d.mkdir(parents=True, exist_ok=True)

    m21c = load_json(Path(os.environ["M21C_MERGE_SUMMARY"]))
    m21d = load_json(Path(os.environ["M21D_MERGE_SUMMARY"]))
    skew = load_json(Path(os.environ["M21D_SKEW_SUMMARY"]))
    top_hosts = read_tsv(Path(os.environ["M21D_TOP_HOSTS"]))

    input_manifest = {
        "schema": "s3.m21.final_summary.input_manifest.v1",
        "created_at_utc": utc_now(),
        "inputs": {
            "m21c_merge_summary": os.environ["M21C_MERGE_SUMMARY"],
            "m21d_merge_summary": os.environ["M21D_MERGE_SUMMARY"],
            "m21d_skew_summary": os.environ["M21D_SKEW_SUMMARY"],
            "m21d_top_hosts": os.environ["M21D_TOP_HOSTS"],
        },
    }
    write_json(inputs / "M21_final_summary_input_manifest.json", input_manifest)

    m21c_union = int(m21c.get("source_uri_union_count") or 0)
    m21c_matrix = int(m21c.get("matrix_row_count") or 0)
    m21c_verdict = m21c.get("by_verdict", {})
    m21c_unrecoverable = int(m21c_verdict.get("historical_source_uri_not_recoverable_current_cache", 0))

    m21d_union = int(m21d.get("source_uri_union_count") or 0)
    m21d_matrix = int(m21d.get("matrix_row_count") or 0)
    m21d_verdict = m21d.get("by_verdict", {})
    m21d_converged = int(m21d_verdict.get("current_cache_converged_object_present", 0))
    m21d_unrecoverable = int(m21d_verdict.get("sample_not_recoverable_current_cache", 0))

    bj_missing = int(skew.get("bj_missing_row_total") or 0)
    source_uri_total = int(skew.get("source_uri_total") or 0)
    object_hit = int(skew.get("source_uri_object_index_hit") or 0)
    object_miss = int(skew.get("source_uri_object_index_miss") or 0)

    by_ta = skew.get("by_ta", {})
    by_host = skew.get("by_source_host_top", {})

    top_hosts_enriched = []
    for r in top_hosts:
        try:
            count = int(r.get("count") or 0)
        except Exception:
            count = 0
        top_hosts_enriched.append({
            "rank": r.get("rank"),
            "host": r.get("host"),
            "count": count,
            "percent_of_bj_missing": pct(count, bj_missing),
        })

    final_json = {
        "schema": "s3.m21.final_stage_summary_report.v1",
        "status": "PASS",
        "created_at_utc": utc_now(),
        "title": "M21 final stage summary report",
        "scope": "M21-C small-scale VRP difference attribution and M21-D single-node validator effective view skew diagnosis",
        "m21c": {
            "name": "M21-C small-scale VRP difference object attribution",
            "status": "source_level_attribution_completed_object_recovery_gap_observed",
            "source_uri_union_count": m21c_union,
            "matrix_row_count": m21c_matrix,
            "by_verdict": m21c_verdict,
            "by_presence_pattern": m21c.get("by_presence_pattern", {}),
            "by_source_host_top": m21c.get("by_source_host_top", {}),
            "by_ta": m21c.get("by_ta", {}),
            "conclusion": [
                "M21-C has completed affected VRP to ROA source URI source-level attribution.",
                "All 18 recovered source URIs are missing from the current cache of probe-bj, probe-cd, and probe-sg.",
                "Therefore, this stage should be treated as source-level attribution plus historical object recovery gap, not strong object-level attribution.",
            ],
            "next_required": [
                "Trigger raw-on-demand object preservation during the actual VRP-diff window.",
                "Preserve raw ROA and corresponding manifest evidence near real time.",
                "Join source URI to manifest fileList and raw object hash when evidence is available.",
            ],
        },
        "m21d": {
            "name": "M21-D BJ 12:42 single-node validator effective view skew case",
            "status": "independent_anomaly_case_preserved_current_cache_sample_checked",
            "bj_missing_row_total": bj_missing,
            "source_uri_total": source_uri_total,
            "source_uri_object_index_hit": object_hit,
            "source_uri_object_index_miss": object_miss,
            "object_index_hit_ratio": pct(object_hit, source_uri_total),
            "by_ta": by_ta,
            "by_source_host_top": by_host,
            "top_hosts_enriched": top_hosts_enriched[:15],
            "current_cache_sample": {
                "source_uri_union_count": m21d_union,
                "matrix_row_count": m21d_matrix,
                "by_verdict": m21d_verdict,
                "by_presence_pattern": m21d.get("by_presence_pattern", {}),
                "by_source_host_top": m21d.get("by_source_host_top", {}),
            },
            "conclusion": [
                "M21-D has preserved BJ 12:42 large-scale VRP absence as an independent anomaly case.",
                "The original skew is APNIC-dominant and concentrated in several repository hosts.",
                "Current-cache sample checking shows 22 sampled URIs present on all three probes and 118 unavailable on all three probes.",
                "No current-cache pattern of CD/SG present while BJ missing remains in the sample, indicating the original skew was likely a historical window/cache-effective-view phenomenon.",
            ],
            "next_required": [
                "Add strong-window raw-on-demand triggering at the moment of VRP difference detection.",
                "Collect validator last_update_done and repository status around anomaly windows.",
                "Join source host to RRDP/rsync repository and manifest context.",
            ],
        },
        "overall_conclusion": [
            "M21 confirms that VRP output differences can be mapped upward to ROA source URI provenance.",
            "M21 also shows that post-hoc current-cache recovery is insufficient for strong object-level attribution.",
            "M21-C and M21-D should remain separate evidence lines: small-scale affected VRP attribution vs. single-node large-scale effective view skew diagnosis.",
            "The next milestone should be M22: strong-window raw-on-demand evidence preservation and manifest/object-level attribution.",
        ],
    }

    report_json_path = outputs / "M21_final_stage_summary_report.json"
    report_md_path = outputs / "M21_final_stage_summary_report.md"
    weekly_txt_path = outputs / "M21_final_summary_for_weekly.txt"
    design_notes_path = outputs / "M21_to_M22_transition_notes.md"

    write_json(report_json_path, final_json)

    md = []
    md.append("# M21 最终阶段总结报告\n\n")
    md.append(f"- created_at_utc: `{final_json['created_at_utc']}`\n")
    md.append("- scope: M21-C 小规模 VRP 差异对象级归因；M21-D 单节点大规模 validator effective view skew 诊断\n\n")

    md.append("## 1. 阶段目标\n\n")
    md.append("M21 的目标是将验证输出层 VRP 差异继续映射到 ROA source URI、对象层 URI/hash、manifest 和 repository / PP 状态，形成跨层归因链路。\n\n")

    md.append("## 2. M21-C：小规模 VRP 差异对象级归因\n\n")
    md.append("### 2.1 关键结果\n\n")
    md.append(f"- source_uri_union_count: `{m21c_union}`\n")
    md.append(f"- matrix_row_count: `{m21c_matrix}`\n")
    md.append(f"- historical_source_uri_not_recoverable_current_cache: `{m21c_unrecoverable}`\n")
    md.append(f"- by_ta: `{m21c.get('by_ta', {})}`\n")
    md.append(f"- by_source_host_top: `{m21c.get('by_source_host_top', {})}`\n\n")
    md.append("### 2.2 结论\n\n")
    md.append("M21-C 已完成 affected VRP 到 ROA source URI 的 source-level attribution。三地当前 cache presence 检查显示，18 条 source URI 在 BJ/CD/SG 当前 cache 中均不可恢复。因此，当前不能给出 raw object / manifest 层面的强归因，应将其固化为 source-level attribution 与 historical object recovery gap。\n\n")

    md.append("## 3. M21-D：BJ 12:42 大规模 effective view skew 诊断\n\n")
    md.append("### 3.1 原始异常样本\n\n")
    md.append(f"- bj_missing_row_total: `{bj_missing}`\n")
    md.append(f"- source_uri_total: `{source_uri_total}`\n")
    md.append(f"- source_uri_object_index_hit: `{object_hit}` ({pct(object_hit, source_uri_total)})\n")
    md.append(f"- source_uri_object_index_miss: `{object_miss}`\n")
    md.append(f"- by_ta: `{by_ta}`\n\n")
    md.append("### 3.2 Top repository hosts\n\n")
    for r in top_hosts_enriched[:10]:
        md.append(f"- #{r['rank']} {r['host']}: `{r['count']}` ({r['percent_of_bj_missing']})\n")
    md.append("\n### 3.3 当前 cache sample 复查\n\n")
    md.append(f"- sample source_uri_union_count: `{m21d_union}`\n")
    md.append(f"- current_cache_converged_object_present: `{m21d_converged}`\n")
    md.append(f"- sample_not_recoverable_current_cache: `{m21d_unrecoverable}`\n")
    md.append(f"- by_presence_pattern: `{m21d.get('by_presence_pattern', {})}`\n\n")
    md.append("### 3.4 结论\n\n")
    md.append("M21-D 将 BJ 12:42 大规模 VRP 缺失固化为独立异常样本。原始异常表现为 BJ 相比 CD/SG 缺失 27,377 条 VRP，主要集中在 APNIC 及若干 repository host。后续当前 cache 抽样复查显示，140 条 top-host sample 中 22 条三地共同存在，118 条三地共同不可恢复，未再观察到 BJ 单独缺失模式。因此，该异常更可能是历史窗口内的 validator cache / effective object view skew，而不是长期稳定的 BJ 对象缺失。\n\n")

    md.append("## 4. 总体结论\n\n")
    md.append("1. M21 已证明 VRP 差异可以映射到 ROA source URI provenance。\n")
    md.append("2. M21-C 显示，事后从当前 cache 恢复历史 affected ROA 对象并不可靠。\n")
    md.append("3. M21-D 显示，单节点大规模 VRP 缺失可能是窗口性 effective view skew，必须在差异发生窗口保存对象证据。\n")
    md.append("4. 后续 M22 应重点建设强窗口触发的 raw-on-demand 机制，并联动 manifest/object hash 与 repository/PP 上下文。\n\n")

    md.append("## 5. M22 转入建议\n\n")
    md.append("### M22-A：strong-window raw-on-demand trigger\n")
    md.append("- 当 collector 发现 VRP diff / affected VRP 后，立即生成 source URI request，并下发三地 probe。\n\n")
    md.append("### M22-B：raw ROA + manifest evidence preservation\n")
    md.append("- 在差异窗口内保存 raw ROA、同目录 manifest、raw_sha256 和 manifest fileList。\n\n")
    md.append("### M22-C：object-level attribution verdict\n")
    md.append("- 输出 object_presence_divergence、same_uri_hash_divergence、manifest_version_skew、validator_semantic_candidate 等 verdict。\n")

    write_text(report_md_path, "".join(md))

    weekly = []
    weekly.append("M21 阶段总结：\n")
    weekly.append("1、完成小规模 VRP 差异的 source-level 归因。系统已将 19 条 affected VRP 进一步反查到 ROA source URI，并完成三地当前 cache presence 检查。结果显示，18 条 source URI 在三地当前 cache 中均不可恢复，因此当前只能固化为 source-level attribution，不能强行给出 raw object / manifest 层面的强归因。\n")
    weekly.append("2、完成 BJ 12:42 大规模 validator effective view skew 独立异常样本固化。该样本中 BJ 相比 CD/SG 缺失 27,377 条 VRP，缺失主要集中在 APNIC 及 rpki.cernet.net、rpki-rps.cnnic.cn、rpki-repo.registro.br 等 repository host。后续当前 cache 抽样复查显示，top-host sample 中 22 条三地共同存在、118 条三地共同不可恢复，说明该异常更可能是历史窗口内的 cache / effective view 偏移。\n")
    weekly.append("3、M21 的核心结论是：VRP 差异可以映射到 ROA source URI，但强对象级归因必须依赖差异窗口内的 raw-on-demand 对象留存。下一步进入 M22，重点建设强窗口触发的 raw ROA / manifest / object hash 留存与归因机制。\n")
    write_text(weekly_txt_path, "".join(weekly))

    transition = []
    transition.append("# M21 → M22 转入说明\n\n")
    transition.append("M21 证明了 VRP provenance 映射的可行性，同时暴露出 post-hoc current-cache recovery 的不足。M22 应从“事后恢复”转向“差异窗口内证据留存”。\n\n")
    transition.append("## M22-A\n建立 strong-window raw-on-demand trigger：VRP diff 出现后立即冻结 affected source URI 列表。\n\n")
    transition.append("## M22-B\n三地 probe 同步保存 raw ROA、manifest、hash 和路径证据。\n\n")
    transition.append("## M22-C\ncollector 汇总三地证据，输出 object-to-VRP attribution verdict。\n")
    write_text(design_notes_path, "".join(transition))

    archive_info = make_archive(final_dir)

    check = "\n".join([
        "M21_FINAL_STAGE_SUMMARY_REPORT=PASS",
        "",
        f"m21c_source_uri_union_count = {m21c_union}",
        f"m21c_by_verdict = {m21c_verdict}",
        f"m21d_bj_missing_row_total = {bj_missing}",
        f"m21d_source_uri_union_count = {m21d_union}",
        f"m21d_by_verdict = {m21d_verdict}",
        f"report_md = {report_md_path}",
        f"report_json = {report_json_path}",
        f"weekly_txt = {weekly_txt_path}",
        f"transition_notes = {design_notes_path}",
        f"archive_path = {archive_info['archive_path']}",
        f"archive_sha256 = {archive_info['archive_sha256']}",
    ]) + "\n"

    write_text(checks / "M21_final_stage_summary_report_check.txt", check)

    final_json["archive"] = archive_info
    write_json(report_json_path, final_json)

    print(check)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
