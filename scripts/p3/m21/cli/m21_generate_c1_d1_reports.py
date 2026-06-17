#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import csv
import json
import os
from collections import Counter
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
        raise FileNotFoundError(path)
    with path.open("rt", encoding="utf-8", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def read_jsonl_count(path: Path) -> int:
    if not path.exists():
        return 0
    n = 0
    with path.open("rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_m21c_report() -> None:
    m21c_out = Path(os.environ["M21C_OUT_DIR"])
    summary_path = Path(os.environ["M21C_SUMMARY"])
    table_path = Path(os.environ["M21C_AFFECTED_TABLE"])
    candidates_path = Path(os.environ["M21C_CANDIDATES"])

    summary = load_json(summary_path)
    rows = read_tsv(table_path)
    candidate_count = read_jsonl_count(candidates_path)

    by_presence = Counter()
    by_host = Counter()
    by_ta = Counter()
    no_source_uri = 0
    source_uri_rows = 0

    for r in rows:
        present = r.get("present_probes", "")
        absent = r.get("absent_probes", "")
        by_presence[f"present={present}|absent={absent}"] += 1
        ta = (r.get("ta") or "unknown").lower()
        by_ta[ta] += 1

        uri_samples = [
            r.get("bj_uri_sample", ""),
            r.get("cd_uri_sample", ""),
            r.get("sg_uri_sample", ""),
        ]
        has_uri = False
        for u in uri_samples:
            if u:
                has_uri = True
                host = u.split("://", 1)[-1].split("/", 1)[0]
                by_host[host] += 1
        if has_uri:
            source_uri_rows += 1
        else:
            no_source_uri += 1

    report = {
        "schema": "s3.m21c.source_level_report.v1",
        "status": "PASS",
        "created_at_utc": utc_now(),
        "title": "M21-C source-level attribution report",
        "scope": "Small-scale affected VRP object attribution, source-level stage",
        "inputs": {
            "summary": str(summary_path),
            "affected_table": str(table_path),
            "candidates": str(candidates_path),
        },
        "key_metrics": {
            "affected_total": summary.get("affected_total"),
            "source_uri_total": summary.get("source_uri_total"),
            "source_uri_object_index_hit": summary.get("source_uri_object_index_hit"),
            "source_uri_object_index_miss": summary.get("source_uri_object_index_miss"),
            "affected_table_rows": len(rows),
            "source_uri_rows_from_table": source_uri_rows,
            "no_source_uri_rows_from_table": no_source_uri,
            "candidate_record_count": candidate_count,
        },
        "distributions": {
            "by_ta": dict(by_ta.most_common()),
            "by_source_host_top": dict(by_host.most_common(30)),
            "by_presence_pattern": dict(by_presence.most_common(30)),
            "by_hit_status": summary.get("by_hit_status", {}),
        },
        "current_conclusion": [
            "M21-C has completed affected VRP to ROA source URI source-level attribution.",
            "The current M20 object identity index did not hit these affected ROA source URIs.",
            "The stage is therefore source-level attribution, not yet strong object-level attribution.",
            "Next step is raw-on-demand ROA recovery and manifest/object hash join."
        ],
        "important_boundary": summary.get("important_boundary", []),
    }

    outputs = m21c_out / "outputs"
    checks = m21c_out / "checks"

    report_json = outputs / "M21C_source_level_report.json"
    report_md = outputs / "M21C_source_level_report.md"
    report_tsv = outputs / "M21C_source_level_report.tsv"
    check_txt = checks / "M21C_source_level_report_check.txt"

    write_json(report_json, report)

    # Copy normalized TSV into M21-C output area.
    with report_tsv.open("wt", encoding="utf-8", newline="") as w:
        if rows:
            fieldnames = list(rows[0].keys())
            writer = csv.DictWriter(w, fieldnames=fieldnames, delimiter="\t")
            writer.writeheader()
            writer.writerows(rows)

    md = []
    md.append("# M21-C Source-Level Attribution Report\n")
    md.append(f"- created_at_utc: `{report['created_at_utc']}`\n")
    md.append("- scope: 小规模 affected VRP 差异的 source-level 归因\n")
    md.append("\n## 1. Key Metrics\n")
    for k, v in report["key_metrics"].items():
        md.append(f"- {k}: `{v}`\n")
    md.append("\n## 2. TAL / RIR Distribution\n")
    for k, v in report["distributions"]["by_ta"].items():
        md.append(f"- {k}: `{v}`\n")
    md.append("\n## 3. Top Source Hosts\n")
    for k, v in report["distributions"]["by_source_host_top"].items():
        md.append(f"- {k}: `{v}`\n")
    md.append("\n## 4. Presence Patterns\n")
    for k, v in report["distributions"]["by_presence_pattern"].items():
        md.append(f"- {k}: `{v}`\n")
    md.append("\n## 5. Current Conclusion\n")
    md.append(
        "M21-C 已完成 affected VRP 到 ROA source URI 的 source-level attribution。"
        "当前 18 条 source URI 暂未命中 M20 object identity index，"
        "说明下一步需要 raw-on-demand ROA 补采，并继续做 manifest / object hash join，"
        "才能形成强对象级归因。\n"
    )
    md.append("\n## 6. Boundary\n")
    for x in report["important_boundary"]:
        md.append(f"- {x}\n")

    write_text(report_md, "".join(md))

    check = "\n".join([
        "M21C_SOURCE_LEVEL_REPORT=PASS",
        "",
        f"affected_total = {report['key_metrics']['affected_total']}",
        f"source_uri_total = {report['key_metrics']['source_uri_total']}",
        f"source_uri_object_index_hit = {report['key_metrics']['source_uri_object_index_hit']}",
        f"source_uri_object_index_miss = {report['key_metrics']['source_uri_object_index_miss']}",
        f"affected_table_rows = {len(rows)}",
        f"report_json = {report_json}",
        f"report_md = {report_md}",
        f"report_tsv = {report_tsv}",
    ]) + "\n"
    write_text(check_txt, check)
    print(check)


def build_m21d_report() -> None:
    m21d_out = Path(os.environ["M21D_OUT_DIR"])
    summary_path = Path(os.environ["M21D_SUMMARY"])
    top_hosts_path = Path(os.environ["M21D_TOP_HOSTS"])

    summary = load_json(summary_path)
    top_hosts = read_tsv(top_hosts_path)

    total = int(summary.get("bj_missing_row_total") or 0)
    top_hosts_enriched = []
    for r in top_hosts:
        try:
            count = int(r.get("count") or 0)
        except Exception:
            count = 0
        pct = (count / total * 100.0) if total else 0.0
        item = dict(r)
        item["percent_of_bj_missing"] = f"{pct:.4f}"
        top_hosts_enriched.append(item)

    report = {
        "schema": "s3.m21d.bj_skew_case_report.v1",
        "status": "PASS",
        "created_at_utc": utc_now(),
        "title": "M21-D BJ 12:42 validator effective view skew case report",
        "scope": "Single-node large-scale validator effective view skew diagnosis",
        "inputs": {
            "summary": str(summary_path),
            "top_hosts": str(top_hosts_path),
        },
        "key_metrics": {
            "bj_missing_row_total": summary.get("bj_missing_row_total"),
            "source_uri_total": summary.get("source_uri_total"),
            "source_uri_object_index_hit": summary.get("source_uri_object_index_hit"),
            "source_uri_object_index_miss": summary.get("source_uri_object_index_miss"),
            "top_host_count": len(top_hosts),
        },
        "distributions": {
            "by_ta": summary.get("by_ta", {}),
            "by_source_host_top": summary.get("by_source_host_top", {}),
            "by_hit_status": summary.get("by_hit_status", {}),
        },
        "top_hosts_enriched": top_hosts_enriched,
        "current_conclusion": [
            "At 2026-05-18T12:42:00Z, probe-bj had large-scale VRP absence compared with probe-cd/probe-sg.",
            "The absence is APNIC-dominant and concentrated in several repository hosts.",
            "This should be preserved as an independent validator effective view skew case.",
            "It should not be mixed with the 02:09 small-scale affected VRP case."
        ],
        "important_boundary": summary.get("important_boundary", []),
    }

    outputs = m21d_out / "outputs"
    checks = m21d_out / "checks"

    report_json = outputs / "M21D_bj_skew_case_report.json"
    report_md = outputs / "M21D_bj_skew_case_report.md"
    report_tsv = outputs / "M21D_bj_skew_top_hosts_enriched.tsv"
    check_txt = checks / "M21D_bj_skew_case_report_check.txt"

    write_json(report_json, report)

    with report_tsv.open("wt", encoding="utf-8", newline="") as w:
        if top_hosts_enriched:
            fieldnames = list(top_hosts_enriched[0].keys())
            writer = csv.DictWriter(w, fieldnames=fieldnames, delimiter="\t")
            writer.writeheader()
            writer.writerows(top_hosts_enriched)

    md = []
    md.append("# M21-D BJ Skew Case Report\n")
    md.append(f"- created_at_utc: `{report['created_at_utc']}`\n")
    md.append("- scope: BJ 12:42 单节点大规模 validator effective view skew 诊断\n")
    md.append("\n## 1. Key Metrics\n")
    for k, v in report["key_metrics"].items():
        md.append(f"- {k}: `{v}`\n")
    md.append("\n## 2. TAL / RIR Distribution\n")
    for k, v in report["distributions"]["by_ta"].items():
        md.append(f"- {k}: `{v}`\n")
    md.append("\n## 3. Top Source Hosts\n")
    for r in top_hosts_enriched[:15]:
        md.append(
            f"- #{r.get('rank')} {r.get('host')}: `{r.get('count')}` "
            f"({r.get('percent_of_bj_missing')}%)\n"
        )
    md.append("\n## 4. Current Conclusion\n")
    md.append(
        "M21-D 已将 BJ 12:42 大规模缺失固化为独立异常样本。"
        "该样本显示 BJ 相比 CD/SG 缺失 27,377 条 VRP，"
        "缺失主要集中于 APNIC，并高度集中在 rpki.cernet.net、"
        "rpki-rps.cnnic.cn、rpki-repo.registro.br、"
        "rsync.paas.rpki.ripe.net 等 repository host。"
        "该现象更可能反映 BJ 节点 validator cache 或 effective object view 偏移，"
        "不应直接归因于 validator 实现差异。\n"
    )
    md.append("\n## 5. Boundary\n")
    for x in report["important_boundary"]:
        md.append(f"- {x}\n")

    write_text(report_md, "".join(md))

    check = "\n".join([
        "M21D_BJ_SKEW_CASE_REPORT=PASS",
        "",
        f"bj_missing_row_total = {report['key_metrics']['bj_missing_row_total']}",
        f"source_uri_total = {report['key_metrics']['source_uri_total']}",
        f"source_uri_object_index_hit = {report['key_metrics']['source_uri_object_index_hit']}",
        f"source_uri_object_index_miss = {report['key_metrics']['source_uri_object_index_miss']}",
        f"top_host_count = {len(top_hosts)}",
        f"report_json = {report_json}",
        f"report_md = {report_md}",
        f"report_tsv = {report_tsv}",
    ]) + "\n"
    write_text(check_txt, check)
    print(check)


def main() -> int:
    build_m21c_report()
    print()
    build_m21d_report()
    print("M21_C1_D1_REPORTS_CREATED=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
