#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            yield json.loads(line)


def write_csv(path, rows, fields):
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m22f-records", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    records_path = Path(args.m22f_records)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    records = [r for r in iter_jsonl(records_path)]
    mapped = [r for r in records if r.get("evidence_level") == "ROA-level" and r.get("roa_uri")]

    tal = Counter(r.get("tal") for r in records)
    tal_mapped = Counter(r.get("tal") for r in mapped)
    tal_repo_host = Counter((r.get("tal"), r.get("repo_host")) for r in mapped)
    tal_repo_base = Counter((r.get("tal"), r.get("repo_base")) for r in mapped)
    tal_roa = Counter((r.get("tal"), r.get("roa_uri")) for r in mapped)
    repo_base = Counter(r.get("repo_base") for r in mapped)
    repo_host = Counter(r.get("repo_host") for r in mapped)
    roa_uri = Counter(r.get("roa_uri") for r in mapped)
    asn = Counter(r.get("asn") for r in mapped)
    prefix = Counter(r.get("prefix") for r in mapped)

    # Cluster by repo_base
    groups = defaultdict(list)
    for r in mapped:
        groups[r.get("repo_base")].append(r)

    cluster_rows = []
    for rb, rs in groups.items():
        tal_c = Counter(r.get("tal") for r in rs)
        roa_c = Counter(r.get("roa_uri") for r in rs)
        asn_c = Counter(r.get("asn") for r in rs)
        prefix_c = Counter(r.get("prefix") for r in rs)
        cluster_rows.append({
            "repo_base": rb,
            "repo_host": rs[0].get("repo_host"),
            "candidate_count": len(rs),
            "unique_roa_uri_count": len(roa_c),
            "unique_asn_count": len(asn_c),
            "unique_prefix_count": len(prefix_c),
            "tal_top": repr(tal_c.most_common(10)),
            "asn_top": repr(asn_c.most_common(10)),
            "prefix_top": repr(prefix_c.most_common(10)),
            "roa_top": repr(roa_c.most_common(10)),
            "case_study_priority": "P0" if len(rs) >= 50 else ("P1" if len(rs) >= 10 else "P2"),
        })

    cluster_rows.sort(key=lambda x: (-x["candidate_count"], x["repo_base"] or ""))

    # ROA derivation table
    roa_groups = defaultdict(list)
    for r in mapped:
        roa_groups[r.get("roa_uri")].append(r)

    roa_rows = []
    for uri, rs in roa_groups.items():
        tal_c = Counter(r.get("tal") for r in rs)
        asn_c = Counter(r.get("asn") for r in rs)
        prefix_c = Counter(r.get("prefix") for r in rs)
        roa_rows.append({
            "roa_uri": uri,
            "repo_base": rs[0].get("repo_base"),
            "tal_top": repr(tal_c.most_common(5)),
            "candidate_count": len(rs),
            "unique_asn_count": len(asn_c),
            "unique_prefix_count": len(prefix_c),
            "asn_top": repr(asn_c.most_common(10)),
            "prefix_top": repr(prefix_c.most_common(10)),
        })
    roa_rows.sort(key=lambda x: (-x["candidate_count"], x["roa_uri"] or ""))

    # CSV outputs
    write_csv(out / "cluster_by_repo_base.csv", cluster_rows, [
        "case_study_priority", "candidate_count", "unique_roa_uri_count",
        "unique_asn_count", "unique_prefix_count", "repo_host", "repo_base",
        "tal_top", "asn_top", "prefix_top", "roa_top"
    ])
    write_csv(out / "cluster_by_roa_uri.csv", roa_rows, [
        "candidate_count", "unique_asn_count", "unique_prefix_count",
        "roa_uri", "repo_base", "tal_top", "asn_top", "prefix_top"
    ])

    tal_rows = []
    for t, total in sorted(tal.items()):
        m = tal_mapped.get(t, 0)
        tal_rows.append({
            "tal": t,
            "total_candidates": total,
            "roa_level_candidates": m,
            "vrp_only_candidates": total - m,
            "roa_mapping_ratio": round(m / total, 4) if total else 0,
            "unique_repo_base_count": len({rb for (tt, rb), n in tal_repo_base.items() if tt == t}),
            "unique_roa_uri_count": len({uri for (tt, uri), n in tal_roa.items() if tt == t}),
        })
    write_csv(out / "tal_roa_mapping_summary.csv", tal_rows, [
        "tal", "total_candidates", "roa_level_candidates", "vrp_only_candidates",
        "roa_mapping_ratio", "unique_repo_base_count", "unique_roa_uri_count"
    ])

    summary = {
        "schema": "s3.m22g.roa_repository_cluster_stats.v1",
        "generated_at_utc": utc_now(),
        "input_records": str(records_path),
        "record_count": len(records),
        "roa_level_record_count": len(mapped),
        "tal_distribution": tal.most_common(),
        "tal_mapped_distribution": tal_mapped.most_common(),
        "repo_host_top20": repo_host.most_common(20),
        "repo_base_top20": repo_base.most_common(20),
        "roa_uri_top20": roa_uri.most_common(20),
        "asn_top20": asn.most_common(20),
        "prefix_top20": prefix.most_common(20),
        "cluster_by_repo_base_top20": cluster_rows[:20],
        "cluster_by_roa_uri_top20": roa_rows[:20],
        "outputs": {
            "cluster_by_repo_base_csv": str(out / "cluster_by_repo_base.csv"),
            "cluster_by_roa_uri_csv": str(out / "cluster_by_roa_uri.csv"),
            "tal_roa_mapping_summary_csv": str(out / "tal_roa_mapping_summary.csv"),
            "summary_json": str(out / "m22g_roa_repository_cluster_summary.json"),
            "summary_md": str(out / "m22g_roa_repository_cluster_summary.md"),
        },
        "semantic_boundary": "roa_repository_cluster_stats_for_current_jsonext_mapped_subset",
        "next_stage": "M22H_MANIFEST_MAPPING_FOR_MAPPED_REPOSITORY_CLUSTERS",
    }

    (out / "m22g_roa_repository_cluster_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    md = []
    md.append("# M22G ROA / Repository Cluster Stats")
    md.append("")
    md.append(f"- record_count: `{len(records)}`")
    md.append(f"- roa_level_record_count: `{len(mapped)}`")
    md.append("")
    md.append("## TAL Mapping Summary")
    for r in tal_rows:
        md.append(
            f"- {r['tal']}: total=`{r['total_candidates']}`, "
            f"ROA-level=`{r['roa_level_candidates']}`, "
            f"ratio=`{r['roa_mapping_ratio']}`, "
            f"unique_repo_base=`{r['unique_repo_base_count']}`, "
            f"unique_roa_uri=`{r['unique_roa_uri_count']}`"
        )
    md.append("")
    md.append("## Top Repo Host")
    for k, v in repo_host.most_common(20):
        md.append(f"- `{k}`: `{v}`")
    md.append("")
    md.append("## Top Repo Base")
    for k, v in repo_base.most_common(20):
        md.append(f"- `{k}`: `{v}`")
    md.append("")
    md.append("## Top ROA URI")
    for k, v in roa_uri.most_common(20):
        md.append(f"- `{k}`: `{v}`")
    md.append("")
    md.append("## Recommended Repository Case-study Clusters")
    for r in cluster_rows[:20]:
        md.append(
            f"- {r['case_study_priority']} count=`{r['candidate_count']}`, "
            f"unique_roa=`{r['unique_roa_uri_count']}`, "
            f"repo=`{r['repo_base']}`"
        )
    md.append("")
    md.append("## Interpretation")
    md.append("- This analysis covers only candidates mapped to ROA-level using the current JSONEXT snapshot.")
    md.append("- LACNIC/RIPE unmapped candidates may require historical JSONEXT sidecars or same-window provenance capture.")
    (out / "m22g_roa_repository_cluster_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    check = "\n".join([
        "M22G_ROA_REPOSITORY_CLUSTER_STATS=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"record_count = {len(records)}",
        f"roa_level_record_count = {len(mapped)}",
        f"tal_mapped_distribution = {tal_mapped.most_common()}",
        f"summary_json = {out / 'm22g_roa_repository_cluster_summary.json'}",
        f"summary_md = {out / 'm22g_roa_repository_cluster_summary.md'}",
        f"cluster_by_repo_base_csv = {out / 'cluster_by_repo_base.csv'}",
        f"cluster_by_roa_uri_csv = {out / 'cluster_by_roa_uri.csv'}",
        "semantic_boundary = roa_repository_cluster_stats_for_current_jsonext_mapped_subset",
        "next_stage = M22H_MANIFEST_MAPPING_FOR_MAPPED_REPOSITORY_CLUSTERS",
        "",
    ])
    (out / "M22G_ROA_REPOSITORY_CLUSTER_STATS_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
