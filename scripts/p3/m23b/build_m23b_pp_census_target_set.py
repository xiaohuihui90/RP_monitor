#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_csv(path: Path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict], fields: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def repo_host(repo_base: str) -> str:
    try:
        return urlparse(repo_base).netloc
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m22f-records", required=True)
    ap.add_argument("--m22g2-repo-cluster", required=True)
    ap.add_argument("--m23a-root-cause", required=True)
    ap.add_argument("--m23a-candidate-seed", required=True)
    ap.add_argument("--m23a-longitudinal", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    m22f = read_csv(Path(args.m22f_records))
    repo_cluster = read_csv(Path(args.m22g2_repo_cluster))
    m23a_root = read_csv(Path(args.m23a_root_cause))
    m23a_seed = read_csv(Path(args.m23a_candidate_seed))
    longitudinal = read_csv(Path(args.m23a_longitudinal))

    root_by_repo = {r["repo_base"]: r for r in m23a_root if r.get("repo_base")}
    long_by_repo = {r["repo_base"]: r for r in longitudinal if r.get("repo_base")}
    repo_cluster_by_repo = {r["repo_base"]: r for r in repo_cluster if r.get("repo_base")}

    # Group mapped M22F records by repo_base
    mapped = [r for r in m22f if r.get("repo_base") and r.get("evidence_level") == "ROA-level"]
    by_repo = defaultdict(list)
    for r in mapped:
        by_repo[r["repo_base"]].append(r)

    targets = []

    # P1 from all mapped repo_base
    for repo_base, rows in by_repo.items():
        tal_c = Counter(r.get("tal", "") for r in rows if r.get("tal"))
        roa_c = Counter(r.get("roa_uri", "") for r in rows if r.get("roa_uri"))
        prefix_c = Counter(r.get("prefix", "") for r in rows if r.get("prefix"))
        asn_c = Counter(r.get("asn", "") for r in rows if r.get("asn"))
        vrp_c = Counter(r.get("vrp_key", "") for r in rows if r.get("vrp_key"))

        cluster = repo_cluster_by_repo.get(repo_base, {})
        root = root_by_repo.get(repo_base, {})
        lon = long_by_repo.get(repo_base, {})

        candidate_count = len(rows)
        unique_roa = len(roa_c)
        amplification = round(candidate_count / unique_roa, 4) if unique_roa else 0

        priority = "P1"
        if repo_base in root_by_repo:
            priority = "P0"

        observed_feature = lon.get("root_cause_feature_update", "")
        if observed_feature == "fetch_failure_observed":
            capture_reason = "high_amplification_with_reachability_candidate"
        elif observed_feature == "manifest_version_change_observed":
            capture_reason = "high_amplification_with_manifest_version_change"
        elif priority == "P0":
            capture_reason = "high_amplification_manifest_mapped_seed"
        else:
            capture_reason = "roa_level_mapped_candidate_repo"

        targets.append({
            "target_id": f"m23b_target_{len(targets)+1:05d}",
            "target_priority": priority,
            "capture_mode": "same_window_deep" if priority == "P0" else "lightweight_census",
            "capture_reason": capture_reason,
            "tal_top": tal_c.most_common(1)[0][0] if tal_c else "",
            "repo_host": repo_host(repo_base),
            "repo_base": repo_base,
            "candidate_count": candidate_count,
            "unique_vrp_key_count": len(vrp_c),
            "unique_roa_count": unique_roa,
            "unique_prefix_count": len(prefix_c),
            "unique_asn_count": len(asn_c),
            "amplification_candidate_per_roa": amplification,
            "source_bridge_status": "ROA-level",
            "source_bridge_mapping_rate": "1.0",
            "root_cause_seed_available": bool(root),
            "observed_feature": observed_feature,
            "C1_roa_fanout_amplification": root.get("roa_fanout_amplification", ""),
            "C2_manifest_publication_cluster": root.get("manifest_publication_cluster", ""),
            "C3_manifest_version_change_candidate": "True" if observed_feature == "manifest_version_change_observed" else "Unknown",
            "C4_pp_reachability_candidate": "True" if observed_feature == "fetch_failure_observed" else root.get("pp_fetch_reachability_candidate", ""),
            "evidence_level": "E2_MANIFEST_BACKFILL" if priority == "P0" else "E1_SOURCE_BRIDGE",
            "next_action": "M23B-D same-window capture" if priority == "P0" else "M23B-C lightweight census",
        })

    # P2 unmapped group from M22F, grouped by TAL
    unmapped = [r for r in m22f if r.get("evidence_level") == "VRP-only"]
    by_tal_unmapped = defaultdict(list)
    for r in unmapped:
        by_tal_unmapped[r.get("tal", "unknown")].append(r)

    for tal, rows in by_tal_unmapped.items():
        if not rows:
            continue
        prefix_c = Counter(r.get("prefix", "") for r in rows if r.get("prefix"))
        asn_c = Counter(r.get("asn", "") for r in rows if r.get("asn"))
        vrp_c = Counter(r.get("vrp_key", "") for r in rows if r.get("vrp_key"))

        targets.append({
            "target_id": f"m23b_target_{len(targets)+1:05d}",
            "target_priority": "P2",
            "capture_mode": "source_provenance_recovery",
            "capture_reason": "unmapped_current_jsonext_source_bridge_gap",
            "tal_top": tal,
            "repo_host": "",
            "repo_base": "",
            "candidate_count": len(rows),
            "unique_vrp_key_count": len(vrp_c),
            "unique_roa_count": 0,
            "unique_prefix_count": len(prefix_c),
            "unique_asn_count": len(asn_c),
            "amplification_candidate_per_roa": "",
            "source_bridge_status": "VRP-only",
            "source_bridge_mapping_rate": "0.0",
            "root_cause_seed_available": False,
            "observed_feature": "source_provenance_gap_candidate",
            "C1_roa_fanout_amplification": "Unknown",
            "C2_manifest_publication_cluster": "Unknown",
            "C3_manifest_version_change_candidate": "Unknown",
            "C4_pp_reachability_candidate": "Unknown",
            "evidence_level": "E0_VRP_ONLY",
            "next_action": "historical_jsonext_or_future_same_window_source_capture",
        })

    targets.sort(key=lambda r: (
        {"P0": 0, "P1": 1, "P2": 2, "P3": 3}.get(r["target_priority"], 9),
        -int(r["candidate_count"]) if str(r["candidate_count"]).isdigit() else 0,
    ))

    # reassign stable IDs after sorting
    for i, r in enumerate(targets, 1):
        r["target_id"] = f"m23b_target_{i:05d}"

    fields = [
        "target_id", "target_priority", "capture_mode", "capture_reason",
        "tal_top", "repo_host", "repo_base",
        "candidate_count", "unique_vrp_key_count", "unique_roa_count",
        "unique_prefix_count", "unique_asn_count",
        "amplification_candidate_per_roa",
        "source_bridge_status", "source_bridge_mapping_rate",
        "root_cause_seed_available", "observed_feature",
        "C1_roa_fanout_amplification",
        "C2_manifest_publication_cluster",
        "C3_manifest_version_change_candidate",
        "C4_pp_reachability_candidate",
        "evidence_level", "next_action",
    ]

    write_csv(out / "m23b_pp_census_target_set.csv", targets, fields)

    plan = {
        "schema": "s3.m23b.pp_census_target_set.v1",
        "created_at_utc": utc_now(),
        "target_count": len(targets),
        "by_priority": dict(Counter(r["target_priority"] for r in targets)),
        "by_evidence_level": dict(Counter(r["evidence_level"] for r in targets)),
        "targets": targets,
        "semantic_boundary": "candidate_aware_pp_census_target_set_not_live_capture_yet",
        "next_stage": "M23B_B_FEATURE_SCHEMA_AND_M23B_C_LIGHTWEIGHT_CENSUS",
    }

    (out / "m23b_pp_census_target_set.json").write_text(
        json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    md = []
    md.append("# M23B PP Census Target Set")
    md.append("")
    md.append(f"- target_count: `{len(targets)}`")
    md.append(f"- by_priority: `{dict(Counter(r['target_priority'] for r in targets))}`")
    md.append(f"- by_evidence_level: `{dict(Counter(r['evidence_level'] for r in targets))}`")
    md.append("")
    md.append("## Top Targets")
    for r in targets[:30]:
        md.append(
            f"- `{r['target_id']}` priority=`{r['target_priority']}` tal=`{r['tal_top']}` "
            f"repo_host=`{r['repo_host']}` candidates=`{r['candidate_count']}` "
            f"evidence=`{r['evidence_level']}` reason=`{r['capture_reason']}`"
        )
    (out / "m23b_pp_census_target_set.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    check = "\n".join([
        "M23B_A_TARGET_SET=PASS" if targets else "M23B_A_TARGET_SET=FAIL",
        f"created_at_utc = {plan['created_at_utc']}",
        f"target_count = {len(targets)}",
        f"by_priority = {dict(Counter(r['target_priority'] for r in targets))}",
        f"by_evidence_level = {dict(Counter(r['evidence_level'] for r in targets))}",
        f"target_set_json = {out / 'm23b_pp_census_target_set.json'}",
        f"target_set_csv = {out / 'm23b_pp_census_target_set.csv'}",
        f"target_set_md = {out / 'm23b_pp_census_target_set.md'}",
        "semantic_boundary = candidate_aware_pp_census_target_set_not_live_capture_yet",
        "next_stage = M23B_B_FEATURE_SCHEMA",
        "",
    ])
    (out / "M23B_A_TARGET_SET_CHECK.txt").write_text(check, encoding="utf-8")
    print(check)


if __name__ == "__main__":
    main()
