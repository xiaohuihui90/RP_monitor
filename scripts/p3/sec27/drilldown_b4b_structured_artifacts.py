#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path
from collections import Counter


TARGETS = [
    ("ROA_MANIFEST", "data/p3_collector/m21_manifest_pp_alignment/history/m21_a1_roa_repository_listing_20260607T144706Z/outputs/m21_a2_roa_to_manifest_candidate_records.jsonl"),
    ("MANIFEST_FILELIST_INDEX", "data/p3_collector/m21_manifest_pp_alignment/history/m21_a1_roa_repository_listing_20260607T144706Z/indexes/m21_a3_manifest_filelist_index.jsonl"),
    ("MANIFEST_FILELIST_INDEX_FIXED", "data/p3_collector/m21_manifest_pp_alignment/history/m21_a1_roa_repository_listing_20260607T144706Z/indexes/m21_a3c_manifest_filelist_index.jsonl"),
    ("ROA_FILELIST_MATCH", "data/p3_collector/m21_manifest_pp_alignment/history/m21_a1_roa_repository_listing_20260607T144706Z/outputs/m21_a3_roa_manifest_filelist_match_records.jsonl"),
    ("ROA_FILELIST_MATCH_FIXED", "data/p3_collector/m21_manifest_pp_alignment/history/m21_a1_roa_repository_listing_20260607T144706Z/outputs/m21_a3c_roa_manifest_filelist_match_records.jsonl"),
    ("M22D_REVERSE_EVIDENCE", "data/probe/m22_raw_evidence/history/m22_raw_evidence_probe_probe-cd_m22a_replay_from_m21c_20260519_20260519T073414Z/indexes/m22d_roa_reverse_evidence_records.jsonl"),
    ("M22C_HASH_SUMMARY", "data/probe/m22_raw_evidence/history/m22_raw_evidence_probe_probe-cd_m22a_replay_from_m21c_20260519_20260519T073414Z/outputs/M22C_roa_hash_verification_summary.json"),
    ("M22D_VERDICT", "data/probe/m22_raw_evidence/history/m22_raw_evidence_probe_probe-cd_m22a_replay_from_m21c_20260519_20260519T073414Z/outputs/M22D_roa_reverse_evidence_verdict.json"),
]

OUT_DIR = Path("data/p3_analysis/sec27/b4b_r1_schema_drilldown")
REPORT = Path("data/p3_analysis/sec27/reports/sec27_b4b_r1_schema_drilldown_report.json")
DETAIL = OUT_DIR / "b4b_r1_schema_drilldown_detail.json"
SUMMARY_CSV = Path("paper_tables/latest/sec27_b4b_r1/table_b4b_r1_schema_summary.csv")


INTERESTING = [
    "schema",
    "source_uri",
    "roa_uri",
    "uri",
    "object_uri",
    "manifest_uri",
    "mft_uri",
    "file_name",
    "filename",
    "file",
    "hash",
    "sha256",
    "object_hash",
    "file_hash",
    "tal",
    "repo_host",
    "repo_base",
    "vrp_key",
    "match",
    "verdict",
    "evidence_level",
]


def read_records(path: Path, limit: int = 200):
    if not path.exists():
        return []

    text = path.read_text(encoding="utf-8", errors="ignore").lstrip()

    if not text:
        return []

    if path.suffix == ".json":
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                return [obj]
            if isinstance(obj, list):
                return [x for x in obj[:limit] if isinstance(x, dict)]
        except Exception:
            return []

    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if len(rows) >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def flatten_keys(obj, prefix=""):
    keys = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            kk = f"{prefix}.{k}" if prefix else str(k)
            keys.append(kk)
            if isinstance(v, dict):
                keys.extend(flatten_keys(v, kk))
            elif isinstance(v, list) and v and isinstance(v[0], dict):
                keys.extend(flatten_keys(v[0], kk + "[]"))
    return keys


def preview(v):
    if isinstance(v, (str, int, float, bool)) or v is None:
        return str(v)[:300]
    if isinstance(v, list):
        return f"list(len={len(v)}) " + str(v[:2])[:300]
    if isinstance(v, dict):
        return "dict " + str({k: v[k] for k in list(v)[:8]})[:300]
    return str(type(v))


def get_nested(obj, path):
    cur = obj
    for part in path.replace("[]", "").split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and cur and isinstance(cur[0], dict):
            cur = cur[0].get(part)
        else:
            return None
    return cur


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_CSV.parent.mkdir(parents=True, exist_ok=True)

    profiles = []
    summary_rows = []

    for cls, path_s in TARGETS:
        path = Path(path_s)
        records = read_records(path)

        key_counter = Counter()
        nested_counter = Counter()
        interesting_values = {}

        for rec in records:
            for k in rec.keys():
                key_counter[k] += 1

            for k in flatten_keys(rec):
                nested_counter[k] += 1

            for k in INTERESTING:
                if k in rec and k not in interesting_values:
                    interesting_values[k] = preview(rec.get(k))

            for nk in flatten_keys(rec):
                tail = nk.split(".")[-1].replace("[]", "")
                if tail in INTERESTING and nk not in interesting_values:
                    interesting_values[nk] = preview(get_nested(rec, nk))

        profile = {
            "class": cls,
            "path": path_s,
            "exists": path.exists(),
            "size_bytes": path.stat().st_size if path.exists() else None,
            "record_count_sampled": len(records),
            "top_level_keys": [k for k, _ in key_counter.most_common(80)],
            "nested_keys": [k for k, _ in nested_counter.most_common(120)],
            "interesting_values": interesting_values,
            "sample_records": records[:3],
        }
        profiles.append(profile)

        summary_rows.append({
            "class": cls,
            "path": path_s,
            "exists": str(path.exists()),
            "record_count_sampled": len(records),
            "key_count": len(profile["top_level_keys"]),
            "interesting_keys": ";".join(sorted(interesting_values.keys())),
            "top_level_keys": ";".join(profile["top_level_keys"][:60]),
        })

    DETAIL.write_text(json.dumps(profiles, indent=2, ensure_ascii=False), encoding="utf-8")

    with SUMMARY_CSV.open("w", newline="", encoding="utf-8") as f:
        fields = [
            "class",
            "path",
            "exists",
            "record_count_sampled",
            "key_count",
            "interesting_keys",
            "top_level_keys",
        ]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in summary_rows:
            w.writerow(r)

    report = {
        "schema": "sec27.b4b_r1_schema_drilldown_report.v1",
        "status": "PASS",
        "target_count": len(TARGETS),
        "existing_count": sum(1 for _, p in TARGETS if Path(p).exists()),
        "records_profiled": sum(x["record_count_sampled"] for x in profiles),
        "detail_json": str(DETAIL),
        "summary_csv": str(SUMMARY_CSV),
        "file_summaries": [
            {
                "class": x["class"],
                "path": x["path"],
                "exists": x["exists"],
                "record_count_sampled": x["record_count_sampled"],
                "top_level_keys": x["top_level_keys"][:40],
                "interesting_keys_found": sorted(x["interesting_values"].keys()),
            }
            for x in profiles
        ],
    }

    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print("status =", report["status"])
    print("existing_count =", report["existing_count"])
    print("records_profiled =", report["records_profiled"])
    for x in report["file_summaries"]:
        print("----")
        print("class =", x["class"])
        print("path =", x["path"])
        print("exists =", x["exists"])
        print("record_count_sampled =", x["record_count_sampled"])
        print("top_level_keys =", x["top_level_keys"])
        print("interesting_keys_found =", x["interesting_keys_found"])
    print("WROTE", REPORT)
    print("WROTE", DETAIL)
    print("WROTE", SUMMARY_CSV)


if __name__ == "__main__":
    main()
