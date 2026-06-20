#!/usr/bin/env python3
from __future__ import annotations

import csv
import glob
import json
from collections import Counter, defaultdict
from pathlib import Path


B4C = Path("data/p3_analysis/sec27/b4c_candidate_evidence_table/candidate_evidence_table.jsonl")
LIFETIME_PATTERN = "data/p3_collector/m17_vrp_entry_diff/history/m17_window_*/outputs/m18_lifetime_seed_records.jsonl"
DIGEST_PATTERN = "data/p3_collector/m17_vrp_entry_diff/reports/win_*/M17_result_digest.json"

OUT_DIR = Path("data/p3_analysis/sec27/b5d_r1_join_key_diagnosis")
REPORT = Path("data/p3_analysis/sec27/reports/sec27_b5d_r1_join_key_diagnosis_report.json")
SUMMARY_CSV = Path("paper_tables/latest/sec27_b5d_r1/table_b5d_r1_join_key_diagnosis_summary.csv")


def read_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            if isinstance(o, dict):
                yield o


def key_class(v):
    s = str(v or "")
    if not s:
        return "EMPTY"
    if s.startswith("sha256:"):
        return "SHA256_KEY"
    if "|" in s:
        return "PIPE_TUPLE_KEY"
    if s.startswith("ipv4|") or s.startswith("ipv6|"):
        return "IP_VERSION_TUPLE_KEY"
    if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
        return "BARE_SHA256"
    return "OTHER"


def load_b4c():
    keys = set()
    source_uris = set()
    rows = []
    class_counter = Counter()

    for r in read_jsonl(B4C):
        vk = r.get("vrp_key")
        src = r.get("source_uri")
        if vk:
            keys.add(str(vk))
            class_counter[key_class(vk)] += 1
        if src:
            source_uris.add(str(src))
        if len(rows) < 10:
            rows.append({
                "vrp_key": vk,
                "source_uri": src,
                "tal": r.get("tal"),
                "repo_host": r.get("repo_host"),
                "source_filename": r.get("source_filename"),
                "final_evidence_level": r.get("final_evidence_level"),
            })

    return keys, source_uris, class_counter, rows


def load_lifetime():
    paths = sorted(Path(p) for p in glob.glob(LIFETIME_PATTERN))
    keys = set()
    rows = []
    class_counter = Counter()
    by_file = []

    for p in paths:
        c = 0
        file_keys = set()
        for r in read_jsonl(p):
            c += 1
            vk = r.get("vrp_key")
            if vk:
                keys.add(str(vk))
                file_keys.add(str(vk))
                class_counter[key_class(vk)] += 1
            if len(rows) < 20:
                rows.append({
                    "_file": str(p),
                    "vrp_key": vk,
                    "window_id": r.get("window_id"),
                    "first_seen_window": r.get("first_seen_window"),
                    "last_seen_window": r.get("last_seen_window"),
                    "duration_windows": r.get("duration_windows"),
                    "probe_pair": r.get("probe_pair"),
                    "diff_type": r.get("diff_type"),
                    "event_type": r.get("event_type"),
                    "temporal_class": r.get("temporal_class"),
                })
        by_file.append({
            "path": str(p),
            "record_count": c,
            "unique_vrp_key_count": len(file_keys),
        })

    return paths, keys, class_counter, rows, by_file


def nested_find(obj, target_keys):
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in target_keys:
                hits.append((k, v))
            hits.extend(nested_find(v, target_keys))
    elif isinstance(obj, list):
        for x in obj[:50]:
            hits.extend(nested_find(x, target_keys))
    return hits


def profile_digests():
    paths = sorted(Path(p) for p in glob.glob(DIGEST_PATTERN))
    samples = []
    key_counter = Counter()
    source_uri_values = []
    vrp_key_values = []

    target_keys = {"vrp_key", "source_uri", "roa_uri", "tal", "asn", "prefix", "maxLength", "max_length"}

    for p in paths:
        try:
            obj = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue

        hits = nested_find(obj, target_keys)
        for k, v in hits:
            key_counter[k] += 1
            if k in {"source_uri", "roa_uri"} and isinstance(v, str) and len(source_uri_values) < 20:
                source_uri_values.append(v)
            if k == "vrp_key" and isinstance(v, str) and len(vrp_key_values) < 20:
                vrp_key_values.append(v)

        if len(samples) < 10:
            samples.append({
                "path": str(p),
                "top_keys": list(obj.keys())[:50] if isinstance(obj, dict) else [],
                "window_id": obj.get("window_id") if isinstance(obj, dict) else None,
                "changed_record_count": obj.get("changed_record_count") if isinstance(obj, dict) else None,
                "hit_key_counter": dict(key_counter),
            })

    return paths, key_counter, source_uri_values, vrp_key_values, samples


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_CSV.parent.mkdir(parents=True, exist_ok=True)

    b4c_keys, b4c_sources, b4c_key_classes, b4c_samples = load_b4c()
    lifetime_paths, lifetime_keys, lifetime_key_classes, lifetime_samples, lifetime_by_file = load_lifetime()

    exact_overlap = b4c_keys & lifetime_keys

    digest_paths, digest_key_counter, digest_source_uri_values, digest_vrp_key_values, digest_samples = profile_digests()

    # Check digest source_uri overlap with B4C source_uri
    digest_source_overlap = set(digest_source_uri_values) & b4c_sources
    digest_vrp_overlap_b4c = set(digest_vrp_key_values) & b4c_keys
    digest_vrp_overlap_lifetime = set(digest_vrp_key_values) & lifetime_keys

    with SUMMARY_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["section", "value", "count"])
        w.writerow(["b4c", "unique_vrp_key_count", len(b4c_keys)])
        w.writerow(["b4c", "unique_source_uri_count", len(b4c_sources)])
        w.writerow(["lifetime", "source_file_count", len(lifetime_paths)])
        w.writerow(["lifetime", "unique_vrp_key_count", len(lifetime_keys)])
        w.writerow(["join", "exact_vrp_key_overlap_count", len(exact_overlap)])
        w.writerow(["digest", "digest_file_count", len(digest_paths)])
        w.writerow(["digest", "sample_source_uri_overlap_with_b4c", len(digest_source_overlap)])
        w.writerow(["digest", "sample_vrp_key_overlap_with_b4c", len(digest_vrp_overlap_b4c)])
        w.writerow(["digest", "sample_vrp_key_overlap_with_lifetime", len(digest_vrp_overlap_lifetime)])

        for k, v in b4c_key_classes.items():
            w.writerow(["b4c_vrp_key_class", k, v])
        for k, v in lifetime_key_classes.items():
            w.writerow(["lifetime_vrp_key_class", k, v])
        for k, v in digest_key_counter.items():
            w.writerow(["digest_nested_key_hits", k, v])

    detail = {
        "b4c_samples": b4c_samples,
        "lifetime_samples": lifetime_samples,
        "lifetime_by_file": lifetime_by_file,
        "digest_samples": digest_samples,
        "digest_source_uri_values_sample": digest_source_uri_values,
        "digest_vrp_key_values_sample": digest_vrp_key_values,
        "exact_overlap_samples": sorted(exact_overlap)[:20],
    }

    detail_path = OUT_DIR / "b5d_r1_join_key_diagnosis_detail.json"
    detail_path.write_text(json.dumps(detail, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")

    report = {
        "schema": "sec27.b5d_r1_join_key_diagnosis_report.v1",
        "status": "PASS",
        "b4c_unique_vrp_key_count": len(b4c_keys),
        "b4c_unique_source_uri_count": len(b4c_sources),
        "lifetime_source_file_count": len(lifetime_paths),
        "lifetime_unique_vrp_key_count": len(lifetime_keys),
        "exact_vrp_key_overlap_count": len(exact_overlap),
        "b4c_vrp_key_class_distribution": dict(b4c_key_classes),
        "lifetime_vrp_key_class_distribution": dict(lifetime_key_classes),
        "digest_file_count": len(digest_paths),
        "digest_nested_key_hits": dict(digest_key_counter),
        "digest_sample_source_uri_overlap_with_b4c": len(digest_source_overlap),
        "digest_sample_vrp_key_overlap_with_b4c": len(digest_vrp_overlap_b4c),
        "digest_sample_vrp_key_overlap_with_lifetime": len(digest_vrp_overlap_lifetime),
        "outputs": {
            "summary_csv": str(SUMMARY_CSV),
            "detail": str(detail_path),
            "report": str(REPORT),
        },
        "interpretation": [
            "If exact_vrp_key_overlap_count is zero, B4C and M17/M18 lifetime records use different vrp_key namespaces.",
            "If M17_result_digest contains source_uri or roa_uri, it can serve as a bridge for B5D-R2.",
            "If no bridge key exists, longitudinal persistence must be computed within M17/M18 namespace and reported separately from B4C evidence levels.",
        ],
    }

    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    print("status =", report["status"])
    print("b4c_unique_vrp_key_count =", report["b4c_unique_vrp_key_count"])
    print("b4c_unique_source_uri_count =", report["b4c_unique_source_uri_count"])
    print("lifetime_source_file_count =", report["lifetime_source_file_count"])
    print("lifetime_unique_vrp_key_count =", report["lifetime_unique_vrp_key_count"])
    print("exact_vrp_key_overlap_count =", report["exact_vrp_key_overlap_count"])
    print("b4c_vrp_key_class_distribution =", report["b4c_vrp_key_class_distribution"])
    print("lifetime_vrp_key_class_distribution =", report["lifetime_vrp_key_class_distribution"])
    print("digest_nested_key_hits =", report["digest_nested_key_hits"])
    print("WROTE", REPORT)
    print("WROTE", SUMMARY_CSV)
    print("WROTE", detail_path)


if __name__ == "__main__":
    main()
