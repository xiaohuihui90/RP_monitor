#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path


ARTIFACT_LIST = Path("data/p3_analysis/sec27/b5c_longitudinal_preflight/b5c_candidate_series_artifacts.txt")
OUT_DIR = Path("data/p3_analysis/sec27/b5c_longitudinal_preflight")
REPORT = Path("data/p3_analysis/sec27/reports/sec27_b5c_longitudinal_preflight_report.json")
SUMMARY_CSV = Path("paper_tables/latest/sec27_b5c/table_b5c_longitudinal_source_profile.csv")

WINDOW_KEYS = {
    "window_id",
    "target_window_id",
    "run_id",
    "cycle_id",
    "validator_cycle_id",
    "created_at_utc",
    "window_start",
    "window_end",
    "timestamp",
    "observed_at",
}

CANDIDATE_KEYS = {
    "vrp_key",
    "source_uri",
    "roa_uri",
    "repo_host",
    "repo_base",
    "tal",
    "candidate_id",
    "final_evidence_level",
    "evidence_level",
    "persistence_class",
}

REQUIRED_FOR_LONGITUDINAL = {"vrp_key", "source_uri"}


def read_records(path: Path, limit: int = 500):
    if not path.exists() or path.stat().st_size == 0:
        return []

    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:2000].lstrip()
    except Exception:
        return []

    if path.suffix == ".json":
        try:
            obj = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(obj, dict):
                return [obj]
            if isinstance(obj, list):
                return [x for x in obj[:limit] if isinstance(x, dict)]
        except Exception:
            return []

    rows = []
    try:
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
    except Exception:
        return []

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


def tail_key(k: str) -> str:
    return k.split(".")[-1].replace("[]", "")


def classify_path(path: Path) -> str:
    s = str(path).lower()
    if "b4c_candidate_evidence_table" in s:
        return "B4C_CANDIDATE_EVIDENCE_TABLE"
    if "b5b_candidate_persistence" in s:
        return "B5B_CANDIDATE_PERSISTENCE"
    if "m17" in s:
        return "M17_INCREMENTAL_OR_DIFF"
    if "m18" in s:
        return "M18_CONVERGENCE_OR_TIMING"
    if "m19" in s:
        return "M19_ROA_TO_VRP"
    if "m21" in s:
        return "M21_JSONEXT_OR_MANIFEST_ALIGNMENT"
    if "persistent" in s:
        return "PERSISTENT_CANDIDATE"
    if "window" in s:
        return "WINDOW_LEVEL"
    if "candidate" in s:
        return "CANDIDATE_OTHER"
    return "OTHER"


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_CSV.parent.mkdir(parents=True, exist_ok=True)

    paths = []
    if ARTIFACT_LIST.exists():
        for line in ARTIFACT_LIST.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line:
                p = Path(line)
                if p.exists():
                    paths.append(p)

    rows = []
    candidate_sources = []

    for p in paths:
        records = read_records(p, 500)
        key_counter = Counter()
        sample_values = {}

        for rec in records:
            for k in flatten_keys(rec):
                key_counter[k] += 1

        flat_keys = set(key_counter.keys())
        flat_tail_keys = {tail_key(k) for k in flat_keys}

        window_key_hits = sorted(WINDOW_KEYS & flat_tail_keys)
        candidate_key_hits = sorted(CANDIDATE_KEYS & flat_tail_keys)

        has_window_marker = bool(window_key_hits)
        has_candidate_identity = bool(REQUIRED_FOR_LONGITUDINAL & flat_tail_keys)
        has_vrp_key = "vrp_key" in flat_tail_keys
        has_source_uri = "source_uri" in flat_tail_keys or "roa_uri" in flat_tail_keys
        longitudinal_ready = has_window_marker and has_candidate_identity and (has_vrp_key or has_source_uri)

        if records:
            rec0 = records[0]
            for k in list(rec0.keys())[:50]:
                v = rec0.get(k)
                if isinstance(v, (str, int, float, bool)) or v is None:
                    sample_values[k] = str(v)[:200]
                else:
                    sample_values[k] = str(type(v))

        item = {
            "path": str(p),
            "class": classify_path(p),
            "size_bytes": p.stat().st_size,
            "record_count_sampled": len(records),
            "window_key_hits": window_key_hits,
            "candidate_key_hits": candidate_key_hits,
            "has_window_marker": has_window_marker,
            "has_candidate_identity": has_candidate_identity,
            "has_vrp_key": has_vrp_key,
            "has_source_uri_or_roa_uri": has_source_uri,
            "longitudinal_ready_candidate_source": longitudinal_ready,
            "top_keys": [k for k, _ in key_counter.most_common(80)],
            "sample_values": sample_values,
        }

        rows.append(item)
        if longitudinal_ready:
            candidate_sources.append(item)

    detail_path = OUT_DIR / "b5c_longitudinal_source_profile_detail.json"
    detail_path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")

    with SUMMARY_CSV.open("w", newline="", encoding="utf-8") as f:
        fields = [
            "class",
            "path",
            "record_count_sampled",
            "has_window_marker",
            "has_candidate_identity",
            "has_vrp_key",
            "has_source_uri_or_roa_uri",
            "longitudinal_ready_candidate_source",
            "window_key_hits",
            "candidate_key_hits",
        ]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in sorted(rows, key=lambda x: (not x["longitudinal_ready_candidate_source"], x["class"], x["path"])):
            w.writerow({
                "class": r["class"],
                "path": r["path"],
                "record_count_sampled": r["record_count_sampled"],
                "has_window_marker": r["has_window_marker"],
                "has_candidate_identity": r["has_candidate_identity"],
                "has_vrp_key": r["has_vrp_key"],
                "has_source_uri_or_roa_uri": r["has_source_uri_or_roa_uri"],
                "longitudinal_ready_candidate_source": r["longitudinal_ready_candidate_source"],
                "window_key_hits": ";".join(r["window_key_hits"]),
                "candidate_key_hits": ";".join(r["candidate_key_hits"]),
            })

    by_class = Counter(r["class"] for r in rows)
    ready_by_class = Counter(r["class"] for r in candidate_sources)

    report = {
        "schema": "sec27.b5c_longitudinal_preflight_report.v1",
        "status": "PASS" if rows else "FAIL_NO_ARTIFACTS",
        "artifact_count": len(paths),
        "profiled_file_count": len(rows),
        "longitudinal_ready_source_count": len(candidate_sources),
        "by_class": dict(by_class),
        "ready_by_class": dict(ready_by_class),
        "top_longitudinal_ready_sources": candidate_sources[:30],
        "outputs": {
            "detail": str(detail_path),
            "summary_csv": str(SUMMARY_CSV),
            "report": str(REPORT),
        },
        "interpretation": [
            "B5C preflight identifies files that can support true longitudinal persistence.",
            "A longitudinal-ready source should have both a window/cycle/run marker and a candidate identity such as vrp_key/source_uri.",
            "If no such source exists, only cross-probe persistence can be claimed from current B4C/B3R2 tables.",
        ],
    }

    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")

    print("status =", report["status"])
    print("artifact_count =", report["artifact_count"])
    print("profiled_file_count =", report["profiled_file_count"])
    print("longitudinal_ready_source_count =", report["longitudinal_ready_source_count"])
    print("by_class =", report["by_class"])
    print("ready_by_class =", report["ready_by_class"])
    print("WROTE", detail_path)
    print("WROTE", SUMMARY_CSV)
    print("WROTE", REPORT)


if __name__ == "__main__":
    main()
