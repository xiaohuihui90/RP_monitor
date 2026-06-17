#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import csv
import json
import tarfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


PROBES = ["probe-bj", "probe-cd", "probe-sg"]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("wt", encoding="utf-8") as w:
        for r in rows:
            w.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    return n


def extract_archives(import_dir: Path, extracted_dir: Path) -> List[Path]:
    extracted_dir.mkdir(parents=True, exist_ok=True)
    run_dirs = []

    for tar_path in sorted(import_dir.glob("*.tar.gz")):
        with tarfile.open(tar_path, "r:gz") as tf:
            members = tf.getmembers()
            top_names = sorted({m.name.split("/", 1)[0] for m in members if m.name})
            tf.extractall(extracted_dir)
            for name in top_names:
                rd = extracted_dir / name
                if rd.exists() and rd.is_dir():
                    run_dirs.append(rd)

    # 去重
    seen = set()
    out = []
    for d in run_dirs:
        s = str(d.resolve())
        if s not in seen:
            seen.add(s)
            out.append(d)
    return out


def load_probe_export(run_dir: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    summary_path = run_dir / "outputs" / "M21_probe_cache_presence_summary.json"
    records_path = run_dir / "indexes" / "m21_probe_cache_presence_records.jsonl"

    if not summary_path.exists():
        raise FileNotFoundError(summary_path)
    if not records_path.exists():
        raise FileNotFoundError(records_path)

    summary = read_json(summary_path)
    records = list(read_jsonl(records_path))
    return summary, records


def tuple_label(r: Dict[str, Any]) -> str:
    asn = r.get("asn")
    prefix = r.get("prefix")
    max_length = r.get("max_length")
    ta = r.get("ta")
    return f"AS{asn}|{prefix}|maxLength={max_length}|ta={ta}"


def raw_hash_set(record: Dict[str, Any]) -> List[str]:
    xs = []
    for h in record.get("hits") or []:
        v = h.get("raw_sha256")
        if v:
            xs.append(v)
    return sorted(set(xs))


def first_raw_hash(record: Dict[str, Any]) -> str:
    xs = raw_hash_set(record)
    return xs[0] if xs else ""


def classify_matrix_row(mode: str, row: Dict[str, Any]) -> Tuple[str, str]:
    statuses = {p: row.get(f"{p}_status", "missing_record") for p in PROBES}
    found = {p for p, s in statuses.items() if s == "found"}
    missing = {p for p, s in statuses.items() if s != "found"}

    hashes_by_probe = {
        p: set((row.get(f"{p}_raw_sha256_values") or "").split(","))
        for p in PROBES
    }
    hashes_by_probe = {p: {x for x in xs if x} for p, xs in hashes_by_probe.items()}

    all_hashes = set()
    for xs in hashes_by_probe.values():
        all_hashes |= xs

    if mode == "m21c":
        if len(found) == 0:
            return "historical_source_uri_not_recoverable_current_cache", "medium"
        if len(found) < 3:
            return "current_cache_object_presence_divergence_candidate", "medium"
        if len(all_hashes) == 1:
            return "current_cache_object_consistent_candidate", "medium"
        return "current_cache_same_uri_hash_divergence_candidate", "medium-high"

    # M21-D
    bj_found = "probe-bj" in found
    cd_found = "probe-cd" in found
    sg_found = "probe-sg" in found

    if not bj_found and (cd_found or sg_found):
        return "bj_current_cache_missing_candidate", "medium"
    if bj_found and (cd_found or sg_found):
        if len(all_hashes) == 1:
            return "current_cache_converged_object_present", "medium"
        return "current_cache_hash_skew_candidate", "medium-high"
    if len(found) == 0:
        return "sample_not_recoverable_current_cache", "medium"
    return "other_current_cache_presence_pattern", "low-medium"


def merge(import_dir: Path, out_dir: Path, mode: str) -> Dict[str, Any]:
    extracted_dir = out_dir / "extracted"
    indexes = out_dir / "indexes"
    outputs = out_dir / "outputs"
    checks = out_dir / "checks"

    for d in [extracted_dir, indexes, outputs, checks]:
        d.mkdir(parents=True, exist_ok=True)

    run_dirs = extract_archives(import_dir, extracted_dir)

    summaries = {}
    records_by_probe = {}

    for rd in run_dirs:
        summary, records = load_probe_export(rd)
        probe = summary.get("probe_id")
        if probe in summaries:
            raise RuntimeError(f"duplicate probe export: {probe}")
        summaries[probe] = summary
        records_by_probe[probe] = records

    missing_probe_exports = [p for p in PROBES if p not in summaries]
    if missing_probe_exports:
        raise RuntimeError(f"missing probe exports: {missing_probe_exports}")

    # key = source_uri
    all_keys = set()
    rec_by_probe_key = {p: {} for p in PROBES}

    for probe, records in records_by_probe.items():
        for r in records:
            uri = r.get("source_uri")
            if not uri:
                continue
            all_keys.add(uri)
            rec_by_probe_key[probe][uri] = r

    matrix_rows = []
    verdict_counter = Counter()
    host_counter = Counter()
    ta_counter = Counter()
    presence_pattern_counter = Counter()

    for uri in sorted(all_keys):
        base = None
        for p in PROBES:
            if uri in rec_by_probe_key[p]:
                base = rec_by_probe_key[p][uri]
                break
        base = base or {}

        row: Dict[str, Any] = {
            "schema": f"s3.{mode}.collector_cache_presence_matrix.v1",
            "mode": mode,
            "source_uri": uri,
            "source_host": base.get("source_host") or "unknown",
            "request_id": base.get("request_id") or "",
            "asn": base.get("asn"),
            "prefix": base.get("prefix"),
            "max_length": base.get("max_length"),
            "ta": base.get("ta") or "unknown",
            "tuple_label": tuple_label(base),
        }

        present = []
        missing = []

        for probe in PROBES:
            r = rec_by_probe_key[probe].get(uri)
            if not r:
                row[f"{probe}_status"] = "missing_record"
                row[f"{probe}_hit_count"] = 0
                row[f"{probe}_raw_sha256_values"] = ""
                row[f"{probe}_first_raw_sha256"] = ""
                missing.append(probe)
                continue

            status = r.get("status") or "unknown"
            row[f"{probe}_status"] = status
            row[f"{probe}_hit_count"] = r.get("hit_count", 0)
            hashes = raw_hash_set(r)
            row[f"{probe}_raw_sha256_values"] = ",".join(hashes)
            row[f"{probe}_first_raw_sha256"] = hashes[0] if hashes else ""

            if status == "found":
                present.append(probe)
            else:
                missing.append(probe)

        row["present_probes_current_cache"] = ",".join(present)
        row["missing_probes_current_cache"] = ",".join(missing)
        row["current_presence_count"] = len(present)

        verdict, confidence = classify_matrix_row(mode, row)
        row["verdict"] = verdict
        row["confidence"] = confidence

        matrix_rows.append(row)

        verdict_counter[verdict] += 1
        host_counter[row["source_host"]] += 1
        ta_counter[str(row["ta"]).lower()] += 1
        presence_pattern_counter[
            f"present={','.join(present)}|missing={','.join(missing)}"
        ] += 1

    matrix_jsonl = indexes / f"{mode}_cache_presence_hash_matrix.jsonl"
    write_jsonl(matrix_jsonl, matrix_rows)

    matrix_tsv = outputs / f"{mode}_cache_presence_hash_matrix.tsv"
    if matrix_rows:
        fields = list(matrix_rows[0].keys())
        with matrix_tsv.open("wt", encoding="utf-8", newline="") as w:
            writer = csv.DictWriter(w, fieldnames=fields, delimiter="\t")
            writer.writeheader()
            writer.writerows(matrix_rows)

    summary = {
        "schema": f"s3.{mode}.collector_cache_presence_merge_summary.v1",
        "status": "PASS",
        "mode": mode,
        "created_at_utc": utc_now(),
        "import_dir": str(import_dir),
        "out_dir": str(out_dir),
        "archive_count": len(list(import_dir.glob("*.tar.gz"))),
        "probe_ids": sorted(summaries.keys()),
        "probe_summaries": summaries,
        "source_uri_union_count": len(all_keys),
        "matrix_row_count": len(matrix_rows),
        "by_verdict": dict(verdict_counter.most_common()),
        "by_source_host_top": dict(host_counter.most_common(30)),
        "by_ta": dict(ta_counter.most_common()),
        "by_presence_pattern": dict(presence_pattern_counter.most_common(30)),
        "outputs": {
            "matrix_jsonl": str(matrix_jsonl),
            "matrix_tsv": str(matrix_tsv),
        },
        "important_boundary": [
            "This merge is based on current probe cache presence exports.",
            "It should not be treated as exact historical snapshot recovery.",
            "M21-C source-level attribution and M21-D 12:42 skew diagnosis remain separate evidence lines."
        ],
    }

    summary_path = outputs / f"{mode}_collector_cache_presence_merge_summary.json"
    write_json(summary_path, summary)

    check = "\n".join([
        f"{mode.upper()}_COLLECTOR_CACHE_PRESENCE_MERGE=PASS",
        "",
        f"archive_count = {summary['archive_count']}",
        f"probe_ids = {summary['probe_ids']}",
        f"source_uri_union_count = {summary['source_uri_union_count']}",
        f"matrix_row_count = {summary['matrix_row_count']}",
        f"by_verdict = {summary['by_verdict']}",
        f"by_source_host_top = {summary['by_source_host_top']}",
        f"summary_path = {summary_path}",
        f"matrix_tsv = {matrix_tsv}",
    ]) + "\n"

    check_path = checks / f"{mode}_collector_cache_presence_merge_check.txt"
    check_path.write_text(check, encoding="utf-8")

    print(check)
    return summary


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["m21c", "m21d"])
    ap.add_argument("--import-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    merge(Path(args.import_dir), Path(args.out_dir), args.mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
