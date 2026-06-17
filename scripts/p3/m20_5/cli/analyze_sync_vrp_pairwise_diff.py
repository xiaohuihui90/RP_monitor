#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import gzip
import json
import tarfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple


PROBES = ["probe-bj", "probe-cd", "probe-sg"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_extract(tar_path: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()

    with tarfile.open(tar_path, "r:gz") as tar:
        for m in tar.getmembers():
            if m.name.startswith("/") or ".." in Path(m.name).parts or m.issym() or m.islnk():
                raise RuntimeError(f"unsafe tar member: {m.name}")
            target = (dest / m.name).resolve()
            if not str(target).startswith(str(root)):
                raise RuntimeError(f"unsafe extract escape: {m.name}")
        tar.extractall(dest)


def normalize_asn(v: Any) -> tuple[int | None, str | None]:
    if v is None:
        return None, "asn_missing"

    s = str(v).strip().upper()
    if not s:
        return None, "asn_empty"

    if s.startswith("AS"):
        s = s[2:]

    if not s.isdigit():
        return None, f"asn_invalid:{v}"

    return int(s), None


def normalize_vrp(row: Dict[str, Any]) -> tuple[Tuple[int, str, int, str] | None, str | None]:
    asn_value = row.get("asn", row.get("asID", row.get("as_id")))
    asn, err = normalize_asn(asn_value)
    if err:
        return None, err

    prefix = row.get("prefix")
    if prefix is None or not str(prefix).strip():
        return None, "prefix_missing"

    max_len_value = row.get("max_length", row.get("maxLength", row.get("max_len")))
    if max_len_value is None:
        return None, "max_length_missing"

    try:
        max_len = int(max_len_value)
    except Exception:
        return None, f"max_length_invalid:{max_len_value}"

    ta = str(row.get("ta") or row.get("tal") or row.get("trust_anchor") or "").strip().lower()

    return (asn, str(prefix).strip(), max_len, ta), None


def load_jsonl_gz(path: Path, probe_id: str) -> tuple[Dict[Tuple[int, str, int, str], Dict[str, Any]], list[Dict[str, Any]]]:
    out: Dict[Tuple[int, str, int, str], Dict[str, Any]] = {}
    invalid_rows: list[Dict[str, Any]] = []

    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            if not line.strip():
                continue

            row = json.loads(line)
            key, err = normalize_vrp(row)

            if err:
                invalid_rows.append({
                    "schema": "s3.m20_5g.invalid_vrp_record.v1",
                    "probe_id": probe_id,
                    "canonical_path": str(path),
                    "line_no": line_no,
                    "invalid_reason": err,
                    "row": row,
                })
                continue

            out[key] = row

    return out, invalid_rows


def find_probe_archive(archive_dir: Path, probe_id: str) -> Path:
    matches = sorted(archive_dir.glob(f"m20_5a_vrp_summary_{probe_id}_*.tar.gz"))
    if not matches:
        raise FileNotFoundError(f"archive not found for {probe_id}")
    return matches[-1]


def find_canonical(extract_dir: Path) -> Path:
    candidates = sorted(extract_dir.glob("history/*/vrps.canonical.jsonl.gz"))
    if not candidates:
        candidates = sorted(extract_dir.rglob("vrps.canonical.jsonl.gz"))
    if not candidates:
        raise FileNotFoundError(f"canonical VRP file not found under {extract_dir}")
    return candidates[-1]


def find_summary(extract_dir: Path) -> Dict[str, Any]:
    candidates = sorted(extract_dir.glob("history/*/probe_vrp_summary.json"))
    if not candidates:
        candidates = sorted(extract_dir.rglob("probe_vrp_summary.json"))
    if not candidates:
        return {}
    return json.loads(candidates[-1].read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def key_to_row(key: Tuple[int, str, int, str]) -> Dict[str, Any]:
    asn, prefix, max_len, ta = key
    return {
        "asn": asn,
        "prefix": prefix,
        "max_length": max_len,
        "ta": ta,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze strict-sync VRP pairwise diff")
    ap.add_argument("--archive-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    archive_dir = Path(args.archive_dir).resolve()
    out_dir = Path(args.out_dir).resolve()

    extract_root = out_dir / "extract"
    index_dir = out_dir / "indexes"
    output_dir = out_dir / "outputs"

    for d in [extract_root, index_dir, output_dir]:
        d.mkdir(parents=True, exist_ok=True)

    probe_sets: dict[str, set[Tuple[int, str, int, str]]] = {}
    probe_summaries: dict[str, dict[str, Any]] = {}
    canonical_paths: dict[str, str] = {}
    invalid_rows_all: list[Dict[str, Any]] = []
    invalid_by_probe: Counter[str] = Counter()
    invalid_by_reason: Counter[str] = Counter()

    for probe in PROBES:
        archive = find_probe_archive(archive_dir, probe)
        extract_dir = extract_root / probe
        safe_extract(archive, extract_dir)

        canonical = find_canonical(extract_dir)
        summary = find_summary(extract_dir)

        vrps, invalid_rows = load_jsonl_gz(canonical, probe)

        probe_sets[probe] = set(vrps.keys())
        probe_summaries[probe] = summary
        canonical_paths[probe] = str(canonical)

        invalid_rows_all.extend(invalid_rows)
        invalid_by_probe[probe] += len(invalid_rows)
        for r in invalid_rows:
            invalid_by_reason[r["invalid_reason"]] += 1

        write_json(output_dir / f"{probe}_summary.json", summary)

    invalid_index_path = index_dir / "invalid_vrp_record_index.jsonl"
    write_jsonl(invalid_index_path, invalid_rows_all)

    pairwise = []
    pair_defs = [
        ("probe-bj", "probe-cd"),
        ("probe-bj", "probe-sg"),
        ("probe-cd", "probe-sg"),
    ]

    for a, b in pair_defs:
        only_a = sorted(probe_sets[a] - probe_sets[b])
        only_b = sorted(probe_sets[b] - probe_sets[a])

        only_a_rows = [dict(key_to_row(k), side=f"only_in_{a}", pair=f"{a}_vs_{b}") for k in only_a]
        only_b_rows = [dict(key_to_row(k), side=f"only_in_{b}", pair=f"{a}_vs_{b}") for k in only_b]

        only_a_path = index_dir / f"{a}_vs_{b}.only_in_{a}.jsonl"
        only_b_path = index_dir / f"{a}_vs_{b}.only_in_{b}.jsonl"

        write_jsonl(only_a_path, only_a_rows)
        write_jsonl(only_b_path, only_b_rows)

        ta_counter = Counter()
        asn_counter = Counter()
        prefix_counter = Counter()

        for k in only_a + only_b:
            asn, prefix, max_len, ta = k
            ta_counter[ta] += 1
            asn_counter[str(asn)] += 1
            prefix_counter[prefix] += 1

        rec = {
            "pair": f"{a}_vs_{b}",
            "left_probe": a,
            "right_probe": b,
            "left_count": len(probe_sets[a]),
            "right_count": len(probe_sets[b]),
            "intersection_count": len(probe_sets[a] & probe_sets[b]),
            "only_in_left_count": len(only_a),
            "only_in_right_count": len(only_b),
            "symmetric_diff_count": len(only_a) + len(only_b),
            "only_in_left_path": str(only_a_path),
            "only_in_right_path": str(only_b_path),
            "top_ta": ta_counter.most_common(20),
            "top_asn": asn_counter.most_common(20),
            "top_prefix": prefix_counter.most_common(20),
        }

        pairwise.append(rec)
        write_json(output_dir / f"{a}_vs_{b}_summary.json", rec)

    global_all = set.union(*probe_sets.values())
    global_intersection = set.intersection(*probe_sets.values())

    per_probe_only_rows = []
    for probe in PROBES:
        others = set()
        for p2 in PROBES:
            if p2 != probe:
                others |= probe_sets[p2]

        only_probe = sorted(probe_sets[probe] - others)
        for k in only_probe:
            per_probe_only_rows.append(dict(key_to_row(k), side=f"only_in_{probe}"))

    per_probe_only_path = index_dir / "global_probe_unique_vrps.jsonl"
    write_jsonl(per_probe_only_path, per_probe_only_rows)

    summary = {
        "schema": "s3.m20_5g.sync_vrp_pairwise_diff_summary.v2",
        "created_at_utc": utc_now_iso(),
        "archive_dir": str(archive_dir),
        "out_dir": str(out_dir),
        "probes": PROBES,
        "canonical_paths": canonical_paths,
        "probe_counts": {p: len(probe_sets[p]) for p in PROBES},
        "probe_summaries": {
            p: {
                "run_id": probe_summaries[p].get("run_id"),
                "vrp_count": probe_summaries[p].get("vrp_count"),
                "vrp_digest": probe_summaries[p].get("vrp_digest"),
                "last_update_done": probe_summaries[p].get("last_update_done"),
                "collection_started_at_utc": probe_summaries[p].get("collection_started_at_utc"),
                "collection_finished_at_utc": probe_summaries[p].get("collection_finished_at_utc"),
                "latency_ms": probe_summaries[p].get("latency_ms"),
                "cli_export_policy": probe_summaries[p].get("cli_export_policy"),
            }
            for p in PROBES
        },
        "invalid_record_count": len(invalid_rows_all),
        "invalid_record_index": str(invalid_index_path),
        "invalid_by_probe": dict(invalid_by_probe),
        "invalid_by_reason": dict(invalid_by_reason),
        "global_union_count": len(global_all),
        "global_intersection_count": len(global_intersection),
        "global_symmetric_region_count": len(global_all - global_intersection),
        "global_probe_unique_vrp_count": len(per_probe_only_rows),
        "global_probe_unique_vrp_path": str(per_probe_only_path),
        "pairwise": pairwise,
        "important_boundary": [
            "Invalid ASN records are excluded from set-level VRP diff.",
            "Invalid records are preserved in invalid_vrp_record_index.jsonl for later inspection.",
        ],
    }

    summary_path = output_dir / "M20_5G_sync_vrp_pairwise_diff_summary.json"
    write_json(summary_path, summary)

    print("M20_5G_SYNC_VRP_PAIRWISE_DIFF=PASS")
    print(f"archive_dir = {archive_dir}")
    print(f"out_dir = {out_dir}")
    print(f"probe_counts = {summary['probe_counts']}")
    print(f"invalid_record_count = {summary['invalid_record_count']}")
    print(f"invalid_by_probe = {summary['invalid_by_probe']}")
    print(f"invalid_by_reason = {summary['invalid_by_reason']}")
    print(f"global_union_count = {summary['global_union_count']}")
    print(f"global_intersection_count = {summary['global_intersection_count']}")
    print(f"global_symmetric_region_count = {summary['global_symmetric_region_count']}")
    print(f"global_probe_unique_vrp_count = {summary['global_probe_unique_vrp_count']}")
    print("pairwise:")
    for rec in pairwise:
        print(
            f"  {rec['pair']}: "
            f"only_left={rec['only_in_left_count']} "
            f"only_right={rec['only_in_right_count']} "
            f"symdiff={rec['symmetric_diff_count']}"
        )
    print(f"summary_path = {summary_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
