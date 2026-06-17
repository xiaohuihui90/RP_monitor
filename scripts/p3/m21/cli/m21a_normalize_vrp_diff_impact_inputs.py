#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List


SOURCE_HINT_KEYS = {
    "uri", "source", "source_uri", "roa_uri", "object_uri",
    "manifest_uri", "mft_uri", "hash", "object_hash", "sha256",
    "path", "filename", "repo", "repository"
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    return n


def safe_int(v: Any) -> int | None:
    try:
        if v is None:
            return None
        s = str(v).strip().upper()
        if s.startswith("AS"):
            s = s[2:]
        return int(s)
    except Exception:
        return None


def load_raw_schema(raw_schema_dir: Path) -> Dict[str, Any]:
    out = {
        "schema_files": [],
        "observed_raw_vrp_keys": {},
        "raw_vrp_source_hint_keys": [],
        "direct_vrp_to_object_link_available": False,
    }

    key_counter = Counter()

    for p in sorted(raw_schema_dir.glob("*_raw_schema.json")):
        obj = read_json(p)
        out["schema_files"].append(str(p))

        for key, count in obj.get("observed_keys_top", []):
            key_counter[key] += int(count)

    out["observed_raw_vrp_keys"] = dict(key_counter)

    source_keys = sorted(k for k in key_counter if k in SOURCE_HINT_KEYS)
    out["raw_vrp_source_hint_keys"] = source_keys
    out["direct_vrp_to_object_link_available"] = bool(source_keys)

    return out


def profile_object_index(object_index: Path) -> Dict[str, Any]:
    key_counter = Counter()
    object_type_counter = Counter()
    status_counter = Counter()
    sample_keys = []
    sample_rows = []
    n = 0

    if not object_index.exists():
        return {
            "object_index_exists": False,
            "object_index_path": str(object_index),
        }

    for row in read_jsonl(object_index):
        n += 1
        key_counter.update(row.keys())

        if len(sample_rows) < 3:
            sample_rows.append(row)
            sample_keys.append(sorted(row.keys()))

        obj_type = (
            row.get("object_type")
            or row.get("object_type_guess")
            or row.get("type")
            or row.get("suffix")
            or "unknown"
        )
        object_type_counter[str(obj_type)] += 1

        status = (
            row.get("hash_level_status")
            or row.get("semantic_diff_status")
            or row.get("recover_status")
            or row.get("status")
            or "unknown"
        )
        status_counter[str(status)] += 1

    return {
        "object_index_exists": True,
        "object_index_path": str(object_index),
        "object_index_record_count": n,
        "object_index_top_keys": key_counter.most_common(100),
        "object_index_by_object_type": dict(object_type_counter),
        "object_index_by_status": dict(status_counter),
        "object_index_sample_keys": sample_keys,
        "object_index_sample_rows": sample_rows,
    }


def parse_side_probe(side: str) -> str:
    # examples: only_in_probe-bj
    if side.startswith("only_in_"):
        return side[len("only_in_"):]
    return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description="M21-A normalize VRP diff impact inputs")
    ap.add_argument("--pairwise-analysis-dir", required=True)
    ap.add_argument("--object-index", required=True)
    ap.add_argument("--raw-schema-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    pairwise_dir = Path(args.pairwise_analysis_dir).resolve()
    object_index = Path(args.object_index).resolve()
    raw_schema_dir = Path(args.raw_schema_dir).resolve()
    out_dir = Path(args.out_dir).resolve()

    indexes_dir = out_dir / "indexes"
    outputs_dir = out_dir / "outputs"
    checks_dir = out_dir / "checks"
    docs_dir = out_dir / "docs"

    for d in [indexes_dir, outputs_dir, checks_dir, docs_dir]:
        d.mkdir(parents=True, exist_ok=True)

    pairwise_summary_path = pairwise_dir / "outputs" / "M20_5G_sync_vrp_pairwise_diff_summary.json"
    if not pairwise_summary_path.exists():
        raise FileNotFoundError(f"missing pairwise summary: {pairwise_summary_path}")

    pairwise_summary = read_json(pairwise_summary_path)

    diff_files = sorted(
        p for p in (pairwise_dir / "indexes").glob("*.jsonl")
        if ".only_in_" in p.name
    )

    affected_entries: List[Dict[str, Any]] = []

    for f in diff_files:
        for row in read_jsonl(f):
            asn = safe_int(row.get("asn"))
            prefix = str(row.get("prefix", "")).strip()
            max_length = row.get("max_length")
            ta = str(row.get("ta", "")).strip().lower()
            pair = row.get("pair") or f.name.split(".")[0]
            side = row.get("side") or "unknown"
            probe = parse_side_probe(side)

            affected_entries.append({
                "schema": "s3.m21a.vrp_diff_impact_entry.v1",
                "pair": pair,
                "side": side,
                "probe": probe,
                "asn": asn,
                "prefix": prefix,
                "max_length": int(max_length) if max_length is not None else None,
                "ta": ta,
                "source_diff_file": str(f),
            })

    affected_entry_path = indexes_dir / "m21a_vrp_diff_affected_entry_index.jsonl"
    write_jsonl(affected_entry_path, affected_entries)

    asn_map = defaultdict(lambda: {
        "asn": None,
        "diff_entry_count": 0,
        "pairs": set(),
        "probes": set(),
        "tas": set(),
        "prefixes": set(),
    })

    prefix_map = defaultdict(lambda: {
        "prefix": None,
        "diff_entry_count": 0,
        "pairs": set(),
        "probes": set(),
        "tas": set(),
        "asns": set(),
    })

    ta_map = defaultdict(lambda: {
        "ta": None,
        "diff_entry_count": 0,
        "pairs": set(),
        "probes": set(),
        "asns": set(),
        "prefixes": set(),
    })

    pair_counter = Counter()
    probe_counter = Counter()
    ta_counter = Counter()
    asn_counter = Counter()
    prefix_counter = Counter()

    for e in affected_entries:
        asn = e["asn"]
        prefix = e["prefix"]
        ta = e["ta"]
        pair = e["pair"]
        probe = e["probe"]

        pair_counter[pair] += 1
        probe_counter[probe] += 1
        ta_counter[ta] += 1
        asn_counter[str(asn)] += 1
        prefix_counter[prefix] += 1

        if asn is not None:
            m = asn_map[asn]
            m["asn"] = asn
            m["diff_entry_count"] += 1
            m["pairs"].add(pair)
            m["probes"].add(probe)
            m["tas"].add(ta)
            m["prefixes"].add(prefix)

        if prefix:
            m = prefix_map[prefix]
            m["prefix"] = prefix
            m["diff_entry_count"] += 1
            m["pairs"].add(pair)
            m["probes"].add(probe)
            m["tas"].add(ta)
            if asn is not None:
                m["asns"].add(asn)

        if ta:
            m = ta_map[ta]
            m["ta"] = ta
            m["diff_entry_count"] += 1
            m["pairs"].add(pair)
            m["probes"].add(probe)
            if asn is not None:
                m["asns"].add(asn)
            m["prefixes"].add(prefix)

    def finalize_rows(d: Dict[Any, Dict[str, Any]], list_limit: int = 50) -> List[Dict[str, Any]]:
        rows = []
        for _, m in d.items():
            row = {}
            for k, v in m.items():
                if isinstance(v, set):
                    vals = sorted(v)
                    row[k + "_count"] = len(vals)
                    row[k + "_sample"] = vals[:list_limit]
                else:
                    row[k] = v
            rows.append(row)
        rows.sort(key=lambda x: x.get("diff_entry_count", 0), reverse=True)
        return rows

    affected_asn_rows = finalize_rows(asn_map)
    affected_prefix_rows = finalize_rows(prefix_map)
    affected_ta_rows = finalize_rows(ta_map)

    affected_asn_path = indexes_dir / "m21a_affected_asn_index.jsonl"
    affected_prefix_path = indexes_dir / "m21a_affected_prefix_index.jsonl"
    affected_ta_path = indexes_dir / "m21a_affected_ta_index.jsonl"

    write_jsonl(affected_asn_path, affected_asn_rows)
    write_jsonl(affected_prefix_path, affected_prefix_rows)
    write_jsonl(affected_ta_path, affected_ta_rows)

    raw_schema_profile = load_raw_schema(raw_schema_dir)
    object_profile = profile_object_index(object_index)

    direct_link_available = bool(raw_schema_profile.get("direct_vrp_to_object_link_available"))

    provenance_gap_report = {
        "schema": "s3.m21a.vrp_to_object_provenance_gap_report.v1",
        "created_at_utc": utc_now_iso(),
        "direct_vrp_to_object_link_available": direct_link_available,
        "raw_vrp_source_hint_keys": raw_schema_profile.get("raw_vrp_source_hint_keys", []),
        "observed_raw_vrp_keys": raw_schema_profile.get("observed_raw_vrp_keys", {}),
        "object_index_available": object_profile.get("object_index_exists", False),
        "object_index_path": str(object_index),
        "gap": (
            "raw_vrp_has_no_source_uri_or_object_hash"
            if not direct_link_available
            else "raw_vrp_contains_possible_source_hint"
        ),
        "m21b_required": not direct_link_available,
        "recommended_next_step": (
            "build_roa_to_vrp_provenance_mapping_from_raw_roa_objects"
            if not direct_link_available
            else "try_direct_vrp_source_to_object_join"
        ),
        "important_boundary": [
            "Routinator raw VRP output currently exposes only asn/prefix/maxLength/ta.",
            "VRP entries cannot be directly mapped to ROA object URI/hash without additional provenance mapping.",
            "M20 object identity index can support object-layer lookup after ROA-to-VRP provenance is built."
        ],
    }

    provenance_gap_path = outputs_dir / "M21A_vrp_to_object_provenance_gap_report.json"
    write_json(provenance_gap_path, provenance_gap_report)

    summary = {
        "schema": "s3.m21a.vrp_diff_impact_input_summary.v1",
        "status": "PASS",
        "created_at_utc": utc_now_iso(),

        "pairwise_summary_path": str(pairwise_summary_path),
        "object_index_path": str(object_index),
        "raw_schema_dir": str(raw_schema_dir),
        "out_dir": str(out_dir),

        "probe_counts": pairwise_summary.get("probe_counts"),
        "global_symmetric_region_count": pairwise_summary.get("global_symmetric_region_count"),
        "pairwise": pairwise_summary.get("pairwise"),

        "affected_entry_count": len(affected_entries),
        "affected_asn_count": len(affected_asn_rows),
        "affected_prefix_count": len(affected_prefix_rows),
        "affected_ta_count": len(affected_ta_rows),

        "by_pair": dict(pair_counter),
        "by_probe_side": dict(probe_counter),
        "by_ta": dict(ta_counter),
        "top_asn": asn_counter.most_common(30),
        "top_prefix": prefix_counter.most_common(30),

        "direct_vrp_to_object_link_available": direct_link_available,
        "m21b_required": not direct_link_available,

        "affected_entry_index": str(affected_entry_path),
        "affected_asn_index": str(affected_asn_path),
        "affected_prefix_index": str(affected_prefix_path),
        "affected_ta_index": str(affected_ta_path),
        "provenance_gap_report": str(provenance_gap_path),

        "object_index_profile": object_profile,
        "raw_schema_profile": raw_schema_profile,

        "next_step": (
            "M21-B build ROA-to-VRP provenance mapping"
            if not direct_link_available
            else "M21-B direct source/object join"
        ),
    }

    summary_path = outputs_dir / "M21A_vrp_diff_impact_input_summary.json"
    write_json(summary_path, summary)

    check_text = "\n".join([
        "M21A_VRP_DIFF_IMPACT_INPUT_NORMALIZATION=PASS",
        "",
        f"affected_entry_count = {len(affected_entries)}",
        f"affected_asn_count = {len(affected_asn_rows)}",
        f"affected_prefix_count = {len(affected_prefix_rows)}",
        f"affected_ta_count = {len(affected_ta_rows)}",
        f"by_pair = {dict(pair_counter)}",
        f"by_probe_side = {dict(probe_counter)}",
        f"by_ta = {dict(ta_counter)}",
        f"top_asn = {asn_counter.most_common(10)}",
        f"top_prefix = {prefix_counter.most_common(10)}",
        "",
        f"direct_vrp_to_object_link_available = {direct_link_available}",
        f"m21b_required = {not direct_link_available}",
        f"object_index_exists = {object_profile.get('object_index_exists')}",
        f"object_index_record_count = {object_profile.get('object_index_record_count')}",
        "",
        f"summary_path = {summary_path}",
        f"provenance_gap_report = {provenance_gap_path}",
    ]) + "\n"

    check_path = checks_dir / "M21A_vrp_diff_impact_input_normalization.txt"
    check_path.write_text(check_text, encoding="utf-8")

    print(check_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
