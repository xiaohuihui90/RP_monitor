#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def norm_asn(v: Any) -> int:
    s = str(v).strip().upper()
    if s.startswith("AS"):
        s = s[2:]
    return int(s)


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def load_affected(path: Path) -> Dict[tuple[int, str, int, str], Dict[str, Any]]:
    out = {}
    for r in read_jsonl(path):
        k = (
            norm_asn(r["asn"]),
            str(r["prefix"]).strip(),
            int(r["max_length"]),
            str(r["ta"]).lower(),
        )
        out[k] = r
    return out


def load_jsonext(path: Path) -> list[Dict[str, Any]]:
    obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if isinstance(obj, dict):
        return obj.get("roas", [])
    if isinstance(obj, list):
        return obj
    return []


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


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract affected VRP provenance from Routinator jsonext output")
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--affected-vrp-set", required=True)
    ap.add_argument("--jsonext", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    probe_id = args.probe_id
    affected_path = Path(args.affected_vrp_set).resolve()
    jsonext_path = Path(args.jsonext).resolve()
    out_dir = Path(args.out_dir).resolve()

    affected = load_affected(affected_path)
    roas = load_jsonext(jsonext_path)

    matched_rows = []
    matched_keys = set()
    by_ta = Counter()
    by_source_type = Counter()
    by_source_uri = Counter()
    source_count_counter = Counter()

    for rec in roas:
        if not isinstance(rec, dict):
            continue

        try:
            asn = norm_asn(rec.get("asn"))
            prefix = str(rec.get("prefix")).strip()
            max_length = int(rec.get("maxLength", rec.get("max_length")))
        except Exception:
            continue

        sources = rec.get("source", [])
        if not isinstance(sources, list):
            sources = []

        source_count_counter[str(len(sources))] += 1

        for src in sources:
            if not isinstance(src, dict):
                continue

            tal = str(src.get("tal", "")).lower().strip()
            if not tal:
                continue

            k = (asn, prefix, max_length, tal)
            if k not in affected:
                continue

            matched_keys.add(k)
            by_ta[tal] += 1
            by_source_type[str(src.get("type", "unknown"))] += 1
            by_source_uri[str(src.get("uri", ""))] += 1

            matched_rows.append({
                "schema": "s3.m21b.jsonext_affected_vrp_provenance.v1",
                "probe_id": probe_id,
                "created_at_utc": utc_now_iso(),
                "jsonext_path": str(jsonext_path),

                "affected_vrp": affected[k],
                "vrp_tuple": {
                    "asn": asn,
                    "prefix": prefix,
                    "max_length": max_length,
                    "ta": tal,
                },

                "source": {
                    "type": src.get("type"),
                    "uri": src.get("uri"),
                    "tal": src.get("tal"),
                    "validity": src.get("validity"),
                    "chainValidity": src.get("chainValidity"),
                    "stale": src.get("stale"),
                },

                "routinator_jsonext_record": rec,
            })

    missing_rows = []
    for k, aff in sorted(affected.items()):
        if k not in matched_keys:
            missing_rows.append({
                "schema": "s3.m21b.jsonext_missing_affected_vrp.v1",
                "probe_id": probe_id,
                "affected_vrp": aff,
                "missing_key": {
                    "asn": k[0],
                    "prefix": k[1],
                    "max_length": k[2],
                    "ta": k[3],
                },
            })

    out_dir.mkdir(parents=True, exist_ok=True)

    match_path = out_dir / "m21b_jsonext_affected_provenance_matches.jsonl"
    missing_path = out_dir / "m21b_jsonext_missing_affected_vrps.jsonl"

    write_jsonl(match_path, matched_rows)
    write_jsonl(missing_path, missing_rows)

    summary = {
        "schema": "s3.m21b.jsonext_affected_provenance_summary.v1",
        "status": "PASS",
        "created_at_utc": utc_now_iso(),
        "probe_id": probe_id,
        "affected_vrp_count": len(affected),
        "jsonext_total_vrp_count": len(roas),
        "matched_record_count": len(matched_rows),
        "matched_unique_affected_vrp_count": len(matched_keys),
        "matched_unique_affected_vrp_ratio": (len(matched_keys) / len(affected)) if affected else None,
        "missing_affected_vrp_count": len(missing_rows),
        "by_ta": dict(by_ta),
        "by_source_type": dict(by_source_type),
        "top_source_uri": by_source_uri.most_common(20),
        "source_count_distribution": dict(source_count_counter),
        "match_index": str(match_path),
        "missing_index": str(missing_path),
        "important_boundary": [
            "TAL is read from Routinator jsonext source[].tal.",
            "This provenance is validator effective-output provenance, not raw-object byte provenance.",
            "For strict historical attribution, jsonext must be exported in the same synchronized round as VRP diff."
        ],
    }

    summary_path = out_dir / "M21B_jsonext_affected_provenance_summary.json"
    write_json(summary_path, summary)

    print("M21B_JSONEXT_AFFECTED_PROVENANCE=PASS")
    print(f"probe_id = {probe_id}")
    print(f"affected_vrp_count = {len(affected)}")
    print(f"jsonext_total_vrp_count = {len(roas)}")
    print(f"matched_record_count = {len(matched_rows)}")
    print(f"matched_unique_affected_vrp_count = {len(matched_keys)}")
    print(f"missing_affected_vrp_count = {len(missing_rows)}")
    print(f"by_ta = {dict(by_ta)}")
    print(f"summary_path = {summary_path}")
    print(f"match_index = {match_path}")
    print(f"missing_index = {missing_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
