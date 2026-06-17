#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def norm_asn(v: Any) -> int:
    s = str(v).strip().upper()
    if s.startswith("AS"):
        s = s[2:]
    return int(s)


def load_affected(path: Path) -> dict[tuple[int, str, int, str], Dict[str, Any]]:
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


def load_vrps_json(path: Path) -> list[Dict[str, Any]]:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            obj = json.load(f)
    else:
        obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))

    if isinstance(obj, dict):
        return obj.get("roas", [])
    if isinstance(obj, list):
        return obj
    return []


def find_current_vrp_matches(vrp_json: Path, affected: dict) -> list[Dict[str, Any]]:
    roas = load_vrps_json(vrp_json)
    rows = []

    for r in roas:
        k = (
            norm_asn(r["asn"]),
            str(r["prefix"]).strip(),
            int(r.get("maxLength", r.get("max_length"))),
            str(r["ta"]).lower(),
        )
        if k in affected:
            rows.append({
                "schema": "s3.m21b.current_vrp_affected_match.v1",
                "key": {
                    "asn": k[0],
                    "prefix": k[1],
                    "max_length": k[2],
                    "ta": k[3],
                },
                "affected": affected[k],
                "current_vrp_record": r,
            })

    return rows


def hex_tokens_for_vrp(asn: int, prefix: str, max_length: int) -> list[str]:
    # Routinator cache filenames often encode strings like:
    # "<prefix>/<plen>-<maxlen> => <asn>" in hex.
    plain_forms = []

    pfx = prefix.replace("/", f"-{max_length} => {asn}")
    plain_forms.append(pfx)

    # More exact form:
    try:
        base, plen = prefix.split("/")
        plain_forms.append(f"{base}/{plen}-{max_length} => {asn}")
    except Exception:
        pass

    plain_forms.append(f"AS{asn}")
    plain_forms.append(str(asn))

    tokens = []
    for s in plain_forms:
        tokens.append(s.lower())
        tokens.append(s.encode("utf-8").hex().lower())

    return sorted(set(tokens))


def search_file_paths(cache_roots: list[Path], current_matches: list[Dict[str, Any]], max_hits_per_vrp: int) -> list[Dict[str, Any]]:
    candidate_files = []
    for root in cache_roots:
        if root.exists():
            for p in root.rglob("*"):
                if p.is_file():
                    candidate_files.append(p)

    path_rows = []
    path_text_cache = [(p, str(p).lower()) for p in candidate_files]

    for m in current_matches:
        k = m["key"]
        tokens = hex_tokens_for_vrp(k["asn"], k["prefix"], k["max_length"])
        hits = []

        for p, s in path_text_cache:
            if any(tok in s for tok in tokens):
                hits.append(str(p))
                if len(hits) >= max_hits_per_vrp:
                    break

        path_rows.append({
            "schema": "s3.m21b.affected_vrp_path_search.v1",
            "key": k,
            "tokens_sample": tokens[:10],
            "hit_count_capped": len(hits),
            "hits": hits,
        })

    return path_rows


def search_object_index(object_index: Path, current_matches: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    if not object_index.exists():
        return []

    target_tokens_by_id = []
    for m in current_matches:
        k = m["key"]
        tokens = hex_tokens_for_vrp(k["asn"], k["prefix"], k["max_length"])
        target_tokens_by_id.append((k, tokens))

    rows = []
    for line in object_index.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue

        obj = json.loads(line)
        text = json.dumps(obj, ensure_ascii=False).lower()

        for k, tokens in target_tokens_by_id:
            if any(tok in text for tok in tokens):
                rows.append({
                    "schema": "s3.m21b.affected_vrp_object_index_hit.v1",
                    "key": k,
                    "object_uri": obj.get("object_uri"),
                    "canonical_uri": obj.get("canonical_uri"),
                    "object_type": obj.get("object_type"),
                    "hash_level_status": obj.get("hash_level_status"),
                    "distinct_raw_sha256_count": obj.get("distinct_raw_sha256_count"),
                    "probe_set": obj.get("probe_set"),
                    "recovered_probes": obj.get("recovered_probes"),
                    "raw_bytes_required_for_semantic_diff": obj.get("raw_bytes_required_for_semantic_diff"),
                })

    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--affected-vrp-set", required=True)
    ap.add_argument("--current-vrp-json", required=True)
    ap.add_argument("--object-index", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--cache-root", action="append", default=[])
    ap.add_argument("--max-hits-per-vrp", type=int, default=20)
    args = ap.parse_args()

    affected = load_affected(Path(args.affected_vrp_set).resolve())
    current_vrp_json = Path(args.current_vrp_json).resolve()
    object_index = Path(args.object_index).resolve()
    out_dir = Path(args.out_dir).resolve()

    if args.cache_root:
        cache_roots = [Path(x).expanduser() for x in args.cache_root]
    else:
        cache_roots = [
            Path.home() / ".rpki-cache",
            Path("/var/lib/routinator/rpki-cache"),
        ]

    out_dir.mkdir(parents=True, exist_ok=True)

    current_matches = find_current_vrp_matches(current_vrp_json, affected)
    path_hits = search_file_paths(cache_roots, current_matches, args.max_hits_per_vrp)
    object_index_hits = search_object_index(object_index, current_matches)

    by_ta = Counter(m["key"]["ta"] for m in current_matches)
    by_path_hit_count = Counter()
    for r in path_hits:
        if r["hit_count_capped"] > 0:
            by_path_hit_count["with_path_hit"] += 1
        else:
            by_path_hit_count["without_path_hit"] += 1

    current_match_path = out_dir / "m21b_current_cd_affected_vrp_matches.jsonl"
    path_hit_path = out_dir / "m21b_affected_vrp_path_search.jsonl"
    object_hit_path = out_dir / "m21b_affected_vrp_object_index_hits.jsonl"

    write_jsonl(current_match_path, current_matches)
    write_jsonl(path_hit_path, path_hits)
    write_jsonl(object_hit_path, object_index_hits)

    summary = {
        "schema": "s3.m21b.affected_roa_object_location_diag.v1",
        "created_at_utc": utc_now_iso(),
        "affected_total": len(affected),
        "current_vrp_json": str(current_vrp_json),
        "current_affected_match_count": len(current_matches),
        "current_affected_by_ta": dict(by_ta),
        "cache_roots": [str(x) for x in cache_roots],
        "path_search_count": len(path_hits),
        "path_search_status": dict(by_path_hit_count),
        "object_index_hit_count": len(object_index_hits),
        "current_match_index": str(current_match_path),
        "path_hit_index": str(path_hit_path),
        "object_index_hit_index": str(object_hit_path),
        "interpretation": [
            "If current_affected_match_count > 0 but path/object hits are zero, the ROA files used by validator output are not discoverable by simple .roa path enumeration.",
            "If path hits exist but exporter matched zero, ROA parser or tuple normalization needs fixing.",
            "If object_index hits exist, prefer M20 raw-on-demand path for M21-B provenance."
        ],
    }

    write_json(out_dir / "M21B_affected_roa_location_diag_summary.json", summary)

    print("M21B_AFFECTED_ROA_LOCATION_DIAG=PASS")
    print(f"affected_total = {len(affected)}")
    print(f"current_affected_match_count = {len(current_matches)}")
    print(f"current_affected_by_ta = {dict(by_ta)}")
    print(f"path_search_status = {dict(by_path_hit_count)}")
    print(f"object_index_hit_count = {len(object_index_hits)}")
    print(f"summary_path = {out_dir / 'M21B_affected_roa_location_diag_summary.json'}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
