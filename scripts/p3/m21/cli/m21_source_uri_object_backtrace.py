#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set
from urllib.parse import urlparse


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
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


def host_of(uri: str) -> str:
    if not uri:
        return "unknown"
    try:
        return urlparse(uri).netloc or "unknown"
    except Exception:
        return "unknown"


def norm_uri_keys(uri: str) -> Set[str]:
    """
    Build multiple URI identity keys so that:
      rsync://host/path/file.roa
    can match:
      cache://.rpki-cache/repository/rsync/host/path/file.roa
      /.../repository/stored/rrdp/.../rsync/host/path/file.roa
    """
    keys: Set[str] = set()
    if not uri:
        return keys

    s = str(uri).strip()
    keys.add(s)

    # Parse normal rsync URI.
    if s.startswith("rsync://"):
        p = urlparse(s)
        host = p.netloc
        path = p.path.lstrip("/")
        if host and path:
            keys.add(f"rsync/{host}/{path}")
            keys.add(f"{host}/{path}")
            keys.add(path)

    # Routinator cache URI form.
    marker = "/repository/rsync/"
    if marker in s:
        tail = s.split(marker, 1)[1].lstrip("/")
        keys.add(f"rsync/{tail}")
        keys.add(tail)

    marker2 = "repository/rsync/"
    if marker2 in s:
        tail = s.split(marker2, 1)[1].lstrip("/")
        keys.add(f"rsync/{tail}")
        keys.add(tail)

    # Stored RRDP path that contains /rsync/<host>/<path>.
    marker3 = "/rsync/"
    if marker3 in s:
        tail = s.rsplit(marker3, 1)[1].lstrip("/")
        keys.add(f"rsync/{tail}")
        keys.add(tail)

    # Generic suffix fallback.
    parts = s.split("/")
    if len(parts) >= 4:
        keys.add("/".join(parts[-4:]))
    if len(parts) >= 6:
        keys.add("/".join(parts[-6:]))

    return {k for k in keys if k}


def compact_object_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "identity_key": row.get("identity_key"),
        "object_uri": row.get("object_uri"),
        "canonical_uri": row.get("canonical_uri"),
        "object_type": row.get("object_type"),
        "object_family": row.get("object_family"),
        "probe_set": row.get("probe_set"),
        "probe_count": row.get("probe_count"),
        "missing_probes": row.get("missing_probes"),
        "missing_probe_count": row.get("missing_probe_count"),
        "distinct_raw_sha256_count": row.get("distinct_raw_sha256_count"),
        "distinct_raw_sha256_values": row.get("distinct_raw_sha256_values"),
        "hash_level_status": row.get("hash_level_status"),
        "raw_hash_divergence_observed": row.get("raw_hash_divergence_observed"),
        "semantic_diff_required": row.get("semantic_diff_required"),
        "coverage_mode": row.get("coverage_mode"),
        "coverage_scope": row.get("coverage_scope"),
    }


def build_object_uri_index(object_index_path: Path) -> Dict[str, List[Dict[str, Any]]]:
    idx: Dict[str, List[Dict[str, Any]]] = {}

    for row in read_jsonl(object_index_path):
        compact = compact_object_row(row)

        candidate_uris = [
            row.get("object_uri"),
            row.get("canonical_uri"),
            row.get("identity_key"),
        ]

        probe_values = row.get("probe_values") or {}
        if isinstance(probe_values, dict):
            for vals in probe_values.values():
                if isinstance(vals, list):
                    for v in vals:
                        if isinstance(v, dict):
                            candidate_uris.append(v.get("probe_source_path"))
                            candidate_uris.append(v.get("probe_cas_path"))

        for u in candidate_uris:
            if not u:
                continue
            for key in norm_uri_keys(str(u)):
                idx.setdefault(key, []).append(compact)

    return idx


def lookup_object_hits(uri: str, idx: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    seen = set()

    for key in norm_uri_keys(uri):
        for h in idx.get(key, []):
            identity = h.get("identity_key") or h.get("object_uri") or json.dumps(h, sort_keys=True)
            if identity in seen:
                continue
            seen.add(identity)
            hits.append(h)

    return hits


def affected_tuple(row: Dict[str, Any]) -> Dict[str, Any]:
    aff = row.get("affected_input") or {}
    raw = aff.get("raw") if isinstance(aff, dict) else {}
    raw = raw or {}

    return {
        "asn": aff.get("asn") or raw.get("asn"),
        "prefix": aff.get("prefix") or raw.get("prefix"),
        "max_length": aff.get("max_length") or raw.get("max_length") or raw.get("maxLength"),
        "ta": aff.get("ta") or raw.get("ta") or raw.get("tal"),
    }


def collect_source_uris(row: Dict[str, Any]) -> Dict[str, List[str]]:
    by_probe = row.get("source_uri_by_probe") or {}
    out: Dict[str, List[str]] = {}
    for probe, uris in by_probe.items():
        if not isinstance(uris, list):
            continue
        cleaned = []
        for u in uris:
            if u and str(u).strip():
                cleaned.append(str(u).strip())
        out[probe] = sorted(set(cleaned))
    return out


def run_affected_mode(args: argparse.Namespace, idx: Dict[str, List[Dict[str, Any]]]) -> None:
    affected_map = Path(args.affected_map)
    out_dir = Path(args.out_dir)
    outputs = out_dir / "outputs"
    indexes = out_dir / "indexes"
    checks = out_dir / "checks"

    records = []
    source_uri_total = 0
    source_uri_hit = 0
    source_uri_miss = 0
    affected_total = 0
    affected_with_hit = 0

    by_ta = Counter()
    by_host = Counter()
    by_presence = Counter()
    by_hit_status = Counter()

    for row in read_jsonl(affected_map):
        affected_total += 1
        tup = affected_tuple(row)
        ta = str(tup.get("ta") or "unknown").lower()
        by_ta[ta] += 1

        present = row.get("present_probes") or []
        absent = row.get("absent_probes") or []
        by_presence[f"present={','.join(present)}|absent={','.join(absent)}"] += 1

        uri_by_probe = collect_source_uris(row)
        all_uris = sorted(set(u for xs in uri_by_probe.values() for u in xs))

        affected_has_hit = False

        if not all_uris:
            records.append({
                "schema": "s3.m21c.affected_vrp_source_uri_object_candidate.v1",
                "mode": "affected",
                "vrp_key": row.get("vrp_key"),
                "affected_tuple": tup,
                "present_probes": present,
                "absent_probes": absent,
                "source_uri": None,
                "source_host": "none",
                "object_index_hit_count": 0,
                "object_hits": [],
                "hit_status": "no_source_uri",
            })
            by_hit_status["no_source_uri"] += 1
            continue

        for uri in all_uris:
            source_uri_total += 1
            host = host_of(uri)
            by_host[host] += 1

            hits = lookup_object_hits(uri, idx)
            hit_status = "object_index_hit" if hits else "object_index_miss"

            if hits:
                source_uri_hit += 1
                affected_has_hit = True
            else:
                source_uri_miss += 1

            by_hit_status[hit_status] += 1

            records.append({
                "schema": "s3.m21c.affected_vrp_source_uri_object_candidate.v1",
                "mode": "affected",
                "vrp_key": row.get("vrp_key"),
                "affected_tuple": tup,
                "present_probes": present,
                "absent_probes": absent,
                "source_uri": uri,
                "source_host": host,
                "source_uri_by_probe": uri_by_probe,
                "validity_by_probe": row.get("validity_by_probe"),
                "chain_validity_by_probe": row.get("chain_validity_by_probe"),
                "stale_by_probe": row.get("stale_by_probe"),
                "object_index_hit_count": len(hits),
                "object_hits": hits[:20],
                "hit_status": hit_status,
            })

        if affected_has_hit:
            affected_with_hit += 1

    candidate_path = indexes / "m21c_affected_vrp_source_uri_object_candidates.jsonl"
    n = write_jsonl(candidate_path, records)

    summary = {
        "schema": "s3.m21c.affected_object_backtrace_summary.v1",
        "status": "PASS",
        "created_at_utc": utc_now_iso(),
        "mode": "affected",
        "affected_map": str(affected_map),
        "object_index": str(args.object_index),
        "affected_total": affected_total,
        "affected_with_object_index_hit": affected_with_hit,
        "source_uri_total": source_uri_total,
        "source_uri_object_index_hit": source_uri_hit,
        "source_uri_object_index_miss": source_uri_miss,
        "by_ta": dict(by_ta.most_common()),
        "by_source_host_top": dict(by_host.most_common(30)),
        "by_presence_pattern": dict(by_presence.most_common(30)),
        "by_hit_status": dict(by_hit_status.most_common()),
        "outputs": {
            "candidate_jsonl": str(candidate_path),
        },
        "important_boundary": [
            "This stage maps VRP source.uri to object-index candidates.",
            "It is not yet final causal attribution.",
            "Final M21-C needs manifest fileList, object hash, and repository/PP context join."
        ],
    }

    write_json(outputs / "M21C_affected_object_backtrace_summary.json", summary)

    check = "\n".join([
        "M21C_AFFECTED_OBJECT_BACKTRACE=PASS",
        "",
        f"affected_total = {affected_total}",
        f"affected_with_object_index_hit = {affected_with_hit}",
        f"source_uri_total = {source_uri_total}",
        f"source_uri_object_index_hit = {source_uri_hit}",
        f"source_uri_object_index_miss = {source_uri_miss}",
        f"by_ta = {dict(by_ta.most_common())}",
        f"by_source_host_top = {dict(by_host.most_common(15))}",
        f"by_hit_status = {dict(by_hit_status.most_common())}",
        f"candidate_path = {candidate_path}",
        f"summary_path = {outputs / 'M21C_affected_object_backtrace_summary.json'}",
    ]) + "\n"

    checks.mkdir(parents=True, exist_ok=True)
    (checks / "M21C_affected_object_backtrace_check.txt").write_text(check, encoding="utf-8")
    print(check)


def run_bj_skew_mode(args: argparse.Namespace, idx: Dict[str, List[Dict[str, Any]]]) -> None:
    selected_join = Path(args.selected_join)
    out_dir = Path(args.out_dir)
    outputs = out_dir / "outputs"
    indexes = out_dir / "indexes"
    checks = out_dir / "checks"

    records = []
    row_total = 0
    source_uri_total = 0
    source_uri_hit = 0
    source_uri_miss = 0

    by_ta = Counter()
    by_host = Counter()
    by_host_ta = Counter()
    by_hit_status = Counter()

    for row in read_jsonl(selected_join):
        present = set(row.get("present_probes") or [])
        absent = set(row.get("absent_probes") or [])

        if "probe-bj" not in absent:
            continue
        if not (("probe-cd" in present) or ("probe-sg" in present)):
            continue

        row_total += 1
        tup = affected_tuple(row)
        sample = row.get("sample_tuple") or {}
        ta = str(tup.get("ta") or sample.get("ta") or sample.get("tal") or "unknown").lower()
        by_ta[ta] += 1

        uri_by_probe = collect_source_uris(row)
        cd_sg_uris = sorted(set((uri_by_probe.get("probe-cd") or []) + (uri_by_probe.get("probe-sg") or [])))

        if not cd_sg_uris:
            by_hit_status["no_cd_sg_source_uri"] += 1
            records.append({
                "schema": "s3.m21d.bj_skew_source_uri_object_candidate.v1",
                "mode": "bj_skew",
                "vrp_key": row.get("vrp_key"),
                "tuple": tup or sample,
                "present_probes": sorted(present),
                "absent_probes": sorted(absent),
                "source_uri": None,
                "source_host": "none",
                "hit_status": "no_cd_sg_source_uri",
                "object_index_hit_count": 0,
                "object_hits": [],
            })
            continue

        for uri in cd_sg_uris:
            source_uri_total += 1
            host = host_of(uri)
            by_host[host] += 1
            by_host_ta[f"{host}|{ta}"] += 1

            hits = lookup_object_hits(uri, idx)
            hit_status = "object_index_hit" if hits else "object_index_miss"
            if hits:
                source_uri_hit += 1
            else:
                source_uri_miss += 1

            by_hit_status[hit_status] += 1

            records.append({
                "schema": "s3.m21d.bj_skew_source_uri_object_candidate.v1",
                "mode": "bj_skew",
                "vrp_key": row.get("vrp_key"),
                "tuple": tup or sample,
                "present_probes": sorted(present),
                "absent_probes": sorted(absent),
                "source_uri": uri,
                "source_host": host,
                "source_uri_by_probe": uri_by_probe,
                "validity_by_probe": row.get("validity_by_probe"),
                "chain_validity_by_probe": row.get("chain_validity_by_probe"),
                "object_index_hit_count": len(hits),
                "object_hits": hits[:10],
                "hit_status": hit_status,
            })

    candidate_path = indexes / "m21d_bj_skew_source_uri_object_candidates.jsonl"
    n = write_jsonl(candidate_path, records)

    top_hosts_tsv = outputs / "m21d_bj_skew_top_hosts.tsv"
    top_hosts_tsv.parent.mkdir(parents=True, exist_ok=True)
    with top_hosts_tsv.open("wt", encoding="utf-8") as w:
        w.write("rank\thost\tcount\n")
        for i, (host, count) in enumerate(by_host.most_common(50), 1):
            w.write(f"{i}\t{host}\t{count}\n")

    summary = {
        "schema": "s3.m21d.bj_skew_object_backtrace_summary.v1",
        "status": "PASS",
        "created_at_utc": utc_now_iso(),
        "mode": "bj_skew",
        "selected_join": str(selected_join),
        "object_index": str(args.object_index),
        "bj_missing_row_total": row_total,
        "source_uri_total": source_uri_total,
        "source_uri_object_index_hit": source_uri_hit,
        "source_uri_object_index_miss": source_uri_miss,
        "by_ta": dict(by_ta.most_common()),
        "by_source_host_top": dict(by_host.most_common(30)),
        "by_source_host_ta_top": dict(by_host_ta.most_common(40)),
        "by_hit_status": dict(by_hit_status.most_common()),
        "outputs": {
            "candidate_jsonl": str(candidate_path),
            "top_hosts_tsv": str(top_hosts_tsv),
        },
        "important_boundary": [
            "This stage diagnoses BJ large-scale missing VRP region using JSONEXT source.uri.",
            "It identifies repository hosts and object-index candidates.",
            "Final root cause still needs manifest/object hash and repository update context."
        ],
    }

    write_json(outputs / "M21D_bj_skew_object_backtrace_summary.json", summary)

    check = "\n".join([
        "M21D_BJ_SKEW_OBJECT_BACKTRACE=PASS",
        "",
        f"bj_missing_row_total = {row_total}",
        f"source_uri_total = {source_uri_total}",
        f"source_uri_object_index_hit = {source_uri_hit}",
        f"source_uri_object_index_miss = {source_uri_miss}",
        f"by_ta = {dict(by_ta.most_common())}",
        f"by_source_host_top = {dict(by_host.most_common(15))}",
        f"by_hit_status = {dict(by_hit_status.most_common())}",
        f"candidate_path = {candidate_path}",
        f"top_hosts_tsv = {top_hosts_tsv}",
        f"summary_path = {outputs / 'M21D_bj_skew_object_backtrace_summary.json'}",
    ]) + "\n"

    checks.mkdir(parents=True, exist_ok=True)
    (checks / "M21D_bj_skew_object_backtrace_check.txt").write_text(check, encoding="utf-8")
    print(check)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["affected", "bj-skew"])
    ap.add_argument("--object-index", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--affected-map", default="")
    ap.add_argument("--selected-join", default="")
    args = ap.parse_args()

    object_index = Path(args.object_index)
    if not object_index.exists():
        raise FileNotFoundError(object_index)

    print(f"loading_object_index={object_index}")
    idx = build_object_uri_index(object_index)
    print(f"object_uri_index_key_count={len(idx)}")

    if args.mode == "affected":
        if not args.affected_map:
            raise ValueError("--affected-map required for mode=affected")
        run_affected_mode(args, idx)
    else:
        if not args.selected_join:
            raise ValueError("--selected-join required for mode=bj-skew")
        run_bj_skew_mode(args, idx)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
