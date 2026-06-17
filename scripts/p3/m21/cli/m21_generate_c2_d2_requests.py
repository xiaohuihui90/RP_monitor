#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import csv
import json
import os
from collections import defaultdict, Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse


PROBES = ["probe-bj", "probe-cd", "probe-sg"]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def host_of(uri: str) -> str:
    try:
        return urlparse(uri).netloc or "unknown"
    except Exception:
        return "unknown"


def safe_tuple(row: Dict[str, Any]) -> Dict[str, Any]:
    x = row.get("affected_tuple") or row.get("tuple") or row.get("sample_tuple") or {}
    return {
        "asn": x.get("asn"),
        "prefix": x.get("prefix"),
        "max_length": x.get("max_length") or x.get("maxLength"),
        "ta": x.get("ta") or x.get("tal"),
    }


def uniq_by_uri(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for r in records:
        uri = r.get("source_uri")
        if not uri or uri in seen:
            continue
        seen.add(uri)
        out.append(r)
    return out


def write_probe_requests(out_dir: Path, request_name: str, rows: List[Dict[str, Any]], request_type: str) -> Dict[str, str]:
    paths = {}
    created_at = utc_now()

    for probe in PROBES:
        req = {
            "schema": "s3.m21.probe_raw_on_demand_request.v1",
            "request_name": request_name,
            "request_type": request_type,
            "target_probe_id": probe,
            "created_at_utc": created_at,
            "requested_uri_count": len(rows),
            "match_hints": [
                "rsync_uri_direct",
                "repository_rsync_tail",
                "stored_rrdp_rsync_tail",
                "filename_tail"
            ],
            "requests": rows,
            "important_boundary": [
                "This is a probe-side cache/object presence request.",
                "It does not trigger Routinator repository update.",
                "Probe-side exporter should compute raw_sha256 for found objects."
            ],
        }

        p = out_dir / f"{request_name}_{probe}.json"
        write_json(p, req)
        paths[probe] = str(p)

    return paths


def build_m21c_requests() -> None:
    out_dir = Path(os.environ["M21C_OUT_DIR"])
    candidates_path = Path(os.environ["M21C_CANDIDATES"])

    inputs = out_dir / "inputs"
    checks = out_dir / "checks"
    inputs.mkdir(parents=True, exist_ok=True)

    raw_rows = []
    for r in read_jsonl(candidates_path):
        uri = r.get("source_uri")
        if not uri:
            continue
        if r.get("hit_status") != "object_index_miss":
            continue

        tup = safe_tuple(r)
        raw_rows.append({
            "request_id": f"m21c-{len(raw_rows)+1:04d}",
            "source_uri": uri,
            "source_host": r.get("source_host") or host_of(uri),
            "vrp_key": r.get("vrp_key"),
            "asn": tup.get("asn"),
            "prefix": tup.get("prefix"),
            "max_length": tup.get("max_length"),
            "ta": tup.get("ta"),
            "present_probes": r.get("present_probes") or [],
            "absent_probes": r.get("absent_probes") or [],
            "source_uri_by_probe": r.get("source_uri_by_probe") or {},
        })

    rows = uniq_by_uri(raw_rows)

    tsv_path = inputs / "m21c_raw_on_demand_uri_list.tsv"
    with tsv_path.open("wt", encoding="utf-8", newline="") as w:
        fields = [
            "request_id", "source_uri", "source_host", "vrp_key",
            "asn", "prefix", "max_length", "ta",
            "present_probes", "absent_probes"
        ]
        writer = csv.DictWriter(w, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for r in rows:
            rr = dict(r)
            rr["present_probes"] = ",".join(rr.get("present_probes") or [])
            rr["absent_probes"] = ",".join(rr.get("absent_probes") or [])
            writer.writerow({k: rr.get(k, "") for k in fields})

    request_paths = write_probe_requests(
        inputs,
        "m21c_probe_request",
        rows,
        "m21c_affected_roa_raw_on_demand",
    )

    by_host = Counter(r["source_host"] for r in rows)
    by_ta = Counter(str(r.get("ta") or "unknown").lower() for r in rows)

    summary = {
        "schema": "s3.m21c.raw_on_demand_request_summary.v1",
        "status": "PASS",
        "created_at_utc": utc_now(),
        "candidate_input": str(candidates_path),
        "uri_count": len(rows),
        "by_source_host": dict(by_host.most_common()),
        "by_ta": dict(by_ta.most_common()),
        "outputs": {
            "uri_list_tsv": str(tsv_path),
            "probe_requests": request_paths,
        },
    }

    summary_path = inputs / "M21C_raw_on_demand_request_summary.json"
    write_json(summary_path, summary)

    check = "\n".join([
        "M21C_RAW_ON_DEMAND_REQUEST_CREATED=PASS",
        "",
        f"uri_count = {len(rows)}",
        f"by_source_host = {dict(by_host.most_common())}",
        f"by_ta = {dict(by_ta.most_common())}",
        f"uri_list_tsv = {tsv_path}",
        f"probe_bj_request = {request_paths['probe-bj']}",
        f"probe_cd_request = {request_paths['probe-cd']}",
        f"probe_sg_request = {request_paths['probe-sg']}",
        f"summary_path = {summary_path}",
    ]) + "\n"

    write_text(checks / "M21C_raw_on_demand_request_check.txt", check)
    print(check)


def build_m21d_requests() -> None:
    out_dir = Path(os.environ["M21D_OUT_DIR"])
    candidates_path = Path(os.environ["M21D_CANDIDATES"])

    top_n_hosts = int(os.environ.get("M21D_TOP_N_HOSTS", "7"))
    sample_per_host = int(os.environ.get("M21D_SAMPLE_PER_HOST", "20"))

    inputs = out_dir / "inputs"
    checks = out_dir / "checks"
    inputs.mkdir(parents=True, exist_ok=True)

    by_host: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for r in read_jsonl(candidates_path):
        uri = r.get("source_uri")
        if not uri:
            continue

        host = r.get("source_host") or host_of(uri)
        tup = safe_tuple(r)

        by_host[host].append({
            "request_id": "",
            "source_uri": uri,
            "source_host": host,
            "vrp_key": r.get("vrp_key"),
            "asn": tup.get("asn"),
            "prefix": tup.get("prefix"),
            "max_length": tup.get("max_length"),
            "ta": tup.get("ta"),
            "present_probes": r.get("present_probes") or [],
            "absent_probes": r.get("absent_probes") or [],
            "source_uri_by_probe": r.get("source_uri_by_probe") or {},
        })

    ranked_hosts = sorted(by_host.items(), key=lambda kv: len(kv[1]), reverse=True)[:top_n_hosts]

    sample_rows = []
    for host, rows in ranked_hosts:
        uniq_rows = uniq_by_uri(rows)
        for r in uniq_rows[:sample_per_host]:
            r = dict(r)
            r["request_id"] = f"m21d-{len(sample_rows)+1:04d}"
            sample_rows.append(r)

    tsv_path = inputs / "m21d_top_host_sample_uri_list.tsv"
    with tsv_path.open("wt", encoding="utf-8", newline="") as w:
        fields = [
            "request_id", "source_host", "source_uri", "vrp_key",
            "asn", "prefix", "max_length", "ta",
            "present_probes", "absent_probes"
        ]
        writer = csv.DictWriter(w, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        for r in sample_rows:
            rr = dict(r)
            rr["present_probes"] = ",".join(rr.get("present_probes") or [])
            rr["absent_probes"] = ",".join(rr.get("absent_probes") or [])
            writer.writerow({k: rr.get(k, "") for k in fields})

    request_paths = write_probe_requests(
        inputs,
        "m21d_probe_request",
        sample_rows,
        "m21d_bj_skew_top_host_cache_presence",
    )

    host_counts = {host: len(rows) for host, rows in ranked_hosts}
    sample_host_counts = Counter(r["source_host"] for r in sample_rows)
    by_ta = Counter(str(r.get("ta") or "unknown").lower() for r in sample_rows)

    summary = {
        "schema": "s3.m21d.top_host_sample_request_summary.v1",
        "status": "PASS",
        "created_at_utc": utc_now(),
        "candidate_input": str(candidates_path),
        "top_n_hosts": top_n_hosts,
        "sample_per_host": sample_per_host,
        "top_host_count": len(ranked_hosts),
        "sample_uri_count": len(sample_rows),
        "top_host_original_counts": host_counts,
        "sample_by_host": dict(sample_host_counts.most_common()),
        "sample_by_ta": dict(by_ta.most_common()),
        "outputs": {
            "sample_uri_list_tsv": str(tsv_path),
            "probe_requests": request_paths,
        },
    }

    summary_path = inputs / "M21D_top_host_sample_request_summary.json"
    write_json(summary_path, summary)

    check = "\n".join([
        "M21D_TOP_HOST_SAMPLE_CREATED=PASS",
        "",
        f"top_n_hosts = {top_n_hosts}",
        f"sample_per_host = {sample_per_host}",
        f"top_host_count = {len(ranked_hosts)}",
        f"sample_uri_count = {len(sample_rows)}",
        f"top_host_original_counts = {host_counts}",
        f"sample_by_host = {dict(sample_host_counts.most_common())}",
        f"sample_by_ta = {dict(by_ta.most_common())}",
        f"sample_uri_list_tsv = {tsv_path}",
        f"probe_bj_request = {request_paths['probe-bj']}",
        f"probe_cd_request = {request_paths['probe-cd']}",
        f"probe_sg_request = {request_paths['probe-sg']}",
        f"summary_path = {summary_path}",
    ]) + "\n"

    write_text(checks / "M21D_top_host_sample_request_check.txt", check)
    print(check)


def main() -> int:
    build_m21c_requests()
    print()
    build_m21d_requests()
    print("M21_C2_D2_REQUESTS_CREATED=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
