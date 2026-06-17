#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse


PROBES = ["probe-bj", "probe-cd", "probe-sg"]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def parse_utc(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def add_seconds_utc(s: str, seconds: int) -> str:
    return (parse_utc(s) + timedelta(seconds=seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("wt", encoding="utf-8") as w:
        for r in rows:
            w.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
            n += 1
    return n


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


def collect_m21c_source_uri_records(candidates_path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen = set()

    for r in read_jsonl(candidates_path):
        uri = r.get("source_uri")
        if not uri:
            continue

        if uri in seen:
            continue
        seen.add(uri)

        tup = safe_tuple(r)
        source_host = r.get("source_host") or host_of(uri)

        rows.append({
            "request_id": f"m22-req-{len(rows) + 1:04d}",
            "vrp_key": r.get("vrp_key"),
            "asn": tup.get("asn"),
            "prefix": tup.get("prefix"),
            "max_length": tup.get("max_length"),
            "ta": tup.get("ta"),
            "source_uri": uri,
            "source_host": source_host,
            "expected_present_probes": r.get("present_probes") or [],
            "expected_absent_probes": r.get("absent_probes") or [],
            "source_uri_by_probe": r.get("source_uri_by_probe") or {},
            "validity_by_probe": r.get("validity_by_probe"),
            "chain_validity_by_probe": r.get("chain_validity_by_probe"),
            "m21_hit_status": r.get("hit_status"),
            "m21_object_index_hit_count": r.get("object_index_hit_count"),
            "evidence_targets": [
                "roa_raw",
                "roa_raw_sha256",
                "manifest_raw",
                "manifest_raw_sha256",
                "manifest_filelist",
                "cache_path"
            ],
        })

    return rows


def build_probe_request(
    trigger_id: str,
    probe_id: str,
    request_rows: List[Dict[str, Any]],
    created_at: str,
    deadline_seconds: int,
    window_level: str,
    evidence_level: str,
) -> Dict[str, Any]:
    deadline_utc = add_seconds_utc(created_at, deadline_seconds)

    return {
        "schema": "s3.m22.raw_evidence_request.v1",
        "trigger_id": trigger_id,
        "target_probe_id": probe_id,
        "request_type": "raw_roa_manifest_on_demand",
        "window_level": window_level,
        "evidence_level": evidence_level,
        "created_at_utc": created_at,
        "deadline_utc": deadline_utc,
        "deadline_seconds": deadline_seconds,
        "requested_source_uri_count": len(request_rows),
        "requests": request_rows,
        "match_hints": [
            "rsync_uri_direct",
            "repository_rsync_tail",
            "stored_rrdp_rsync_tail",
            "same_directory_manifest",
            "filename_tail"
        ],
        "important_boundary": [
            "This M22-A1 request is generated from M21-C historical source URIs.",
            "It is manual replay, not strong-window evidence.",
            "The request format is intended for M22-B probe raw evidence collector."
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["m21c-replay"])
    ap.add_argument("--m21c-candidates", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--trigger-id", default="")
    ap.add_argument("--target-utc", default="")
    ap.add_argument("--deadline-seconds", type=int, default=300)
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    inputs = out_dir / "inputs"
    requests_dir = out_dir / "requests"
    outputs = out_dir / "outputs"
    checks = out_dir / "checks"

    for d in [inputs, requests_dir, outputs, checks]:
        d.mkdir(parents=True, exist_ok=True)

    created_at = utc_now()
    trigger_id = args.trigger_id or f"m22a_replay_from_m21c_{utc_tag()}"
    target_utc = args.target_utc or created_at

    window_level = "manual_replay"
    evidence_level = "replay_not_strong"
    trigger_type = "manual_replay_from_m21c_source_uri"

    source_rows = collect_m21c_source_uri_records(Path(args.m21c_candidates))

    by_host = Counter(r["source_host"] for r in source_rows)
    by_ta = Counter(str(r.get("ta") or "unknown").lower() for r in source_rows)
    by_m21_hit_status = Counter(str(r.get("m21_hit_status") or "unknown") for r in source_rows)

    source_input_path = inputs / "m22a_m21c_source_uri_input.snapshot.jsonl"
    write_jsonl(source_input_path, source_rows)

    request_paths = {}
    for probe_id in PROBES:
        req = build_probe_request(
            trigger_id=trigger_id,
            probe_id=probe_id,
            request_rows=source_rows,
            created_at=created_at,
            deadline_seconds=args.deadline_seconds,
            window_level=window_level,
            evidence_level=evidence_level,
        )
        p = requests_dir / f"M22_raw_on_demand_request_{probe_id}.json"
        write_json(p, req)
        request_paths[probe_id] = str(p)

    trigger_event = {
        "schema": "s3.m22.trigger_event.v1",
        "trigger_id": trigger_id,
        "trigger_type": trigger_type,
        "window_level": window_level,
        "evidence_level": evidence_level,
        "target_utc": target_utc,
        "created_at_utc": created_at,
        "deadline_seconds": args.deadline_seconds,
        "deadline_utc": add_seconds_utc(created_at, args.deadline_seconds),
        "probe_ids": PROBES,
        "source_uri_count": len(source_rows),
        "source_host_count": len(by_host),
        "affected_vrp_count_estimate": len({r.get("vrp_key") for r in source_rows if r.get("vrp_key")}),
        "by_source_host": dict(by_host.most_common()),
        "by_ta": dict(by_ta.most_common()),
        "by_m21_hit_status": dict(by_m21_hit_status.most_common()),
        "input_paths": {
            "m21c_candidates": str(Path(args.m21c_candidates)),
            "source_uri_snapshot": str(source_input_path),
        },
        "request_paths": request_paths,
        "important_boundary": [
            "This is M22-A1 manual replay trigger built from M21-C historical source URIs.",
            "It validates M22 trigger/request schema and directory layout.",
            "It must not be used as strong-window object evidence."
        ],
    }

    trigger_event_path = outputs / "M22_trigger_event.json"
    write_json(trigger_event_path, trigger_event)

    summary = {
        "schema": "s3.m22a.trigger_build_summary.v1",
        "status": "PASS",
        "created_at_utc": created_at,
        "mode": args.mode,
        "trigger_id": trigger_id,
        "trigger_type": trigger_type,
        "window_level": window_level,
        "evidence_level": evidence_level,
        "source_uri_count": len(source_rows),
        "source_host_count": len(by_host),
        "probe_request_count": len(request_paths),
        "by_source_host": dict(by_host.most_common()),
        "by_ta": dict(by_ta.most_common()),
        "by_m21_hit_status": dict(by_m21_hit_status.most_common()),
        "outputs": {
            "trigger_event": str(trigger_event_path),
            "source_uri_snapshot": str(source_input_path),
            "requests_dir": str(requests_dir),
            "request_paths": request_paths,
        },
        "next_step": [
            "M22-B probe raw evidence collector should consume these request files.",
            "For this M22-A1 run, evidence_level remains replay_not_strong.",
        ],
    }

    summary_path = outputs / "M22A_trigger_build_summary.json"
    write_json(summary_path, summary)

    check = "\n".join([
        "M22A_TRIGGER_BUILD=PASS",
        "",
        f"trigger_id = {trigger_id}",
        f"trigger_type = {trigger_type}",
        f"window_level = {window_level}",
        f"evidence_level = {evidence_level}",
        f"source_uri_count = {len(source_rows)}",
        f"source_host_count = {len(by_host)}",
        f"probe_request_count = {len(request_paths)}",
        f"by_source_host = {dict(by_host.most_common())}",
        f"by_ta = {dict(by_ta.most_common())}",
        f"trigger_event = {trigger_event_path}",
        f"probe_bj_request = {request_paths['probe-bj']}",
        f"probe_cd_request = {request_paths['probe-cd']}",
        f"probe_sg_request = {request_paths['probe-sg']}",
        f"summary_path = {summary_path}",
    ]) + "\n"

    check_path = checks / "M22A_trigger_build_check.txt"
    check_path.write_text(check, encoding="utf-8")

    print(check)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
