#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tarfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set
from urllib.parse import urlparse


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


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


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def host_of(uri: str) -> str:
    try:
        return urlparse(uri).netloc or "unknown"
    except Exception:
        return "unknown"


def norm_keys_from_source_uri(uri: str) -> Set[str]:
    keys: Set[str] = set()
    if not uri:
        return keys

    s = str(uri).strip()
    keys.add(s)

    if s.startswith("rsync://"):
        p = urlparse(s)
        host = p.netloc
        path = p.path.lstrip("/")
        if host and path:
            keys.add(f"{host}/{path}")
            keys.add(f"rsync/{host}/{path}")
            keys.add(path)
            keys.add(Path(path).name)

    parts = s.split("/")
    if len(parts) >= 4:
        keys.add("/".join(parts[-4:]))
    if len(parts) >= 6:
        keys.add("/".join(parts[-6:]))
    if parts:
        keys.add(parts[-1])

    return {k for k in keys if k}


def norm_keys_from_path(path: Path) -> Set[str]:
    keys: Set[str] = set()
    s = str(path)
    keys.add(s)
    keys.add(path.name)

    marker = "/repository/rsync/"
    if marker in s:
        tail = s.split(marker, 1)[1].lstrip("/")
        keys.add(tail)
        keys.add(f"rsync/{tail}")
        keys.add(Path(tail).name)

    marker2 = "repository/rsync/"
    if marker2 in s:
        tail = s.split(marker2, 1)[1].lstrip("/")
        keys.add(tail)
        keys.add(f"rsync/{tail}")
        keys.add(Path(tail).name)

    marker3 = "/rsync/"
    if marker3 in s:
        tail = s.rsplit(marker3, 1)[1].lstrip("/")
        keys.add(tail)
        keys.add(f"rsync/{tail}")
        keys.add(Path(tail).name)

    parts = s.split("/")
    if len(parts) >= 4:
        keys.add("/".join(parts[-4:]))
    if len(parts) >= 6:
        keys.add("/".join(parts[-6:]))

    return {k for k in keys if k}


def iter_roa_files(cache_roots: List[Path]) -> Iterable[Path]:
    seen = set()
    for root in cache_roots:
        if not root.exists():
            continue
        for p in root.rglob("*.roa"):
            try:
                rp = p.resolve()
            except Exception:
                rp = p
            key = str(rp)
            if key in seen:
                continue
            seen.add(key)
            if p.is_file():
                yield p


def build_file_index(cache_roots: List[Path]) -> Dict[str, List[Path]]:
    idx: Dict[str, List[Path]] = {}

    for p in iter_roa_files(cache_roots):
        for k in norm_keys_from_path(p):
            idx.setdefault(k, []).append(p)

    return idx


def find_hits(uri: str, idx: Dict[str, List[Path]], max_hits: int) -> List[Path]:
    hits: List[Path] = []
    seen = set()

    for k in norm_keys_from_source_uri(uri):
        for p in idx.get(k, []):
            sp = str(p)
            if sp in seen:
                continue
            seen.add(sp)
            hits.append(p)
            if len(hits) >= max_hits:
                return hits

    return hits


def copy_to_cas(src: Path, raw_sha256: str, cas_root: Path) -> str:
    digest = raw_sha256.split("sha256:", 1)[-1]
    sub = digest[:2]
    dst = cas_root / sub / f"{digest}.roa"
    dst.parent.mkdir(parents=True, exist_ok=True)
    if not dst.exists():
        shutil.copy2(src, dst)
    return str(dst)


def make_archive(run_dir: Path, export_dir: Path, run_id: str) -> Dict[str, str]:
    export_dir.mkdir(parents=True, exist_ok=True)
    archive = export_dir / f"{run_id}.tar.gz"
    sha_path = export_dir / f"{run_id}.tar.gz.sha256"

    with tarfile.open(archive, "w:gz") as tf:
        tf.add(run_dir, arcname=run_id)

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    sha_path.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")

    return {
        "archive_path": str(archive),
        "archive_sha256": str(sha_path),
        "archive_digest": "sha256:" + digest,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--request-json", required=True)
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--label", default="")
    ap.add_argument("--cache-root", action="append", default=[])
    ap.add_argument("--max-hits-per-uri", type=int, default=20)
    ap.add_argument("--no-copy-raw", action="store_true")
    args = ap.parse_args()

    request_path = Path(args.request_json)
    out_root = Path(args.out_root)
    request = load_json(request_path)

    label = args.label or request.get("request_type") or request.get("request_name") or "m21_probe_cache_presence"
    run_id = f"{label}_{args.probe_id}_{utc_tag()}"

    run_dir = out_root / "history" / run_id
    indexes = run_dir / "indexes"
    outputs = run_dir / "outputs"
    checks = run_dir / "checks"
    raw_objects = run_dir / "raw_objects" / "sha256"
    export_dir = out_root / "exports"
    latest_dir = out_root / "latest"

    for d in [indexes, outputs, checks, raw_objects, export_dir, latest_dir]:
        d.mkdir(parents=True, exist_ok=True)

    roots = [Path(p).expanduser() for p in args.cache_root]
    if not roots:
        roots = [
            Path.home() / ".rpki-cache",
            Path("/var/lib/routinator/rpki-cache"),
        ]

    print(f"probe_id={args.probe_id}")
    print(f"request_json={request_path}")
    print(f"out_root={out_root}")
    print(f"run_id={run_id}")
    print(f"cache_roots={[str(x) for x in roots]}")
    print("building_file_index...")
    idx = build_file_index(roots)
    print(f"file_index_key_count={len(idx)}")

    requests = request.get("requests") or []
    records: List[Dict[str, Any]] = []

    found_uri_count = 0
    missing_uri_count = 0
    copied_raw_count = 0
    raw_bytes_total = 0
    by_source_host = Counter()
    by_ta = Counter()
    by_status = Counter()

    for req in requests:
        uri = req.get("source_uri")
        host = req.get("source_host") or host_of(uri or "")
        ta = str(req.get("ta") or "unknown").lower()
        by_source_host[host] += 1
        by_ta[ta] += 1

        if not uri:
            rec = {
                "schema": "s3.m21.probe_cache_presence_record.v1",
                "probe_id": args.probe_id,
                "request_id": req.get("request_id"),
                "source_uri": uri,
                "source_host": host,
                "ta": ta,
                "status": "missing_no_source_uri",
                "hit_count": 0,
                "hits": [],
                "request": req,
            }
            records.append(rec)
            missing_uri_count += 1
            by_status[rec["status"]] += 1
            continue

        hits = find_hits(uri, idx, args.max_hits_per_uri)

        hit_records = []
        for p in hits:
            try:
                raw_sha = sha256_file(p)
                size = p.stat().st_size
                cas_path = None
                if not args.no_copy_raw:
                    cas_path = copy_to_cas(p, raw_sha, raw_objects)
                    copied_raw_count += 1
                    raw_bytes_total += size

                hit_records.append({
                    "path": str(p),
                    "raw_sha256": raw_sha,
                    "raw_size_bytes": size,
                    "cas_path": cas_path,
                })
            except Exception as e:
                hit_records.append({
                    "path": str(p),
                    "error": repr(e),
                })

        status = "found" if hit_records else "missing"
        if hit_records:
            found_uri_count += 1
        else:
            missing_uri_count += 1
        by_status[status] += 1

        records.append({
            "schema": "s3.m21.probe_cache_presence_record.v1",
            "probe_id": args.probe_id,
            "request_id": req.get("request_id"),
            "request_type": request.get("request_type"),
            "source_uri": uri,
            "source_host": host,
            "asn": req.get("asn"),
            "prefix": req.get("prefix"),
            "max_length": req.get("max_length"),
            "ta": ta,
            "present_probes_expected": req.get("present_probes"),
            "absent_probes_expected": req.get("absent_probes"),
            "status": status,
            "hit_count": len(hit_records),
            "hits": hit_records,
            "request": req,
        })

    records_path = indexes / "m21_probe_cache_presence_records.jsonl"
    write_jsonl(records_path, records)

    summary = {
        "schema": "s3.m21.probe_cache_presence_summary.v1",
        "status": "PASS",
        "probe_id": args.probe_id,
        "run_id": run_id,
        "label": label,
        "created_at_utc": utc_now(),
        "request_json": str(request_path),
        "request_type": request.get("request_type"),
        "requested_uri_count": len(requests),
        "found_uri_count": found_uri_count,
        "missing_uri_count": missing_uri_count,
        "copied_raw_count": copied_raw_count,
        "raw_bytes_total": raw_bytes_total,
        "cache_roots": [str(x) for x in roots],
        "file_index_key_count": len(idx),
        "by_source_host": dict(by_source_host.most_common()),
        "by_ta": dict(by_ta.most_common()),
        "by_status": dict(by_status.most_common()),
        "outputs": {
            "records_path": str(records_path),
        },
        "important_boundary": [
            "This is probe-side cache presence and raw object evidence.",
            "It does not trigger Routinator repository update.",
            "Found/missing depends on current local cache state."
        ],
    }

    summary_path = outputs / "M21_probe_cache_presence_summary.json"
    write_json(summary_path, summary)

    latest_summary = latest_dir / "M21_probe_cache_presence_summary.json"
    shutil.copy2(summary_path, latest_summary)

    archive_info = make_archive(run_dir, export_dir, run_id)
    summary.update(archive_info)
    write_json(summary_path, summary)
    shutil.copy2(summary_path, latest_summary)

    check = "\n".join([
        "M21_PROBE_CACHE_PRESENCE_EXPORT=PASS",
        "",
        f"probe_id = {args.probe_id}",
        f"run_id = {run_id}",
        f"label = {label}",
        f"requested_uri_count = {len(requests)}",
        f"found_uri_count = {found_uri_count}",
        f"missing_uri_count = {missing_uri_count}",
        f"copied_raw_count = {copied_raw_count}",
        f"raw_bytes_total = {raw_bytes_total}",
        f"by_status = {dict(by_status.most_common())}",
        f"by_ta = {dict(by_ta.most_common())}",
        f"summary_path = {summary_path}",
        f"records_path = {records_path}",
        f"archive_path = {archive_info['archive_path']}",
        f"archive_sha256 = {archive_info['archive_sha256']}",
    ]) + "\n"

    check_path = checks / "M21_probe_cache_presence_check.txt"
    check_path.write_text(check, encoding="utf-8")

    print(check)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
