#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tarfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set
from urllib.parse import urlparse


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def utc_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)
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


def uri_dir_keys(uri: str) -> Set[str]:
    keys: Set[str] = set()
    if not uri:
        return keys

    s = str(uri).strip()
    if s.startswith("rsync://"):
        p = urlparse(s)
        host = p.netloc
        path = p.path.lstrip("/")
        parent = str(Path(path).parent)
        if host and parent and parent != ".":
            keys.add(f"{host}/{parent}")
            keys.add(f"rsync/{host}/{parent}")
            keys.add(parent)

    parts = s.split("/")
    if len(parts) >= 2:
        keys.add("/".join(parts[:-1]))
    if len(parts) >= 5:
        keys.add("/".join(parts[-5:-1]))
    if len(parts) >= 7:
        keys.add("/".join(parts[-7:-1]))

    return {k for k in keys if k}


def uri_file_keys(uri: str) -> Set[str]:
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
    if parts:
        keys.add(parts[-1])
    if len(parts) >= 4:
        keys.add("/".join(parts[-4:]))
    if len(parts) >= 6:
        keys.add("/".join(parts[-6:]))

    return {k for k in keys if k}


def path_file_keys(path: Path) -> Set[str]:
    keys: Set[str] = set()
    s = str(path)
    keys.add(s)
    keys.add(path.name)

    for marker in ["/repository/rsync/", "repository/rsync/"]:
        if marker in s:
            tail = s.split(marker, 1)[1].lstrip("/")
            keys.add(tail)
            keys.add(f"rsync/{tail}")
            keys.add(Path(tail).name)

    if "/rsync/" in s:
        tail = s.rsplit("/rsync/", 1)[1].lstrip("/")
        keys.add(tail)
        keys.add(f"rsync/{tail}")
        keys.add(Path(tail).name)

    parts = s.split("/")
    if len(parts) >= 4:
        keys.add("/".join(parts[-4:]))
    if len(parts) >= 6:
        keys.add("/".join(parts[-6:]))

    return {k for k in keys if k}


def path_dir_keys(path: Path) -> Set[str]:
    keys: Set[str] = set()
    s = str(path)

    parent = str(path.parent)
    keys.add(parent)

    for marker in ["/repository/rsync/", "repository/rsync/"]:
        if marker in s:
            tail = s.split(marker, 1)[1].lstrip("/")
            tail_parent = str(Path(tail).parent)
            if tail_parent and tail_parent != ".":
                keys.add(tail_parent)
                keys.add(f"rsync/{tail_parent}")

    if "/rsync/" in s:
        tail = s.rsplit("/rsync/", 1)[1].lstrip("/")
        tail_parent = str(Path(tail).parent)
        if tail_parent and tail_parent != ".":
            keys.add(tail_parent)
            keys.add(f"rsync/{tail_parent}")

    parts = s.split("/")
    if len(parts) >= 5:
        keys.add("/".join(parts[-5:-1]))
    if len(parts) >= 7:
        keys.add("/".join(parts[-7:-1]))

    return {k for k in keys if k}


def iter_files(cache_roots: List[Path], suffix: str) -> Iterable[Path]:
    seen = set()
    for root in cache_roots:
        if not root.exists():
            continue
        for p in root.rglob(f"*{suffix}"):
            if not p.is_file():
                continue
            try:
                rp = str(p.resolve())
            except Exception:
                rp = str(p)
            if rp in seen:
                continue
            seen.add(rp)
            yield p


def build_file_index(cache_roots: List[Path], suffix: str) -> Dict[str, List[Path]]:
    idx: Dict[str, List[Path]] = defaultdict(list)
    for p in iter_files(cache_roots, suffix):
        for k in path_file_keys(p):
            idx[k].append(p)
    return dict(idx)


def build_dir_index(cache_roots: List[Path], suffix: str) -> Dict[str, List[Path]]:
    idx: Dict[str, List[Path]] = defaultdict(list)
    for p in iter_files(cache_roots, suffix):
        for k in path_dir_keys(p):
            idx[k].append(p)
    return dict(idx)


def lookup_roa(uri: str, roa_idx: Dict[str, List[Path]], max_hits: int) -> List[Path]:
    hits: List[Path] = []
    seen = set()
    for k in uri_file_keys(uri):
        for p in roa_idx.get(k, []):
            sp = str(p)
            if sp in seen:
                continue
            seen.add(sp)
            hits.append(p)
            if len(hits) >= max_hits:
                return hits
    return hits


def lookup_mft_candidates(uri: str, roa_hits: List[Path], mft_dir_idx: Dict[str, List[Path]], max_candidates: int) -> List[Path]:
    hits: List[Path] = []
    seen = set()

    # Priority 1: same local directory as found ROA.
    for roa in roa_hits:
        for p in sorted(roa.parent.glob("*.mft")):
            sp = str(p)
            if sp not in seen:
                seen.add(sp)
                hits.append(p)
                if len(hits) >= max_candidates:
                    return hits

    # Priority 2: same rsync/source URI directory.
    for k in uri_dir_keys(uri):
        for p in mft_dir_idx.get(k, []):
            sp = str(p)
            if sp not in seen:
                seen.add(sp)
                hits.append(p)
                if len(hits) >= max_candidates:
                    return hits

    return hits


def copy_to_cas(src: Path, raw_sha256: str, cas_root: Path, suffix: str) -> str:
    digest = raw_sha256.split("sha256:", 1)[-1]
    dst = cas_root / digest[:2] / f"{digest}{suffix}"
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
    ap.add_argument("--label", default="m22_raw_evidence_probe")
    ap.add_argument("--cache-root", action="append", default=[])
    ap.add_argument("--max-roa-hits", type=int, default=20)
    ap.add_argument("--max-mft-candidates", type=int, default=20)
    ap.add_argument("--no-copy-raw", action="store_true")
    args = ap.parse_args()

    request_path = Path(args.request_json)
    request = load_json(request_path)

    probe_id = args.probe_id
    trigger_id = request.get("trigger_id") or "unknown_trigger"
    run_id = f"{args.label}_{probe_id}_{trigger_id}_{utc_tag()}"

    out_root = Path(args.out_root)
    run_dir = out_root / "history" / run_id
    outputs = run_dir / "outputs"
    indexes = run_dir / "indexes"
    checks = run_dir / "checks"
    logs = run_dir / "logs"
    raw_roa_root = run_dir / "raw_objects" / "roa" / "sha256"
    raw_mft_root = run_dir / "raw_objects" / "manifest" / "sha256"
    latest = out_root / "latest"
    exports = out_root / "exports"

    for d in [outputs, indexes, checks, logs, raw_roa_root, raw_mft_root, latest, exports]:
        d.mkdir(parents=True, exist_ok=True)

    cache_roots = [Path(x).expanduser() for x in args.cache_root]
    if not cache_roots:
        cache_roots = [
            Path.home() / ".rpki-cache",
            Path("/var/lib/routinator/rpki-cache"),
        ]

    print(f"probe_id={probe_id}")
    print(f"trigger_id={trigger_id}")
    print(f"request_json={request_path}")
    print(f"run_id={run_id}")
    print(f"cache_roots={[str(x) for x in cache_roots]}")
    print("building_roa_index...")
    roa_idx = build_file_index(cache_roots, ".roa")
    print(f"roa_index_key_count={len(roa_idx)}")
    print("building_manifest_dir_index...")
    mft_dir_idx = build_dir_index(cache_roots, ".mft")
    print(f"manifest_dir_index_key_count={len(mft_dir_idx)}")

    requests = request.get("requests") or []

    roa_records = []
    manifest_records = []
    manifest_filelist_records = []
    source_to_manifest_records = []

    roa_found = 0
    roa_missing = 0
    raw_roa_copied = 0
    raw_mft_copied = 0
    manifest_candidate_total = 0
    manifest_found_request_count = 0

    by_roa_status = Counter()
    by_manifest_status = Counter()
    by_source_host = Counter()
    by_ta = Counter()

    for req in requests:
        source_uri = req.get("source_uri")
        source_host = req.get("source_host") or host_of(source_uri or "")
        ta = str(req.get("ta") or "unknown").lower()

        by_source_host[source_host] += 1
        by_ta[ta] += 1

        roa_hits = lookup_roa(source_uri or "", roa_idx, args.max_roa_hits)

        roa_hit_items = []
        for p in roa_hits:
            try:
                raw_sha = sha256_file(p)
                size = p.stat().st_size
                cas_path = None
                if not args.no_copy_raw:
                    cas_path = copy_to_cas(p, raw_sha, raw_roa_root, ".roa")
                    raw_roa_copied += 1
                roa_hit_items.append({
                    "cache_path": str(p),
                    "raw_sha256": raw_sha,
                    "raw_size_bytes": size,
                    "cas_path": cas_path,
                    "match_basis": "source_uri_or_cache_tail",
                })
            except Exception as e:
                roa_hit_items.append({
                    "cache_path": str(p),
                    "error": repr(e),
                    "match_basis": "source_uri_or_cache_tail",
                })

        roa_status = "found" if roa_hit_items else "missing"
        if roa_status == "found":
            roa_found += 1
        else:
            roa_missing += 1
        by_roa_status[roa_status] += 1

        roa_records.append({
            "schema": "s3.m22.probe.roa_presence_record.v1",
            "probe_id": probe_id,
            "trigger_id": trigger_id,
            "request_id": req.get("request_id"),
            "vrp_key": req.get("vrp_key"),
            "asn": req.get("asn"),
            "prefix": req.get("prefix"),
            "max_length": req.get("max_length"),
            "ta": req.get("ta"),
            "source_uri": source_uri,
            "source_host": source_host,
            "status": roa_status,
            "hit_count": len(roa_hit_items),
            "hits": roa_hit_items,
            "request": req,
        })

        mft_candidates = lookup_mft_candidates(
            source_uri or "",
            roa_hits,
            mft_dir_idx,
            args.max_mft_candidates,
        )
        manifest_candidate_total += len(mft_candidates)

        mft_items = []
        for p in mft_candidates:
            try:
                raw_sha = sha256_file(p)
                size = p.stat().st_size
                cas_path = None
                if not args.no_copy_raw:
                    cas_path = copy_to_cas(p, raw_sha, raw_mft_root, ".mft")
                    raw_mft_copied += 1
                mft_items.append({
                    "manifest_cache_path": str(p),
                    "manifest_raw_sha256": raw_sha,
                    "manifest_raw_size_bytes": size,
                    "manifest_cas_path": cas_path,
                    "manifest_parse_status": "not_parsed_in_m22b1_minimal",
                })
            except Exception as e:
                mft_items.append({
                    "manifest_cache_path": str(p),
                    "error": repr(e),
                    "manifest_parse_status": "error_before_parse",
                })

        manifest_status = "found" if mft_items else "missing"
        if mft_items:
            manifest_found_request_count += 1
        by_manifest_status[manifest_status] += 1

        manifest_records.append({
            "schema": "s3.m22.probe.manifest_presence_record.v1",
            "probe_id": probe_id,
            "trigger_id": trigger_id,
            "request_id": req.get("request_id"),
            "source_uri": source_uri,
            "source_host": source_host,
            "status": manifest_status,
            "candidate_count": len(mft_items),
            "manifest_candidates": mft_items,
            "important_boundary": [
                "M22-B1 minimal collector preserves raw manifest candidates.",
                "ASN.1 manifest fileList parsing is deferred to M22-B2/M22-C."
            ],
        })

        source_to_manifest_records.append({
            "schema": "s3.m22.probe.source_uri_to_manifest_candidates.v1",
            "probe_id": probe_id,
            "trigger_id": trigger_id,
            "request_id": req.get("request_id"),
            "source_uri": source_uri,
            "source_host": source_host,
            "roa_status": roa_status,
            "roa_hit_count": len(roa_hit_items),
            "manifest_status": manifest_status,
            "manifest_candidate_count": len(mft_items),
            "roa_hit_paths": [x.get("cache_path") for x in roa_hit_items if x.get("cache_path")],
            "manifest_candidate_paths": [x.get("manifest_cache_path") for x in mft_items if x.get("manifest_cache_path")],
        })

        for item in mft_items:
            manifest_filelist_records.append({
                "schema": "s3.m22.probe.manifest_filelist_record.v1",
                "probe_id": probe_id,
                "trigger_id": trigger_id,
                "request_id": req.get("request_id"),
                "source_uri": source_uri,
                "source_host": source_host,
                "manifest_cache_path": item.get("manifest_cache_path"),
                "manifest_raw_sha256": item.get("manifest_raw_sha256"),
                "filelist_parse_status": "not_parsed_in_m22b1_minimal",
                "filelist_contains_roa": None,
                "filelist_roa_hash": None,
            })

    roa_records_path = indexes / "roa_presence_records.jsonl"
    manifest_records_path = indexes / "manifest_presence_records.jsonl"
    source_to_manifest_path = indexes / "source_uri_to_manifest_candidates.jsonl"
    manifest_filelist_path = indexes / "manifest_filelist_records.jsonl"

    write_jsonl(roa_records_path, roa_records)
    write_jsonl(manifest_records_path, manifest_records)
    write_jsonl(source_to_manifest_path, source_to_manifest_records)
    write_jsonl(manifest_filelist_path, manifest_filelist_records)

    summary = {
        "schema": "s3.m22.probe.raw_evidence_summary.v1",
        "status": "PASS",
        "probe_id": probe_id,
        "trigger_id": trigger_id,
        "run_id": run_id,
        "label": args.label,
        "created_at_utc": utc_now(),
        "request_json": str(request_path),
        "window_level": request.get("window_level"),
        "evidence_level": request.get("evidence_level"),
        "requested_source_uri_count": len(requests),
        "roa_found_count": roa_found,
        "roa_missing_count": roa_missing,
        "raw_roa_copied_count": raw_roa_copied,
        "manifest_candidate_count": manifest_candidate_total,
        "manifest_found_request_count": manifest_found_request_count,
        "raw_manifest_copied_count": raw_mft_copied,
        "cache_roots": [str(x) for x in cache_roots],
        "roa_index_key_count": len(roa_idx),
        "manifest_dir_index_key_count": len(mft_dir_idx),
        "by_roa_status": dict(by_roa_status.most_common()),
        "by_manifest_status": dict(by_manifest_status.most_common()),
        "by_source_host": dict(by_source_host.most_common()),
        "by_ta": dict(by_ta.most_common()),
        "outputs": {
            "roa_presence_records": str(roa_records_path),
            "manifest_presence_records": str(manifest_records_path),
            "source_uri_to_manifest_candidates": str(source_to_manifest_path),
            "manifest_filelist_records": str(manifest_filelist_path),
        },
        "important_boundary": [
            "This M22-B1 run is a minimal raw evidence collector test.",
            "It preserves raw ROA and raw manifest candidates when found.",
            "Manifest ASN.1 fileList parsing is not yet implemented in M22-B1.",
            "If evidence_level is replay_not_strong, outputs must not be treated as strong-window evidence."
        ],
    }

    summary_path = outputs / "M22_probe_raw_evidence_summary.json"
    write_json(summary_path, summary)

    check = "\n".join([
        "M22_PROBE_RAW_EVIDENCE_EXPORT=PASS",
        "",
        f"probe_id = {probe_id}",
        f"trigger_id = {trigger_id}",
        f"run_id = {run_id}",
        f"window_level = {request.get('window_level')}",
        f"evidence_level = {request.get('evidence_level')}",
        f"requested_source_uri_count = {len(requests)}",
        f"roa_found_count = {roa_found}",
        f"roa_missing_count = {roa_missing}",
        f"raw_roa_copied_count = {raw_roa_copied}",
        f"manifest_candidate_count = {manifest_candidate_total}",
        f"manifest_found_request_count = {manifest_found_request_count}",
        f"raw_manifest_copied_count = {raw_mft_copied}",
        f"by_roa_status = {dict(by_roa_status.most_common())}",
        f"by_manifest_status = {dict(by_manifest_status.most_common())}",
        f"summary_path = {summary_path}",
        f"roa_records_path = {roa_records_path}",
        f"manifest_records_path = {manifest_records_path}",
    ]) + "\n"

    check_path = checks / "M22_probe_raw_evidence_check.txt"
    check_path.write_text(check, encoding="utf-8")

    archive_info = make_archive(run_dir, exports, run_id)
    summary.update(archive_info)
    write_json(summary_path, summary)
    shutil.copy2(summary_path, latest / "M22_probe_raw_evidence_summary.json")

    print(check)
    print(f"archive_path = {archive_info['archive_path']}")
    print(f"archive_sha256 = {archive_info['archive_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
