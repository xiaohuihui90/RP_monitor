#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc_z(s: str) -> datetime:
    if not s.endswith("Z"):
        raise ValueError(f"target UTC must end with Z: {s}")
    return datetime.fromisoformat(s[:-1] + "+00:00")


def wait_until(target_utc: str) -> None:
    target = parse_utc_z(target_utc)
    while True:
        now = datetime.now(timezone.utc)
        remain = (target - now).total_seconds()
        if remain <= 0:
            return
        time.sleep(min(remain, 5.0))


def norm_asn(v: Any) -> int:
    s = str(v).strip().upper()
    if s.startswith("AS"):
        s = s[2:]
    return int(s)


def vrp_key(asn: int, prefix: str, max_length: int, ta: str) -> str:
    obj = {
        "asn": int(asn),
        "prefix": str(prefix),
        "max_length": int(max_length),
        "ta": str(ta).lower(),
    }
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def gzip_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as f_in, gzip.open(dst, "wb", compresslevel=6) as f_out:
        shutil.copyfileobj(f_in, f_out)


def load_jsonext(path: Path) -> list[Dict[str, Any]]:
    obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if isinstance(obj, dict):
        return obj.get("roas", [])
    if isinstance(obj, list):
        return obj
    return []


def build_indexes(jsonext_raw: Path, tuple_index_gz: Path, provenance_index_gz: Path) -> Dict[str, Any]:
    roas = load_jsonext(jsonext_raw)

    tuple_sources: dict[str, dict] = {}
    provenance_rows = 0
    invalid_count = 0

    by_ta = Counter()
    by_source_type = Counter()
    source_count_distribution = Counter()

    provenance_index_gz.parent.mkdir(parents=True, exist_ok=True)

    with gzip.open(provenance_index_gz, "wt", encoding="utf-8") as prov_out:
        for rec in roas:
            if not isinstance(rec, dict):
                invalid_count += 1
                continue

            try:
                asn = norm_asn(rec.get("asn"))
                prefix = str(rec.get("prefix")).strip()
                max_length = int(rec.get("maxLength", rec.get("max_length")))
            except Exception:
                invalid_count += 1
                continue

            sources = rec.get("source", [])
            if not isinstance(sources, list):
                sources = []

            source_count_distribution[str(len(sources))] += 1

            for src in sources:
                if not isinstance(src, dict):
                    continue

                ta = str(src.get("tal", "")).strip().lower()
                if not ta:
                    continue

                key = vrp_key(asn, prefix, max_length, ta)
                uri = src.get("uri")

                by_ta[ta] += 1
                by_source_type[str(src.get("type", "unknown"))] += 1

                if key not in tuple_sources:
                    tuple_sources[key] = {
                        "schema": "s3.m21b.jsonext_vrp_tuple.v1",
                        "vrp_key": key,
                        "asn": asn,
                        "prefix": prefix,
                        "max_length": max_length,
                        "ta": ta,
                        "source_uri_set": set(),
                        "source_count": 0,
                    }

                tuple_sources[key]["source_count"] += 1
                if uri:
                    tuple_sources[key]["source_uri_set"].add(str(uri))

                row = {
                    "schema": "s3.m21b.jsonext_vrp_provenance.v1",
                    "vrp_key": key,
                    "asn": asn,
                    "prefix": prefix,
                    "max_length": max_length,
                    "ta": ta,
                    "source": {
                        "type": src.get("type"),
                        "uri": src.get("uri"),
                        "tal": src.get("tal"),
                        "validity": src.get("validity"),
                        "chainValidity": src.get("chainValidity"),
                        "stale": src.get("stale"),
                    },
                }
                prov_out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                provenance_rows += 1

    with gzip.open(tuple_index_gz, "wt", encoding="utf-8") as tuple_out:
        for key, row in sorted(tuple_sources.items(), key=lambda kv: (kv[1]["ta"], kv[1]["asn"], kv[1]["prefix"], kv[1]["max_length"])):
            row = dict(row)
            row["source_uri_count"] = len(row["source_uri_set"])
            row["source_uri_sample"] = sorted(row["source_uri_set"])[:5]
            del row["source_uri_set"]
            tuple_out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    return {
        "jsonext_roa_record_count": len(roas),
        "tuple_unique_count": len(tuple_sources),
        "provenance_row_count": provenance_rows,
        "invalid_record_count": invalid_count,
        "by_ta": dict(sorted(by_ta.items())),
        "by_source_type": dict(sorted(by_source_type.items())),
        "source_count_distribution": dict(sorted(source_count_distribution.items())),
    }


def make_archive(run_dir: Path, archive_path: Path) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)

    if archive_path.exists():
        archive_path.unlink()

    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(run_dir, arcname=run_dir.name)

    sha = file_sha256(archive_path).replace("sha256:", "")
    archive_path.with_suffix(archive_path.suffix + ".sha256").write_text(
        f"{sha}  {archive_path.name}\n",
        encoding="utf-8",
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="M21-B3 probe-side Routinator jsonext joint snapshot collector")
    ap.add_argument("--probe-id", required=True)
    ap.add_argument("--target-utc", required=True)
    ap.add_argument("--out-root", required=True)
    ap.add_argument("--routinator-bin", default="routinator")
    ap.add_argument("--allow-update", action="store_true", help="do not pass --noupdate")
    args = ap.parse_args()

    probe_id = args.probe_id
    target_utc = args.target_utc
    target_tag = target_utc.replace("-", "").replace(":", "").replace("T", "T").replace("Z", "Z")
    run_id = f"m21b_jsonext_joint_{probe_id}_{target_tag}"

    out_root = Path(args.out_root).resolve()
    run_dir = out_root / "history" / run_id
    raw_dir = run_dir / "raw"
    idx_dir = run_dir / "indexes"
    out_dir = run_dir / "outputs"
    chk_dir = run_dir / "checks"
    log_dir = run_dir / "logs"

    for d in [raw_dir, idx_dir, out_dir, chk_dir, log_dir]:
        d.mkdir(parents=True, exist_ok=True)

    started_wait_at = utc_now_iso()
    wait_until(target_utc)
    collection_started_at = utc_now_iso()

    raw_json = raw_dir / "vrps.jsonext.raw.json"
    raw_json_gz = raw_dir / "vrps.jsonext.raw.json.gz"
    tuple_index_gz = idx_dir / "vrp_tuple_index.jsonl.gz"
    provenance_index_gz = idx_dir / "vrp_provenance_index.jsonl.gz"

    cmd = [
        args.routinator_bin,
        "vrps",
        "--format",
        "jsonext",
        "--output",
        str(raw_json),
    ]

    if not args.allow_update:
        cmd.insert(2, "--noupdate")

    t0 = time.time()
    proc = subprocess.run(
        cmd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    latency_ms = int((time.time() - t0) * 1000)
    collection_finished_at = utc_now_iso()

    (log_dir / "routinator_jsonext.stdout.log").write_text(proc.stdout or "", encoding="utf-8")
    (log_dir / "routinator_jsonext.stderr.log").write_text(proc.stderr or "", encoding="utf-8")
    (log_dir / "routinator_jsonext.cmd.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")

    export_status = "success" if proc.returncode == 0 and raw_json.exists() and raw_json.stat().st_size > 0 else "failed"

    index_stats = {}
    if export_status == "success":
        index_stats = build_indexes(raw_json, tuple_index_gz, provenance_index_gz)
        gzip_file(raw_json, raw_json_gz)
        raw_size_bytes = raw_json.stat().st_size
        raw_json.unlink()
    else:
        raw_size_bytes = raw_json.stat().st_size if raw_json.exists() else 0

    summary = {
        "schema": "s3.m21b.probe_jsonext_joint_snapshot_summary.v1",
        "status": "PASS" if export_status == "success" else "FAIL",
        "probe_id": probe_id,
        "run_id": run_id,
        "target_utc": target_utc,
        "created_at_utc": utc_now_iso(),

        "started_wait_at_utc": started_wait_at,
        "collection_started_at_utc": collection_started_at,
        "collection_finished_at_utc": collection_finished_at,
        "latency_ms": latency_ms,

        "validator_id": "routinator",
        "format": "jsonext",
        "cli_export_policy": "allow_update" if args.allow_update else "noupdate",
        "export_status": export_status,
        "returncode": proc.returncode,

        "raw_json_gz": str(raw_json_gz) if raw_json_gz.exists() else None,
        "raw_json_gz_size_bytes": raw_json_gz.stat().st_size if raw_json_gz.exists() else 0,
        "raw_size_bytes": raw_size_bytes,
        "tuple_index_gz": str(tuple_index_gz),
        "provenance_index_gz": str(provenance_index_gz),

        "index_stats": index_stats,

        "warnings": [],
        "errors": [] if export_status == "success" else [proc.stderr[-1000:]],
    }

    write_json(out_dir / "M21B_probe_jsonext_joint_snapshot_summary.json", summary)

    check_text = "\n".join([
        "M21B_PROBE_JSONEXT_JOINT_SNAPSHOT=PASS" if export_status == "success" else "M21B_PROBE_JSONEXT_JOINT_SNAPSHOT=FAIL",
        "",
        f"probe_id = {probe_id}",
        f"run_id = {run_id}",
        f"target_utc = {target_utc}",
        f"collection_started_at_utc = {collection_started_at}",
        f"collection_finished_at_utc = {collection_finished_at}",
        f"latency_ms = {latency_ms}",
        f"cli_export_policy = {summary['cli_export_policy']}",
        f"export_status = {export_status}",
        f"jsonext_roa_record_count = {index_stats.get('jsonext_roa_record_count')}",
        f"tuple_unique_count = {index_stats.get('tuple_unique_count')}",
        f"provenance_row_count = {index_stats.get('provenance_row_count')}",
        f"by_ta = {index_stats.get('by_ta')}",
        f"summary_path = {out_dir / 'M21B_probe_jsonext_joint_snapshot_summary.json'}",
        f"raw_json_gz = {raw_json_gz}",
        f"tuple_index_gz = {tuple_index_gz}",
        f"provenance_index_gz = {provenance_index_gz}",
    ]) + "\n"

    (chk_dir / "M21B_probe_jsonext_joint_snapshot_check.txt").write_text(check_text, encoding="utf-8")
    print(check_text)

    latest_dir = out_root / "latest"
    latest_dir.mkdir(parents=True, exist_ok=True)
    write_json(latest_dir / "M21B_probe_jsonext_joint_snapshot_summary.json", summary)

    exports_dir = out_root / "exports"
    archive_path = exports_dir / f"{run_id}.tar.gz"
    make_archive(run_dir, archive_path)

    print(f"archive_path = {archive_path}")
    print(f"archive_sha256 = {archive_path}.sha256")

    return 0 if export_status == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
