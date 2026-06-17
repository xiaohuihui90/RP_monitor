#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield line_no, json.loads(line)
            except Exception as e:
                yield line_no, {"_parse_error": str(e), "_raw": line[:300]}


def safe_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_rsync(uri: str, dst: Path, timeout_sec: int):
    dst.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["rsync", "-av", "--contimeout=10", "--timeout=20", uri, str(dst)]
    stdout_path = dst.parent / "rsync.stdout"
    stderr_path = dst.parent / "rsync.stderr"
    t0 = time.time()

    with stdout_path.open("wb") as so, stderr_path.open("wb") as se:
        try:
            p = subprocess.run(cmd, stdout=so, stderr=se, timeout=timeout_sec)
            rc = p.returncode
            status = "success" if rc == 0 and dst.exists() and dst.stat().st_size > 0 else "failed"
        except subprocess.TimeoutExpired:
            rc = -999
            status = "timeout"

    duration = round(time.time() - t0, 3)
    stderr_tail = ""
    if stderr_path.exists():
        stderr_tail = stderr_path.read_text(encoding="utf-8", errors="ignore")[-1000:]

    return {
        "returncode": rc,
        "fetch_status": status,
        "duration_sec": duration,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stderr_tail": stderr_tail,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--a1-records", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--timeout-sec", type=int, default=40)
    args = ap.parse_args()

    a1_records = Path(args.a1_records)
    out_dir = Path(args.out_dir)

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    fetches = out_dir / "fetches" / "manifests"
    indexes = out_dir / "indexes"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)
    fetches.mkdir(parents=True, exist_ok=True)
    indexes.mkdir(parents=True, exist_ok=True)

    fetch_records_path = outputs / "m21_a2_manifest_fetch_records.jsonl"
    roa_to_manifest_candidate_path = outputs / "m21_a2_roa_to_manifest_candidate_records.jsonl"
    manifest_index_path = indexes / "m21_a2_manifest_object_index.jsonl"
    summary_path = outputs / "m21_a2_manifest_fetch_summary.json"
    check_path = checks / "M21_A2_MANIFEST_FETCH_CHECK.txt"

    # mft_uri -> related A1 records
    manifest_to_records = defaultdict(list)

    for _, rec in iter_jsonl(a1_records):
        if not isinstance(rec, dict) or rec.get("_parse_error"):
            continue
        repo = rec.get("repository_base_uri")
        mft_files = rec.get("mft_candidate_files") or []
        if not repo or not mft_files:
            continue
        if rec.get("repository_list_status") != "list_success":
            continue

        for mft in mft_files:
            if not str(mft).endswith(".mft"):
                continue
            mft_uri = repo + mft
            manifest_to_records[mft_uri].append(rec)

    counters = Counter()

    with fetch_records_path.open("w", encoding="utf-8") as fetch_out, \
         roa_to_manifest_candidate_path.open("w", encoding="utf-8") as cand_out, \
         manifest_index_path.open("w", encoding="utf-8") as idx_out:

        for mft_uri, recs in sorted(manifest_to_records.items()):
            counters["manifest_candidate_unique"] += 1
            item_dir = fetches / safe_hash(mft_uri)
            local_mft = item_dir / "manifest.mft"

            res = fetch_rsync(mft_uri, local_mft, args.timeout_sec)
            status = res["fetch_status"]

            if status == "success":
                counters["manifest_fetch_success"] += 1
                object_sha256 = sha256_file(local_mft)
                object_size = local_mft.stat().st_size
            else:
                counters["manifest_fetch_failed"] += 1
                object_sha256 = None
                object_size = None

            first = recs[0]
            fetch_rec = {
                "schema": "s3.m21.a2.manifest_fetch_record.v1",
                "manifest_uri": mft_uri,
                "mft_filename": mft_uri.rsplit("/", 1)[-1],
                "repository_base_uri": first.get("repository_base_uri"),
                "source_host": first.get("source_host"),
                "source_scheme": first.get("source_scheme"),
                "related_vrp_count": len(recs),
                "related_roa_filename_seen_count": sum(1 for r in recs if r.get("roa_filename_seen_in_repository_listing")),
                "fetch_status": status,
                "returncode": res["returncode"],
                "duration_sec": res["duration_sec"],
                "local_manifest_path": str(local_mft) if status == "success" else None,
                "object_sha256": object_sha256,
                "object_size_bytes": object_size,
                "stderr_tail": res["stderr_tail"],
                "semantic_boundary": "manifest_object_fetched_late_not_same_window_input",
                "strong_causal_claim_allowed": False,
            }
            fetch_out.write(json.dumps(fetch_rec, ensure_ascii=False, sort_keys=True) + "\n")

            if status == "success":
                idx_out.write(json.dumps(fetch_rec, ensure_ascii=False, sort_keys=True) + "\n")

            for r in recs:
                cand = {
                    "schema": "s3.m21.a2.roa_to_manifest_candidate_record.v1",
                    "vrp_key": r.get("vrp_key"),
                    "afi": r.get("afi"),
                    "tal": r.get("tal"),
                    "prefix": r.get("prefix"),
                    "asn": r.get("asn"),
                    "maxLength": r.get("maxLength"),
                    "roa_uri": r.get("roa_uri"),
                    "roa_filename": r.get("roa_filename"),
                    "roa_filename_seen_in_repository_listing": r.get("roa_filename_seen_in_repository_listing"),
                    "manifest_uri": mft_uri,
                    "manifest_fetch_status": status,
                    "local_manifest_path": str(local_mft) if status == "success" else None,
                    "manifest_object_sha256": object_sha256,
                    "repository_base_uri": r.get("repository_base_uri"),
                    "source_host": r.get("source_host"),
                    "m20_join_status": r.get("m20_join_status"),
                    "jsonext_generatedTime": r.get("jsonext_generatedTime"),
                    "stale": r.get("stale"),
                    "validity": r.get("validity"),
                    "chainValidity": r.get("chainValidity"),
                    "semantic_boundary": "manifest_candidate_not_filelist_confirmation",
                    "strong_causal_claim_allowed": False,
                }
                cand_out.write(json.dumps(cand, ensure_ascii=False, sort_keys=True) + "\n")
                counters["roa_to_manifest_candidate_records_written"] += 1

    summary = {
        "schema": "s3.m21.a2.manifest_fetch_summary.v1",
        "generated_at_utc": utc_now(),
        "a1_records": str(a1_records),
        "counters": dict(counters),
        "outputs": {
            "manifest_fetch_records": str(fetch_records_path),
            "roa_to_manifest_candidate_records": str(roa_to_manifest_candidate_path),
            "manifest_object_index": str(manifest_index_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "manifest_fetched_but_filelist_not_yet_parsed",
        "strong_causal_claim_allowed": False,
        "next_stage": "M21_A3_MANIFEST_FILELIST_PARSE_AND_ROA_MATCH",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M21_A2_MANIFEST_FETCH=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"manifest_candidate_unique = {counters['manifest_candidate_unique']}",
        f"manifest_fetch_success = {counters['manifest_fetch_success']}",
        f"manifest_fetch_failed = {counters['manifest_fetch_failed']}",
        f"roa_to_manifest_candidate_records_written = {counters['roa_to_manifest_candidate_records_written']}",
        f"manifest_fetch_records = {fetch_records_path}",
        f"roa_to_manifest_candidate_records = {roa_to_manifest_candidate_path}",
        f"manifest_object_index = {manifest_index_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = manifest_fetched_but_filelist_not_yet_parsed",
        "strong_causal_claim_allowed = False",
        "next_stage = M21_A3_MANIFEST_FILELIST_PARSE_AND_ROA_MATCH",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
