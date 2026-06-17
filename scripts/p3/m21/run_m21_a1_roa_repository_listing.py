#!/usr/bin/env python3
from __future__ import annotations

import argparse
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


def rsync_list(repo_uri: str, timeout_sec: int):
    cmd = ["rsync", "--list-only", "--contimeout=10", "--timeout=20", repo_uri]
    t0 = time.time()
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_sec,
        )
        return {
            "returncode": p.returncode,
            "duration_sec": round(time.time() - t0, 3),
            "stdout": p.stdout.decode("utf-8", errors="ignore"),
            "stderr": p.stderr.decode("utf-8", errors="ignore"),
        }
    except subprocess.TimeoutExpired as e:
        return {
            "returncode": -999,
            "duration_sec": round(time.time() - t0, 3),
            "stdout": "",
            "stderr": f"timeout_expired:{e}",
        }


def parse_listing(stdout: str):
    files = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # rsync --list-only typically ends line with filename
        name = line.split()[-1]
        files.append(name)
    return files


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--m19-hint-records", required=True)
    ap.add_argument("--m20-joined-records", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--max-repos", type=int, default=20)
    ap.add_argument("--timeout-sec", type=int, default=40)
    args = ap.parse_args()

    hint_path = Path(args.m19_hint_records)
    joined_path = Path(args.m20_joined_records)
    out_dir = Path(args.out_dir)

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    logs = out_dir / "logs"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)

    records_path = outputs / "m21_a1_roa_repository_listing_records.jsonl"
    summary_path = outputs / "m21_a1_roa_repository_listing_summary.json"
    repo_summary_path = outputs / "m21_a1_repository_summary.json"
    check_path = checks / "M21_A1_ROA_REPOSITORY_LISTING_CHECK.txt"

    # Collect ROA hints from M19-B9.
    hints = []
    repo_to_records = defaultdict(list)

    for _, r in iter_jsonl(hint_path):
        if not isinstance(r, dict) or r.get("_parse_error"):
            continue
        if not r.get("roa_uri"):
            continue
        repo = r.get("repository_base_uri")
        if not repo:
            continue
        hints.append(r)
        repo_to_records[repo].append(r)

    # Enrich with M20 join status when available.
    join_by_key = {}
    for _, r in iter_jsonl(joined_path):
        if isinstance(r, dict) and not r.get("_parse_error"):
            join_by_key[r.get("vrp_key")] = r

    counters = Counter()
    repo_results = []

    with records_path.open("w", encoding="utf-8") as out:
        for repo_i, (repo, recs) in enumerate(repo_to_records.items(), 1):
            if repo_i > args.max_repos:
                break

            counters["repository_attempted"] += 1
            res = rsync_list(repo, args.timeout_sec)
            files = parse_listing(res["stdout"]) if res["returncode"] == 0 else []

            mft_files = [x for x in files if x.lower().endswith(".mft")]
            roa_files = set(x for x in files if x.lower().endswith(".roa"))

            repo_status = "list_success" if res["returncode"] == 0 else "list_failed"
            if repo_status == "list_success":
                counters["repository_list_success"] += 1
            else:
                counters["repository_list_failed"] += 1

            if mft_files:
                counters["repository_with_mft_candidate"] += 1

            repo_result = {
                "repository_base_uri": repo,
                "record_count": len(recs),
                "source_host": recs[0].get("source_host"),
                "returncode": res["returncode"],
                "duration_sec": res["duration_sec"],
                "repo_status": repo_status,
                "mft_files": mft_files,
                "mft_file_count": len(mft_files),
                "roa_file_count": len(roa_files),
                "stderr_tail": res["stderr"][-1000:],
            }
            repo_results.append(repo_result)

            for r in recs:
                roa_filename = r.get("roa_filename")
                vrp_key = r.get("vrp_key")
                joined = join_by_key.get(vrp_key, {})

                roa_seen = bool(roa_filename and roa_filename in roa_files)
                if roa_seen:
                    counters["roa_filename_seen_in_repository_listing"] += 1
                else:
                    counters["roa_filename_not_seen_in_repository_listing"] += 1

                out_rec = {
                    "schema": "s3.m21.a1.roa_repository_listing_record.v1",
                    "vrp_key": vrp_key,
                    "afi": r.get("afi"),
                    "tal": r.get("tal"),
                    "prefix": r.get("prefix"),
                    "asn": r.get("asn"),
                    "maxLength": r.get("maxLength"),

                    "roa_uri": r.get("roa_uri"),
                    "roa_filename": roa_filename,
                    "repository_base_uri": repo,
                    "source_host": r.get("source_host"),
                    "source_scheme": r.get("source_scheme"),

                    "repository_list_status": repo_status,
                    "repository_list_returncode": res["returncode"],
                    "repository_list_duration_sec": res["duration_sec"],
                    "roa_filename_seen_in_repository_listing": roa_seen,

                    "mft_candidate_files": mft_files,
                    "mft_candidate_count": len(mft_files),

                    "m20_join_status": joined.get("m20_join_status"),
                    "m20_join_confidence": joined.get("m20_join_confidence"),

                    "jsonext_generatedTime": r.get("jsonext_generatedTime"),
                    "stale": r.get("stale"),
                    "validity": r.get("validity"),
                    "chainValidity": r.get("chainValidity"),

                    "semantic_boundary": "repository_listing_not_manifest_filelist_confirmation",
                    "strong_causal_claim_allowed": False,
                }
                out.write(json.dumps(out_rec, ensure_ascii=False, sort_keys=True) + "\n")
                counters["records_written"] += 1

    repo_summary = {
        "schema": "s3.m21.a1.repository_summary.v1",
        "generated_at_utc": utc_now(),
        "repository_results": repo_results,
    }
    repo_summary_path.write_text(json.dumps(repo_summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = {
        "schema": "s3.m21.a1.roa_repository_listing_summary.v1",
        "generated_at_utc": utc_now(),
        "m19_hint_records": str(hint_path),
        "m20_joined_records": str(joined_path),
        "counters": dict(counters),
        "unique_repository_count_total": len(repo_to_records),
        "repository_attempt_limit": args.max_repos,
        "outputs": {
            "records_jsonl": str(records_path),
            "summary_json": str(summary_path),
            "repo_summary_json": str(repo_summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "repository_listing_not_manifest_filelist_confirmation",
        "strong_causal_claim_allowed": False,
        "next_stage": "M21_A2_MANIFEST_FETCH_AND_FILELIST_PARSE",
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M21_A1_ROA_REPOSITORY_LISTING=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"unique_repository_count_total = {len(repo_to_records)}",
        f"repository_attempted = {counters['repository_attempted']}",
        f"repository_list_success = {counters['repository_list_success']}",
        f"repository_list_failed = {counters['repository_list_failed']}",
        f"repository_with_mft_candidate = {counters['repository_with_mft_candidate']}",
        f"records_written = {counters['records_written']}",
        f"roa_filename_seen_in_repository_listing = {counters['roa_filename_seen_in_repository_listing']}",
        f"roa_filename_not_seen_in_repository_listing = {counters['roa_filename_not_seen_in_repository_listing']}",
        f"records_jsonl = {records_path}",
        f"summary_json = {summary_path}",
        f"repo_summary_json = {repo_summary_path}",
        "semantic_boundary = repository_listing_not_manifest_filelist_confirmation",
        "strong_causal_claim_allowed = False",
        "next_stage = M21_A2_MANIFEST_FETCH_AND_FILELIST_PARSE",
    ]
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
