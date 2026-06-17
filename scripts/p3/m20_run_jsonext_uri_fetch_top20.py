#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def safe_name(uri: str) -> str:
    return hashlib.sha256(uri.encode()).hexdigest()[:16]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets-jsonl", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--timeout-sec", type=int, default=30)
    args = ap.parse_args()

    targets = Path(args.targets_jsonl)
    out_dir = Path(args.out_dir)
    fetch_dir = out_dir / "fetches"
    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    logs = out_dir / "logs"

    fetch_dir.mkdir(parents=True, exist_ok=True)
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)

    records_path = outputs / "m20_jsonext_uri_fetch_records.jsonl"
    summary_path = outputs / "m20_jsonext_uri_fetch_summary.json"
    check_path = checks / "M20_B1_JSONEXT_URI_FETCH_CHECK.txt"

    counters = {
        "input_targets": 0,
        "fetch_success": 0,
        "fetch_failed": 0,
        "unsupported_scheme": 0,
    }

    with records_path.open("w", encoding="utf-8") as out:
        for r in iter_jsonl(targets):
            counters["input_targets"] += 1

            uri = r.get("fetch_target_uri")
            parsed = urlparse(uri or "")
            item_dir = fetch_dir / safe_name(uri or f"missing-{counters['input_targets']}")
            item_dir.mkdir(parents=True, exist_ok=True)

            meta = {
                "schema": "s3.m20.jsonext_uri_fetch_record.v1",
                "created_at_utc": utc_now(),
                "vrp_key": r.get("vrp_key"),
                "fetch_target_uri": uri,
                "source_scheme": parsed.scheme,
                "source_host": parsed.netloc,
                "target_dir": str(item_dir),
                "fetch_status": None,
                "returncode": None,
                "duration_sec": None,
                "stdout_path": str(item_dir / "rsync.stdout"),
                "stderr_path": str(item_dir / "rsync.stderr"),
                "local_object_path": str(item_dir / "object.roa"),
                "semantic_boundary": "late_targeted_fetch_not_same_window_input",
                "strong_causal_claim_allowed": False,
            }

            if parsed.scheme != "rsync":
                counters["unsupported_scheme"] += 1
                meta["fetch_status"] = "unsupported_scheme"
                out.write(json.dumps(meta, ensure_ascii=False, sort_keys=True) + "\n")
                continue

            cmd = ["rsync", "-av", "--contimeout=10", "--timeout=20", uri, str(item_dir / "object.roa")]
            t0 = time.time()

            with open(item_dir / "rsync.stdout", "wb") as so, open(item_dir / "rsync.stderr", "wb") as se:
                try:
                    proc = subprocess.run(cmd, stdout=so, stderr=se, timeout=args.timeout_sec)
                    meta["returncode"] = proc.returncode
                except subprocess.TimeoutExpired:
                    meta["returncode"] = -999
                    meta["fetch_status"] = "timeout"

            meta["duration_sec"] = round(time.time() - t0, 3)

            obj_path = item_dir / "object.roa"
            if meta["returncode"] == 0 and obj_path.exists() and obj_path.stat().st_size > 0:
                counters["fetch_success"] += 1
                meta["fetch_status"] = "success"
                meta["object_size_bytes"] = obj_path.stat().st_size
                meta["object_sha256"] = hashlib.sha256(obj_path.read_bytes()).hexdigest()
            else:
                counters["fetch_failed"] += 1
                if not meta["fetch_status"]:
                    meta["fetch_status"] = "failed"

            out.write(json.dumps(meta, ensure_ascii=False, sort_keys=True) + "\n")

    summary = {
        "schema": "s3.m20.jsonext_uri_fetch_summary.v1",
        "generated_at_utc": utc_now(),
        "targets_jsonl": str(targets),
        "counters": counters,
        "outputs": {
            "records_jsonl": str(records_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "late_targeted_fetch_not_same_window_input",
        "strong_causal_claim_allowed": False,
        "next_stage": "M20_B2_BACKFILLED_OBJECT_INDEX_OR_FETCH_FAILURE_ANALYSIS",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M20_B1_JSONEXT_URI_FETCH=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"input_targets = {counters['input_targets']}",
        f"fetch_success = {counters['fetch_success']}",
        f"fetch_failed = {counters['fetch_failed']}",
        f"unsupported_scheme = {counters['unsupported_scheme']}",
        f"records_jsonl = {records_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = late_targeted_fetch_not_same_window_input",
        "strong_causal_claim_allowed = False",
        "next_stage = M20_B2_BACKFILLED_OBJECT_INDEX_OR_FETCH_FAILURE_ANALYSIS",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
