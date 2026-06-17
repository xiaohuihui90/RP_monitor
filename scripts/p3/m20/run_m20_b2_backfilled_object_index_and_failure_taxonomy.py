#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
from typing import Any


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


def classify_failure(record: dict[str, Any]) -> str:
    status = record.get("fetch_status")
    rc = record.get("returncode")
    stderr_path = record.get("stderr_path")

    stderr = ""
    if stderr_path:
        p = Path(stderr_path)
        if p.exists():
            stderr = p.read_text(encoding="utf-8", errors="ignore").lower()

    if status == "success":
        return "success"

    if rc == -999 or "timeout" in stderr:
        return "timeout"

    if rc == 35:
        return "rsync_connection_or_timeout_failure"

    if "connection refused" in stderr:
        return "connection_refused"

    if "no route to host" in stderr:
        return "no_route_to_host"

    if "name or service not known" in stderr or "temporary failure in name resolution" in stderr:
        return "dns_resolution_failure"

    if "permission denied" in stderr:
        return "permission_denied"

    if "not found" in stderr or "no such file" in stderr:
        return "object_not_found"

    if rc not in [0, None]:
        return f"rsync_returncode_{rc}"

    return "unknown_failure"


def sha256_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_tail(path_text: str | None, n: int = 1000) -> str:
    if not path_text:
        return ""
    p = Path(path_text)
    if not p.exists():
        return ""
    text = p.read_text(encoding="utf-8", errors="ignore")
    return text[-n:]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fetch-records", required=True)
    ap.add_argument("--targets-jsonl", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    fetch_records_path = Path(args.fetch_records)
    targets_path = Path(args.targets_jsonl)
    out_dir = Path(args.out_dir)

    indexes = out_dir / "indexes"
    outputs = out_dir / "outputs"
    checks = out_dir / "checks"

    indexes.mkdir(parents=True, exist_ok=True)
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)

    roa_index_path = indexes / "m20_backfilled_roa_object_index.jsonl"
    failure_records_path = outputs / "m20_fetch_failure_taxonomy_records.jsonl"
    summary_path = outputs / "m20_b2_backfilled_object_index_summary.json"
    check_path = checks / "M20_B2_BACKFILLED_OBJECT_INDEX_CHECK.txt"

    targets_by_key = {}
    for _, t in iter_jsonl(targets_path):
        if isinstance(t, dict) and not t.get("_parse_error"):
            targets_by_key[t.get("vrp_key")] = t

    counters = Counter()
    host_status = Counter()
    host_failure_class = Counter()

    with roa_index_path.open("w", encoding="utf-8") as roa_out, \
         failure_records_path.open("w", encoding="utf-8") as fail_out:

        for _, r in iter_jsonl(fetch_records_path):
            if not isinstance(r, dict) or r.get("_parse_error"):
                counters["parse_error"] += 1
                continue

            counters["fetch_record_count"] += 1

            vrp_key = r.get("vrp_key")
            target = targets_by_key.get(vrp_key, {})
            host = r.get("source_host") or target.get("source_host") or "unknown"
            status = r.get("fetch_status") or "unknown"
            failure_class = classify_failure(r)

            host_status[f"{host}|{status}"] += 1
            host_failure_class[f"{host}|{failure_class}"] += 1
            counters[f"fetch_status_{status}"] += 1
            counters[f"failure_class_{failure_class}"] += 1

            local_obj = Path(r.get("local_object_path") or "")
            if status == "success" and local_obj.exists() and local_obj.stat().st_size > 0:
                object_sha256 = sha256_file(local_obj)
                idx = {
                    "schema": "s3.m20.backfilled_roa_object_index.v1",
                    "vrp_key": vrp_key,
                    "afi": target.get("afi"),
                    "tal": target.get("tal"),
                    "prefix": target.get("prefix"),
                    "asn": target.get("asn"),
                    "maxLength": target.get("maxLength"),

                    "source_uri": r.get("fetch_target_uri"),
                    "roa_uri": r.get("fetch_target_uri"),
                    "repository_base_uri": target.get("repository_base_uri"),
                    "source_host": host,
                    "source_scheme": r.get("source_scheme"),

                    "local_object_path": str(local_obj),
                    "object_size_bytes": local_obj.stat().st_size,
                    "object_sha256": object_sha256,

                    "fetch_duration_sec": r.get("duration_sec"),
                    "fetch_status": status,
                    "fetch_returncode": r.get("returncode"),

                    "validity": target.get("validity"),
                    "chainValidity": target.get("chainValidity"),
                    "stale": target.get("stale"),
                    "jsonext_generatedTime": target.get("jsonext_generatedTime"),

                    "semantic_boundary": "late_backfilled_object_not_same_window_input",
                    "strong_causal_claim_allowed": False,
                }
                roa_out.write(json.dumps(idx, ensure_ascii=False, sort_keys=True) + "\n")
                counters["backfilled_roa_object_count"] += 1
            else:
                fail = {
                    "schema": "s3.m20.fetch_failure_taxonomy_record.v1",
                    "vrp_key": vrp_key,
                    "afi": target.get("afi"),
                    "tal": target.get("tal"),
                    "prefix": target.get("prefix"),
                    "asn": target.get("asn"),
                    "maxLength": target.get("maxLength"),

                    "fetch_target_uri": r.get("fetch_target_uri"),
                    "repository_base_uri": target.get("repository_base_uri"),
                    "source_host": host,
                    "source_scheme": r.get("source_scheme"),

                    "fetch_status": status,
                    "returncode": r.get("returncode"),
                    "duration_sec": r.get("duration_sec"),
                    "failure_class": failure_class,

                    "stderr_path": r.get("stderr_path"),
                    "stderr_tail": read_tail(r.get("stderr_path"), 1000),

                    "semantic_boundary": "late_targeted_fetch_failure_not_same_window_input",
                    "strong_causal_claim_allowed": False,
                }
                fail_out.write(json.dumps(fail, ensure_ascii=False, sort_keys=True) + "\n")
                counters["fetch_failure_record_count"] += 1

    summary = {
        "schema": "s3.m20.b2.backfilled_object_index_summary.v1",
        "generated_at_utc": utc_now(),
        "fetch_records": str(fetch_records_path),
        "targets_jsonl": str(targets_path),
        "counters": dict(counters),
        "host_status": host_status.most_common(),
        "host_failure_class": host_failure_class.most_common(),
        "outputs": {
            "backfilled_roa_index": str(roa_index_path),
            "failure_taxonomy_records": str(failure_records_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "late_backfilled_object_not_same_window_input",
        "strong_causal_claim_allowed": False,
        "next_stage": "M20_B3_JOIN_BACKFILLED_OBJECTS_OR_FETCH_FAILURE_ANALYSIS",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M20_B2_BACKFILLED_OBJECT_INDEX=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"fetch_record_count = {counters['fetch_record_count']}",
        f"backfilled_roa_object_count = {counters['backfilled_roa_object_count']}",
        f"fetch_failure_record_count = {counters['fetch_failure_record_count']}",
        f"fetch_status_success = {counters['fetch_status_success']}",
        f"fetch_status_failed = {counters['fetch_status_failed']}",
        f"failure_class_rsync_connection_or_timeout_failure = {counters['failure_class_rsync_connection_or_timeout_failure']}",
        f"backfilled_roa_index = {roa_index_path}",
        f"failure_taxonomy_records = {failure_records_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = late_backfilled_object_not_same_window_input",
        "strong_causal_claim_allowed = False",
        "next_stage = M20_B3_JOIN_BACKFILLED_OBJECTS_OR_FETCH_FAILURE_ANALYSIS",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state_path = Path("data/p3_collector/m20_targeted_backfill/state/current_m20_b2_run.env")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        "\n".join([
            f'export M20_B2_OUT_DIR="{out_dir}"',
            f'export M20_B2_BACKFILLED_ROA_INDEX="{roa_index_path}"',
            f'export M20_B2_FAILURE_RECORDS="{failure_records_path}"',
            f'export M20_B2_SUMMARY="{summary_path}"',
            f'export M20_B2_CHECK="{check_path}"',
            "",
        ]),
        encoding="utf-8",
    )

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
