#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter


REQUIRED_FIELDS = [
    "vrp_key",
    "afi",
    "tal",
    "prefix",
    "asn",
    "maxLength",
    "transient_or_persistent",
    "m19_mapping_priority",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iter_jsonl(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield line_no, json.loads(line)
            except Exception as e:
                yield line_no, {"_parse_error": str(e), "_raw": line[:300]}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-top200", required=True)
    ap.add_argument("--seed-top1000", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    seed_top200 = Path(args.seed_top200)
    seed_top1000 = Path(args.seed_top1000)
    out_dir = Path(args.out_dir)
    check_dir = out_dir / "checks"
    outputs_dir = out_dir / "outputs"
    check_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    result = {
        "schema": "s3.m19.seed_precheck.v1",
        "generated_at_utc": utc_now(),
        "seed_top200": str(seed_top200),
        "seed_top1000": str(seed_top1000),
        "semantic_boundary": "candidate_level_not_causal_attribution",
        "strong_causal_claim_allowed": False,
        "files": {},
    }

    blockers = []

    for label, path in [("top200", seed_top200), ("top1000", seed_top1000)]:
        counters = Counter()
        missing_examples = []
        parse_errors = []
        sample = []

        tal_counter = Counter()
        afi_counter = Counter()
        asn_counter = Counter()
        class_counter = Counter()

        for line_no, rec in iter_jsonl(path):
            if "_parse_error" in rec:
                counters["parse_error"] += 1
                parse_errors.append({"line_no": line_no, "error": rec["_parse_error"]})
                continue

            counters["record_count"] += 1

            missing = [k for k in REQUIRED_FIELDS if not rec.get(k)]
            if missing:
                counters["missing_required_field_record_count"] += 1
                if len(missing_examples) < 20:
                    missing_examples.append({
                        "line_no": line_no,
                        "missing": missing,
                        "record": rec,
                    })

            tal_counter[str(rec.get("tal") or "unknown")] += 1
            afi_counter[str(rec.get("afi") or "unknown")] += 1
            asn_counter[str(rec.get("asn") or "unknown")] += 1
            class_counter[str(rec.get("transient_or_persistent") or "unknown")] += 1

            if len(sample) < 5:
                sample.append(rec)

        file_result = {
            "path": str(path),
            "exists": path.exists(),
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "counters": dict(counters),
            "tal_top20": tal_counter.most_common(20),
            "afi_counts": dict(afi_counter),
            "asn_top20": asn_counter.most_common(20),
            "classification_counts": dict(class_counter),
            "missing_examples": missing_examples,
            "parse_errors": parse_errors[:20],
            "sample": sample,
        }

        result["files"][label] = file_result

        if not path.exists():
            blockers.append(f"{label}_file_missing")
        if counters["record_count"] == 0:
            blockers.append(f"{label}_record_count_zero")
        if counters["parse_error"] > 0:
            blockers.append(f"{label}_parse_errors")
        if counters["missing_required_field_record_count"] > 0:
            blockers.append(f"{label}_missing_required_fields")

    result["blockers"] = blockers
    result["status"] = "PASS" if not blockers else "FAIL"
    result["next_stage"] = "M19_BATCH_1_SOURCE_URI_AND_MAPPING_FEASIBILITY_DIAG" if not blockers else "FIX_M19_SEED_INPUT"

    summary_path = outputs_dir / "m19_seed_precheck_summary.json"
    summary_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    check_path = check_dir / "M19_SEED_PRECHECK.txt"
    lines = [
        f"M19_SEED_PRECHECK={result['status']}",
        f"generated_at_utc = {result['generated_at_utc']}",
        f"seed_top200 = {seed_top200}",
        f"seed_top1000 = {seed_top1000}",
        f"top200_record_count = {result['files']['top200']['counters'].get('record_count', 0)}",
        f"top1000_record_count = {result['files']['top1000']['counters'].get('record_count', 0)}",
        f"top200_afi_counts = {result['files']['top200']['afi_counts']}",
        f"top1000_afi_counts = {result['files']['top1000']['afi_counts']}",
        f"top200_tal_top20 = {result['files']['top200']['tal_top20']}",
        f"top1000_tal_top20 = {result['files']['top1000']['tal_top20']}",
        f"blockers = {blockers}",
        f"summary_json = {summary_path}",
        "semantic_boundary = candidate_level_not_causal_attribution",
        "strong_causal_claim_allowed = False",
        f"next_stage = {result['next_stage']}",
    ]
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state_path = Path("data/p3_collector/m19_roa_to_vrp/state/current_m19_precheck.env")
    state_path.write_text(
        "\n".join([
            f'export M19_PRECHECK_DIR="{out_dir}"',
            f'export M19_PRECHECK_CHECK="{check_path}"',
            f'export M19_PRECHECK_SUMMARY="{summary_path}"',
            f'export M19_SEED_TOP200="{seed_top200}"',
            f'export M19_SEED_TOP1000="{seed_top1000}"',
            "",
        ]),
        encoding="utf-8",
    )

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
