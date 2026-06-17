#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import tarfile
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
from typing import Any


SOURCE_KEYS = [
    "source_uri", "sourceUri", "source", "uri", "roa_uri", "roaUri",
    "object_uri", "objectUri", "certificate_uri", "rpki_uri",
]


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


def find_source_like(obj: Any) -> list[dict[str, Any]]:
    hits = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            lk = str(k).lower()
            if any(s.lower() == lk for s in SOURCE_KEYS) or ("uri" in lk and isinstance(v, str)):
                if isinstance(v, str) and v.strip():
                    hits.append({"key": k, "value": v.strip()})

            if isinstance(v, (dict, list)):
                hits.extend(find_source_like(v))

    elif isinstance(obj, list):
        for x in obj:
            hits.extend(find_source_like(x))

    return hits


def sample_raw_sidecar(raw_sidecar_incoming: Path, max_files: int = 20, max_records_per_file: int = 1000) -> dict[str, Any]:
    result = {
        "raw_file_count_scanned": 0,
        "raw_record_sample_count": 0,
        "raw_source_like_record_count": 0,
        "raw_top_level_keys": Counter(),
        "raw_root_keys": Counter(),
        "raw_scans": [],
    }

    tar_files = sorted(raw_sidecar_incoming.glob("*/*raw_vrp_sidecar.tar.gz"))[-max_files:]

    for tar_path in tar_files:
        scan = {
            "path": str(tar_path),
            "members": [],
        }

        try:
            with tarfile.open(tar_path, "r:*") as tf:
                members = [m for m in tf.getmembers() if m.isfile() and m.name.endswith(".json")]
                for m in members:
                    if "raw_vrp" not in m.name and "manifest" not in m.name:
                        continue

                    entry = {"member": m.name, "parse_status": "unknown"}
                    f = tf.extractfile(m)
                    if f is None:
                        entry["parse_status"] = "extract_failed"
                        scan["members"].append(entry)
                        continue

                    try:
                        obj = json.loads(f.read().decode("utf-8", errors="ignore"))
                    except Exception as e:
                        entry["parse_status"] = f"json_failed:{e}"
                        scan["members"].append(entry)
                        continue

                    entry["parse_status"] = "ok"
                    if isinstance(obj, dict):
                        root_keys = sorted(obj.keys())
                        entry["root_keys"] = root_keys
                        for k in root_keys:
                            result["raw_root_keys"][k] += 1

                        roas = obj.get("roas")
                        if isinstance(roas, list):
                            n = 0
                            src_count = 0
                            key_counter = Counter()

                            for r in roas[:max_records_per_file]:
                                if not isinstance(r, dict):
                                    continue
                                n += 1
                                for k in r.keys():
                                    key_counter[k] += 1
                                    result["raw_top_level_keys"][k] += 1
                                if find_source_like(r):
                                    src_count += 1

                            entry["record_sample_count"] = n
                            entry["source_like_record_count"] = src_count
                            entry["top_level_keys"] = key_counter.most_common(20)
                            result["raw_record_sample_count"] += n
                            result["raw_source_like_record_count"] += src_count

                    scan["members"].append(entry)
        except Exception as e:
            scan["error"] = str(e)

        result["raw_file_count_scanned"] += 1
        result["raw_scans"].append(scan)

    result["raw_top_level_keys"] = result["raw_top_level_keys"].most_common(50)
    result["raw_root_keys"] = result["raw_root_keys"].most_common(50)
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-jsonl", required=True)
    ap.add_argument("--m17-root", required=True)
    ap.add_argument("--m245-root", required=True)
    ap.add_argument("--raw-sidecar-incoming", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    seed_path = Path(args.seed_jsonl)
    raw_sidecar_incoming = Path(args.raw_sidecar_incoming)
    out_dir = Path(args.out_dir)
    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)

    counters = Counter()
    seed_records = []
    seed_source_examples = []

    for line_no, rec in iter_jsonl(seed_path):
        if "_parse_error" in rec:
            counters["seed_parse_error"] += 1
            continue

        counters["input_count"] += 1
        seed_records.append(rec)

        hits = find_source_like(rec)
        if hits:
            counters["seed_source_like_record_count"] += 1
            if len(seed_source_examples) < 20:
                seed_source_examples.append({
                    "line_no": line_no,
                    "vrp_key": rec.get("vrp_key"),
                    "hits": hits[:10],
                })

    raw_scan = sample_raw_sidecar(raw_sidecar_incoming)

    source_uri_found_count = counters["seed_source_like_record_count"] + raw_scan["raw_source_like_record_count"]
    source_uri_missing_count = counters["input_count"] - counters["seed_source_like_record_count"]

    result = {
        "schema": "s3.m19.b1.source_uri_diag.v1",
        "generated_at_utc": utc_now(),
        "seed_jsonl": str(seed_path),
        "input_count": counters["input_count"],
        "seed_source_like_record_count": counters["seed_source_like_record_count"],
        "source_uri_found_count": source_uri_found_count,
        "source_uri_missing_count": source_uri_missing_count,
        "raw_scan": raw_scan,
        "seed_source_examples": seed_source_examples,
        "diagnosis": "raw_vrp_source_uri_missing_or_insufficient" if source_uri_found_count == 0 else "source_like_field_observed",
        "jsonext_required": source_uri_found_count == 0,
        "semantic_boundary": "source_uri_availability_diagnosis_not_mapping",
        "strong_causal_claim_allowed": False,
        "next_stage": "M19_B2_OBJECT_INDEX_BUILD",
    }

    summary_json = outputs / "m19_source_uri_diag.json"
    summary_md = outputs / "m19_source_uri_diag.md"
    check_txt = checks / "M19_B1_SOURCE_URI_DIAG_CHECK.txt"

    summary_json.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary_md.write_text(
        "\n".join([
            "# M19 B1 Source URI Diagnosis",
            "",
            f"- input_count: `{result['input_count']}`",
            f"- seed_source_like_record_count: `{result['seed_source_like_record_count']}`",
            f"- raw_source_like_record_count: `{raw_scan['raw_source_like_record_count']}`",
            f"- diagnosis: `{result['diagnosis']}`",
            f"- jsonext_required: `{result['jsonext_required']}`",
            "",
        ]) + "\n",
        encoding="utf-8",
    )

    lines = [
        "M19_B1_SOURCE_URI_DIAG=PASS",
        f"generated_at_utc = {result['generated_at_utc']}",
        f"input_count = {result['input_count']}",
        f"seed_source_like_record_count = {result['seed_source_like_record_count']}",
        f"raw_source_like_record_count = {raw_scan['raw_source_like_record_count']}",
        f"raw_record_sample_count = {raw_scan['raw_record_sample_count']}",
        f"raw_file_count_scanned = {raw_scan['raw_file_count_scanned']}",
        f"diagnosis = {result['diagnosis']}",
        f"jsonext_required = {result['jsonext_required']}",
        f"summary_json = {summary_json}",
        f"summary_md = {summary_md}",
        "semantic_boundary = source_uri_availability_diagnosis_not_mapping",
        "strong_causal_claim_allowed = False",
        "next_stage = M19_B2_OBJECT_INDEX_BUILD",
    ]

    check_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(check_txt.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
