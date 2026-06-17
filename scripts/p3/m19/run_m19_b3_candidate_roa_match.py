#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, Counter


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


def norm_asn(s) -> str:
    if s is None:
        return ""
    x = str(s).strip()
    if not x:
        return ""
    if x.upper().startswith("AS"):
        return "AS" + x[2:]
    return "AS" + x


def norm_key(afi, tal, prefix, asn, maxlen):
    return (
        str(afi or "").lower(),
        str(tal or "").lower(),
        str(prefix or ""),
        norm_asn(asn),
        str(maxlen if maxlen is not None else ""),
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-jsonl", required=True)
    ap.add_argument("--roa-index", required=True)
    ap.add_argument("--source-uri-diag", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    seed_path = Path(args.seed_jsonl)
    roa_index_path = Path(args.roa_index)
    source_diag_path = Path(args.source_uri_diag)
    out_dir = Path(args.out_dir)
    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)

    records_path = outputs / "m19_roa_candidate_match_records.jsonl"
    summary_path = outputs / "m19_roa_candidate_match_summary.json"
    check_path = checks / "M19_B3_ROA_MATCH_CHECK.txt"

    roa_by_key = defaultdict(list)
    counters = Counter()

    for _, r in iter_jsonl(roa_index_path):
        if not isinstance(r, dict) or r.get("_parse_error"):
            counters["roa_index_parse_error"] += 1
            continue
        k = norm_key(r.get("afi"), r.get("tal"), r.get("prefix"), r.get("asn"), r.get("maxLength"))
        roa_by_key[k].append(r)
        counters["roa_index_records"] += 1

    source_diag = {}
    try:
        source_diag = json.loads(source_diag_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        pass

    with records_path.open("w", encoding="utf-8") as out:
        for line_no, seed in iter_jsonl(seed_path):
            if not isinstance(seed, dict) or seed.get("_parse_error"):
                counters["seed_parse_error"] += 1
                continue

            counters["input_seed_records"] += 1

            k = norm_key(seed.get("afi"), seed.get("tal"), seed.get("prefix"), seed.get("asn"), seed.get("maxLength"))
            matches = roa_by_key.get(k, [])

            if len(matches) == 1:
                status = "mapped_to_roa"
                confidence = "medium"
                failure_reason = []
                counters["mapped_to_roa"] += 1
            elif len(matches) > 1:
                status = "ambiguous_roa_candidate"
                confidence = "weak"
                failure_reason = ["multiple_roa_payload_candidates"]
                counters["ambiguous_roa_candidate"] += 1
            else:
                status = "roa_candidate_not_found"
                confidence = "none"
                failure_reason = ["roa_candidate_not_found_in_current_l2_index"]
                counters["roa_candidate_not_found"] += 1

            if source_diag.get("jsonext_required") is True:
                failure_reason.append("source_uri_missing_or_insufficient_in_raw_vrp")

            rec = {
                "schema": "s3.m19.roa_candidate_match_record.v1",
                "vrp_key": seed.get("vrp_key"),
                "afi": seed.get("afi"),
                "tal": seed.get("tal"),
                "prefix": seed.get("prefix"),
                "asn": norm_asn(seed.get("asn")),
                "maxLength": str(seed.get("maxLength")),
                "m18_context": {
                    "transient_or_persistent": seed.get("transient_or_persistent"),
                    "probe_seen_count": seed.get("probe_seen_count"),
                    "global_duration_windows": seed.get("global_duration_windows"),
                    "trailing_cache_candidate_v1": seed.get("trailing_cache_candidate_v1"),
                    "m19_mapping_priority": seed.get("m19_mapping_priority"),
                },
                "roa_candidate_count": len(matches),
                "roa_candidates": matches[:10],
                "mapping_status": status,
                "mapping_confidence": confidence,
                "failure_reason": failure_reason,
                "provenance": [
                    "m18_d7b_seed",
                    "candidate_payload_match",
                    "m245_object_index_candidate",
                ],
                "strong_causal_claim_allowed": False,
            }
            out.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")

    summary = {
        "schema": "s3.m19.b3.roa_match_summary.v1",
        "generated_at_utc": utc_now(),
        "seed_jsonl": str(seed_path),
        "roa_index": str(roa_index_path),
        "source_uri_diag": str(source_diag_path),
        "counters": dict(counters),
        "outputs": {
            "records_jsonl": str(records_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "candidate_roa_match_not_causal_attribution",
        "strong_causal_claim_allowed": False,
        "next_stage": "M19_B4_MANIFEST_PP_JOIN",
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M19_B3_ROA_MATCH=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"input_seed_records = {counters['input_seed_records']}",
        f"roa_index_records = {counters['roa_index_records']}",
        f"mapped_to_roa = {counters['mapped_to_roa']}",
        f"ambiguous_roa_candidate = {counters['ambiguous_roa_candidate']}",
        f"roa_candidate_not_found = {counters['roa_candidate_not_found']}",
        f"records_jsonl = {records_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = candidate_roa_match_not_causal_attribution",
        "strong_causal_claim_allowed = False",
        "next_stage = M19_B4_MANIFEST_PP_JOIN",
    ]
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
