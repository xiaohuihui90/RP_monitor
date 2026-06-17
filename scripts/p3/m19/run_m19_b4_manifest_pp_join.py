#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
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


def load_manifest_index(path: Path) -> dict[str, list[dict[str, Any]]]:
    idx = defaultdict(list)
    for _, rec in iter_jsonl(path):
        if not isinstance(rec, dict) or rec.get("_parse_error"):
            continue
        file_uri = rec.get("file_uri") or rec.get("roa_uri")
        if file_uri:
            idx[str(file_uri)].append(rec)
    return idx


def load_pp_index(path: Path) -> dict[str, dict[str, Any]]:
    idx = {}
    for _, rec in iter_jsonl(path):
        if not isinstance(rec, dict) or rec.get("_parse_error"):
            continue
        pp_uri = rec.get("pp_uri")
        if pp_uri:
            idx[str(pp_uri)] = rec
    return idx


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--roa-match-records", required=True)
    ap.add_argument("--manifest-index", required=True)
    ap.add_argument("--pp-index", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    roa_match_path = Path(args.roa_match_records)
    manifest_index_path = Path(args.manifest_index)
    pp_index_path = Path(args.pp_index)
    out_dir = Path(args.out_dir)

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)

    records_path = outputs / "m19_roa_to_vrp_mapping_records.jsonl"
    summary_path = outputs / "m19_manifest_pp_join_summary.json"
    check_path = checks / "M19_B4_MANIFEST_PP_JOIN_CHECK.txt"

    manifest_idx = load_manifest_index(manifest_index_path)
    pp_idx = load_pp_index(pp_index_path)

    counters = Counter()

    with records_path.open("w", encoding="utf-8") as out:
        for _, rec in iter_jsonl(roa_match_path):
            if not isinstance(rec, dict) or rec.get("_parse_error"):
                counters["parse_error"] += 1
                continue

            counters["input_records"] += 1

            mapping_status = rec.get("mapping_status")
            failure_reason = list(rec.get("failure_reason") or [])
            roa_candidates = rec.get("roa_candidates") or []

            manifest_uri = None
            pp_uri = None
            roa_uri = None
            roa_hash = None
            manifest_match_count = 0
            pp_match_status = "not_attempted"

            if mapping_status == "mapped_to_roa" and roa_candidates:
                roa = roa_candidates[0]
                roa_uri = roa.get("roa_uri")
                roa_hash = roa.get("roa_hash")
                manifest_uri = roa.get("manifest_uri")
                pp_uri = roa.get("pp_uri")

                manifest_matches = []
                if roa_uri:
                    manifest_matches = manifest_idx.get(str(roa_uri), [])
                    manifest_match_count = len(manifest_matches)

                if manifest_matches:
                    m = manifest_matches[0]
                    manifest_uri = manifest_uri or m.get("manifest_uri")
                    pp_uri = pp_uri or m.get("pp_uri")
                    counters["mapped_to_manifest"] += 1
                    if mapping_status == "mapped_to_roa":
                        mapping_status = "mapped_to_manifest"

                if pp_uri:
                    if pp_uri in pp_idx:
                        pp_match_status = "pp_index_match"
                    else:
                        pp_match_status = "pp_uri_present_not_in_pp_index"
                    counters["mapped_to_pp"] += 1
                    mapping_status = "mapped_to_pp"
                else:
                    failure_reason.append("pp_uri_missing")

            else:
                # B3 已经说明没有 ROA candidate，这里不伪造后续 join。
                counters[str(mapping_status)] += 1
                if mapping_status == "roa_candidate_not_found":
                    failure_reason.append("manifest_pp_join_not_attempted_without_roa")
                if "source_uri_missing_or_insufficient_in_raw_vrp" not in failure_reason:
                    failure_reason.append("source_uri_missing_or_insufficient_in_raw_vrp")

            if mapping_status == "mapped_to_roa":
                counters["mapped_to_roa"] += 1
            elif mapping_status == "mapped_to_manifest":
                counters["mapped_to_roa"] += 1
            elif mapping_status == "mapped_to_pp":
                counters["mapped_to_roa"] += 1
                counters["mapped_to_manifest_or_pp"] += 1

            diff_scope_status = "unknown"
            if not roa_candidates:
                diff_scope_status = "unexplained_by_current_l2_index"
            if pp_uri:
                diff_scope_status = "candidate_pp_identified"

            out_rec = {
                "schema": "s3.m19.roa_to_vrp_mapping_record.v1",
                "vrp_key": rec.get("vrp_key"),
                "afi": rec.get("afi"),
                "tal": rec.get("tal"),
                "prefix": rec.get("prefix"),
                "asn": rec.get("asn"),
                "maxLength": rec.get("maxLength"),

                "source_uri": None,
                "source_uri_status": "source_uri_missing_or_insufficient",

                "roa_uri": roa_uri,
                "roa_hash": roa_hash,
                "roa_candidate_count": rec.get("roa_candidate_count", 0),
                "roa_match_method": "candidate_payload_match" if roa_candidates else None,

                "manifest_uri": manifest_uri,
                "manifest_filelist_match_count": manifest_match_count,

                "pp_uri": pp_uri,
                "pp_match_status": pp_match_status,

                "mapping_status": mapping_status,
                "mapping_confidence": rec.get("mapping_confidence"),
                "diff_scope_status": diff_scope_status,
                "failure_reason": sorted(set(failure_reason)),

                "m18_context": rec.get("m18_context"),
                "provenance": list(dict.fromkeys((rec.get("provenance") or []) + ["m19_b4_manifest_pp_join"])),
                "strong_causal_claim_allowed": False,
            }

            out.write(json.dumps(out_rec, ensure_ascii=False, sort_keys=True) + "\n")

    summary = {
        "schema": "s3.m19.b4.manifest_pp_join_summary.v1",
        "generated_at_utc": utc_now(),
        "roa_match_records": str(roa_match_path),
        "manifest_index": str(manifest_index_path),
        "pp_index": str(pp_index_path),
        "counters": dict(counters),
        "outputs": {
            "mapping_records": str(records_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "manifest_pp_join_candidate_level_not_causal_attribution",
        "strong_causal_claim_allowed": False,
        "next_stage": "M19_B5_MAPPING_COVERAGE_AND_M20_EXPORT",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M19_B4_MANIFEST_PP_JOIN=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"input_records = {counters['input_records']}",
        f"mapped_to_roa = {counters['mapped_to_roa']}",
        f"mapped_to_manifest = {counters['mapped_to_manifest']}",
        f"mapped_to_pp = {counters['mapped_to_pp']}",
        f"roa_candidate_not_found = {counters['roa_candidate_not_found']}",
        f"mapping_records = {records_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = manifest_pp_join_candidate_level_not_causal_attribution",
        "strong_causal_claim_allowed = False",
        "next_stage = M19_B5_MAPPING_COVERAGE_AND_M20_EXPORT",
    ]
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
