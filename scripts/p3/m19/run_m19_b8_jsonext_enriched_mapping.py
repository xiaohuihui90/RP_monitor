#!/usr/bin/env python3
from __future__ import annotations

import argparse
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


def normalize_source_uri(uri: Any) -> str | None:
    if not uri:
        return None
    s = str(uri).strip()
    return s if s else None


def infer_source_protocol(uri: str | None) -> str | None:
    if not uri:
        return None
    if uri.startswith("rsync://"):
        return "rsync"
    if uri.startswith("https://"):
        return "https"
    if uri.startswith("http://"):
        return "http"
    return "unknown"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonext-bridge-records", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    bridge_path = Path(args.jsonext_bridge_records)
    out_dir = Path(args.out_dir)

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)

    records_path = outputs / "m19_jsonext_enriched_mapping_records.jsonl"
    summary_path = outputs / "m19_jsonext_enriched_mapping_summary.json"
    check_path = checks / "M19_B8_JSONEXT_ENRICHED_MAPPING_CHECK.txt"

    counters = Counter()

    with records_path.open("w", encoding="utf-8") as out:
        for line_no, rec in iter_jsonl(bridge_path):
            if not isinstance(rec, dict) or rec.get("_parse_error"):
                counters["parse_error"] += 1
                continue

            counters["input_records"] += 1

            status = rec.get("jsonext_match_status")
            candidates = rec.get("jsonext_source_candidates") or []

            source_uri = None
            source_type = None
            validity = None
            chain_validity = None
            stale = None
            jsonext_generated_time = None
            source_candidate_count = len(candidates)

            if status == "mapped_to_source_uri" and source_candidate_count >= 1:
                src = candidates[0]
                source_uri = normalize_source_uri(src.get("source_uri"))
                source_type = src.get("source_type")
                validity = src.get("validity")
                chain_validity = src.get("chainValidity")
                stale = src.get("stale")
                jsonext_generated_time = src.get("jsonext_generatedTime")

            if status == "mapped_to_source_uri" and source_uri:
                mapping_status = "mapped_to_roa_uri_via_jsonext"
                mapping_confidence = "jsonext_exact_key_match"
                failure_reason = []
                counters["mapped_to_roa_uri_via_jsonext"] += 1
            elif status == "ambiguous_source_uri":
                mapping_status = "ambiguous_source_uri"
                mapping_confidence = "jsonext_multiple_exact_key_matches"
                failure_reason = ["ambiguous_jsonext_source_candidates"]
                counters["ambiguous_source_uri"] += 1
            else:
                mapping_status = "source_uri_not_found_in_jsonext"
                mapping_confidence = "none"
                failure_reason = ["source_uri_not_found_in_current_jsonext_snapshot"]
                counters["source_uri_not_found_in_jsonext"] += 1

            source_protocol = infer_source_protocol(source_uri)

            out_rec = {
                "schema": "s3.m19.jsonext_enriched_mapping_record.v1",

                "vrp_key": rec.get("vrp_key"),
                "afi": rec.get("afi"),
                "tal": rec.get("tal"),
                "prefix": rec.get("prefix"),
                "asn": rec.get("asn"),
                "maxLength": rec.get("maxLength"),

                "source_uri": source_uri,
                "source_type": source_type,
                "source_protocol": source_protocol,
                "roa_uri": source_uri if source_type == "roa" else source_uri,
                "roa_hash": None,

                "jsonext_source_candidate_count": source_candidate_count,
                "jsonext_match_status": status,
                "jsonext_match_confidence": rec.get("jsonext_match_confidence"),
                "jsonext_generatedTime": jsonext_generated_time,

                "validity": validity,
                "chainValidity": chain_validity,
                "stale": stale,

                "manifest_uri": None,
                "manifest_number": None,
                "manifest_this_update": None,
                "manifest_next_update": None,
                "pp_uri": None,

                "mapping_status": mapping_status,
                "mapping_confidence": mapping_confidence,
                "failure_reason": failure_reason,

                "m18_context": rec.get("m18_context"),

                "provenance": [
                    "m18_d7b_seed",
                    "m19_b7_jsonext_current_snapshot_bridge",
                    "m19_b8_jsonext_enriched_mapping",
                ],
                "semantic_boundary": "jsonext_current_snapshot_bridge_not_retroactive_causal_attribution",
                "strong_causal_claim_allowed": False,
            }

            out.write(json.dumps(out_rec, ensure_ascii=False, sort_keys=True) + "\n")

            if source_protocol:
                counters[f"source_protocol_{source_protocol}"] += 1
            if stale:
                counters["stale_field_available"] += 1
            if validity:
                counters["validity_available"] += 1
            if chain_validity:
                counters["chainValidity_available"] += 1

    input_count = counters["input_records"]
    coverage = {
        "mapped_to_roa_uri_via_jsonext_ratio": counters["mapped_to_roa_uri_via_jsonext"] / input_count if input_count else 0,
        "source_uri_not_found_ratio": counters["source_uri_not_found_in_jsonext"] / input_count if input_count else 0,
        "ambiguous_source_uri_ratio": counters["ambiguous_source_uri"] / input_count if input_count else 0,
    }

    summary = {
        "schema": "s3.m19.b8.jsonext_enriched_mapping_summary.v1",
        "generated_at_utc": utc_now(),
        "jsonext_bridge_records": str(bridge_path),
        "counters": dict(counters),
        "coverage": coverage,
        "outputs": {
            "records_jsonl": str(records_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "jsonext_current_snapshot_bridge_not_retroactive_causal_attribution",
        "strong_causal_claim_allowed": False,
        "next_stage": "M19_B9_MANIFEST_PP_HINT_EXTRACTION_OR_M17C_JSONEXT_SIDECAR_EXTENSION",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M19_B8_JSONEXT_ENRICHED_MAPPING=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"input_records = {counters['input_records']}",
        f"mapped_to_roa_uri_via_jsonext = {counters['mapped_to_roa_uri_via_jsonext']}",
        f"source_uri_not_found_in_jsonext = {counters['source_uri_not_found_in_jsonext']}",
        f"ambiguous_source_uri = {counters['ambiguous_source_uri']}",
        f"mapped_to_roa_uri_via_jsonext_ratio = {coverage['mapped_to_roa_uri_via_jsonext_ratio']}",
        f"source_protocol_rsync = {counters['source_protocol_rsync']}",
        f"source_protocol_https = {counters['source_protocol_https']}",
        f"validity_available = {counters['validity_available']}",
        f"chainValidity_available = {counters['chainValidity_available']}",
        f"stale_field_available = {counters['stale_field_available']}",
        f"records_jsonl = {records_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = jsonext_current_snapshot_bridge_not_retroactive_causal_attribution",
        "strong_causal_claim_allowed = False",
        "next_stage = M19_B9_MANIFEST_PP_HINT_EXTRACTION_OR_M17C_JSONEXT_SIDECAR_EXTENSION",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state_path = Path("data/p3_collector/m19_roa_to_vrp/state/current_m19_b8_run.env")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        "\n".join([
            f'export M19_B8_OUT_DIR="{out_dir}"',
            f'export M19_B8_RECORDS="{records_path}"',
            f'export M19_B8_SUMMARY="{summary_path}"',
            f'export M19_B8_CHECK="{check_path}"',
            "",
        ]),
        encoding="utf-8",
    )

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
