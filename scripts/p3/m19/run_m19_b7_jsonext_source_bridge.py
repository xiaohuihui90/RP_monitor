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
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield line_no, json.loads(line)
            except Exception as e:
                yield line_no, {"_parse_error": str(e), "_raw": line[:300]}


def normalize_asn(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    if not s:
        return ""
    if s.upper().startswith("AS"):
        return "AS" + s[2:]
    return "AS" + s


def norm_key(afi: str, tal: str, prefix: str, asn: str, maxlen: Any):
    return (
        str(afi or "").lower(),
        str(tal or "").lower(),
        str(prefix or "").strip(),
        normalize_asn(asn),
        str(maxlen if maxlen is not None else "").strip(),
    )


def infer_afi(prefix: str) -> str:
    return "ipv6" if ":" in str(prefix) else "ipv4"


def extract_source_list(roa: dict[str, Any]) -> list[dict[str, Any]]:
    src = roa.get("source")
    if isinstance(src, list):
        return [x for x in src if isinstance(x, dict)]
    if isinstance(src, dict):
        return [src]
    return []


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-jsonl", required=True)
    ap.add_argument("--jsonext", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    seed_path = Path(args.seed_jsonl)
    jsonext_path = Path(args.jsonext)
    out_dir = Path(args.out_dir)

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)

    records_path = outputs / "m19_jsonext_source_bridge_records.jsonl"
    summary_path = outputs / "m19_jsonext_source_bridge_summary.json"
    check_path = checks / "M19_B7_JSONEXT_SOURCE_BRIDGE_CHECK.txt"

    counters = Counter()
    index = defaultdict(list)

    obj = json.loads(jsonext_path.read_text(encoding="utf-8", errors="ignore"))
    roas = obj.get("roas", []) if isinstance(obj, dict) else obj
    if not isinstance(roas, list):
        roas = []

    for roa in roas:
        if not isinstance(roa, dict):
            continue

        prefix = roa.get("prefix")
        asn = normalize_asn(roa.get("asn"))
        maxlen = roa.get("maxLength")
        afi = infer_afi(prefix)

        for src in extract_source_list(roa):
            tal = str(src.get("tal") or roa.get("ta") or roa.get("tal") or "").lower()
            uri = src.get("uri")
            if not tal:
                tal = "unknown"

            k = norm_key(afi, tal, prefix, asn, maxlen)
            index[k].append({
                "afi": afi,
                "tal": tal,
                "prefix": prefix,
                "asn": asn,
                "maxLength": str(maxlen),
                "source_type": src.get("type"),
                "source_uri": uri,
                "validity": src.get("validity"),
                "chainValidity": src.get("chainValidity"),
                "stale": src.get("stale"),
                "jsonext_generatedTime": obj.get("metadata", {}).get("generatedTime") if isinstance(obj, dict) else None,
            })
            counters["jsonext_source_records_indexed"] += 1

    with records_path.open("w", encoding="utf-8") as out:
        for _, seed in iter_jsonl(seed_path):
            if not isinstance(seed, dict) or seed.get("_parse_error"):
                counters["seed_parse_error"] += 1
                continue

            counters["input_seed_count"] += 1

            k = norm_key(
                seed.get("afi"),
                seed.get("tal"),
                seed.get("prefix"),
                seed.get("asn"),
                seed.get("maxLength"),
            )
            matches = index.get(k, [])

            if len(matches) == 1:
                status = "mapped_to_source_uri"
                confidence = "jsonext_exact_key_match"
                counters["mapped_to_source_uri"] += 1
            elif len(matches) > 1:
                status = "ambiguous_source_uri"
                confidence = "jsonext_multiple_exact_key_matches"
                counters["ambiguous_source_uri"] += 1
            else:
                status = "source_uri_not_found_in_jsonext"
                confidence = "none"
                counters["source_uri_not_found_in_jsonext"] += 1

            rec = {
                "schema": "s3.m19.jsonext_source_bridge_record.v1",
                "vrp_key": seed.get("vrp_key"),
                "afi": seed.get("afi"),
                "tal": seed.get("tal"),
                "prefix": seed.get("prefix"),
                "asn": normalize_asn(seed.get("asn")),
                "maxLength": str(seed.get("maxLength")),
                "m18_context": {
                    "transient_or_persistent": seed.get("transient_or_persistent"),
                    "probe_seen_count": seed.get("probe_seen_count"),
                    "global_duration_windows": seed.get("global_duration_windows"),
                    "trailing_cache_candidate_v1": seed.get("trailing_cache_candidate_v1"),
                },
                "jsonext_match_status": status,
                "jsonext_match_confidence": confidence,
                "jsonext_source_candidate_count": len(matches),
                "jsonext_source_candidates": matches[:10],
                "semantic_boundary": "jsonext_current_snapshot_bridge_not_retroactive_causal_attribution",
                "strong_causal_claim_allowed": False,
            }
            out.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")

    input_count = counters["input_seed_count"]
    coverage = {
        "mapped_to_source_uri_ratio": counters["mapped_to_source_uri"] / input_count if input_count else 0,
        "ambiguous_source_uri_ratio": counters["ambiguous_source_uri"] / input_count if input_count else 0,
        "source_uri_not_found_ratio": counters["source_uri_not_found_in_jsonext"] / input_count if input_count else 0,
    }

    summary = {
        "schema": "s3.m19.b7.jsonext_source_bridge_summary.v1",
        "generated_at_utc": utc_now(),
        "seed_jsonl": str(seed_path),
        "jsonext": str(jsonext_path),
        "counters": dict(counters),
        "coverage": coverage,
        "outputs": {
            "records_jsonl": str(records_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "jsonext_current_snapshot_bridge_not_retroactive_causal_attribution",
        "strong_causal_claim_allowed": False,
        "next_stage": "M19_JSONEXT_SIDECAR_EXTENSION_FOR_FUTURE_WINDOWS",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M19_B7_JSONEXT_SOURCE_BRIDGE=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"input_seed_count = {counters['input_seed_count']}",
        f"jsonext_source_records_indexed = {counters['jsonext_source_records_indexed']}",
        f"mapped_to_source_uri = {counters['mapped_to_source_uri']}",
        f"ambiguous_source_uri = {counters['ambiguous_source_uri']}",
        f"source_uri_not_found_in_jsonext = {counters['source_uri_not_found_in_jsonext']}",
        f"mapped_to_source_uri_ratio = {coverage['mapped_to_source_uri_ratio']}",
        f"records_jsonl = {records_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = jsonext_current_snapshot_bridge_not_retroactive_causal_attribution",
        "strong_causal_claim_allowed = False",
        "next_stage = M19_JSONEXT_SIDECAR_EXTENSION_FOR_FUTURE_WINDOWS",
    ]
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
