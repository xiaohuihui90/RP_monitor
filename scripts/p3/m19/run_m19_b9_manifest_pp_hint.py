#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
from urllib.parse import urlparse
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


def parse_repo_hint(uri: str | None) -> dict[str, Any]:
    if not uri:
        return {
            "source_uri_parse_status": "missing",
            "source_scheme": None,
            "source_host": None,
            "source_path": None,
            "roa_filename": None,
            "repository_base_uri": None,
            "repository_scope_key": None,
            "fetch_ready": False,
        }

    try:
        p = urlparse(uri)
        path = p.path or ""
        base_path = path.rsplit("/", 1)[0] if "/" in path else ""
        roa_filename = path.rsplit("/", 1)[-1] if path else None

        if p.scheme and p.netloc and base_path:
            base_uri = f"{p.scheme}://{p.netloc}{base_path}/"
            scope_key = f"{p.scheme}://{p.netloc}{base_path}/"
        else:
            base_uri = None
            scope_key = None

        return {
            "source_uri_parse_status": "ok",
            "source_scheme": p.scheme or None,
            "source_host": p.netloc or None,
            "source_path": path or None,
            "roa_filename": roa_filename,
            "repository_base_uri": base_uri,
            "repository_scope_key": scope_key,
            "fetch_ready": bool(uri and p.scheme in {"rsync", "https", "http"} and p.netloc),
        }
    except Exception as e:
        return {
            "source_uri_parse_status": f"parse_failed:{e}",
            "source_scheme": None,
            "source_host": None,
            "source_path": None,
            "roa_filename": None,
            "repository_base_uri": None,
            "repository_scope_key": None,
            "fetch_ready": False,
        }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jsonext-enriched-records", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    in_path = Path(args.jsonext_enriched_records)
    out_dir = Path(args.out_dir)

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)

    records_path = outputs / "m19_candidate_manifest_pp_hint_records.jsonl"
    summary_path = outputs / "m19_manifest_pp_hint_summary.json"
    m20_candidates_path = outputs / "m20_jsonext_uri_backfill_candidates.jsonl"
    check_path = checks / "M19_B9_MANIFEST_PP_HINT_CHECK.txt"

    counters = Counter()
    repo_scope_counter = Counter()
    source_host_counter = Counter()
    tal_counter = Counter()

    with records_path.open("w", encoding="utf-8") as rec_out, \
         m20_candidates_path.open("w", encoding="utf-8") as m20_out:

        for _, rec in iter_jsonl(in_path):
            if not isinstance(rec, dict) or rec.get("_parse_error"):
                counters["parse_error_or_invalid"] += 1
                continue

            counters["input_records"] += 1

            source_uri = rec.get("source_uri") or rec.get("roa_uri")
            mapping_status = rec.get("mapping_status")
            hint = parse_repo_hint(source_uri)

            if source_uri and mapping_status == "mapped_to_roa_uri_via_jsonext":
                counters["roa_uri_available"] += 1
            else:
                counters["roa_uri_missing"] += 1

            if hint["repository_base_uri"]:
                counters["repository_base_hint_available"] += 1
                repo_scope_counter[hint["repository_base_uri"]] += 1

            if hint["source_host"]:
                source_host_counter[hint["source_host"]] += 1

            tal = rec.get("tal") or "unknown"
            tal_counter[tal] += 1

            if hint["fetch_ready"]:
                counters["fetch_ready"] += 1
            else:
                counters["fetch_not_ready"] += 1

            # 当前 B9 不解析 manifest fileList，只生成 manifest/PP hints。
            if source_uri and hint["repository_base_uri"]:
                pp_hint_status = "repository_base_hint_from_roa_uri"
                manifest_hint_status = "manifest_unknown_requires_repository_or_cache_lookup"
            elif source_uri:
                pp_hint_status = "source_uri_available_but_repo_base_parse_failed"
                manifest_hint_status = "manifest_unknown"
            else:
                pp_hint_status = "source_uri_missing"
                manifest_hint_status = "manifest_unknown_source_missing"

            out_rec = {
                "schema": "s3.m19.manifest_pp_hint_record.v1",

                "vrp_key": rec.get("vrp_key"),
                "afi": rec.get("afi"),
                "tal": rec.get("tal"),
                "prefix": rec.get("prefix"),
                "asn": rec.get("asn"),
                "maxLength": rec.get("maxLength"),

                "source_uri": source_uri,
                "source_protocol": rec.get("source_protocol"),
                "source_type": rec.get("source_type"),
                "roa_uri": rec.get("roa_uri"),

                "source_uri_parse_status": hint["source_uri_parse_status"],
                "source_scheme": hint["source_scheme"],
                "source_host": hint["source_host"],
                "source_path": hint["source_path"],
                "roa_filename": hint["roa_filename"],

                "repository_base_uri": hint["repository_base_uri"],
                "repository_scope_key": hint["repository_scope_key"],

                "manifest_uri": None,
                "manifest_hint_status": manifest_hint_status,

                "pp_uri": None,
                "pp_hint_uri": hint["repository_base_uri"],
                "pp_hint_status": pp_hint_status,

                "fetch_ready": hint["fetch_ready"],
                "fetch_target_uri": source_uri if hint["fetch_ready"] else None,
                "fetch_target_type": "roa_uri" if hint["fetch_ready"] else None,

                "validity": rec.get("validity"),
                "chainValidity": rec.get("chainValidity"),
                "stale": rec.get("stale"),
                "jsonext_generatedTime": rec.get("jsonext_generatedTime"),

                "m18_context": rec.get("m18_context"),
                "m19_b8_mapping_status": rec.get("mapping_status"),
                "m19_b8_mapping_confidence": rec.get("mapping_confidence"),

                "mapping_status": (
                    "roa_uri_available_manifest_pp_hint_only"
                    if source_uri else
                    "source_uri_not_found_in_jsonext"
                ),
                "mapping_confidence": (
                    "jsonext_roa_uri_exact_key_match_repo_hint"
                    if source_uri else
                    "none"
                ),

                "provenance": list(dict.fromkeys((rec.get("provenance") or []) + [
                    "m19_b9_manifest_pp_hint_extraction"
                ])),
                "semantic_boundary": "repository_hint_not_manifest_or_pp_confirmation",
                "strong_causal_claim_allowed": False,
            }

            rec_out.write(json.dumps(out_rec, ensure_ascii=False, sort_keys=True) + "\n")

            if hint["fetch_ready"]:
                m20 = {
                    "schema": "s3.m20.jsonext_uri_backfill_candidate.v1",
                    "vrp_key": rec.get("vrp_key"),
                    "afi": rec.get("afi"),
                    "tal": rec.get("tal"),
                    "prefix": rec.get("prefix"),
                    "asn": rec.get("asn"),
                    "maxLength": rec.get("maxLength"),

                    "fetch_target_uri": source_uri,
                    "fetch_target_type": "roa_uri",
                    "repository_base_uri": hint["repository_base_uri"],
                    "source_host": hint["source_host"],
                    "source_scheme": hint["source_scheme"],

                    "reason": [
                        "jsonext_roa_uri_available",
                        "manifest_pp_unknown",
                        "targeted_fetch_can_start_from_roa_uri",
                    ],
                    "priority": "high",
                    "fetch_ready": True,

                    "validity": rec.get("validity"),
                    "chainValidity": rec.get("chainValidity"),
                    "stale": rec.get("stale"),
                    "jsonext_generatedTime": rec.get("jsonext_generatedTime"),

                    "semantic_boundary": "late_targeted_backfill_candidate_not_same_window_input",
                    "strong_causal_claim_allowed": False,
                }
                m20_out.write(json.dumps(m20, ensure_ascii=False, sort_keys=True) + "\n")
                counters["m20_jsonext_uri_backfill_candidate_count"] += 1

    summary = {
        "schema": "s3.m19.b9.manifest_pp_hint_summary.v1",
        "generated_at_utc": utc_now(),
        "jsonext_enriched_records": str(in_path),
        "counters": dict(counters),
        "coverage": {
            "roa_uri_available_ratio": counters["roa_uri_available"] / counters["input_records"] if counters["input_records"] else 0,
            "repository_base_hint_ratio": counters["repository_base_hint_available"] / counters["input_records"] if counters["input_records"] else 0,
            "fetch_ready_ratio": counters["fetch_ready"] / counters["input_records"] if counters["input_records"] else 0,
        },
        "repo_scope_top20": repo_scope_counter.most_common(20),
        "source_host_top20": source_host_counter.most_common(20),
        "tal_top20": tal_counter.most_common(20),
        "outputs": {
            "records_jsonl": str(records_path),
            "summary_json": str(summary_path),
            "m20_jsonext_uri_backfill_candidates": str(m20_candidates_path),
            "check_txt": str(check_path),
        },
        "interpretation": {
            "manifest_confirmed": False,
            "pp_confirmed": False,
            "repository_hint_available": counters["repository_base_hint_available"] > 0,
            "m20_fetch_ready": counters["fetch_ready"] > 0,
        },
        "semantic_boundary": "repository_hint_not_manifest_or_pp_confirmation",
        "strong_causal_claim_allowed": False,
        "next_stage": "M20_JSONEXT_URI_TARGETED_BACKFILL_SMALL_BATCH",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M19_B9_MANIFEST_PP_HINT=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"input_records = {counters['input_records']}",
        f"roa_uri_available = {counters['roa_uri_available']}",
        f"roa_uri_missing = {counters['roa_uri_missing']}",
        f"repository_base_hint_available = {counters['repository_base_hint_available']}",
        f"fetch_ready = {counters['fetch_ready']}",
        f"m20_jsonext_uri_backfill_candidate_count = {counters['m20_jsonext_uri_backfill_candidate_count']}",
        f"records_jsonl = {records_path}",
        f"summary_json = {summary_path}",
        f"m20_jsonext_uri_backfill_candidates = {m20_candidates_path}",
        "manifest_confirmed = False",
        "pp_confirmed = False",
        "semantic_boundary = repository_hint_not_manifest_or_pp_confirmation",
        "strong_causal_claim_allowed = False",
        "next_stage = M20_JSONEXT_URI_TARGETED_BACKFILL_SMALL_BATCH",
    ]

    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state_path = Path("data/p3_collector/m19_roa_to_vrp/state/current_m19_b9_run.env")
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        "\n".join([
            f'export M19_B9_OUT_DIR="{out_dir}"',
            f'export M19_B9_RECORDS="{records_path}"',
            f'export M19_B9_SUMMARY="{summary_path}"',
            f'export M19_B9_CHECK="{check_path}"',
            f'export M19_B9_M20_CANDIDATES="{m20_candidates_path}"',
            "",
        ]),
        encoding="utf-8",
    )

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
