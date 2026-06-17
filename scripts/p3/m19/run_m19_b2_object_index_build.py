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
                yield json.loads(line)
            except Exception:
                yield {"_parse_error": True, "_line_no": line_no, "_raw": line[:300]}


def find_uri_like(obj: Any) -> list[str]:
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and ("uri" in str(k).lower() or v.startswith(("rsync://", "https://", "http://"))):
                out.append(v)
            elif isinstance(v, (dict, list)):
                out.extend(find_uri_like(v))
    elif isinstance(obj, list):
        for x in obj:
            out.extend(find_uri_like(x))
    return out


def normalize_asn(v: Any) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    if not s:
        return ""
    if s.upper().startswith("AS"):
        return "AS" + s[2:]
    return "AS" + s


def infer_afi(prefix: str) -> str:
    return "ipv6" if ":" in prefix else "ipv4"


def get_first(d: dict[str, Any], keys: list[str], default=None):
    for k in keys:
        if k in d and d[k] not in [None, ""]:
            return d[k]
    return default


def maybe_roa_payload_record(rec: dict[str, Any], source_file: Path) -> dict[str, Any] | None:
    prefix = get_first(rec, ["prefix", "ip_prefix", "vrp_prefix", "roa_prefix"])
    asn = get_first(rec, ["asn", "origin_asn", "origin", "originAS", "origin_as"])
    max_len = get_first(rec, ["maxLength", "max_length", "maxlen", "maxlength"])
    tal = get_first(rec, ["tal", "ta", "trust_anchor", "rir"])

    if not prefix or not asn:
        return None

    uri_hits = find_uri_like(rec)
    roa_uri = get_first(rec, ["roa_uri", "source_uri", "uri", "object_uri"], None)
    if not roa_uri and uri_hits:
        roa_uri = uri_hits[0]

    return {
        "schema": "s3.m19.roa_payload_index.v1",
        "afi": infer_afi(str(prefix)),
        "tal": str(tal or "unknown").lower(),
        "prefix": str(prefix),
        "asn": normalize_asn(asn),
        "maxLength": str(max_len if max_len is not None else ""),
        "roa_uri": roa_uri,
        "roa_hash": get_first(rec, ["roa_hash", "hash", "object_hash", "sha256"]),
        "manifest_uri": get_first(rec, ["manifest_uri", "mft_uri"]),
        "pp_uri": get_first(rec, ["pp_uri", "notification_uri", "rrdp_notification_uri"]),
        "source_file": str(source_file),
        "provenance": "m245_existing_record_candidate",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--m245-root", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    m245_root = Path(args.m245_root)
    out_dir = Path(args.out_dir)
    indexes = out_dir / "indexes"
    checks = out_dir / "checks"
    outputs = out_dir / "outputs"
    indexes.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)
    outputs.mkdir(parents=True, exist_ok=True)

    roa_index_path = indexes / "m19_roa_payload_index.jsonl"
    manifest_index_path = indexes / "m19_manifest_filelist_index.jsonl"
    pp_index_path = indexes / "m19_pp_index.jsonl"
    summary_path = outputs / "m19_object_index_summary.json"
    check_path = checks / "M19_B2_OBJECT_INDEX_CHECK.txt"

    counters = Counter()
    seen_roa = set()
    seen_manifest = set()
    seen_pp = set()

    with roa_index_path.open("w", encoding="utf-8") as roa_out, \
         manifest_index_path.open("w", encoding="utf-8") as mft_out, \
         pp_index_path.open("w", encoding="utf-8") as pp_out:

        jsonl_files = sorted(m245_root.glob("m245_window_*/indexes/*.jsonl"))

        for path in jsonl_files:
            counters["jsonl_files_scanned"] += 1
            for rec in iter_jsonl(path):
                if not isinstance(rec, dict) or rec.get("_parse_error"):
                    counters["parse_error_or_non_dict"] += 1
                    continue

                counters["records_scanned"] += 1

                roa = maybe_roa_payload_record(rec, path)
                if roa:
                    key = (roa["afi"], roa["tal"], roa["prefix"], roa["asn"], roa["maxLength"], roa.get("roa_uri"))
                    if key not in seen_roa:
                        seen_roa.add(key)
                        roa_out.write(json.dumps(roa, ensure_ascii=False, sort_keys=True) + "\n")
                        counters["roa_index_count"] += 1

                manifest_uri = rec.get("manifest_uri") or rec.get("mft_uri")
                file_uri = rec.get("file_uri") or rec.get("roa_uri") or rec.get("object_uri")
                if manifest_uri or file_uri:
                    mft_rec = {
                        "schema": "s3.m19.manifest_filelist_index.v1",
                        "manifest_uri": manifest_uri,
                        "file_uri": file_uri,
                        "file_hash": rec.get("file_hash") or rec.get("hash") or rec.get("object_hash"),
                        "manifest_number": rec.get("manifest_number"),
                        "manifest_this_update": rec.get("manifest_this_update"),
                        "manifest_next_update": rec.get("manifest_next_update"),
                        "tal": rec.get("tal") or rec.get("ta") or rec.get("rir"),
                        "pp_uri": rec.get("pp_uri") or rec.get("notification_uri"),
                        "source_file": str(path),
                        "provenance": "m245_existing_manifest_candidate",
                    }
                    key = (mft_rec["manifest_uri"], mft_rec["file_uri"], mft_rec["file_hash"])
                    if key not in seen_manifest:
                        seen_manifest.add(key)
                        mft_out.write(json.dumps(mft_rec, ensure_ascii=False, sort_keys=True) + "\n")
                        counters["manifest_index_count"] += 1

                pp_uri = rec.get("pp_uri") or rec.get("notification_uri") or rec.get("rrdp_notification_uri")
                if pp_uri:
                    pp_rec = {
                        "schema": "s3.m19.pp_index.v1",
                        "pp_uri": pp_uri,
                        "tal": rec.get("tal") or rec.get("ta") or rec.get("rir"),
                        "source_file": str(path),
                        "provenance": "m245_existing_pp_candidate",
                    }
                    if pp_uri not in seen_pp:
                        seen_pp.add(pp_uri)
                        pp_out.write(json.dumps(pp_rec, ensure_ascii=False, sort_keys=True) + "\n")
                        counters["pp_index_count"] += 1

    summary = {
        "schema": "s3.m19.b2.object_index_summary.v1",
        "generated_at_utc": utc_now(),
        "m245_root": str(m245_root),
        "counters": dict(counters),
        "outputs": {
            "roa_index": str(roa_index_path),
            "manifest_index": str(manifest_index_path),
            "pp_index": str(pp_index_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "object_index_candidate_extraction_not_same_input_claim",
        "strong_causal_claim_allowed": False,
        "next_stage": "M19_B3_CANDIDATE_ROA_MATCH",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M19_B2_OBJECT_INDEX=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"jsonl_files_scanned = {counters['jsonl_files_scanned']}",
        f"records_scanned = {counters['records_scanned']}",
        f"roa_index_count = {counters['roa_index_count']}",
        f"manifest_index_count = {counters['manifest_index_count']}",
        f"pp_index_count = {counters['pp_index_count']}",
        f"roa_index = {roa_index_path}",
        f"manifest_index = {manifest_index_path}",
        f"pp_index = {pp_index_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = object_index_candidate_extraction_not_same_input_claim",
        "strong_causal_claim_allowed = False",
        "next_stage = M19_B3_CANDIDATE_ROA_MATCH",
    ]
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
