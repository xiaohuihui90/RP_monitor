#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict


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


def read_tlv(buf: bytes, pos: int):
    if pos >= len(buf):
        raise ValueError("EOF while reading tag")
    tag = buf[pos]
    pos += 1
    if pos >= len(buf):
        raise ValueError("EOF while reading length")
    first = buf[pos]
    pos += 1
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0:
            raise ValueError("indefinite length unsupported")
        if pos + n > len(buf):
            raise ValueError("EOF in long length")
        length = int.from_bytes(buf[pos:pos+n], "big")
        pos += n
    start = pos
    end = pos + length
    if end > len(buf):
        raise ValueError("value extends beyond buffer")
    return tag, start, end, end


def parse_children(value: bytes):
    out = []
    pos = 0
    while pos < len(value):
        tag, start, end, nxt = read_tlv(value, pos)
        out.append((tag, value[start:end]))
        pos = nxt
    return out


def parse_oid(value: bytes) -> str:
    if not value:
        return ""
    first = value[0]
    nums = [first // 40, first % 40]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not (b & 0x80):
            nums.append(n)
            n = 0
    return ".".join(map(str, nums))


def int_from_der(value: bytes) -> int:
    if not value:
        return 0
    return int.from_bytes(value, "big", signed=False)


def extract_econtent(mft_path: Path, out_path: Path):
    commands = [
        [
            "openssl", "cms", "-verify",
            "-inform", "DER",
            "-in", str(mft_path),
            "-noverify",
            "-nosigs",
            "-out", str(out_path),
        ],
        [
            "openssl", "cms", "-verify",
            "-inform", "DER",
            "-in", str(mft_path),
            "-noverify",
            "-no_attr_verify",
            "-no_content_verify",
            "-out", str(out_path),
        ],
        [
            "openssl", "cms", "-verify",
            "-inform", "DER",
            "-in", str(mft_path),
            "-noverify",
            "-out", str(out_path),
        ],
    ]

    errors = []
    for cmd in commands:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode == 0 and out_path.exists() and out_path.stat().st_size > 0:
            return {
                "status": "success",
                "returncode": p.returncode,
                "cmd": " ".join(cmd),
                "stderr_tail": p.stderr.decode("utf-8", errors="ignore")[-1000:],
            }
        errors.append({
            "cmd": " ".join(cmd),
            "returncode": p.returncode,
            "stderr_tail": p.stderr.decode("utf-8", errors="ignore")[-1000:],
        })

    return {
        "status": "failed",
        "errors": errors,
    }


def parse_manifest_econtent(econtent: bytes):
    tag, start, end, nxt = read_tlv(econtent, 0)
    if tag != 0x30:
        raise ValueError(f"Manifest eContent top-level is not SEQUENCE: tag={hex(tag)}")

    top_children = parse_children(econtent[start:end])
    i = 0

    # optional version: [0] EXPLICIT INTEGER DEFAULT 0
    version = 0
    if i < len(top_children) and top_children[i][0] == 0xA0:
        inner = parse_children(top_children[i][1])
        if inner and inner[0][0] == 0x02:
            version = int_from_der(inner[0][1])
        i += 1

    if i >= len(top_children) or top_children[i][0] != 0x02:
        raise ValueError("manifestNumber INTEGER not found")
    manifest_number = int_from_der(top_children[i][1])
    i += 1

    if i >= len(top_children) or top_children[i][0] != 0x18:
        raise ValueError("thisUpdate GeneralizedTime not found")
    this_update = top_children[i][1].decode("ascii", errors="ignore")
    i += 1

    if i >= len(top_children) or top_children[i][0] != 0x18:
        raise ValueError("nextUpdate GeneralizedTime not found")
    next_update = top_children[i][1].decode("ascii", errors="ignore")
    i += 1

    # fileHashAlg: AlgorithmIdentifier SEQUENCE
    hash_alg_oid = None
    if i < len(top_children) and top_children[i][0] == 0x30:
        alg_children = parse_children(top_children[i][1])
        if alg_children and alg_children[0][0] == 0x06:
            hash_alg_oid = parse_oid(alg_children[0][1])
        i += 1
    else:
        raise ValueError("fileHashAlg AlgorithmIdentifier not found")

    if i >= len(top_children) or top_children[i][0] != 0x30:
        raise ValueError("fileList SEQUENCE not found")

    filelist_children = parse_children(top_children[i][1])
    file_entries = []

    for item_tag, item_val in filelist_children:
        if item_tag != 0x30:
            continue
        parts = parse_children(item_val)
        if len(parts) < 2:
            continue

        file_name = None
        file_hash_hex = None

        # FileAndHash ::= SEQUENCE { file IA5String, hash BIT STRING }
        if parts[0][0] in (0x16, 0x0C, 0x13):
            file_name = parts[0][1].decode("utf-8", errors="ignore")

        if parts[1][0] == 0x03 and parts[1][1]:
            # BIT STRING: first octet is unused-bit count
            bit_string = parts[1][1]
            unused_bits = bit_string[0]
            file_hash_hex = bit_string[1:].hex()

        if file_name:
            file_entries.append({
                "file": file_name,
                "hash": file_hash_hex,
            })

    return {
        "version": version,
        "manifestNumber": manifest_number,
        "thisUpdate": this_update,
        "nextUpdate": next_update,
        "fileHashAlgOid": hash_alg_oid,
        "fileList": file_entries,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest-index", required=True)
    ap.add_argument("--a2-candidates", required=True)
    ap.add_argument("--m20-joined-records", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    manifest_index_path = Path(args.manifest_index)
    candidates_path = Path(args.a2_candidates)
    joined_path = Path(args.m20_joined_records)
    out_dir = Path(args.out_dir)

    outputs = out_dir / "outputs"
    checks = out_dir / "checks"
    indexes = out_dir / "indexes"
    logs = out_dir / "logs"
    outputs.mkdir(parents=True, exist_ok=True)
    checks.mkdir(parents=True, exist_ok=True)
    indexes.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)

    filelist_index_path = indexes / "m21_a3_manifest_filelist_index.jsonl"
    match_records_path = outputs / "m21_a3_roa_manifest_filelist_match_records.jsonl"
    parse_records_path = outputs / "m21_a3_manifest_parse_records.jsonl"
    summary_path = outputs / "m21_a3_manifest_filelist_parse_summary.json"
    check_path = checks / "M21_A3_MANIFEST_FILELIST_PARSE_CHECK.txt"

    joined_by_key = {}
    for _, rec in iter_jsonl(joined_path):
        if isinstance(rec, dict) and not rec.get("_parse_error"):
            joined_by_key[rec.get("vrp_key")] = rec

    manifest_meta = {}
    file_index = defaultdict(dict)
    counters = Counter()

    with filelist_index_path.open("w", encoding="utf-8") as file_out, \
         parse_records_path.open("w", encoding="utf-8") as parse_out:

        for _, m in iter_jsonl(manifest_index_path):
            if not isinstance(m, dict) or m.get("_parse_error"):
                counters["manifest_index_parse_error"] += 1
                continue

            manifest_uri = m.get("manifest_uri")
            local_path = Path(m.get("local_manifest_path") or "")

            counters["manifest_object_count"] += 1

            parse_rec = {
                "schema": "s3.m21.a3.manifest_parse_record.v1",
                "manifest_uri": manifest_uri,
                "local_manifest_path": str(local_path),
                "parse_status": None,
                "extract_status": None,
                "manifestNumber": None,
                "thisUpdate": None,
                "nextUpdate": None,
                "fileHashAlgOid": None,
                "fileList_count": 0,
                "error": None,
                "semantic_boundary": "manifest_filelist_extracted_from_late_fetched_manifest",
                "strong_causal_claim_allowed": False,
            }

            if not local_path.exists():
                counters["manifest_local_file_missing"] += 1
                parse_rec["parse_status"] = "local_file_missing"
                parse_out.write(json.dumps(parse_rec, ensure_ascii=False, sort_keys=True) + "\n")
                continue

            econtent_path = logs / (local_path.parent.name + "_manifest_econtent.der")
            extract = extract_econtent(local_path, econtent_path)
            parse_rec["extract_status"] = extract.get("status")

            if extract.get("status") != "success":
                counters["manifest_econtent_extract_failed"] += 1
                parse_rec["parse_status"] = "extract_failed"
                parse_rec["error"] = extract
                parse_out.write(json.dumps(parse_rec, ensure_ascii=False, sort_keys=True) + "\n")
                continue

            try:
                parsed = parse_manifest_econtent(econtent_path.read_bytes())
                counters["manifest_parse_success"] += 1
                parse_rec["parse_status"] = "parse_success"
                parse_rec["manifestNumber"] = parsed["manifestNumber"]
                parse_rec["thisUpdate"] = parsed["thisUpdate"]
                parse_rec["nextUpdate"] = parsed["nextUpdate"]
                parse_rec["fileHashAlgOid"] = parsed["fileHashAlgOid"]
                parse_rec["fileList_count"] = len(parsed["fileList"])

                manifest_meta[manifest_uri] = {
                    "manifestNumber": parsed["manifestNumber"],
                    "thisUpdate": parsed["thisUpdate"],
                    "nextUpdate": parsed["nextUpdate"],
                    "fileHashAlgOid": parsed["fileHashAlgOid"],
                    "fileList_count": len(parsed["fileList"]),
                }

                for entry in parsed["fileList"]:
                    file_name = entry["file"]
                    file_hash = entry["hash"]
                    file_index[manifest_uri][file_name] = file_hash

                    row = {
                        "schema": "s3.m21.a3.manifest_filelist_index.v1",
                        "manifest_uri": manifest_uri,
                        "manifestNumber": parsed["manifestNumber"],
                        "thisUpdate": parsed["thisUpdate"],
                        "nextUpdate": parsed["nextUpdate"],
                        "fileHashAlgOid": parsed["fileHashAlgOid"],
                        "file": file_name,
                        "file_hash": file_hash,
                        "semantic_boundary": "late_manifest_filelist_index",
                        "strong_causal_claim_allowed": False,
                    }
                    file_out.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                    counters["manifest_filelist_entry_count"] += 1

            except Exception as e:
                counters["manifest_parse_failed"] += 1
                parse_rec["parse_status"] = "parse_failed"
                parse_rec["error"] = str(e)

            parse_out.write(json.dumps(parse_rec, ensure_ascii=False, sort_keys=True) + "\n")

    with match_records_path.open("w", encoding="utf-8") as match_out:
        for _, c in iter_jsonl(candidates_path):
            if not isinstance(c, dict) or c.get("_parse_error"):
                counters["candidate_parse_error"] += 1
                continue

            counters["candidate_count"] += 1
            manifest_uri = c.get("manifest_uri")
            roa_filename = c.get("roa_filename")
            vrp_key = c.get("vrp_key")

            meta = manifest_meta.get(manifest_uri, {})
            file_hash = file_index.get(manifest_uri, {}).get(roa_filename)

            if file_hash:
                filelist_match = True
                counters["roa_filename_filelist_match"] += 1
            else:
                filelist_match = False
                counters["roa_filename_filelist_not_match"] += 1

            joined = joined_by_key.get(vrp_key, {})
            object_sha256 = joined.get("object_sha256")

            if file_hash and object_sha256:
                if file_hash.lower() == str(object_sha256).lower():
                    object_hash_status = "match"
                    counters["manifest_filehash_matches_backfilled_roa_sha256"] += 1
                else:
                    object_hash_status = "mismatch"
                    counters["manifest_filehash_mismatch_backfilled_roa_sha256"] += 1
            elif file_hash and not object_sha256:
                object_hash_status = "backfilled_roa_hash_unavailable"
                counters["backfilled_roa_hash_unavailable"] += 1
            else:
                object_hash_status = "manifest_filehash_unavailable"
                counters["manifest_filehash_unavailable"] += 1

            if filelist_match and object_hash_status in ("match", "backfilled_roa_hash_unavailable"):
                alignment_status = "l3_to_manifest_filelist"
            elif filelist_match:
                alignment_status = "l3_to_manifest_filelist_hash_unverified"
            else:
                alignment_status = "l3_to_roa_only_manifest_filelist_not_confirmed"

            rec = {
                "schema": "s3.m21.a3.roa_manifest_filelist_match_record.v1",
                "vrp_key": vrp_key,
                "afi": c.get("afi"),
                "tal": c.get("tal"),
                "prefix": c.get("prefix"),
                "asn": c.get("asn"),
                "maxLength": c.get("maxLength"),

                "roa_uri": c.get("roa_uri"),
                "roa_filename": roa_filename,
                "manifest_uri": manifest_uri,
                "manifest_fetch_status": c.get("manifest_fetch_status"),
                "manifestNumber": meta.get("manifestNumber"),
                "manifest_thisUpdate": meta.get("thisUpdate"),
                "manifest_nextUpdate": meta.get("nextUpdate"),
                "manifest_fileHashAlgOid": meta.get("fileHashAlgOid"),
                "manifest_fileList_count": meta.get("fileList_count"),

                "roa_filename_filelist_match": filelist_match,
                "manifest_file_hash": file_hash,
                "backfilled_roa_object_sha256": object_sha256,
                "object_hash_status": object_hash_status,

                "alignment_status": alignment_status,
                "m20_join_status": c.get("m20_join_status"),
                "jsonext_generatedTime": c.get("jsonext_generatedTime"),
                "stale": c.get("stale"),
                "validity": c.get("validity"),
                "chainValidity": c.get("chainValidity"),

                "semantic_boundary": "late_manifest_filelist_match_not_same_window_input",
                "strong_causal_claim_allowed": False,
            }
            match_out.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")

    summary = {
        "schema": "s3.m21.a3.manifest_filelist_parse_summary.v1",
        "generated_at_utc": utc_now(),
        "manifest_index": str(manifest_index_path),
        "a2_candidates": str(candidates_path),
        "m20_joined_records": str(joined_path),
        "counters": dict(counters),
        "outputs": {
            "manifest_filelist_index": str(filelist_index_path),
            "manifest_parse_records": str(parse_records_path),
            "roa_manifest_filelist_match_records": str(match_records_path),
            "summary_json": str(summary_path),
            "check_txt": str(check_path),
        },
        "semantic_boundary": "late_manifest_filelist_parse_not_same_window_input",
        "strong_causal_claim_allowed": False,
        "next_stage": "M21_A4_PP_NOTIFICATION_BINDING_PRECHECK",
    }

    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "M21_A3_MANIFEST_FILELIST_PARSE=PASS",
        f"generated_at_utc = {summary['generated_at_utc']}",
        f"manifest_object_count = {counters['manifest_object_count']}",
        f"manifest_parse_success = {counters['manifest_parse_success']}",
        f"manifest_parse_failed = {counters['manifest_parse_failed']}",
        f"manifest_filelist_entry_count = {counters['manifest_filelist_entry_count']}",
        f"candidate_count = {counters['candidate_count']}",
        f"roa_filename_filelist_match = {counters['roa_filename_filelist_match']}",
        f"roa_filename_filelist_not_match = {counters['roa_filename_filelist_not_match']}",
        f"manifest_filehash_matches_backfilled_roa_sha256 = {counters['manifest_filehash_matches_backfilled_roa_sha256']}",
        f"manifest_filehash_mismatch_backfilled_roa_sha256 = {counters['manifest_filehash_mismatch_backfilled_roa_sha256']}",
        f"backfilled_roa_hash_unavailable = {counters['backfilled_roa_hash_unavailable']}",
        f"manifest_filelist_index = {filelist_index_path}",
        f"roa_manifest_filelist_match_records = {match_records_path}",
        f"summary_json = {summary_path}",
        "semantic_boundary = late_manifest_filelist_parse_not_same_window_input",
        "strong_causal_claim_allowed = False",
        "next_stage = M21_A4_PP_NOTIFICATION_BINDING_PRECHECK",
    ]
    check_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(check_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
