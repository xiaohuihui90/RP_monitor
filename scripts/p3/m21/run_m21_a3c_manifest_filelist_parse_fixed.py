#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict


RPKI_MANIFEST_ECONTENT_OID = "1.2.840.113549.1.9.16.1.26"


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
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n

    start = pos
    end = pos + length
    if end > len(buf):
        raise ValueError("value extends beyond buffer")
    return tag, start, end, end


def parse_children(value: bytes):
    children = []
    pos = 0
    while pos < len(value):
        tag, start, end, nxt = read_tlv(value, pos)
        children.append((tag, value[start:end], pos, nxt))
        pos = nxt
    return children


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
    return int.from_bytes(value, "big", signed=False) if value else 0


def der_time(value: bytes) -> str:
    return value.decode("ascii", errors="ignore")


def find_first_octet_string(value: bytes) -> bytes | None:
    try:
        children = parse_children(value)
    except Exception:
        return None

    for tag, val, _, _ in children:
        if tag == 0x04:
            return val
        # constructed universal / context-specific
        if tag in (0x30, 0x31) or (tag & 0xE0) == 0xA0:
            found = find_first_octet_string(val)
            if found is not None:
                return found
    return None


def extract_rpki_manifest_econtent_from_cms(cms_der: bytes) -> bytes:
    """
    Locate EncapsulatedContentInfo:
      contentType = id-ct-rpkiManifest
      eContent    = [0] EXPLICIT OCTET STRING
    and return the OCTET STRING value, i.e., Manifest eContent DER.
    """

    def walk(value: bytes, depth: int = 0):
        try:
            children = parse_children(value)
        except Exception:
            return None

        # Look for siblings: OID id-ct-rpkiManifest followed by context [0].
        for i, (tag, val, _, _) in enumerate(children):
            if tag == 0x06 and parse_oid(val) == RPKI_MANIFEST_ECONTENT_OID:
                for j in range(i + 1, len(children)):
                    tag2, val2, _, _ = children[j]
                    if tag2 == 0xA0:
                        octets = find_first_octet_string(val2)
                        if octets is not None:
                            return octets

        # Recurse into constructed nodes.
        for tag, val, _, _ in children:
            if tag in (0x30, 0x31) or (tag & 0xE0) == 0xA0:
                found = walk(val, depth + 1)
                if found is not None:
                    return found

        return None

    found = walk(cms_der)
    if found is None:
        raise ValueError("id-ct-rpkiManifest eContent OCTET STRING not found")
    return found


def parse_manifest_econtent(econtent: bytes):
    tag, start, end, _ = read_tlv(econtent, 0)
    if tag != 0x30:
        raise ValueError(f"Manifest eContent top-level is not SEQUENCE: tag={hex(tag)}")

    children = parse_children(econtent[start:end])
    idx = 0

    version = 0
    if idx < len(children) and children[idx][0] == 0xA0:
        inner = parse_children(children[idx][1])
        if inner and inner[0][0] == 0x02:
            version = int_from_der(inner[0][1])
        idx += 1

    if idx >= len(children) or children[idx][0] != 0x02:
        raise ValueError("manifestNumber INTEGER not found")
    manifest_number = int_from_der(children[idx][1])
    idx += 1

    if idx >= len(children) or children[idx][0] not in (0x17, 0x18):
        raise ValueError("thisUpdate time not found")
    this_update = der_time(children[idx][1])
    idx += 1

    if idx >= len(children) or children[idx][0] not in (0x17, 0x18):
        raise ValueError("nextUpdate time not found")
    next_update = der_time(children[idx][1])
    idx += 1

    # RFC 9286 Manifest eContent uses fileHashAlg OBJECT IDENTIFIER.
    # Some older code mistakenly expects AlgorithmIdentifier SEQUENCE.
    if idx >= len(children) or children[idx][0] != 0x06:
        raise ValueError(f"fileHashAlg OBJECT IDENTIFIER not found; tag={hex(children[idx][0]) if idx < len(children) else 'EOF'}")
    file_hash_alg_oid = parse_oid(children[idx][1])
    idx += 1

    if idx >= len(children) or children[idx][0] != 0x30:
        raise ValueError("fileList SEQUENCE not found")
    filelist_children = parse_children(children[idx][1])

    entries = []
    for item_tag, item_val, _, _ in filelist_children:
        if item_tag != 0x30:
            continue
        parts = parse_children(item_val)
        if len(parts) < 2:
            continue

        name = None
        file_hash = None

        if parts[0][0] in (0x16, 0x0C, 0x13):
            name = parts[0][1].decode("utf-8", errors="ignore")

        if parts[1][0] == 0x03 and parts[1][1]:
            bit_string = parts[1][1]
            unused_bits = bit_string[0]
            file_hash = bit_string[1:].hex()

        if name:
            entries.append({
                "file": name,
                "hash": file_hash,
            })

    return {
        "version": version,
        "manifestNumber": manifest_number,
        "thisUpdate": this_update,
        "nextUpdate": next_update,
        "fileHashAlgOid": file_hash_alg_oid,
        "fileList": entries,
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

    parse_records_path = outputs / "m21_a3c_manifest_parse_records.jsonl"
    filelist_index_path = indexes / "m21_a3c_manifest_filelist_index.jsonl"
    match_records_path = outputs / "m21_a3c_roa_manifest_filelist_match_records.jsonl"
    summary_path = outputs / "m21_a3c_manifest_filelist_parse_summary.json"
    check_path = checks / "M21_A3C_MANIFEST_FILELIST_PARSE_FIXED_CHECK.txt"

    joined_by_key = {}
    for _, rec in iter_jsonl(joined_path):
        if isinstance(rec, dict) and not rec.get("_parse_error"):
            joined_by_key[rec.get("vrp_key")] = rec

    manifest_meta = {}
    file_index = defaultdict(dict)
    counters = Counter()

    with parse_records_path.open("w", encoding="utf-8") as parse_out, \
         filelist_index_path.open("w", encoding="utf-8") as file_out:

        for _, m in iter_jsonl(manifest_index_path):
            if not isinstance(m, dict) or m.get("_parse_error"):
                counters["manifest_index_parse_error"] += 1
                continue

            counters["manifest_object_count"] += 1

            manifest_uri = m.get("manifest_uri")
            local_path = Path(m.get("local_manifest_path") or "")

            parse_rec = {
                "schema": "s3.m21.a3c.manifest_parse_record.v1",
                "manifest_uri": manifest_uri,
                "local_manifest_path": str(local_path),
                "parse_status": None,
                "manifestNumber": None,
                "thisUpdate": None,
                "nextUpdate": None,
                "fileHashAlgOid": None,
                "fileList_count": 0,
                "error": None,
                "semantic_boundary": "late_manifest_filelist_parse_fixed_not_same_window_input",
                "strong_causal_claim_allowed": False,
            }

            try:
                if not local_path.exists():
                    raise FileNotFoundError(str(local_path))

                cms_der = local_path.read_bytes()
                econtent = extract_rpki_manifest_econtent_from_cms(cms_der)
                econtent_path = logs / (local_path.parent.name + "_a3c_econtent.der")
                econtent_path.write_bytes(econtent)

                parsed = parse_manifest_econtent(econtent)

                parse_rec["parse_status"] = "parse_success"
                parse_rec["manifestNumber"] = parsed["manifestNumber"]
                parse_rec["thisUpdate"] = parsed["thisUpdate"]
                parse_rec["nextUpdate"] = parsed["nextUpdate"]
                parse_rec["fileHashAlgOid"] = parsed["fileHashAlgOid"]
                parse_rec["fileList_count"] = len(parsed["fileList"])
                parse_rec["econtent_path"] = str(econtent_path)

                manifest_meta[manifest_uri] = {
                    "manifestNumber": parsed["manifestNumber"],
                    "thisUpdate": parsed["thisUpdate"],
                    "nextUpdate": parsed["nextUpdate"],
                    "fileHashAlgOid": parsed["fileHashAlgOid"],
                    "fileList_count": len(parsed["fileList"]),
                }

                counters["manifest_parse_success"] += 1

                for entry in parsed["fileList"]:
                    file_name = entry.get("file")
                    file_hash = entry.get("hash")
                    if not file_name:
                        continue

                    file_index[manifest_uri][file_name] = file_hash

                    row = {
                        "schema": "s3.m21.a3c.manifest_filelist_index.v1",
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
            joined = joined_by_key.get(vrp_key, {})
            object_sha256 = joined.get("object_sha256")

            if file_hash:
                filelist_match = True
                counters["roa_filename_filelist_match"] += 1
            else:
                filelist_match = False
                counters["roa_filename_filelist_not_match"] += 1

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

            if filelist_match and object_hash_status == "match":
                alignment_status = "l3_to_manifest_filelist_and_object_hash_confirmed"
                alignment_confidence = "medium_late_backfill"
            elif filelist_match:
                alignment_status = "l3_to_manifest_filelist_hash_unverified"
                alignment_confidence = "medium_weak_hash_missing"
            else:
                alignment_status = "l3_to_roa_only_manifest_filelist_not_confirmed"
                alignment_confidence = "weak"

            out_rec = {
                "schema": "s3.m21.a3c.roa_manifest_filelist_match_record.v1",
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
                "alignment_confidence": alignment_confidence,
                "m20_join_status": c.get("m20_join_status"),
                "jsonext_generatedTime": c.get("jsonext_generatedTime"),
                "stale": c.get("stale"),
                "validity": c.get("validity"),
                "chainValidity": c.get("chainValidity"),
                "semantic_boundary": "late_manifest_filelist_match_not_same_window_input",
                "strong_causal_claim_allowed": False,
            }

            match_out.write(json.dumps(out_rec, ensure_ascii=False, sort_keys=True) + "\n")

    summary = {
        "schema": "s3.m21.a3c.manifest_filelist_parse_summary.v1",
        "generated_at_utc": utc_now(),
        "manifest_index": str(manifest_index_path),
        "a2_candidates": str(candidates_path),
        "m20_joined_records": str(joined_path),
        "counters": dict(counters),
        "outputs": {
            "manifest_parse_records": str(parse_records_path),
            "manifest_filelist_index": str(filelist_index_path),
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
        "M21_A3C_MANIFEST_FILELIST_PARSE_FIXED=PASS",
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
        f"manifest_filehash_unavailable = {counters['manifest_filehash_unavailable']}",
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
