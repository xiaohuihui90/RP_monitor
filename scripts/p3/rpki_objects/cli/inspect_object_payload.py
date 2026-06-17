#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Inspect one RPKI object or validator cache wrapper file.

Example:
  python scripts/p3/rpki_objects/cli/inspect_object_payload.py \
    --input /path/to/object.mft \
    --canonical-uri cache://rsync/rpki.ripe.net/repository/x.mft \
    --preferred-object-type mft
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

from scripts.p3.rpki_objects.canonical_uri import (
    canonicalize_object_uri,
    object_type_from_uri,
)
from scripts.p3.rpki_objects.cms_extract import extract_rpki_signed_object
from scripts.p3.rpki_objects.semantic_hash import sha256_file
from scripts.p3.rpki_objects.parsers.mft import build_mft_semantic_record


def _json_safe(obj: Any) -> Any:
    if isinstance(obj, (bytes, bytearray)):
        return {
            "__bytes__": True,
            "len": len(obj),
        }
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe(x) for x in obj]
    return obj


def inspect_object(
    input_path: Path,
    canonical_uri: str | None,
    preferred_object_type: str | None,
    source_adapter: str | None,
) -> Dict[str, Any]:
    if not input_path.exists():
        return {
            "schema": "s3.object.inspect_payload.v1",
            "input": str(input_path),
            "parse_status": "raw_file_missing",
            "parse_error": "input file does not exist",
        }

    raw_uri = canonical_uri or str(input_path)
    cu = canonicalize_object_uri(raw_uri)
    inferred_type = preferred_object_type or object_type_from_uri(cu)

    data = input_path.read_bytes()
    source_hash = sha256_file(input_path)

    cms_info = extract_rpki_signed_object(
        data,
        preferred_object_type=inferred_type,
    )

    selected = cms_info.get("selected") or {}
    selected_type = selected.get("object_type")

    result: Dict[str, Any] = {
        "schema": "s3.object.inspect_payload.v1",
        "input": str(input_path),
        "canonical_uri": cu,
        "preferred_object_type": preferred_object_type,
        "inferred_object_type": inferred_type,
        "source_adapter": source_adapter,
        "source_file_sha256": source_hash,
        "cms_extract_status": cms_info.get("parse_status"),
        "wrapper": cms_info.get("wrapper"),
        "candidate_count": cms_info.get("candidate_count"),
        "candidate_summary": cms_info.get("candidate_summary"),
        "selected_summary": {
            "object_type": selected.get("object_type"),
            "econtent_type_oid": selected.get("econtent_type_oid"),
            "econtent_type_native": selected.get("econtent_type_native"),
            "cms_payload_offset": selected.get("cms_payload_offset"),
            "cms_payload_len": selected.get("cms_payload_len"),
            "cms_payload_sha256": selected.get("cms_payload_sha256"),
            "econtent_sha256": selected.get("econtent_sha256"),
            "econtent_len": selected.get("econtent_len"),
        },
        "semantic_record": None,
    }

    if cms_info.get("parse_status") != "ok":
        result["parse_status"] = cms_info.get("parse_status")
        result["parse_error"] = cms_info.get("parse_error")
        return result

    if selected_type == "mft":
        try:
            semantic_record = build_mft_semantic_record(
                canonical_uri=cu,
                cms_info=cms_info,
                source_adapter=source_adapter,
                source_file=str(input_path),
                source_file_sha256=source_hash,
            )
            result["semantic_record"] = semantic_record
            result["parse_status"] = semantic_record.get("parse_status")
        except Exception as exc:
            result["parse_status"] = "mft_parse_failed"
            result["parse_error"] = repr(exc)
    else:
        result["parse_status"] = "object_parser_not_implemented"
        result["parse_error"] = f"parser not implemented for object_type={selected_type!r}"

    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Input object/cache-wrapper file path")
    parser.add_argument("--canonical-uri", default=None, help="Optional canonical/raw URI")
    parser.add_argument("--preferred-object-type", default=None, help="Preferred object type, e.g. mft")
    parser.add_argument("--source-adapter", default="generic_file_v1")
    parser.add_argument("--out-json", default=None, help="Optional output JSON path")
    args = parser.parse_args()

    result = inspect_object(
        input_path=Path(args.input),
        canonical_uri=args.canonical_uri,
        preferred_object_type=args.preferred_object_type,
        source_adapter=args.source_adapter,
    )

    safe = _json_safe(result)
    text = json.dumps(safe, ensure_ascii=False, indent=2)

    if args.out_json:
        out = Path(args.out_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")

    print(text)
    return 0 if result.get("parse_status") == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
