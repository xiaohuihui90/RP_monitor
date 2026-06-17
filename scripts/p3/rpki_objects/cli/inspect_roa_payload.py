#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.p3.rpki_objects.roa_semantic_inventory import inspect_roa_file


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect one ROA signed object payload.")
    parser.add_argument("--input", required=True, help="Path to .roa file")
    parser.add_argument("--canonical-uri", default=None)
    parser.add_argument("--out-json", required=True)
    args = parser.parse_args()

    try:
        obj = inspect_roa_file(Path(args.input), canonical_uri=args.canonical_uri)
        result = {
            "parse_status": "ok",
            "input": args.input,
            "canonical_uri": args.canonical_uri,
            "econtent_type_oid": obj.get("econtent_type_oid"),
            "cms_payload_sha256": obj.get("cms_payload_sha256"),
            "econtent_sha256": obj.get("econtent_sha256"),
            "wrapper_detected": obj.get("wrapper_detected"),
            "wrapper_type": obj.get("wrapper_type"),
            "source_file_sha256": obj.get("source_file_sha256"),
            "semantic_object_hash": obj.get("semantic_object_hash"),
            "semantic_fields": obj.get("semantic_fields"),
        }
    except Exception as exc:
        result = {
            "parse_status": "failed",
            "input": args.input,
            "canonical_uri": args.canonical_uri,
            "error_class": str(exc).split(":", 1)[0] if str(exc) else exc.__class__.__name__,
            "error": repr(exc),
        }

    Path(args.out_json).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("parse_status") == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
