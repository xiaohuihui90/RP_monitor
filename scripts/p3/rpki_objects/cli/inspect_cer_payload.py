#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from scripts.p3.rpki_objects.parsers.cer import parse_cer_der


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect one RPKI .cer object.")
    parser.add_argument("--input", required=True, help="Path to .cer file")
    parser.add_argument("--canonical-uri", default=None)
    parser.add_argument("--out-json", required=True)
    args = parser.parse_args()

    p = Path(args.input)

    try:
        raw = p.read_bytes()
        parsed = parse_cer_der(raw)
        sf = parsed.get("semantic_fields") or {}

        result = {
            "parse_status": "ok",
            "input": str(p),
            "canonical_uri": args.canonical_uri,
            "source_file_sha256": sha256_hex(raw),
            "der_sha256": parsed.get("der_sha256"),
            "der_offset": parsed.get("der_offset"),
            "der_len": parsed.get("der_len"),
            "wrapper_detected": parsed.get("wrapper_detected"),
            "wrapper_type": parsed.get("wrapper_type"),
            "serial_number": sf.get("serial_number"),
            "subject": sf.get("subject"),
            "issuer": sf.get("issuer"),
            "not_before": sf.get("not_before"),
            "not_after": sf.get("not_after"),
            "ski": sf.get("ski"),
            "aki": sf.get("aki"),
            "certificate_role": sf.get("certificate_role"),
            "basic_constraints_ca": sf.get("basic_constraints_ca"),
            "key_usage": sf.get("key_usage"),
            "sia": sf.get("sia"),
            "aia": sf.get("aia"),
            "crldp_uris": sf.get("crldp_uris"),
            "ip_resources": sf.get("ip_resources"),
            "as_resources": sf.get("as_resources"),
            "semantic_object_hash": parsed.get("semantic_object_hash"),
            "chain_index_hash": parsed.get("chain_index_hash"),
            "resource_set_hash": parsed.get("resource_set_hash"),
            "warnings": parsed.get("warnings") or [],
        }
    except Exception as exc:
        result = {
            "parse_status": "failed",
            "input": str(p),
            "canonical_uri": args.canonical_uri,
            "error_class": str(exc).split(":", 1)[0] if str(exc) else exc.__class__.__name__,
            "error": repr(exc),
        }

    Path(args.out_json).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("parse_status") == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
