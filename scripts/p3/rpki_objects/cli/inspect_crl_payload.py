#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from scripts.p3.rpki_objects.parsers.crl import parse_crl_der


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect one RPKI .crl object.")
    parser.add_argument("--input", required=True, help="Path to .crl file")
    parser.add_argument("--canonical-uri", default=None)
    parser.add_argument("--out-json", required=True)
    args = parser.parse_args()

    p = Path(args.input)

    try:
        raw = p.read_bytes()
        parsed = parse_crl_der(raw)
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
            "version": sf.get("version"),
            "signature_algorithm": sf.get("signature_algorithm"),
            "issuer": sf.get("issuer"),
            "issuer_hash": sf.get("issuer_hash"),
            "this_update": sf.get("this_update"),
            "next_update": sf.get("next_update"),
            "authority_key_identifier": sf.get("authority_key_identifier"),
            "crl_number": sf.get("crl_number"),
            "revoked_certificate_count": sf.get("revoked_certificate_count"),
            "revoked_serial_set_digest": sf.get("revoked_serial_set_digest"),
            "revoked_entries_digest": sf.get("revoked_entries_digest"),
            "crl_semantic_hash": parsed.get("crl_semantic_hash"),
            "crl_issuer_aki_hash": parsed.get("crl_issuer_aki_hash"),
            "crl_revoked_set_hash": parsed.get("crl_revoked_set_hash"),
            "crl_freshness_hash": parsed.get("crl_freshness_hash"),
            "warnings": parsed.get("warnings") or [],
            "revoked_serials_sample": (sf.get("revoked_serials") or [])[:20],
            "revoked_entries_sample": (sf.get("revoked_entries") or [])[:20],
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
