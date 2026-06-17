#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RPKI Manifest parser for S3 semantic object comparison.

This parser handles the eContent of an RPKI Manifest CMS SignedData object.
It does not perform full path validation or signature validation. It extracts
semantic fields needed by S3 object-layer comparison:
  - manifestNumber
  - thisUpdate / nextUpdate
  - fileHashAlg
  - fileList(file, hash)
  - fileList digest
  - semantic_object_hash
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from scripts.p3.rpki_objects.semantic_hash import (
    canonical_json_hash,
    sha256_bytes,
)

try:
    from asn1crypto import algos, core
    ASN1CRYPTO_AVAILABLE = True
    ASN1CRYPTO_ERROR = None
except Exception as exc:  # pragma: no cover
    algos = None
    core = None
    ASN1CRYPTO_AVAILABLE = False
    ASN1CRYPTO_ERROR = repr(exc)


if ASN1CRYPTO_AVAILABLE:
    class FileAndHash(core.Sequence):
        _fields = [
            ("file", core.IA5String),
            ("hash", core.OctetBitString),
        ]

    class FileAndHashList(core.SequenceOf):
        _child_spec = FileAndHash

    class RPKIManifest(core.Sequence):
        _fields = [
            ("version", core.Integer, {"explicit": 0, "optional": True}),
            ("manifest_number", core.Integer),
            ("this_update", core.GeneralizedTime),
            ("next_update", core.GeneralizedTime),
            ("file_hash_alg", algos.DigestAlgorithmId),
            ("file_list", FileAndHashList),
        ]


def _bit_string_to_hash(bit_obj: Any, hash_alg: str = "sha256") -> str:
    """
    Convert ASN.1 BIT STRING content to sha256:<hex>.

    RFC 9286 Manifest fileList hashes are BIT STRING values. For SHA-256,
    the first content octet is the number of unused bits, normally 0, followed
    by 32 bytes.
    """
    contents = getattr(bit_obj, "contents", b"") or b""
    if not contents:
        return ""

    unused_bits = contents[0]
    raw = contents[1:]

    if unused_bits != 0:
        return f"bitstring_unused_bits_{unused_bits}:{raw.hex()}"

    if hash_alg.lower() in {"sha256", "sha-256"} and len(raw) == 32:
        return "sha256:" + raw.hex()

    if re.fullmatch(r"[0-9a-fA-F]{64}", raw.hex()):
        return "sha256:" + raw.hex().lower()

    return raw.hex()


def _normalize_time(value: Any) -> str:
    """
    Return ISO 8601 string. asn1crypto normally returns timezone-aware datetime.
    """
    try:
        return value.isoformat()
    except Exception:
        return str(value)


def parse_mft_econtent(econtent_der: bytes) -> Dict[str, Any]:
    """
    Parse RPKI Manifest eContent DER and return semantic fields.

    Raises RuntimeError / ValueError on parse failure.
    """
    if not ASN1CRYPTO_AVAILABLE:
        raise RuntimeError(f"asn1crypto unavailable: {ASN1CRYPTO_ERROR}")

    mf = RPKIManifest.load(econtent_der)

    file_hash_alg = str(mf["file_hash_alg"].native)
    file_list: List[Dict[str, str]] = []

    for item in mf["file_list"]:
        fname = str(item["file"].native)
        fh = _bit_string_to_hash(item["hash"], hash_alg=file_hash_alg)
        file_list.append({
            "file": fname,
            "hash": fh,
        })

    file_list_sorted = sorted(file_list, key=lambda x: (x.get("file", ""), x.get("hash", "")))
    file_list_digest = canonical_json_hash(file_list_sorted)

    semantic_fields = {
        "manifest_number": int(mf["manifest_number"].native),
        "this_update": _normalize_time(mf["this_update"].native),
        "next_update": _normalize_time(mf["next_update"].native),
        "file_hash_alg": file_hash_alg,
        "file_count": len(file_list_sorted),
        "file_list_digest": file_list_digest,
        "file_list": file_list_sorted,
    }

    semantic_hash_input = {
        "object_type": "mft",
        "manifest_number": semantic_fields["manifest_number"],
        "this_update": semantic_fields["this_update"],
        "next_update": semantic_fields["next_update"],
        "file_hash_alg": semantic_fields["file_hash_alg"],
        "file_list": file_list_sorted,
    }

    return {
        "object_type": "mft",
        "econtent_sha256": sha256_bytes(econtent_der),
        "semantic_fields": semantic_fields,
        "semantic_object_hash": canonical_json_hash(semantic_hash_input),
        "parse_status": "ok",
        "warnings": [],
    }


def build_mft_semantic_record(
    *,
    canonical_uri: str,
    cms_info: Dict[str, Any],
    probe_id: str | None = None,
    snapshot_group_id: str | None = None,
    object_export_id: str | None = None,
    source_adapter: str | None = None,
    source_file: str | None = None,
    source_file_sha256: str | None = None,
) -> Dict[str, Any]:
    """
    Build a complete semantic inventory record for an MFT object.
    """
    selected = cms_info.get("selected") or {}
    wrapper = cms_info.get("wrapper") or {}

    econtent_der = selected.get("econtent_der")
    if not isinstance(econtent_der, (bytes, bytearray)):
        return {
            "schema": "s3.object.semantic_inventory.v1",
            "probe_id": probe_id,
            "snapshot_group_id": snapshot_group_id,
            "object_export_id": object_export_id,
            "canonical_uri": canonical_uri,
            "object_type": "mft",
            "source_adapter": source_adapter,
            "source_file": source_file,
            "source_file_sha256": source_file_sha256,
            "parse_status": "econtent_der_missing",
            "warnings": ["mft_econtent_der_missing"],
        }

    parsed = parse_mft_econtent(bytes(econtent_der))

    return {
        "schema": "s3.object.semantic_inventory.v1",
        "probe_id": probe_id,
        "snapshot_group_id": snapshot_group_id,
        "object_export_id": object_export_id,

        "canonical_uri": canonical_uri,
        "object_type": "mft",

        "source_adapter": source_adapter,
        "source_file": source_file,
        "source_file_sha256": source_file_sha256,

        "wrapper_detected": wrapper.get("wrapper_detected"),
        "wrapper_type": wrapper.get("wrapper_type"),
        "wrapper_sha256": wrapper.get("wrapper_sha256"),
        "wrapper_size": wrapper.get("wrapper_size"),

        "cms_payload_offset": selected.get("cms_payload_offset"),
        "cms_payload_len": selected.get("cms_payload_len"),
        "cms_payload_sha256": selected.get("cms_payload_sha256"),
        "econtent_type_oid": selected.get("econtent_type_oid"),
        "econtent_type_native": selected.get("econtent_type_native"),
        "econtent_sha256": selected.get("econtent_sha256"),

        "semantic_fields": parsed["semantic_fields"],
        "semantic_object_hash": parsed["semantic_object_hash"],
        "parse_status": parsed["parse_status"],
        "warnings": parsed["warnings"],
    }
