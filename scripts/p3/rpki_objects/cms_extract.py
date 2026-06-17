#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CMS SignedData extraction for RPKI objects.

The extractor is validator-independent: it accepts raw DER CMS bytes or
validator cache wrapper bytes and locates embedded CMS SignedData objects.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from scripts.p3.rpki_objects.der_locator import extract_der_objects
from scripts.p3.rpki_objects.semantic_hash import sha256_bytes
from scripts.p3.rpki_objects.wrapper_detect import detect_wrapper

try:
    from asn1crypto import cms
    ASN1CRYPTO_AVAILABLE = True
    ASN1CRYPTO_ERROR = None
except Exception as exc:  # pragma: no cover
    cms = None
    ASN1CRYPTO_AVAILABLE = False
    ASN1CRYPTO_ERROR = repr(exc)


RPKI_ECONTENT_OID_TO_TYPE = {
    "1.2.840.113549.1.9.16.1.26": "mft",
    "1.2.840.113549.1.9.16.1.24": "roa",
    # More object types will be added in later batches.
}


def identify_rpki_object_type(econtent_type_oid: str) -> str:
    return RPKI_ECONTENT_OID_TO_TYPE.get(str(econtent_type_oid), "unknown_signed_object")


def _oid_from_content_type(value) -> str:
    dotted = getattr(value, "dotted", None)
    if dotted:
        return str(dotted)
    native = getattr(value, "native", None)
    # asn1crypto may return friendly name for known OIDs.
    if native == "signed_data":
        return "1.2.840.113549.1.7.2"
    return str(native)


def _econtent_bytes(econtent) -> bytes:
    inner = econtent.native
    if isinstance(inner, bytes):
        return inner
    if isinstance(inner, bytearray):
        return bytes(inner)
    if isinstance(inner, str):
        return inner.encode("latin1")
    # Fallback for ParsableOctetString-like objects.
    try:
        return bytes(econtent)
    except Exception:
        return econtent.contents


def parse_cms_signed_data_der(cms_der: bytes) -> Dict[str, object]:
    """
    Parse a CMS ContentInfo containing signed_data.
    """
    if not ASN1CRYPTO_AVAILABLE:
        raise RuntimeError("asn1crypto unavailable: %s" % ASN1CRYPTO_ERROR)

    ci = cms.ContentInfo.load(cms_der)
    content_type = ci["content_type"].native
    if content_type != "signed_data":
        raise ValueError("content_type is not signed_data: %r" % content_type)

    sd = ci["content"]
    eci = sd["encap_content_info"]
    econtent_type = eci["content_type"]
    econtent_type_oid = _oid_from_content_type(econtent_type)
    econtent_type_native = str(econtent_type.native)

    econtent = eci["content"]
    inner = _econtent_bytes(econtent)

    return {
        "content_type": content_type,
        "cms_payload_sha256": sha256_bytes(cms_der),
        "cms_payload_len": len(cms_der),
        "econtent_type_oid": econtent_type_oid,
        "econtent_type_native": econtent_type_native,
        "econtent_sha256": sha256_bytes(inner),
        "econtent_len": len(inner),
        "object_type": identify_rpki_object_type(econtent_type_oid),
        "econtent_der": inner,
    }


def extract_rpki_signed_objects(data: bytes) -> List[Dict[str, object]]:
    """
    Return all parseable embedded CMS signed_data objects.
    """
    wrapper = detect_wrapper(data)
    results: List[Dict[str, object]] = []

    for cand in extract_der_objects(data):
        cms_der = cand["der"]
        try:
            parsed = parse_cms_signed_data_der(cms_der)
        except Exception:
            continue

        item = {
            "cms_payload_offset": cand["offset"],
            "cms_payload_len": cand["der_len"],
            "cms_payload_sha256": cand["der_sha256"],
            **{k: v for k, v in parsed.items() if k != "cms_payload_sha256" or True},
            "wrapper": {k: v for k, v in wrapper.items() if k != "der_candidate_offsets"},
        }
        # Keep exact DER bytes only out of returned metadata to avoid huge JSON.
        item.pop("econtent_der", None)
        results.append(item)

    return results


def extract_rpki_signed_object(
    data: bytes,
    preferred_object_type: Optional[str] = None,
    preferred_econtent_oid: Optional[str] = None,
) -> Dict[str, object]:
    """
    Select one CMS signed object from raw/wrapper bytes.

    Selection priority:
      1. preferred_econtent_oid
      2. preferred_object_type
      3. first known RPKI object type
      4. first signed_data candidate
    """
    wrapper = detect_wrapper(data)
    if not ASN1CRYPTO_AVAILABLE:
        return {
            "parse_status": "asn1crypto_unavailable",
            "parse_error": ASN1CRYPTO_ERROR,
            "wrapper": wrapper,
            "candidates": [],
        }

    candidates = []
    for cand in extract_der_objects(data):
        cms_der = cand["der"]
        try:
            parsed = parse_cms_signed_data_der(cms_der)
        except Exception:
            continue

        item = {
            "cms_payload_offset": cand["offset"],
            "cms_payload_len": cand["der_len"],
            "cms_payload_sha256": cand["der_sha256"],
            "content_type": parsed["content_type"],
            "econtent_type_oid": parsed["econtent_type_oid"],
            "econtent_type_native": parsed["econtent_type_native"],
            "econtent_sha256": parsed["econtent_sha256"],
            "econtent_len": parsed["econtent_len"],
            "object_type": parsed["object_type"],
            "econtent_der": parsed["econtent_der"],
        }
        candidates.append(item)

    if not candidates:
        return {
            "parse_status": "no_cms_signed_data_found",
            "parse_error": "no parseable CMS signed_data DER object found",
            "wrapper": wrapper,
            "candidates": [],
        }

    selected = None
    if preferred_econtent_oid:
        selected = next((x for x in candidates if x["econtent_type_oid"] == preferred_econtent_oid), None)
    if selected is None and preferred_object_type:
        selected = next((x for x in candidates if x["object_type"] == preferred_object_type), None)
    if selected is None:
        selected = next((x for x in candidates if x["object_type"] != "unknown_signed_object"), None)
    if selected is None:
        selected = candidates[0]

    return {
        "parse_status": "ok",
        "wrapper": wrapper,
        "candidate_count": len(candidates),
        "selected": selected,
        "candidate_summary": [
            {
                "cms_payload_offset": x["cms_payload_offset"],
                "cms_payload_len": x["cms_payload_len"],
                "cms_payload_sha256": x["cms_payload_sha256"],
                "econtent_type_oid": x["econtent_type_oid"],
                "econtent_type_native": x["econtent_type_native"],
                "econtent_sha256": x["econtent_sha256"],
                "object_type": x["object_type"],
            }
            for x in candidates
        ],
    }
