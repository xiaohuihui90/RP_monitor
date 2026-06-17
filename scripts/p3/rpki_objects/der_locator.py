#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DER object locator.

Routinator cache wrapper files may contain metadata before embedded CMS
SignedData. This module scans bytes for ASN.1 DER SEQUENCE candidates and
extracts exact DER object length.
"""

from __future__ import annotations

from typing import Dict, List

from scripts.p3.rpki_objects.semantic_hash import sha256_bytes


class DerLengthError(ValueError):
    pass


def der_total_length(data: bytes, offset: int = 0) -> int:
    """
    Return exact DER object total length from offset.

    Supports definite short-form and long-form length. DER indefinite length
    is rejected.
    """
    if offset < 0 or offset >= len(data):
        raise DerLengthError("offset out of range")
    if data[offset] != 0x30:
        raise DerLengthError("not an ASN.1 SEQUENCE tag at offset")

    if offset + 2 > len(data):
        raise DerLengthError("truncated DER length")

    first_len = data[offset + 1]
    if first_len < 0x80:
        header_len = 2
        content_len = first_len
    else:
        n = first_len & 0x7F
        if n == 0:
            raise DerLengthError("indefinite length is not valid DER")
        if n > 8:
            raise DerLengthError("unsupported DER length octet count")
        if offset + 2 + n > len(data):
            raise DerLengthError("truncated long-form DER length")
        header_len = 2 + n
        content_len = int.from_bytes(data[offset + 2: offset + 2 + n], "big")

    total = header_len + content_len
    if total <= 0:
        raise DerLengthError("invalid DER length")
    if offset + total > len(data):
        raise DerLengthError("DER object exceeds buffer")

    return total


def find_der_sequence_candidates(data: bytes) -> List[int]:
    return [i for i, b in enumerate(data) if b == 0x30]


def extract_der_objects(data: bytes, max_candidates: int = 10000) -> List[Dict[str, object]]:
    """
    Return DER SEQUENCE candidates with exact slices and hashes.

    This function does not guarantee the sequence is CMS; CMS parsing happens
    in cms_extract.py.
    """
    results: List[Dict[str, object]] = []
    for off in find_der_sequence_candidates(data):
        if len(results) >= max_candidates:
            break
        try:
            total = der_total_length(data, off)
            der = data[off: off + total]
            results.append({
                "offset": off,
                "der_len": total,
                "der_sha256": sha256_bytes(der),
                "der": der,
            })
        except Exception:
            continue
    return results
