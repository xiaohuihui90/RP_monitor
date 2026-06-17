#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wrapper detection for RPKI object source bytes.
"""

from __future__ import annotations

import re
from typing import Dict, List

from scripts.p3.rpki_objects.der_locator import extract_der_objects
from scripts.p3.rpki_objects.semantic_hash import sha256_bytes


def ascii_hints(data: bytes, limit: int = 2048) -> List[str]:
    hints: List[str] = []
    cur: List[str] = []

    for b in data[:limit]:
        if 32 <= b <= 126:
            cur.append(chr(b))
        else:
            if len(cur) >= 4:
                hints.append("".join(cur))
            cur = []
    if len(cur) >= 4:
        hints.append("".join(cur))

    # Keep strings that are useful for RPKI cache wrapper diagnostics.
    selected = []
    for h in hints:
        if (
            "rsync://" in h
            or "https://" in h
            or "notification.xml" in h
            or re.search(r"20\d{12}Z", h)
        ):
            selected.append(h)
    return selected[:50]


def detect_wrapper(data: bytes) -> Dict[str, object]:
    """
    Detect whether bytes look like raw DER/CMS or a cache wrapper containing CMS.
    """
    result: Dict[str, object] = {
        "wrapper_detected": False,
        "wrapper_type": "none",
        "wrapper_sha256": sha256_bytes(data),
        "wrapper_size": len(data),
        "starts_with_der_sequence": bool(data[:1] == b"\x30"),
        "ascii_hints": ascii_hints(data),
        "der_candidate_offsets": [],
    }

    der_candidates = extract_der_objects(data, max_candidates=5000)
    result["der_candidate_offsets"] = [x["offset"] for x in der_candidates[:20]]
    result["der_candidate_count"] = len(der_candidates)

    if not data.startswith(b"\x30") and der_candidates:
        result["wrapper_detected"] = True
        hints = " ".join(result["ascii_hints"])
        if "rsync://" in hints or "notification.xml" in hints or "https://" in hints:
            result["wrapper_type"] = "routinator_cache_wrapper"
        else:
            result["wrapper_type"] = "unknown_wrapper"

    return result
