#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hash helpers for S3 semantic RPKI object comparison.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def canonical_json_dumps(obj: Any) -> str:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_json_hash(obj: Any) -> str:
    return sha256_bytes(canonical_json_dumps(obj).encode("utf-8"))


def normalize_sha256(value: str) -> str:
    v = str(value or "").strip()
    if not v:
        return ""
    if v.startswith("sha256:"):
        return "sha256:" + v.split("sha256:", 1)[1].lower()
    if len(v) == 64 and all(c in "0123456789abcdefABCDEF" for c in v):
        return "sha256:" + v.lower()
    return v
