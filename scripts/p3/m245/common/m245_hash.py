#!/usr/bin/env python3
"""
Hash helpers for M24.5.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    p = Path(path)
    h = hashlib.sha256()

    with p.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)

    return "sha256:" + h.hexdigest()


def normalize_hash(value: str | None) -> str | None:
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None
    if v.startswith("sha256:"):
        return v
    if len(v) == 64 and all(c in "0123456789abcdefABCDEF" for c in v):
        return "sha256:" + v.lower()
    return v
