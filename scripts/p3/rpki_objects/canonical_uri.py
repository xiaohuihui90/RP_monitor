#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
S3 RPKI object canonical URI utilities.

This module converts cache-local URI/path representations into a stable,
cross-probe comparable object URI. It does not claim to reconstruct the
original publication URI perfectly; it creates S3's comparison key.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional


def _collapse_slashes(value: str) -> str:
    return re.sub(r"(?<!:)//+", "/", value)


def canonicalize_object_uri(raw_uri: str, source_root: Optional[str] = None) -> str:
    """
    Convert a cache-local URI/path into a cross-probe canonical object URI.

    Examples:
      cache://.rpki-cache/repository/stored/rrdp/x/rsync/rpki.ripe.net/a.mft
      cache://rpki-cache/stored/rrdp/y/rsync/rpki.ripe.net/a.mft
      /var/lib/routinator/rpki-cache/stored/rrdp/y/rsync/rpki.ripe.net/a.mft

    All become:
      cache://rsync/rpki.ripe.net/a.mft
    """
    if raw_uri is None:
        return ""

    u = str(raw_uri).strip().replace("\\", "/")
    if not u:
        return ""

    u = _collapse_slashes(u)

    # Remove explicit source root first if present.
    if source_root:
        root = str(source_root).strip().replace("\\", "/").rstrip("/") + "/"
        if u.startswith(root):
            u = u[len(root):]

    # Remove common absolute roots seen in S3 deployments.
    absolute_roots = [
        "/home/zhangxiaohui/.rpki-cache/",
        "/var/lib/routinator/rpki-cache/",
        "/var/cache/routinator/",
        "/home/zhangxiaohui/rpki-cache/",
    ]
    for root in absolute_roots:
        if u.startswith(root):
            u = u[len(root):]
            break

    # Remove cache:// wrapper.
    if u.startswith("cache://"):
        u = u[len("cache://"):]

    # Remove local cache root/layout names.
    removable_prefixes = [
        ".rpki-cache/repository/",
        ".rpki-cache/",
        "rpki-cache/repository/",
        "rpki-cache/",
        "routinator/rpki-cache/",
        "repository/",
    ]

    changed = True
    while changed:
        changed = False
        for prefix in removable_prefixes:
            if u.startswith(prefix):
                u = u[len(prefix):]
                changed = True

    # If repository/ remains after previous normalization, strip it.
    if u.startswith("repository/"):
        u = u[len("repository/"):]

    # Routinator RRDP stored layout often embeds the effective rsync path:
    # stored/rrdp/<repo>/<hash>/rsync/<host>/<path>
    m = re.search(r"(?:^|/)rsync/(.+)$", u)
    if m:
        return "cache://rsync/" + _collapse_slashes(m.group(1).lstrip("/"))

    # RRDP stored https layout.
    m = re.search(r"(?:^|/)https/(.+)$", u)
    if m:
        return "cache://https/" + _collapse_slashes(m.group(1).lstrip("/"))

    # Direct protocol-like trees.
    if u.startswith("rsync/"):
        return "cache://rsync/" + _collapse_slashes(u[len("rsync/"):].lstrip("/"))
    if u.startswith("https/"):
        return "cache://https/" + _collapse_slashes(u[len("https/"):].lstrip("/"))
    if u.startswith("rrdp/"):
        return "cache://rrdp/" + _collapse_slashes(u[len("rrdp/"):].lstrip("/"))

    if u.startswith("stored/rsync/"):
        return "cache://rsync/" + _collapse_slashes(u[len("stored/rsync/"):].lstrip("/"))
    if u.startswith("stored/rrdp/"):
        return "cache://stored/rrdp/" + _collapse_slashes(u[len("stored/rrdp/"):].lstrip("/"))

    if u.startswith("rsync://"):
        return "cache://rsync-uri/" + u[len("rsync://"):]
    if u.startswith("https://"):
        return "cache://https-uri/" + u[len("https://"):]
    if u.startswith("http://"):
        return "cache://http-uri/" + u[len("http://"):]

    # Last-resort: preserve enough information for diagnostics.
    return "cache://other/" + _collapse_slashes(u.lstrip("/"))


def object_type_from_uri(uri: str) -> str:
    suffix = Path(str(uri or "")).suffix.lower().lstrip(".")
    if suffix == "asa":
        return "aspa"
    return suffix or "unknown"


def repo_host_from_canonical_uri(canonical_uri: str) -> str:
    m = re.match(r"^cache://(?:rsync|https|rsync-uri|https-uri)/([^/]+)/", str(canonical_uri or ""))
    if m:
        return m.group(1)
    return "unknown"
