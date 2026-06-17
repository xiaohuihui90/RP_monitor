#!/usr/bin/env python3
"""
Shared status enums for M24.5.
"""

FETCH_STATUS = [
    "success",
    "failed",
    "timeout",
    "skipped",
    "partial",
]

FAILURE_STAGE = [
    "none",
    "dns_resolve",
    "tcp_connect",
    "tls_handshake",
    "http_fetch",
    "rrdp_notification_fetch",
    "rrdp_snapshot_fetch",
    "rrdp_delta_fetch",
    "rrdp_xml_parse",
    "manifest_fetch",
    "manifest_cms_parse",
    "manifest_filelist_parse",
    "object_fetch",
    "object_hash_compute",
    "local_cache_lookup",
    "local_cache_write",
    "validator_vrp_export",
    "unknown",
]

ERROR_CLASS = [
    "NO_ERROR",
    "timeout",
    "dns_nxdomain",
    "dns_servfail",
    "dns_refused",
    "connection_refused",
    "no_route",
    "tls_error",
    "http_404",
    "http_403",
    "http_5xx",
    "rrdp_parse_error",
    "manifest_parse_error",
    "hash_mismatch",
    "local_index_miss",
    "validator_export_error",
    "permission_denied",
    "unknown",
]


def validate_enum(value: str, allowed: list[str], name: str) -> str:
    if value in allowed:
        return value
    raise ValueError(f"invalid {name}: {value}; allowed={allowed}")
