from __future__ import annotations

from enum import Enum


class FetchStatus(str, Enum):
    success = "success"
    fail = "fail"
    partial = "partial"
    stale = "stale"


class ErrorClass(str, Enum):
    none = "none"
    timeout = "timeout"
    non_timeout = "non_timeout"

    connection_error = "connection_error"
    tls_error = "tls_error"
    http_status_error = "http_status_error"
    body_incomplete = "body_incomplete"
    decode_error = "decode_error"
    xml_parse_error = "xml_parse_error"
    io_error = "io_error"
    unknown_error = "unknown_error"

class FailureStage(str, Enum):
    none = "none"
    notif_fetch = "notif_fetch"
    notif_parse = "notif_parse"
    report = "report"

    dns_resolve = "dns_resolve"
    tcp_connect = "tcp_connect"
    tls_handshake = "tls_handshake"
    http_headers = "http_headers"
    http_body_read = "http_body_read"
    notif_decode = "notif_decode"
    notif_xml_parse = "notif_xml_parse"
    snapshot_fetch = "snapshot_fetch"
    inventory_build = "inventory_build"
    object_root_build = "object_root_build"

class FetchErrorType(str, Enum):
    none = "none"
    timeout = "timeout"
    dns_failure = "dns_failure"
    tcp_connect_failure = "tcp_connect_failure"
    tls_failure = "tls_failure"
    http_status_failure = "http_status_failure"
    http_protocol_failure = "http_protocol_failure"
    redirect_failure = "redirect_failure"
    unknown_fetch_failure = "unknown_fetch_failure"


class FetchErrorSubtype(str, Enum):
    none = "none"
    connect_timeout = "connect_timeout"
    read_timeout = "read_timeout"
    write_timeout = "write_timeout"
    pool_timeout = "pool_timeout"
    name_resolution_failed = "name_resolution_failed"
    connection_refused = "connection_refused"
    network_unreachable = "network_unreachable"
    host_unreachable = "host_unreachable"
    connection_reset = "connection_reset"
    certificate_verify_failed = "certificate_verify_failed"
    tls_handshake_failed = "tls_handshake_failed"
    http_4xx = "http_4xx"
    http_5xx = "http_5xx"
    http_other_status = "http_other_status"
    remote_protocol_error = "remote_protocol_error"
    too_many_redirects = "too_many_redirects"
    unknown = "unknown"


class L2RequestType(str, Enum):
    notif_refs = "notif_refs"
    path_evidence = "path_evidence"
    notification_refetch = "notification_refetch"
    object_set_collect = "object_set_collect"
    rp_output_collect = "rp_output_collect"


class EventType(str, Enum):
    e3_1 = "E3-1"
    e3_2 = "E3-2"
