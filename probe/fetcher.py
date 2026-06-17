from __future__ import annotations

import asyncio
import errno
import socket
import ssl
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import httpx

from shared.enums import ErrorClass, FailureStage, FetchErrorSubtype, FetchErrorType, FetchStatus
from shared.utils import utcnow


@dataclass
class RawFetchResult:
    pp_id: str
    started_at: object
    ended_at: object
    fetch_status: FetchStatus
    error_class: ErrorClass
    failure_stage: FailureStage
    fetch_error_type: FetchErrorType
    fetch_error_subtype: FetchErrorSubtype
    exception_class: str | None
    latency_ms: Optional[int]
    http_status: Optional[int]
    raw_body: Optional[bytes]
    headers: dict[str, str]
    error_detail: Optional[str]
    resolved_ip_set: list[str]
    dns_duration_ms: int | None
    dns_error: str | None
    tls_peer_summary: str | None
    dns_latency_ms: int | None = None
    tcp_connect_latency_ms: int | None = None
    tls_handshake_latency_ms: int | None = None
    http_headers_latency_ms: int | None = None
    http_body_read_latency_ms: int | None = None
    notif_parse_latency_ms: int | None = None


async def resolve_host(uri: str) -> tuple[list[str], int | None, str | None]:
    parsed = urlparse(uri)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return [], None, "missing hostname"

    started = utcnow()
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ended = utcnow()
        ips = sorted({item[4][0] for item in infos})
        return ips, int((ended - started).total_seconds() * 1000), None
    except Exception as exc:
        ended = utcnow()
        return [], int((ended - started).total_seconds() * 1000), _detail(exc)


def _iter_exception_chain(exc: BaseException):
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        yield cur
        nxt = cur.__cause__ or cur.__context__
        cur = nxt if isinstance(nxt, BaseException) else None


def _detail(exc: BaseException) -> str:
    parts = []
    for item in _iter_exception_chain(exc):
        text = f"{item.__class__.__name__}: {item}".strip()
        if text and text not in parts:
            parts.append(text)
    return " | ".join(parts)


def _contains_text(exc: BaseException, needles: list[str]) -> bool:
    text = _detail(exc).lower()
    return any(n in text for n in needles)


def _classify_timeout(exc: BaseException) -> tuple[FetchErrorType, FetchErrorSubtype]:
    name = exc.__class__.__name__
    if name == "ConnectTimeout":
        return FetchErrorType.timeout, FetchErrorSubtype.connect_timeout
    if name == "ReadTimeout":
        return FetchErrorType.timeout, FetchErrorSubtype.read_timeout
    if name == "WriteTimeout":
        return FetchErrorType.timeout, FetchErrorSubtype.write_timeout
    if name == "PoolTimeout":
        return FetchErrorType.timeout, FetchErrorSubtype.pool_timeout
    return FetchErrorType.timeout, FetchErrorSubtype.unknown


def _classify_exception(exc: BaseException) -> tuple[FetchErrorType, FetchErrorSubtype]:
    detail_lower = _detail(exc).lower()

    if isinstance(exc, httpx.TimeoutException):
        return _classify_timeout(exc)
    if isinstance(exc, httpx.TooManyRedirects):
        return FetchErrorType.redirect_failure, FetchErrorSubtype.too_many_redirects
    if isinstance(exc, httpx.RemoteProtocolError):
        return FetchErrorType.http_protocol_failure, FetchErrorSubtype.remote_protocol_error

    for item in _iter_exception_chain(exc):
        if isinstance(item, socket.gaierror):
            return FetchErrorType.dns_failure, FetchErrorSubtype.name_resolution_failed
        if isinstance(item, ssl.SSLCertVerificationError):
            return FetchErrorType.tls_failure, FetchErrorSubtype.certificate_verify_failed
        if isinstance(item, ssl.SSLError):
            return FetchErrorType.tls_failure, FetchErrorSubtype.tls_handshake_failed
        if isinstance(item, ConnectionRefusedError):
            return FetchErrorType.tcp_connect_failure, FetchErrorSubtype.connection_refused
        if isinstance(item, ConnectionResetError):
            return FetchErrorType.tcp_connect_failure, FetchErrorSubtype.connection_reset
        if isinstance(item, OSError):
            if item.errno == errno.ENETUNREACH:
                return FetchErrorType.tcp_connect_failure, FetchErrorSubtype.network_unreachable
            if item.errno == errno.EHOSTUNREACH:
                return FetchErrorType.tcp_connect_failure, FetchErrorSubtype.host_unreachable
            if item.errno == errno.ECONNREFUSED:
                return FetchErrorType.tcp_connect_failure, FetchErrorSubtype.connection_refused

    if _contains_text(exc, ["temporary failure in name resolution", "name or service not known", "nodename nor servname provided", "getaddrinfo failed"]):
        return FetchErrorType.dns_failure, FetchErrorSubtype.name_resolution_failed
    if _contains_text(exc, ["certificate verify failed", "tlsv1 alert", "ssl:", "wrong version number", "handshake failure"]):
        if "certificate verify failed" in detail_lower:
            return FetchErrorType.tls_failure, FetchErrorSubtype.certificate_verify_failed
        return FetchErrorType.tls_failure, FetchErrorSubtype.tls_handshake_failed
    if _contains_text(exc, ["connection refused"]):
        return FetchErrorType.tcp_connect_failure, FetchErrorSubtype.connection_refused
    if _contains_text(exc, ["network is unreachable"]):
        return FetchErrorType.tcp_connect_failure, FetchErrorSubtype.network_unreachable
    if _contains_text(exc, ["no route to host", "host is unreachable"]):
        return FetchErrorType.tcp_connect_failure, FetchErrorSubtype.host_unreachable
    if _contains_text(exc, ["connection reset by peer"]):
        return FetchErrorType.tcp_connect_failure, FetchErrorSubtype.connection_reset
    if isinstance(exc, httpx.ConnectError):
        return FetchErrorType.tcp_connect_failure, FetchErrorSubtype.unknown

    return FetchErrorType.unknown_fetch_failure, FetchErrorSubtype.unknown


def _http_status_subtype(status_code: int) -> FetchErrorSubtype:
    if 400 <= status_code <= 499:
        return FetchErrorSubtype.http_4xx
    if 500 <= status_code <= 599:
        return FetchErrorSubtype.http_5xx
    return FetchErrorSubtype.http_other_status


def _failure_stage_for_fetch_error(err_type: FetchErrorType, err_subtype: FetchErrorSubtype) -> FailureStage:
    if err_type == FetchErrorType.dns_failure:
        return FailureStage.dns_resolve
    if err_type == FetchErrorType.tcp_connect_failure:
        return FailureStage.tcp_connect
    if err_type == FetchErrorType.tls_failure:
        return FailureStage.tls_handshake
    if err_type == FetchErrorType.http_status_failure:
        return FailureStage.http_headers
    if err_type == FetchErrorType.http_protocol_failure:
        return FailureStage.http_body_read
    if err_type == FetchErrorType.redirect_failure:
        return FailureStage.http_headers
    if err_type == FetchErrorType.timeout:
        if err_subtype == FetchErrorSubtype.connect_timeout:
            return FailureStage.tcp_connect
        if err_subtype in {FetchErrorSubtype.read_timeout, FetchErrorSubtype.write_timeout}:
            return FailureStage.http_body_read
        return FailureStage.http_headers
    return FailureStage.notif_fetch


def _error_class_for_fetch_error(err_type: FetchErrorType) -> ErrorClass:
    if err_type == FetchErrorType.timeout:
        return ErrorClass.timeout
    if err_type in {FetchErrorType.dns_failure, FetchErrorType.tcp_connect_failure}:
        return ErrorClass.connection_error
    if err_type == FetchErrorType.tls_failure:
        return ErrorClass.tls_error
    if err_type == FetchErrorType.http_status_failure:
        return ErrorClass.http_status_error
    if err_type == FetchErrorType.http_protocol_failure:
        return ErrorClass.body_incomplete
    if err_type == FetchErrorType.redirect_failure:
        return ErrorClass.http_status_error
    return ErrorClass.unknown_error


async def fetch_notification(pp_id: str, uri: str, timeout_s: int) -> RawFetchResult:
    max_attempts = 2
    resolved_ip_set, dns_duration_ms, dns_error = await resolve_host(uri)

    for attempt in range(1, max_attempts + 1):
        started = utcnow()
        try:
            async with httpx.AsyncClient(timeout=timeout_s, follow_redirects=True) as client:
                resp = await client.get(uri)

            ended = utcnow()
            latency_ms = int((ended - started).total_seconds() * 1000)
            tls_peer_summary = None

            if resp.status_code != 200:
                return RawFetchResult(
                    pp_id=pp_id,
                    started_at=started,
                    ended_at=ended,
                    fetch_status=FetchStatus.fail,
                    error_class=ErrorClass.http_status_error,
                    failure_stage=FailureStage.http_headers,
                    fetch_error_type=FetchErrorType.http_status_failure,
                    fetch_error_subtype=_http_status_subtype(resp.status_code),
                    exception_class=None,
                    latency_ms=latency_ms,
                    http_status=resp.status_code,
                    raw_body=resp.content,
                    headers=dict(resp.headers),
                    error_detail=f"HTTP {resp.status_code}",
                    resolved_ip_set=resolved_ip_set,
                    dns_duration_ms=dns_duration_ms,
                    dns_error=dns_error,
                    tls_peer_summary=tls_peer_summary,
                    dns_latency_ms=dns_duration_ms,
                    http_body_read_latency_ms=latency_ms,
                )

            return RawFetchResult(
                pp_id=pp_id,
                started_at=started,
                ended_at=ended,
                fetch_status=FetchStatus.success,
                error_class=ErrorClass.none,
                failure_stage=FailureStage.none,
                fetch_error_type=FetchErrorType.none,
                fetch_error_subtype=FetchErrorSubtype.none,
                exception_class=None,
                latency_ms=latency_ms,
                http_status=resp.status_code,
                raw_body=resp.content,
                headers=dict(resp.headers),
                error_detail=None,
                resolved_ip_set=resolved_ip_set,
                dns_duration_ms=dns_duration_ms,
                dns_error=dns_error,
                tls_peer_summary=tls_peer_summary,
                dns_latency_ms=dns_duration_ms,
                http_body_read_latency_ms=latency_ms,
            )

        except httpx.TimeoutException as exc:
            ended = utcnow()
            latency_ms = int((ended - started).total_seconds() * 1000)
            if attempt < max_attempts:
                await asyncio.sleep(1)
                continue

            err_type, err_subtype = _classify_timeout(exc)
            failure_stage = _failure_stage_for_fetch_error(err_type, err_subtype)

            return RawFetchResult(
                pp_id=pp_id,
                started_at=started,
                ended_at=ended,
                fetch_status=FetchStatus.fail,
                error_class=ErrorClass.timeout,
                failure_stage=failure_stage,
                fetch_error_type=err_type,
                fetch_error_subtype=err_subtype,
                exception_class=exc.__class__.__name__,
                latency_ms=latency_ms,
                http_status=None,
                raw_body=None,
                headers={},
                error_detail=_detail(exc),
                resolved_ip_set=resolved_ip_set,
                dns_duration_ms=dns_duration_ms,
                dns_error=dns_error,
                tls_peer_summary=None,
                dns_latency_ms=dns_duration_ms,
                http_body_read_latency_ms=latency_ms if failure_stage == FailureStage.http_body_read else None,
                tcp_connect_latency_ms=latency_ms if failure_stage == FailureStage.tcp_connect else None,
            )

        except Exception as exc:
            ended = utcnow()
            latency_ms = int((ended - started).total_seconds() * 1000)
            if attempt < max_attempts:
                await asyncio.sleep(1)
                continue

            err_type, err_subtype = _classify_exception(exc)
            failure_stage = _failure_stage_for_fetch_error(err_type, err_subtype)
            error_class = _error_class_for_fetch_error(err_type)

            if dns_error and not resolved_ip_set and err_type == FetchErrorType.unknown_fetch_failure:
                failure_stage = FailureStage.dns_resolve
                error_class = ErrorClass.connection_error

            return RawFetchResult(
                pp_id=pp_id,
                started_at=started,
                ended_at=ended,
                fetch_status=FetchStatus.fail,
                error_class=error_class,
                failure_stage=failure_stage,
                fetch_error_type=err_type,
                fetch_error_subtype=err_subtype,
                exception_class=exc.__class__.__name__,
                latency_ms=latency_ms,
                http_status=None,
                raw_body=None,
                headers={},
                error_detail=_detail(exc),
                resolved_ip_set=resolved_ip_set,
                dns_duration_ms=dns_duration_ms,
                dns_error=dns_error,
                tls_peer_summary=None,
                dns_latency_ms=dns_duration_ms,
                tcp_connect_latency_ms=latency_ms if failure_stage == FailureStage.tcp_connect else None,
                tls_handshake_latency_ms=latency_ms if failure_stage == FailureStage.tls_handshake else None,
                http_body_read_latency_ms=latency_ms if failure_stage == FailureStage.http_body_read else None,
            )
