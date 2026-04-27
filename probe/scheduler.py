from __future__ import annotations

import asyncio
from pathlib import Path

from rp_adapters.routinator.adapter import RoutinatorAdapter
from shared.config import ProbeConfig
from shared.enums import ErrorClass, FailureStage, FetchErrorSubtype, FetchErrorType, FetchStatus
from shared.rrdp import NotificationParseError, compute_notif_digest, parse_notification
from shared.schemas import (
    Level1Record,
    NotifRefsRecord,
    PathEvidenceRecord,
    ValidatorCycleMetadataRecord,
    ValidatorOutputSummaryRecord,
    ValidatorRepositoryStatusRecord,
)
from shared.utils import gen_id, json_sha256, setup_json_logger, sha256_hex, utcnow

from .fetcher import RawFetchResult, fetch_notification
from .reporter import CollectorReporter


def _header(headers: dict[str, str], name: str) -> str | None:
    lname = name.lower()
    for k, v in headers.items():
        if k.lower() == lname:
            return v
    return None


class ProbeScheduler:
    def __init__(self, config: ProbeConfig, reporter: CollectorReporter):
        self.config = config
        self.reporter = reporter
        self.logger = setup_json_logger(f"probe.{config.probe_id}", config.log_file)

        self.latest_notif_refs: dict[str, NotifRefsRecord] = {}
        self.latest_path_evidence: dict[str, PathEvidenceRecord] = {}

        self.latest_rp_cycle_metadata: ValidatorCycleMetadataRecord | None = None
        self.latest_rp_repository_status: ValidatorRepositoryStatusRecord | None = None
        self.latest_rp_output_summary: ValidatorOutputSummaryRecord | None = None

        self.boot_id = gen_id("boot")
        self.started_at = utcnow()
        self.sequence_no = 0
        self.latest_pp_timestamp: dict[str, object | None] = {pp.pp_id: None for pp in config.pps}

        Path(self.config.artifact_dir).mkdir(parents=True, exist_ok=True)
        self.config_fingerprint = json_sha256(
            {
                "probe_id": config.probe_id,
                "collector_url": config.collector_url,
                "pps": [pp.model_dump() for pp in config.pps],
                "routinator": config.routinator.model_dump(),
            }
        )

        self.rp_adapter = None
        if self.config.routinator.enabled:
            self.rp_adapter = RoutinatorAdapter(
                probe_id=self.config.probe_id,
                base_url=self.config.routinator.base_url,
                timeout_seconds=self.config.routinator.timeout_seconds,
            )

    async def _maybe_collect_rp_status(self) -> None:
        if not self.rp_adapter:
            return
        try:
            cycle = ValidatorCycleMetadataRecord(**(await self.rp_adapter.collect_cycle_metadata()))
            self.latest_rp_cycle_metadata = cycle
            await self.reporter.send_validator_cycle_metadata(cycle)
        except Exception as exc:
            self.logger.warning("rp_cycle_metadata_collect_failed", extra={"extra_json": {"probe_id": self.config.probe_id, "error": str(exc)}})
        try:
            repo = ValidatorRepositoryStatusRecord(**(await self.rp_adapter.collect_repository_status()))
            self.latest_rp_repository_status = repo
            await self.reporter.send_validator_repository_status(repo)
        except Exception as exc:
            self.logger.warning("rp_repository_status_collect_failed", extra={"extra_json": {"probe_id": self.config.probe_id, "error": str(exc)}})
        try:
            output = ValidatorOutputSummaryRecord(**(await self.rp_adapter.collect_output_summary()))
            self.latest_rp_output_summary = output
            await self.reporter.send_validator_output_summary(output)
        except Exception as exc:
            self.logger.warning("rp_output_summary_collect_failed", extra={"extra_json": {"probe_id": self.config.probe_id, "error": str(exc)}})

    def _path_evidence_from_fetch(self, *, pp, timestamp, fetch_result: RawFetchResult) -> PathEvidenceRecord:
        headers = fetch_result.headers or {}
        return PathEvidenceRecord(
            probe_id=self.config.probe_id,
            probe_callback_url=self.config.public_base_url,
            pp_id=pp.pp_id,
            timestamp=timestamp,
            event_id=None,
            notification_uri=pp.notification_uri,
            config_fingerprint=self.config_fingerprint,
            resolved_ip_set=fetch_result.resolved_ip_set,
            dns_error=fetch_result.dns_error,
            dns_duration_ms=fetch_result.dns_duration_ms,
            content_type=_header(headers, "content-type"),
            etag=_header(headers, "etag"),
            last_modified=_header(headers, "last-modified"),
            age=_header(headers, "age"),
            cache_control=_header(headers, "cache-control"),
            server=_header(headers, "server"),
            tls_peer_summary=fetch_result.tls_peer_summary,
            fetch_error_type=fetch_result.fetch_error_type,
            fetch_error_subtype=fetch_result.fetch_error_subtype,
            exception_class=fetch_result.exception_class,
            http_status=fetch_result.http_status,
            latency_ms=fetch_result.latency_ms,
            error_detail=fetch_result.error_detail,
        )

    async def _collect_one_pp(self, pp) -> None:
        if not pp.enabled:
            return

        started = utcnow()
        self.latest_pp_timestamp[pp.pp_id] = started
        self.sequence_no += 1

        fetch_result = await fetch_notification(
            pp_id=pp.pp_id,
            uri=pp.notification_uri,
            timeout_s=self.config.http_timeout_seconds,
        )

        path_evidence = self._path_evidence_from_fetch(pp=pp, timestamp=started, fetch_result=fetch_result)
        self.latest_path_evidence[pp.pp_id] = path_evidence

        headers = fetch_result.headers or {}
        raw_body = fetch_result.raw_body

        if fetch_result.fetch_status != FetchStatus.success or raw_body is None:
            level1 = Level1Record(
                probe_id=self.config.probe_id,
                probe_callback_url=self.config.public_base_url,
                timestamp=started,
                pp_id=pp.pp_id,
                notification_uri=pp.notification_uri,
                config_fingerprint=self.config_fingerprint,
                fetch_status=FetchStatus.fail,
                error_class=fetch_result.error_class,
                failure_stage=fetch_result.failure_stage,
                fetch_error_type=fetch_result.fetch_error_type,
                fetch_error_subtype=fetch_result.fetch_error_subtype,
                exception_class=fetch_result.exception_class,
                latency_ms=fetch_result.latency_ms,
                dns_latency_ms=fetch_result.dns_latency_ms,
                tcp_connect_latency_ms=fetch_result.tcp_connect_latency_ms,
                tls_handshake_latency_ms=fetch_result.tls_handshake_latency_ms,
                http_headers_latency_ms=fetch_result.http_headers_latency_ms,
                http_body_read_latency_ms=fetch_result.http_body_read_latency_ms,
                notif_parse_latency_ms=None,
                http_status=fetch_result.http_status,
                session_id=None,
                serial=None,
                notif_digest=None,
                raw_notification_sha256=sha256_hex(raw_body) if raw_body else None,
                content_type=_header(headers, "content-type"),
                body_len=len(raw_body) if raw_body else None,
                probe_boot_id=self.boot_id,
                sequence_no=self.sequence_no,
                collector_target=self.config.collector_url,
                error_detail=fetch_result.error_detail,
            )
            await self.reporter.send_level1(level1)
            self.logger.warning("level1_fetch_failed", extra={"extra_json": level1.model_dump(mode="json")})
            return

        parse_started = utcnow()
        try:
            parsed = parse_notification(raw_body)
            parse_ended = utcnow()
            notif_parse_latency_ms = int((parse_ended - parse_started).total_seconds() * 1000)
        except Exception as exc:
            parse_ended = utcnow()
            notif_parse_latency_ms = int((parse_ended - parse_started).total_seconds() * 1000)
            error_class = ErrorClass.xml_parse_error if isinstance(exc, NotificationParseError) else ErrorClass.unknown_error
            level1 = Level1Record(
                probe_id=self.config.probe_id,
                probe_callback_url=self.config.public_base_url,
                timestamp=started,
                pp_id=pp.pp_id,
                notification_uri=pp.notification_uri,
                config_fingerprint=self.config_fingerprint,
                fetch_status=FetchStatus.fail,
                error_class=error_class,
                failure_stage=FailureStage.notif_xml_parse,
                fetch_error_type=FetchErrorType.unknown_fetch_failure,
                fetch_error_subtype=FetchErrorSubtype.unknown,
                exception_class=exc.__class__.__name__,
                latency_ms=fetch_result.latency_ms,
                dns_latency_ms=fetch_result.dns_latency_ms,
                tcp_connect_latency_ms=fetch_result.tcp_connect_latency_ms,
                tls_handshake_latency_ms=fetch_result.tls_handshake_latency_ms,
                http_headers_latency_ms=fetch_result.http_headers_latency_ms,
                http_body_read_latency_ms=fetch_result.http_body_read_latency_ms,
                notif_parse_latency_ms=notif_parse_latency_ms,
                http_status=fetch_result.http_status,
                session_id=None,
                serial=None,
                notif_digest=None,
                raw_notification_sha256=sha256_hex(raw_body),
                content_type=_header(headers, "content-type"),
                body_len=len(raw_body),
                probe_boot_id=self.boot_id,
                sequence_no=self.sequence_no,
                collector_target=self.config.collector_url,
                error_detail=str(exc),
            )
            await self.reporter.send_level1(level1)
            self.logger.warning("level1_parse_failed", extra={"extra_json": level1.model_dump(mode="json")})
            return

        notif_digest = compute_notif_digest(parsed)
        raw_sha256 = sha256_hex(raw_body)

        level1 = Level1Record(
            probe_id=self.config.probe_id,
            probe_callback_url=self.config.public_base_url,
            timestamp=started,
            pp_id=pp.pp_id,
            notification_uri=pp.notification_uri,
            config_fingerprint=self.config_fingerprint,
            fetch_status=FetchStatus.success,
            error_class=ErrorClass.none,
            failure_stage=FailureStage.none,
            fetch_error_type=FetchErrorType.none,
            fetch_error_subtype=FetchErrorSubtype.none,
            exception_class=None,
            latency_ms=fetch_result.latency_ms,
            dns_latency_ms=fetch_result.dns_latency_ms,
            tcp_connect_latency_ms=fetch_result.tcp_connect_latency_ms,
            tls_handshake_latency_ms=fetch_result.tls_handshake_latency_ms,
            http_headers_latency_ms=fetch_result.http_headers_latency_ms,
            http_body_read_latency_ms=fetch_result.http_body_read_latency_ms,
            notif_parse_latency_ms=notif_parse_latency_ms,
            http_status=fetch_result.http_status,
            session_id=parsed.session_id,
            serial=parsed.serial,
            notif_digest=notif_digest,
            raw_notification_sha256=raw_sha256,
            content_type=_header(headers, "content-type"),
            body_len=len(raw_body),
            probe_boot_id=self.boot_id,
            sequence_no=self.sequence_no,
            collector_target=self.config.collector_url,
            error_detail=None,
        )
        await self.reporter.send_level1(level1)
        self.logger.info("level1_success", extra={"extra_json": level1.model_dump(mode="json")})

        notif_refs = NotifRefsRecord(
            probe_id=self.config.probe_id,
            probe_callback_url=self.config.public_base_url,
            pp_id=pp.pp_id,
            timestamp=started,
            event_id=None,
            notification_uri=pp.notification_uri,
            config_fingerprint=self.config_fingerprint,
            session_id=parsed.session_id,
            serial=parsed.serial,
            snapshot_ref=parsed.snapshot_ref,
            delta_refs=parsed.delta_refs,
            notif_digest=notif_digest,
            raw_notification_sha256=raw_sha256,
            http_headers=headers,
        )
        self.latest_notif_refs[pp.pp_id] = notif_refs

    async def collect_once(self) -> None:
        for pp in self.config.pps:
            try:
                await self._collect_one_pp(pp)
            except Exception as exc:
                self.logger.exception(
                    "collect_one_pp_unhandled_exception",
                    extra={"extra_json": {"probe_id": self.config.probe_id, "pp_id": getattr(pp, "pp_id", None), "error": str(exc)}},
                )
        await self._maybe_collect_rp_status()

    async def loop_forever(self) -> None:
        await self.run_forever()

    async def run_forever(self) -> None:
        while True:
            await self.collect_once()
            await asyncio.sleep(self.config.poll_interval_seconds)
