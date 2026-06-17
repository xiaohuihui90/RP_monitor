from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .enums import (
    ErrorClass,
    EventType,
    FailureStage,
    FetchErrorSubtype,
    FetchErrorType,
    FetchStatus,
    L2RequestType,
)


class Level1Record(BaseModel):
    probe_id: str
    probe_callback_url: str
    timestamp: datetime
    pp_id: str
    notification_uri: str
    config_fingerprint: str

    fetch_status: FetchStatus
    error_class: ErrorClass
    failure_stage: FailureStage
    fetch_error_type: FetchErrorType = FetchErrorType.none
    fetch_error_subtype: FetchErrorSubtype = FetchErrorSubtype.none
    exception_class: str | None = None
    latency_ms: int | None = None
    dns_latency_ms: int | None = None
    tcp_connect_latency_ms: int | None = None
    tls_handshake_latency_ms: int | None = None
    http_headers_latency_ms: int | None = None
    http_body_read_latency_ms: int | None = None
    notif_parse_latency_ms: int | None = None
    http_status: int | None = None

    session_id: str | None = None
    serial: int | None = None
    notif_digest: str | None = None
    raw_notification_sha256: str | None = None
    content_type: str | None = None
    body_len: int | None = None

    probe_boot_id: str | None = None
    sequence_no: int | None = None
    collector_target: str | None = None
    error_detail: str | None = None


class NotifRefsRecord(BaseModel):
    probe_id: str
    probe_callback_url: str
    pp_id: str
    timestamp: datetime
    event_id: str | None = None
    notification_uri: str
    config_fingerprint: str

    session_id: str
    serial: int
    snapshot_ref: str
    delta_refs: list[str] = Field(default_factory=list)
    notif_digest: str
    raw_notification_sha256: str
    http_headers: dict[str, str] = Field(default_factory=dict)


class PathEvidenceRecord(BaseModel):
    probe_id: str
    probe_callback_url: str
    pp_id: str
    timestamp: datetime
    event_id: str | None = None
    notification_uri: str
    config_fingerprint: str

    resolved_ip_set: list[str] = Field(default_factory=list)
    dns_error: str | None = None
    dns_duration_ms: int | None = None
    content_type: str | None = None
    etag: str | None = None
    last_modified: str | None = None
    age: str | None = None
    cache_control: str | None = None
    server: str | None = None
    tls_peer_summary: str | None = None
    fetch_error_type: FetchErrorType = FetchErrorType.none
    fetch_error_subtype: FetchErrorSubtype = FetchErrorSubtype.none
    exception_class: str | None = None
    http_status: int | None = None
    latency_ms: int | None = None
    error_detail: str | None = None


class IngestResponse(BaseModel):
    status: str = "ok"


class L2Request(BaseModel):
    event_id: str
    pp_id: str
    request_type: L2RequestType
    target_probes: list[str] = Field(default_factory=list)


class EventRecord(BaseModel):
    event_id: str
    event_type: EventType
    pp_id: str
    time_window_start: datetime
    time_window_end: datetime
    probes_involved: list[str] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    status: str = "open"
    candidate_causes: list[str] = Field(default_factory=list)
    l2_action_plan: list[str] = Field(default_factory=list)
    confidence: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)


class ValidatorCycleMetadataRecord(BaseModel):
    probe_id: str
    validator_type: str
    base_url: str
    collected_at: datetime
    source_endpoint: str
    serial: int | str | None = None
    session: str | None = None
    last_update_start: Any | None = None
    last_update_done: Any | None = None
    last_error: Any | None = None
    repository_count: int | None = None
    status_keys: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class ValidatorRepositoryStatusRecord(BaseModel):
    probe_id: str
    validator_type: str
    base_url: str
    collected_at: datetime
    source_endpoint: str
    repository_count: int | None = None
    repositories: Any = Field(default_factory=list)
    trust_anchors: Any | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class ValidatorOutputSummaryRecord(BaseModel):
    probe_id: str
    validator_type: str
    base_url: str
    collected_at: datetime
    source_endpoint: str
    vrp_count: float | None = None
    router_key_count: float | None = None
    aspa_count: float | None = None
    last_update_done: float | None = None
    metrics_excerpt: str | None = None


class RemediationAdviceRecord(BaseModel):
    event_id: str | None = None
    advice_level: str = "observe"
    recommended_actions: list[str] = Field(default_factory=list)
    evidence_basis: list[str] = Field(default_factory=list)
    candidate_causes: list[str] = Field(default_factory=list)


class EvidencePackRecord(BaseModel):
    event: dict[str, Any]
    level1_records: list[dict[str, Any]] = Field(default_factory=list)
    notif_refs: list[dict[str, Any]] = Field(default_factory=list)
    path_evidence: list[dict[str, Any]] = Field(default_factory=list)
    validator_cycle_metadata: list[dict[str, Any]] = Field(default_factory=list)
    validator_repository_status: list[dict[str, Any]] = Field(default_factory=list)
    validator_output_summary: list[dict[str, Any]] = Field(default_factory=list)
    evidence_basis: list[str] = Field(default_factory=list)
    candidate_causes: list[str] = Field(default_factory=list)
    remediation: RemediationAdviceRecord | None = None

class ProbeRuntime(BaseModel):
    probe_id: str
    probe_boot_id: str
    started_at: datetime
    sequence_no: int
    latest_pp_timestamp: dict[str, datetime | None]
    rp_adapter_enabled: bool
    routinator_enabled: bool
    latest_rp_cycle_metadata_ts: datetime | None = None
    latest_rp_repository_status_ts: datetime | None = None
    latest_rp_output_summary_ts: datetime | None = None
