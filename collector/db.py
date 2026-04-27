from __future__ import annotations

import json
import sqlite3
from typing import Any

from shared.schemas import EventRecord, L2Request, Level1Record, NotifRefsRecord, PathEvidenceRecord, ValidatorCycleMetadataRecord, ValidatorRepositoryStatusRecord, ValidatorOutputSummaryRecord
from shared.utils import mkdir_parent, utcnow


class CollectorDB:
    def __init__(self, db_path: str):
        mkdir_parent(db_path)
        self.db_path = db_path
        self._init_db()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS level1_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    probe_id TEXT NOT NULL,
                    probe_callback_url TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    pp_id TEXT NOT NULL,
                    notification_uri TEXT NOT NULL,
                    config_fingerprint TEXT NOT NULL,
                    fetch_status TEXT NOT NULL,
                    error_class TEXT NOT NULL,
                    failure_stage TEXT NOT NULL,
                    fetch_error_type TEXT DEFAULT 'none',
                    fetch_error_subtype TEXT DEFAULT 'none',
                    exception_class TEXT,
                    latency_ms INTEGER,
                    http_status INTEGER,
                    session_id TEXT,
                    serial INTEGER,
                    notif_digest TEXT,
                    raw_notification_sha256 TEXT,
                    content_type TEXT,
                    body_len INTEGER,
                    probe_boot_id TEXT,
                    sequence_no INTEGER,
                    collector_target TEXT,
                    error_detail TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_l1_pp_ts ON level1_records(pp_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_l1_probe_ts ON level1_records(probe_id, timestamp);

                CREATE TABLE IF NOT EXISTS notif_refs_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    probe_id TEXT NOT NULL,
                    probe_callback_url TEXT NOT NULL,
                    pp_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_id TEXT,
                    notification_uri TEXT NOT NULL,
                    config_fingerprint TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    serial INTEGER NOT NULL,
                    snapshot_ref TEXT NOT NULL,
                    delta_refs_json TEXT NOT NULL,
                    notif_digest TEXT NOT NULL,
                    raw_notification_sha256 TEXT NOT NULL,
                    http_headers_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_nr_pp_ts ON notif_refs_records(pp_id, timestamp);

                CREATE TABLE IF NOT EXISTS path_evidence_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    probe_id TEXT NOT NULL,
                    probe_callback_url TEXT NOT NULL,
                    pp_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_id TEXT,
                    notification_uri TEXT NOT NULL,
                    config_fingerprint TEXT NOT NULL,
                    resolved_ip_set_json TEXT NOT NULL,
                    dns_error TEXT,
                    dns_duration_ms INTEGER,
                    content_type TEXT,
                    etag TEXT,
                    last_modified TEXT,
                    age TEXT,
                    cache_control TEXT,
                    server TEXT,
                    tls_peer_summary TEXT,
                    fetch_error_type TEXT DEFAULT 'none',
                    fetch_error_subtype TEXT DEFAULT 'none',
                    exception_class TEXT,
                    http_status INTEGER,
                    latency_ms INTEGER,
                    error_detail TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_pe_pp_ts ON path_evidence_records(pp_id, timestamp);

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    pp_id TEXT NOT NULL,
                    time_window_start TEXT NOT NULL,
                    time_window_end TEXT NOT NULL,
                    probes_involved_json TEXT NOT NULL,
                    summary_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    candidate_causes_json TEXT NOT NULL,
                    l2_action_plan_json TEXT NOT NULL,
                    confidence TEXT,
                    evidence_refs_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_pp_ws ON events(pp_id, time_window_start);

                CREATE TABLE IF NOT EXISTS validator_cycle_metadata_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    probe_id TEXT NOT NULL,
                    validator_type TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    source_endpoint TEXT NOT NULL,
                    serial TEXT,
                    session TEXT,
                    last_update_start TEXT,
                    last_update_done TEXT,
                    last_error_json TEXT,
                    repository_count INTEGER,
                    status_keys_json TEXT NOT NULL,
                    raw_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_vcm_probe_ts ON validator_cycle_metadata_records(probe_id, collected_at);

                CREATE TABLE IF NOT EXISTS validator_repository_status_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    probe_id TEXT NOT NULL,
                    validator_type TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    source_endpoint TEXT NOT NULL,
                    repository_count INTEGER,
                    repositories_json TEXT NOT NULL,
                    trust_anchors_json TEXT,
                    raw_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_vrs_probe_ts ON validator_repository_status_records(probe_id, collected_at);

                CREATE TABLE IF NOT EXISTS validator_output_summary_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    probe_id TEXT NOT NULL,
                    validator_type TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    source_endpoint TEXT NOT NULL,
                    vrp_count REAL,
                    router_key_count REAL,
                    aspa_count REAL,
                    last_update_done REAL,
                    metrics_excerpt TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_vos_probe_ts ON validator_output_summary_records(probe_id, collected_at);

                CREATE TABLE IF NOT EXISTS l2_dispatches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dispatched_at TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    pp_id TEXT NOT NULL,
                    request_type TEXT NOT NULL,
                    target_probes_json TEXT NOT NULL,
                    result_status TEXT NOT NULL,
                    failures_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_l2_evt_ts ON l2_dispatches(event_id, dispatched_at);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def insert_level1(self, record: Level1Record) -> None:
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT INTO level1_records (
                    probe_id, probe_callback_url, timestamp, pp_id, notification_uri, config_fingerprint,
                    fetch_status, error_class, failure_stage, fetch_error_type, fetch_error_subtype, exception_class,
                    latency_ms, http_status, session_id, serial, notif_digest, raw_notification_sha256,
                    content_type, body_len, probe_boot_id, sequence_no, collector_target, error_detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.probe_id,
                    record.probe_callback_url,
                    record.timestamp.isoformat(),
                    record.pp_id,
                    record.notification_uri,
                    record.config_fingerprint,
                    record.fetch_status.value,
                    record.error_class.value,
                    record.failure_stage.value,
                    record.fetch_error_type.value,
                    record.fetch_error_subtype.value,
                    record.exception_class,
                    record.latency_ms,
                    record.http_status,
                    record.session_id,
                    record.serial,
                    record.notif_digest,
                    record.raw_notification_sha256,
                    record.content_type,
                    record.body_len,
                    record.probe_boot_id,
                    record.sequence_no,
                    record.collector_target,
                    record.error_detail,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def insert_notif_refs(self, record: NotifRefsRecord) -> None:
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT INTO notif_refs_records (
                    probe_id, probe_callback_url, pp_id, timestamp, event_id, notification_uri,
                    config_fingerprint, session_id, serial, snapshot_ref, delta_refs_json,
                    notif_digest, raw_notification_sha256, http_headers_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.probe_id,
                    record.probe_callback_url,
                    record.pp_id,
                    record.timestamp.isoformat(),
                    record.event_id,
                    record.notification_uri,
                    record.config_fingerprint,
                    record.session_id,
                    record.serial,
                    record.snapshot_ref,
                    json.dumps(record.delta_refs, ensure_ascii=False),
                    record.notif_digest,
                    record.raw_notification_sha256,
                    json.dumps(record.http_headers, ensure_ascii=False),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def insert_path_evidence(self, record: PathEvidenceRecord) -> None:
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT INTO path_evidence_records (
                    probe_id, probe_callback_url, pp_id, timestamp, event_id, notification_uri,
                    config_fingerprint, resolved_ip_set_json, dns_error, dns_duration_ms,
                    content_type, etag, last_modified, age, cache_control, server, tls_peer_summary,
                    fetch_error_type, fetch_error_subtype, exception_class, http_status, latency_ms, error_detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.probe_id,
                    record.probe_callback_url,
                    record.pp_id,
                    record.timestamp.isoformat(),
                    record.event_id,
                    record.notification_uri,
                    record.config_fingerprint,
                    json.dumps(record.resolved_ip_set, ensure_ascii=False),
                    record.dns_error,
                    record.dns_duration_ms,
                    record.content_type,
                    record.etag,
                    record.last_modified,
                    record.age,
                    record.cache_control,
                    record.server,
                    record.tls_peer_summary,
                    record.fetch_error_type.value,
                    record.fetch_error_subtype.value,
                    record.exception_class,
                    record.http_status,
                    record.latency_ms,
                    record.error_detail,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def upsert_event(self, event: EventRecord) -> None:
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO events (
                    event_id, event_type, pp_id, time_window_start, time_window_end, probes_involved_json,
                    summary_json, status, candidate_causes_json, l2_action_plan_json, confidence, evidence_refs_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.event_type.value,
                    event.pp_id,
                    event.time_window_start.isoformat(),
                    event.time_window_end.isoformat(),
                    json.dumps(event.probes_involved, ensure_ascii=False),
                    json.dumps(event.summary, ensure_ascii=False),
                    event.status,
                    json.dumps(event.candidate_causes, ensure_ascii=False),
                    json.dumps(event.l2_action_plan, ensure_ascii=False),
                    event.confidence,
                    json.dumps(event.evidence_refs, ensure_ascii=False),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        conn = self._conn()
        try:
            r = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
            if not r:
                return None
            return {
                "event_id": r["event_id"],
                "event_type": r["event_type"],
                "pp_id": r["pp_id"],
                "time_window_start": r["time_window_start"],
                "time_window_end": r["time_window_end"],
                "probes_involved": json.loads(r["probes_involved_json"]),
                "summary": json.loads(r["summary_json"]),
                "status": r["status"],
                "candidate_causes": json.loads(r["candidate_causes_json"]),
                "l2_action_plan": json.loads(r["l2_action_plan_json"]),
                "confidence": r["confidence"],
                "evidence_refs": json.loads(r["evidence_refs_json"]),
            }
        finally:
            conn.close()

    def patch_event(
        self,
        event_id: str,
        *,
        status: str | None = None,
        confidence: str | None = None,
        add_evidence_refs: list[str] | None = None,
        add_candidate_causes: list[str] | None = None,
        add_l2_action_plan: list[str] | None = None,
    ) -> None:
        """Patch an existing event in-place.

        Used to reflect post-event actions (L2 dispatch + evidence ingestion)
        without rebuilding the whole EventRecord object.
        """
        current = self.get_event(event_id)
        if current is None:
            return
        evidence_refs: list[str] = current["evidence_refs"]
        candidate_causes: list[str] = current["candidate_causes"]
        l2_action_plan: list[str] = current["l2_action_plan"]

        def _extend_unique(dst: list[str], src: list[str]):
            seen = set(dst)
            for x in src:
                if x not in seen:
                    dst.append(x)
                    seen.add(x)

        if add_evidence_refs:
            _extend_unique(evidence_refs, add_evidence_refs)
        if add_candidate_causes:
            _extend_unique(candidate_causes, add_candidate_causes)
        if add_l2_action_plan:
            _extend_unique(l2_action_plan, add_l2_action_plan)

        new_status = status if status is not None else current["status"]
        new_confidence = confidence if confidence is not None else current["confidence"]

        conn = self._conn()
        try:
            conn.execute(
                """
                UPDATE events
                SET status = ?, confidence = ?, evidence_refs_json = ?, candidate_causes_json = ?, l2_action_plan_json = ?
                WHERE event_id = ?
                """,
                (
                    new_status,
                    new_confidence,
                    json.dumps(evidence_refs, ensure_ascii=False),
                    json.dumps(candidate_causes, ensure_ascii=False),
                    json.dumps(l2_action_plan, ensure_ascii=False),
                    event_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def insert_l2_dispatch(self, event_id: str, request: L2Request, result: dict[str, Any]) -> None:
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT INTO l2_dispatches (
                    dispatched_at, event_id, pp_id, request_type, target_probes_json, result_status, failures_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    utcnow().isoformat(),
                    event_id,
                    request.pp_id,
                    request.request_type.value,
                    json.dumps(request.target_probes, ensure_ascii=False),
                    result.get("status", "unknown"),
                    json.dumps(result.get("failures", []), ensure_ascii=False),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def insert_validator_cycle_metadata(self, record: ValidatorCycleMetadataRecord) -> None:
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT INTO validator_cycle_metadata_records (
                    probe_id, validator_type, base_url, collected_at, source_endpoint, serial, session,
                    last_update_start, last_update_done, last_error_json, repository_count, status_keys_json, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.probe_id, record.validator_type, record.base_url, record.collected_at.isoformat(),
                    record.source_endpoint, str(record.serial) if record.serial is not None else None, record.session,
                    str(record.last_update_start) if record.last_update_start is not None else None,
                    str(record.last_update_done) if record.last_update_done is not None else None,
                    json.dumps(record.last_error, ensure_ascii=False), record.repository_count,
                    json.dumps(record.status_keys, ensure_ascii=False), json.dumps(record.raw, ensure_ascii=False),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def insert_validator_repository_status(self, record: ValidatorRepositoryStatusRecord) -> None:
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT INTO validator_repository_status_records (
                    probe_id, validator_type, base_url, collected_at, source_endpoint, repository_count,
                    repositories_json, trust_anchors_json, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.probe_id, record.validator_type, record.base_url, record.collected_at.isoformat(),
                    record.source_endpoint, record.repository_count, json.dumps(record.repositories, ensure_ascii=False),
                    json.dumps(record.trust_anchors, ensure_ascii=False), json.dumps(record.raw, ensure_ascii=False),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def insert_validator_output_summary(self, record: ValidatorOutputSummaryRecord) -> None:
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT INTO validator_output_summary_records (
                    probe_id, validator_type, base_url, collected_at, source_endpoint, vrp_count, router_key_count,
                    aspa_count, last_update_done, metrics_excerpt
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.probe_id, record.validator_type, record.base_url, record.collected_at.isoformat(),
                    record.source_endpoint, record.vrp_count, record.router_key_count, record.aspa_count,
                    record.last_update_done, record.metrics_excerpt,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def _rows_to_dicts(self, rows, json_fields: dict[str, str]) -> list[dict[str, Any]]:
        items=[]
        for r in rows:
            d=dict(r)
            for out_key, in_key in json_fields.items():
                if d.get(in_key) is not None:
                    d[out_key]=json.loads(d[in_key])
                    if out_key != in_key:
                        d.pop(in_key, None)
            items.append(d)
        return items

    def list_validator_cycle_metadata_for_probes(self, probe_ids: list[str], end_ts: str, limit_per_probe: int = 1) -> list[dict[str, Any]]:
        results=[]
        conn=self._conn()
        try:
            for probe_id in probe_ids:
                rows=conn.execute(
                    "SELECT * FROM validator_cycle_metadata_records WHERE probe_id = ? AND collected_at <= ? ORDER BY collected_at DESC LIMIT ?",
                    (probe_id, end_ts, limit_per_probe),
                ).fetchall()
                results.extend(self._rows_to_dicts(rows, {"last_error":"last_error_json", "status_keys":"status_keys_json", "raw":"raw_json"}))
            return results
        finally:
            conn.close()

    def list_validator_repository_status_for_probes(self, probe_ids: list[str], end_ts: str, limit_per_probe: int = 1) -> list[dict[str, Any]]:
        results=[]
        conn=self._conn()
        try:
            for probe_id in probe_ids:
                rows=conn.execute(
                    "SELECT * FROM validator_repository_status_records WHERE probe_id = ? AND collected_at <= ? ORDER BY collected_at DESC LIMIT ?",
                    (probe_id, end_ts, limit_per_probe),
                ).fetchall()
                results.extend(self._rows_to_dicts(rows, {"repositories":"repositories_json", "trust_anchors":"trust_anchors_json", "raw":"raw_json"}))
            return results
        finally:
            conn.close()

    def list_validator_output_summary_for_probes(self, probe_ids: list[str], end_ts: str, limit_per_probe: int = 1) -> list[dict[str, Any]]:
        results=[]
        conn=self._conn()
        try:
            for probe_id in probe_ids:
                rows=conn.execute(
                    "SELECT * FROM validator_output_summary_records WHERE probe_id = ? AND collected_at <= ? ORDER BY collected_at DESC LIMIT ?",
                    (probe_id, end_ts, limit_per_probe),
                ).fetchall()
                results.extend([dict(r) for r in rows])
            return results
        finally:
            conn.close()

    def build_evidence_pack(self, event_id: str) -> dict[str, Any] | None:
        event = self.get_event(event_id)
        if event is None:
            return None
        probe_ids = event.get("probes_involved", []) or []
        pp_id = event["pp_id"]
        window_end = event["time_window_end"]
        conn=self._conn()
        try:
            l1_rows = conn.execute(
                "SELECT * FROM level1_records WHERE pp_id = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp ASC",
                (pp_id, event["time_window_start"], event["time_window_end"]),
            ).fetchall()
            nr_rows = conn.execute(
                "SELECT * FROM notif_refs_records WHERE event_id = ? ORDER BY timestamp ASC",
                (event_id,),
            ).fetchall()
            pe_rows = conn.execute(
                "SELECT * FROM path_evidence_records WHERE event_id = ? ORDER BY timestamp ASC",
                (event_id,),
            ).fetchall()
        finally:
            conn.close()
        pack = {
            "event": event,
            "level1_records": [dict(r) for r in l1_rows],
            "notif_refs": self._rows_to_dicts(nr_rows, {"delta_refs":"delta_refs_json", "http_headers":"http_headers_json"}),
            "path_evidence": self._rows_to_dicts(pe_rows, {"resolved_ip_set":"resolved_ip_set_json"}),
            "validator_cycle_metadata": self.list_validator_cycle_metadata_for_probes(probe_ids, window_end),
            "validator_repository_status": self.list_validator_repository_status_for_probes(probe_ids, window_end),
            "validator_output_summary": self.list_validator_output_summary_for_probes(probe_ids, window_end),
            "evidence_basis": [
                "event_record",
                "level1_window_records",
                "l2_notif_refs",
                "l2_path_evidence",
                "validator_cycle_metadata",
                "validator_repository_status",
                "validator_output_summary",
            ],
        }
        return pack


    def list_notif_refs_probes_for_event(self, event_id: str) -> list[str]:
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT DISTINCT probe_id FROM notif_refs_records WHERE event_id = ? ORDER BY probe_id ASC",
                (event_id,),
            ).fetchall()
            return [r[0] for r in rows]
        finally:
            conn.close()

    def list_path_evidence_probes_for_event(self, event_id: str) -> list[str]:
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT DISTINCT probe_id FROM path_evidence_records WHERE event_id = ? ORDER BY probe_id ASC",
                (event_id,),
            ).fetchall()
            return [r[0] for r in rows]
        finally:
            conn.close()

    def list_recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY time_window_end DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [
                {
                    "event_id": r["event_id"],
                    "event_type": r["event_type"],
                    "pp_id": r["pp_id"],
                    "time_window_start": r["time_window_start"],
                    "time_window_end": r["time_window_end"],
                    "probes_involved": json.loads(r["probes_involved_json"]),
                    "summary": json.loads(r["summary_json"]),
                    "status": r["status"],
                    "candidate_causes": json.loads(r["candidate_causes_json"]),
                    "l2_action_plan": json.loads(r["l2_action_plan_json"]),
                    "confidence": r["confidence"],
                    "evidence_refs": json.loads(r["evidence_refs_json"]),
                }
                for r in rows
            ]
        finally:
            conn.close()

    def list_recent_l2_dispatches(self, limit: int = 50) -> list[dict[str, Any]]:
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM l2_dispatches ORDER BY dispatched_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [
                {
                    "dispatched_at": r["dispatched_at"],
                    "event_id": r["event_id"],
                    "pp_id": r["pp_id"],
                    "request_type": r["request_type"],
                    "target_probes": json.loads(r["target_probes_json"]),
                    "result_status": r["result_status"],
                    "failures": json.loads(r["failures_json"]),
                }
                for r in rows
            ]
        finally:
            conn.close()

    def latest_level1_by_pp(self, pp_id: str) -> list[dict[str, Any]]:
        conn = self._conn()
        try:
            rows = conn.execute(
                """
                SELECT l1.* FROM level1_records l1
                INNER JOIN (
                    SELECT probe_id, MAX(timestamp) AS max_ts
                    FROM level1_records WHERE pp_id = ? GROUP BY probe_id
                ) t ON l1.probe_id = t.probe_id AND l1.timestamp = t.max_ts
                WHERE l1.pp_id = ?
                ORDER BY l1.probe_id ASC
                """,
                (pp_id, pp_id),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
