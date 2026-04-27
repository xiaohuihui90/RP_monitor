from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException, Query

from shared.config import CollectorConfig, load_collector_config
from shared.schemas import IngestResponse, L2Request, Level1Record, NotifRefsRecord, PathEvidenceRecord, ValidatorCycleMetadataRecord, ValidatorRepositoryStatusRecord, ValidatorOutputSummaryRecord, EvidencePackRecord, RemediationAdviceRecord
from shared.utils import setup_json_logger

from .db import CollectorDB
from .event_detector import EventDetector
from .l2_controller import L2Controller
from .auto_attribution import derive_event_enrichment

app = FastAPI(title="S3 Collector")

collector_config: CollectorConfig | None = None
db: CollectorDB | None = None
event_detector: EventDetector | None = None
logger = None
l2_controller: L2Controller | None = None


def _bump_confidence(cur: str | None) -> str:
    order = [None, "low", "medium", "high"]
    try:
        idx = order.index(cur)
    except ValueError:
        idx = 1
    return order[min(idx + 1, len(order) - 1)] or "low"


def _set_or_bump_confidence(cur: str | None, target: str) -> str:
    order = [None, "low", "medium", "high"]
    try:
        cur_idx = order.index(cur)
    except ValueError:
        cur_idx = 1
    try:
        tgt_idx = order.index(target)
    except ValueError:
        tgt_idx = 1
    return order[max(cur_idx, tgt_idx)] or "low"


def _evaluate_l2_progress(event_id: str):
    assert db is not None
    ev = db.get_event(event_id)
    if not ev:
        return None

    involved = set(ev.get("probes_involved", []) or [])
    summary = ev.get("summary", {}) or {}
    statuses = summary.get("statuses", {}) or {}
    success_probes = {p for p, s in statuses.items() if s == "success"}
    failed_probes = {p for p, s in statuses.items() if s != "success"}
    # fallback when statuses absent
    if not success_probes and not failed_probes:
        success_probes = set(involved)

    notif_refs_probes = set(db.list_notif_refs_probes_for_event(event_id))
    path_evidence_probes = set(db.list_path_evidence_probes_for_event(event_id))

    event_type = ev.get("event_type")

    if event_type == "E3-1":
        expected_notif_refs = set(involved)
        got_notif = len(notif_refs_probes & expected_notif_refs)
        need_notif = len(expected_notif_refs)
        if need_notif > 0 and got_notif >= need_notif:
            return {
                "status": "l2_complete",
                "confidence": "high",
                "evidence_refs": [f"l2_complete:notif_refs:{got_notif}/{need_notif}"],
            }
        if got_notif > 0:
            return {
                "status": "l2_partial",
                "confidence": "medium",
                "evidence_refs": [f"l2_partial:notif_refs:{got_notif}/{need_notif}"],
            }
        return None

    if event_type == "E3-2":
        expected_path = set(failed_probes) if failed_probes else set()
        expected_notif = set(success_probes) if success_probes else set()
        got_path = len(path_evidence_probes & expected_path)
        need_path = len(expected_path)
        got_notif = len(notif_refs_probes & expected_notif)
        need_notif = len(expected_notif)

        path_complete = (need_path == 0) or (got_path >= need_path)
        notif_complete = (need_notif == 0) or (got_notif >= need_notif)
        have_any = got_path > 0 or got_notif > 0

        if have_any and path_complete and notif_complete:
            refs = []
            if need_path:
                refs.append(f"l2_complete:path_evidence:{got_path}/{need_path}")
            if need_notif:
                refs.append(f"l2_complete:notif_refs:{got_notif}/{need_notif}")
            return {"status": "l2_complete", "confidence": "high", "evidence_refs": refs}

        if have_any:
            refs = []
            if need_path:
                refs.append(f"l2_partial:path_evidence:{got_path}/{need_path}")
            if need_notif:
                refs.append(f"l2_partial:notif_refs:{got_notif}/{need_notif}")
            return {"status": "l2_partial", "confidence": "medium", "evidence_refs": refs}

    return None


def _apply_strict_l2_backfill(event_id: str) -> None:
    assert db is not None
    cur = db.get_event(event_id)
    if not cur:
        return
    result = _evaluate_l2_progress(event_id)
    if not result:
        return
    db.patch_event(
        event_id,
        status=result["status"],
        confidence=_set_or_bump_confidence(cur.get("confidence"), result["confidence"]),
        add_evidence_refs=result.get("evidence_refs", []),
    )




def _refresh_event_enrichment(event_id: str) -> None:
    assert db is not None
    pack = db.build_evidence_pack(event_id)
    if not pack:
        return
    enrich = derive_event_enrichment(pack)
    db.patch_event(
        event_id,
        add_candidate_causes=enrich.get("candidate_causes", []),
        add_evidence_refs=[f"evidence_basis:{x}" for x in enrich.get("evidence_basis", [])],
    )

@app.on_event("startup")
async def startup_event():
    global collector_config, db, event_detector, logger, l2_controller
    config_path = os.environ.get("S3_COLLECTOR_CONFIG", "config/collector.yaml")
    collector_config = load_collector_config(config_path)
    db = CollectorDB(collector_config.db_path)
    event_detector = EventDetector(window_seconds=collector_config.event_window_seconds)
    logger = setup_json_logger("collector", collector_config.log_file)
    probe_map = {p.probe_id: p.base_url for p in collector_config.expected_probes}
    l2_controller = L2Controller(probe_map, collector_config.auto_l2)


@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "service": "collector"}


@app.post("/api/v1/ingest/level1", response_model=IngestResponse)
async def ingest_level1(record: Level1Record):
    assert db is not None and event_detector is not None and logger is not None and l2_controller is not None
    db.insert_level1(record)
    events = event_detector.ingest(record)
    for ev in events:
        auto_requests = l2_controller.plan_auto_l2(ev)
        if auto_requests:
            ev.evidence_refs.extend([f"auto_l2_planned:{req.request_type.value}" for req in auto_requests])
            ev.confidence = "medium" if ev.event_type.value == "E3-2" else ev.confidence
        db.upsert_event(ev)
        _refresh_event_enrichment(ev.event_id)
        logger.info("event_emitted", extra={"extra_json": ev.model_dump(mode="json")})
        for req in auto_requests:
            result = await l2_controller.dispatch(req)
            db.insert_l2_dispatch(ev.event_id, req, result)
            logger.info("auto_l2_dispatched", extra={"extra_json": {"event_id": ev.event_id, "request": req.model_dump(mode="json"), "result": result}})
            # Reflect dispatch outcome into event.status/confidence
            if result.get("status") == "ok":
                db.patch_event(
                    ev.event_id,
                    status="l2_dispatched",
                    add_evidence_refs=[f"auto_l2_dispatched:{req.request_type.value}"],
                )
            else:
                db.patch_event(
                    ev.event_id,
                    status="l2_dispatch_partial",
                    confidence="low" if ev.event_type.value == "E3-1" else "medium",
                    add_evidence_refs=[f"auto_l2_dispatch_partial:{req.request_type.value}"],
                )
    logger.info("level1_ingested", extra={"extra_json": record.model_dump(mode="json")})
    return IngestResponse()


@app.post("/api/v1/ingest/l2/notif_refs", response_model=IngestResponse)
async def ingest_l2_notif_refs(record: NotifRefsRecord):
    assert db is not None and logger is not None
    db.insert_notif_refs(record)
    if record.event_id:
        db.patch_event(
            record.event_id,
            status="l2_evidence_received",
            add_evidence_refs=[f"l2_notif_refs:{record.probe_id}:{record.timestamp.isoformat()}"]
        )
        _apply_strict_l2_backfill(record.event_id)
        _refresh_event_enrichment(record.event_id)
    logger.info("l2_notif_refs_ingested", extra={"extra_json": record.model_dump(mode="json")})
    return IngestResponse()


@app.post("/api/v1/ingest/l2/path_evidence", response_model=IngestResponse)
async def ingest_l2_path_evidence(record: PathEvidenceRecord):
    assert db is not None and logger is not None
    db.insert_path_evidence(record)
    if record.event_id:
        db.patch_event(
            record.event_id,
            status="l2_evidence_received",
            add_evidence_refs=[f"l2_path_evidence:{record.probe_id}:{record.timestamp.isoformat()}"]
        )
        _apply_strict_l2_backfill(record.event_id)
        _refresh_event_enrichment(record.event_id)
    logger.info("l2_path_evidence_ingested", extra={"extra_json": record.model_dump(mode="json")})
    return IngestResponse()




@app.post("/api/v1/ingest/rp/cycle-metadata", response_model=IngestResponse)
async def ingest_rp_cycle_metadata(record: ValidatorCycleMetadataRecord):
    assert db is not None and logger is not None
    db.insert_validator_cycle_metadata(record)
    for ev in db.list_recent_events(limit=100):
        if record.probe_id in (ev.get("probes_involved") or []):
            _refresh_event_enrichment(ev["event_id"])
    logger.info("rp_cycle_metadata_ingested", extra={"extra_json": record.model_dump(mode="json")})
    return IngestResponse()


@app.post("/api/v1/ingest/rp/repository-status", response_model=IngestResponse)
async def ingest_rp_repository_status(record: ValidatorRepositoryStatusRecord):
    assert db is not None and logger is not None
    db.insert_validator_repository_status(record)
    for ev in db.list_recent_events(limit=100):
        if record.probe_id in (ev.get("probes_involved") or []):
            _refresh_event_enrichment(ev["event_id"])
    logger.info("rp_repository_status_ingested", extra={"extra_json": record.model_dump(mode="json")})
    return IngestResponse()


@app.post("/api/v1/ingest/rp/output-summary", response_model=IngestResponse)
async def ingest_rp_output_summary(record: ValidatorOutputSummaryRecord):
    assert db is not None and logger is not None
    db.insert_validator_output_summary(record)
    for ev in db.list_recent_events(limit=100):
        if record.probe_id in (ev.get("probes_involved") or []):
            _refresh_event_enrichment(ev["event_id"])
    logger.info("rp_output_summary_ingested", extra={"extra_json": record.model_dump(mode="json")})
    return IngestResponse()


@app.get("/api/v1/level1/latest")
async def level1_latest(pp_id: str = Query(...)):
    assert db is not None
    return {"pp_id": pp_id, "items": db.latest_level1_by_pp(pp_id)}


@app.get("/api/v1/events")
async def events(limit: int = Query(50, ge=1, le=500)):
    assert db is not None
    return {"items": db.list_recent_events(limit=limit)}


@app.get("/api/v1/l2/dispatches")
async def l2_dispatches(limit: int = Query(50, ge=1, le=500)):
    assert db is not None
    return {"items": db.list_recent_l2_dispatches(limit=limit)}




@app.get("/api/v1/events/{event_id}/evidence-pack", response_model=EvidencePackRecord)
async def event_evidence_pack(event_id: str):
    assert db is not None
    pack = db.build_evidence_pack(event_id)
    if pack is None:
        raise HTTPException(status_code=404, detail="event not found")
    enrich = derive_event_enrichment(pack)
    pack["candidate_causes"] = enrich.get("candidate_causes", [])
    pack["evidence_basis"] = enrich.get("evidence_basis", [])
    pack["remediation"] = enrich.get("remediation")
    return EvidencePackRecord(**pack)


@app.get("/api/v1/events/{event_id}/remediation", response_model=RemediationAdviceRecord)
async def event_remediation(event_id: str):
    assert db is not None
    pack = db.build_evidence_pack(event_id)
    if pack is None:
        raise HTTPException(status_code=404, detail="event not found")
    enrich = derive_event_enrichment(pack)
    return RemediationAdviceRecord(**enrich.get("remediation", {"event_id": event_id}))


@app.post("/api/v1/l2/request")
async def request_l2(req: L2Request):
    assert l2_controller is not None and db is not None
    result = await l2_controller.dispatch(req)
    db.insert_l2_dispatch(req.event_id, req, result)
    if req.event_id:
        if result.get("status") == "ok":
            db.patch_event(req.event_id, status="l2_dispatched", add_evidence_refs=[f"manual_l2_dispatched:{req.request_type.value}"])
        else:
            db.patch_event(req.event_id, status="l2_dispatch_partial", add_evidence_refs=[f"manual_l2_dispatch_partial:{req.request_type.value}"])
    if result["status"] != "ok":
        raise HTTPException(status_code=502, detail=result)
    return IngestResponse()
