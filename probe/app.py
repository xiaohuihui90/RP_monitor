from __future__ import annotations

import asyncio
import os

from fastapi import FastAPI, HTTPException

from shared.config import load_probe_config
from shared.schemas import (
    IngestResponse,
    L2Request,
    ProbeRuntime,
    ValidatorCycleMetadataRecord,
    ValidatorOutputSummaryRecord,
    ValidatorRepositoryStatusRecord,
)

from .l2_handlers import handle_l2_request
from .reporter import CollectorReporter
from .scheduler import ProbeScheduler

app = FastAPI(title="S3 Probe Agent")

probe_config = None
scheduler: ProbeScheduler | None = None
background_task: asyncio.Task | None = None


@app.on_event("startup")
async def startup_event():
    global probe_config, scheduler, background_task
    config_path = os.environ.get("S3_PROBE_CONFIG", "config/probe_cd.yaml")
    probe_config = load_probe_config(config_path)
    reporter = CollectorReporter(probe_config.collector_url)
    scheduler = ProbeScheduler(probe_config, reporter)
    background_task = asyncio.create_task(scheduler.loop_forever())


@app.on_event("shutdown")
async def shutdown_event():
    global background_task
    if background_task:
        background_task.cancel()


@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "probe_id": probe_config.probe_id if probe_config else None}


@app.get("/api/v1/runtime", response_model=ProbeRuntime)
async def runtime():
    if scheduler is None:
        raise HTTPException(status_code=500, detail="scheduler not ready")
    return ProbeRuntime(
        probe_id=scheduler.config.probe_id,
        probe_boot_id=scheduler.boot_id,
        started_at=scheduler.started_at,
        sequence_no=scheduler.sequence_no,
        latest_pp_timestamp=scheduler.latest_pp_timestamp,
        rp_adapter_enabled=scheduler.rp_adapter is not None,
        routinator_enabled=scheduler.config.routinator.enabled,
        latest_rp_cycle_metadata_ts=scheduler.latest_rp_cycle_metadata.collected_at if scheduler.latest_rp_cycle_metadata else None,
        latest_rp_repository_status_ts=scheduler.latest_rp_repository_status.collected_at if scheduler.latest_rp_repository_status else None,
        latest_rp_output_summary_ts=scheduler.latest_rp_output_summary.collected_at if scheduler.latest_rp_output_summary else None,
    )


@app.get("/api/v1/rp/cycle-metadata", response_model=ValidatorCycleMetadataRecord)
async def rp_cycle_metadata():
    if scheduler is None or scheduler.latest_rp_cycle_metadata is None:
        raise HTTPException(status_code=404, detail="rp cycle metadata not available")
    return scheduler.latest_rp_cycle_metadata


@app.get("/api/v1/rp/repository-status", response_model=ValidatorRepositoryStatusRecord)
async def rp_repository_status():
    if scheduler is None or scheduler.latest_rp_repository_status is None:
        raise HTTPException(status_code=404, detail="rp repository status not available")
    return scheduler.latest_rp_repository_status


@app.get("/api/v1/rp/output-summary", response_model=ValidatorOutputSummaryRecord)
async def rp_output_summary():
    if scheduler is None or scheduler.latest_rp_output_summary is None:
        raise HTTPException(status_code=404, detail="rp output summary not available")
    return scheduler.latest_rp_output_summary


@app.post("/api/v1/l2/request", response_model=IngestResponse)
async def l2_request(req: L2Request):
    global scheduler
    if scheduler is None:
        raise HTTPException(status_code=500, detail="scheduler not ready")
    try:
        return await handle_l2_request(req, scheduler)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except NotImplementedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

# ===== PHASE2_OBJECT_SHADOW_STARTUP =====
_object_shadow_task = None

@app.on_event("startup")
async def startup_object_shadow_worker():
    global _object_shadow_task

    if os.environ.get("S3_DISABLE_OBJECT_SHADOW_STARTUP", "0") == "1":
        print("[phase2_object_shadow_startup_skipped] S3_DISABLE_OBJECT_SHADOW_STARTUP=1")
        return

    if os.environ.get("S3_OBJECT_SHADOW_ENABLED", "0") != "1":
        print("[phase2_object_shadow_startup_skipped] S3_OBJECT_SHADOW_ENABLED!=1")
        return

    try:
        from probe.object_shadow_worker import start_object_shadow_worker
        _object_shadow_task = start_object_shadow_worker(probe_config)
        print("[phase2_object_shadow_startup_ok]")
    except Exception as exc:
        _object_shadow_task = None
        print(f"[phase2_object_shadow_startup_failed] {exc}")

@app.on_event("shutdown")
async def shutdown_object_shadow_worker():
    global _object_shadow_task
    if _object_shadow_task is not None:
        _object_shadow_task.cancel()
# ===== PHASE2_OBJECT_SHADOW_STARTUP_END =====


@app.get("/api/v1/object-shadow/status")
async def object_shadow_status():
    try:
        from probe.object_shadow_worker import read_object_shadow_status
        return read_object_shadow_status()
    except Exception as exc:
        return {"enabled": False, "status": "status_endpoint_error", "error": str(exc)}



@app.get("/api/v1/object-shadow/index")
async def object_shadow_index(pp_id: str, session_id: str, serial: int):
    try:
        from fastapi.responses import FileResponse, JSONResponse
        from pathlib import Path
        import os

        root = Path(
            os.environ.get(
                "S3_OBJECT_SHADOW_DIR",
                f"./artifacts_phase2/{probe_config.probe_id}/object_shadow",
            )
        ) / "index"

        fname = f"{pp_id}_{session_id}_{int(serial)}_{probe_config.probe_id}_object_index.jsonl"
        path = root / fname

        if not path.exists():
            return JSONResponse(
                {
                    "status": "not_found",
                    "error": "object_index_not_found",
                    "path": str(path),
                    "pp_id": pp_id,
                    "session_id": session_id,
                    "serial": serial,
                    "probe_id": probe_config.probe_id,
                },
                status_code=404,
            )

        return FileResponse(
            str(path),
            media_type="application/x-ndjson",
            filename=fname,
        )
    except Exception as exc:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            {
                "status": "error",
                "error": str(exc),
            },
            status_code=500,
        )

