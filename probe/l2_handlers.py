from __future__ import annotations

from shared.enums import L2RequestType
from shared.schemas import IngestResponse, L2Request


async def handle_l2_request(req: L2Request, scheduler) -> IngestResponse:
    if req.request_type == L2RequestType.notif_refs:
        record = scheduler.latest_notif_refs.get(req.pp_id)
        if record is None:
            raise KeyError("no notif refs available yet")
        record.event_id = req.event_id
        await scheduler.reporter.send_l2_notif_refs(record)
        return IngestResponse()

    if req.request_type == L2RequestType.path_evidence:
        record = scheduler.latest_path_evidence.get(req.pp_id)
        if record is None:
            raise KeyError("no path evidence available yet")
        record.event_id = req.event_id
        await scheduler.reporter.send_l2_path_evidence(record)
        return IngestResponse()

    raise NotImplementedError(f"unsupported request type: {req.request_type}")
