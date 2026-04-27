from __future__ import annotations
def detect_e1_candidate(records: list[dict]) -> dict | None:
    success = [r for r in records if str(r.get("fetch_status", "success")) == "success"]
    if len(success) < 2:
        return None
    pp_ids = {r.get("pp_id") for r in success}
    sessions = {r.get("session_id") for r in success}
    serials = {r.get("serial") for r in success}
    roots = {r.get("object_set_root") for r in success}
    if len(pp_ids) == 1 and len(sessions) == 1 and len(serials) == 1 and len(roots) > 1:
        return {
            "event_type": "E1",
            "pp_id": next(iter(pp_ids)),
            "session_id": next(iter(sessions)),
            "serial": next(iter(serials)),
            "object_set_roots": sorted(list(roots)),
            "success_probe_count": len(success),
        }
    return None
