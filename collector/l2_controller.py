from __future__ import annotations

import httpx

from shared.config import AutoL2Config
from shared.enums import EventType, L2RequestType
from shared.schemas import EventRecord, L2Request


class L2Controller:
    def __init__(self, probe_map: dict[str, str], auto_l2_config: AutoL2Config):
        self.probe_map = {k: v.rstrip("/") for k, v in probe_map.items()}
        self.auto_l2_config = auto_l2_config
        self.timeout_seconds = auto_l2_config.dispatch_timeout_seconds

    async def dispatch(self, req: L2Request) -> dict:
        failures = []
        target_probe_ids = req.target_probes or list(self.probe_map.keys())
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            for probe_id in target_probe_ids:
                base_url = self.probe_map.get(probe_id)
                if not base_url:
                    failures.append({"probe_id": probe_id, "error": "unknown_probe"})
                    continue
                try:
                    resp = await client.post(f"{base_url}/api/v1/l2/request", json=req.model_dump(mode="json"))
                    resp.raise_for_status()
                except Exception as exc:  # noqa: BLE001
                    failures.append({"probe_id": probe_id, "error": str(exc)})
        return {
            "status": "ok" if not failures else "partial_failure",
            "target_probes": target_probe_ids,
            "failures": failures,
        }

    def _should_trigger_e3_1(self, event: EventRecord) -> list[L2RequestType]:
        s = event.summary
        session_ids = s.get("session_ids", [])
        serial_gap = int(s.get("serial_gap", 0) or 0)
        success_probe_count = int(s.get("success_probe_count", len(event.probes_involved)) or 0)
        max_skew = s.get("max_skew_seconds")

        if success_probe_count < self.auto_l2_config.e3_1_min_probes:
            return []
        if len(session_ids) > 1 and self.auto_l2_config.e3_1_trigger_on_session_divergence:
            return [L2RequestType.notif_refs]
        if serial_gap < self.auto_l2_config.e3_1_min_serial_gap:
            return []
        if self.auto_l2_config.e3_1_max_skew_seconds is not None and max_skew is not None and float(max_skew) > float(self.auto_l2_config.e3_1_max_skew_seconds):
            return []
        return [L2RequestType.notif_refs]

    def _should_trigger_e3_2(self, event: EventRecord) -> list[L2RequestType]:
        s = event.summary
        failed_probe_count = int(s.get("failed_probe_count", 0) or 0)
        success_probe_count = int(s.get("success_probe_count", 0) or 0)
        actions: list[L2RequestType] = []
        if failed_probe_count < self.auto_l2_config.e3_2_min_failed_probes:
            return actions
        if self.auto_l2_config.e3_2_require_success_probe and success_probe_count < 1:
            return actions
        actions.append(L2RequestType.path_evidence)
        if success_probe_count >= self.auto_l2_config.e3_2_trigger_notif_refs_when_success_count_at_least:
            actions.append(L2RequestType.notif_refs)
        return actions

    def plan_auto_l2(self, event: EventRecord) -> list[L2Request]:
        if not self.auto_l2_config.enabled:
            return []
        action_types: list[L2RequestType] = []
        if event.event_type == EventType.e3_1:
            action_types = self._should_trigger_e3_1(event)
        elif event.event_type == EventType.e3_2:
            action_types = self._should_trigger_e3_2(event)
        target_probes = sorted(set(event.probes_involved))
        return [
            L2Request(
                event_id=event.event_id,
                pp_id=event.pp_id,
                request_type=action_type,
                target_probes=target_probes,
            )
            for action_type in action_types
        ]
