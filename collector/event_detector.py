from __future__ import annotations

from collections import defaultdict

from shared.enums import EventType, FetchStatus
from shared.schemas import EventRecord, Level1Record
from shared.utils import gen_id


class EventDetector:
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.buckets: dict[tuple[str, str], list[Level1Record]] = defaultdict(list)
        self.emitted_keys: set[tuple[str, str, str]] = set()

    def _window_key(self, record: Level1Record) -> str:
        ts = int(record.timestamp.timestamp())
        slot = ts - (ts % self.window_seconds)
        return str(slot)

    def _max_skew_seconds(self, items: list[Level1Record]) -> float:
        if len(items) < 2:
            return 0.0
        ts_sorted = sorted(x.timestamp for x in items)
        return (ts_sorted[-1] - ts_sorted[0]).total_seconds()

    def ingest(self, record: Level1Record) -> list[EventRecord]:
        bucket_key = (record.pp_id, self._window_key(record))
        items = self.buckets[bucket_key]
        items.append(record)
        return self._analyze(bucket_key, items)

    def _analyze(self, bucket_key: tuple[str, str], items: list[Level1Record]) -> list[EventRecord]:
        pp_id, slot = bucket_key
        if not items:
            return []
        items_sorted = sorted(items, key=lambda x: x.timestamp)
        ws = items_sorted[0].timestamp
        we = items_sorted[-1].timestamp
        out: list[EventRecord] = []

        success_like = [x for x in items_sorted if x.fetch_status == FetchStatus.success]
        non_success = [x for x in items_sorted if x.fetch_status != FetchStatus.success]
        session_ids = {x.session_id for x in success_like if x.session_id}
        serials = {x.serial for x in success_like if x.serial is not None}
        serial_list = sorted(s for s in serials if s is not None)
        serial_gap = (max(serial_list) - min(serial_list)) if len(serial_list) >= 2 else 0
        success_skew = self._max_skew_seconds(success_like)
        all_skew = self._max_skew_seconds(items_sorted)
        version_diverged = len(session_ids) > 1 or len(serials) > 1

        if version_diverged and success_like and not non_success:
            key = (pp_id, slot, EventType.e3_1.value)
            if key not in self.emitted_keys:
                probes_involved = sorted({x.probe_id for x in success_like})
                event = EventRecord(
                    event_id=gen_id("evt"),
                    event_type=EventType.e3_1,
                    pp_id=pp_id,
                    time_window_start=ws,
                    time_window_end=we,
                    probes_involved=probes_involved,
                    summary={
                        "session_ids": sorted(session_ids),
                        "serials": serial_list,
                        "serial_gap": serial_gap,
                        "success_probe_count": len(success_like),
                        "statuses": {x.probe_id: x.fetch_status.value for x in success_like},
                        "probe_views": {
                            x.probe_id: {"session_id": x.session_id, "serial": x.serial, "notif_digest": x.notif_digest}
                            for x in success_like
                        },
                        "max_skew_seconds": success_skew,
                    },
                    candidate_causes=["T3", "T4", "T6"],
                    l2_action_plan=["notif_refs"],
                    confidence="low",
                )
                self.emitted_keys.add(key)
                out.append(event)

        if non_success:
            key = (pp_id, slot, EventType.e3_2.value)
            if key not in self.emitted_keys:
                probes_involved = sorted({x.probe_id for x in items_sorted})
                event = EventRecord(
                    event_id=gen_id("evt"),
                    event_type=EventType.e3_2,
                    pp_id=pp_id,
                    time_window_start=ws,
                    time_window_end=we,
                    probes_involved=probes_involved,
                    summary={
                        "statuses": {x.probe_id: x.fetch_status.value for x in items_sorted},
                        "session_ids": sorted(session_ids),
                        "serials": serial_list,
                        "serial_gap": serial_gap,
                        "success_probe_count": len(success_like),
                        "failed_probe_count": len(non_success),
                        "failures": [
                            {
                                "probe_id": x.probe_id,
                                "fetch_status": x.fetch_status.value,
                                "error_class": x.error_class.value,
                                "failure_stage": x.failure_stage.value,
                                "fetch_error_type": x.fetch_error_type.value,
                                "fetch_error_subtype": x.fetch_error_subtype.value,
                                "exception_class": x.exception_class,
                                "http_status": x.http_status,
                            }
                            for x in non_success
                        ],
                        "probe_views": {
                            x.probe_id: {"session_id": x.session_id, "serial": x.serial, "notif_digest": x.notif_digest}
                            for x in success_like
                        },
                        "max_skew_seconds": all_skew,
                    },
                    candidate_causes=["T5", "T6", "T4"],
                    l2_action_plan=["path_evidence", "notif_refs"],
                    confidence="medium",
                )
                self.emitted_keys.add(key)
                out.append(event)

        return out
