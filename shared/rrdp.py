from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass

from .utils import json_sha256


@dataclass
class ParsedNotification:
    session_id: str
    serial: int
    snapshot_ref: str
    delta_refs: list[str]


class NotificationParseError(ValueError):
    pass


def parse_notification(raw_body: bytes) -> ParsedNotification:
    try:
        root = ET.fromstring(raw_body)
        session_id = root.attrib["session_id"]
        serial = int(root.attrib["serial"])
        snapshot = root.find("{*}snapshot")
        if snapshot is None:
            raise NotificationParseError("missing snapshot element")
        snapshot_ref = snapshot.attrib["uri"]
        delta_refs: list[str] = []
        for delta in root.findall("{*}delta"):
            uri = delta.attrib.get("uri")
            if uri:
                delta_refs.append(uri)
        return ParsedNotification(session_id=session_id, serial=serial, snapshot_ref=snapshot_ref, delta_refs=delta_refs)
    except Exception as exc:  # noqa: BLE001
        if isinstance(exc, NotificationParseError):
            raise
        raise NotificationParseError(str(exc)) from exc


def compute_notif_digest(parsed: ParsedNotification) -> str:
    return json_sha256(
        {
            "session_id": parsed.session_id,
            "serial": parsed.serial,
            "snapshot_ref": parsed.snapshot_ref,
            "delta_refs": parsed.delta_refs,
        }
    )
