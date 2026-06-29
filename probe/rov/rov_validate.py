from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any


STATE_VALID = "Valid"
STATE_INVALID = "Invalid"
STATE_NOT_FOUND = "NotFound"


@dataclass(frozen=True, slots=True)
class VrpRecord:
    tal: str
    asn: int
    prefix: str
    max_length: int
    source_uri: str | None = None
    roa_uri: str | None = None
    manifest_uri: str | None = None

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network(self.prefix, strict=False)

    def compact(self) -> dict[str, Any]:
        return {
            "tal": self.tal,
            "asn": self.asn,
            "prefix": self.prefix,
            "max_length": self.max_length,
            "source_uri": self.source_uri,
            "roa_uri": self.roa_uri,
            "manifest_uri": self.manifest_uri,
        }


class VrpIndex:
    def __init__(self) -> None:
        self.index: dict[int, dict[int, dict[ipaddress.IPv4Network | ipaddress.IPv6Network, list[VrpRecord]]]] = {
            4: {},
            6: {},
        }
        self.record_count = 0

    def add(self, vrp: VrpRecord) -> None:
        net = vrp.network
        by_len = self.index[net.version].setdefault(net.prefixlen, {})
        by_len.setdefault(net, []).append(vrp)
        self.record_count += 1

    def classify(
        self,
        route_prefix: str,
        origin_asn: int,
        max_covering_vrps: int = 5,
    ) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
        route_net = ipaddress.ip_network(route_prefix, strict=False)
        matched: list[VrpRecord] = []
        covered: list[VrpRecord] = []
        for prefix_len in range(route_net.prefixlen, -1, -1):
            bucket = self.index.get(route_net.version, {}).get(prefix_len, {})
            if not bucket:
                continue
            supernet = route_net.supernet(new_prefix=prefix_len) if prefix_len != route_net.prefixlen else route_net
            for vrp in bucket.get(supernet, []):
                if route_net.prefixlen <= vrp.max_length:
                    covered.append(vrp)
                    if origin_asn == vrp.asn:
                        matched.append(vrp)

        if matched:
            return STATE_VALID, [v.compact() for v in matched[:max_covering_vrps]], [v.compact() for v in covered[:max_covering_vrps]]
        if covered:
            return STATE_INVALID, [], [v.compact() for v in covered[:max_covering_vrps]]
        return STATE_NOT_FOUND, [], []


def parse_asn(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    text = str(value).strip()
    if not text:
        return None
    if "{" in text or "}" in text or "," in text:
        return None
    text = text.upper()
    if text.startswith("AS"):
        text = text[2:]
    if not re.fullmatch(r"\d+", text):
        return None
    return int(text)


def parse_network(value: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def stable_id(prefix: str, obj: Any, length: int = 24) -> str:
    payload = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{prefix}_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]

