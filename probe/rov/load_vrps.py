from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from .rov_validate import VrpIndex, VrpRecord, parse_asn, parse_network


PROGRESS_EVERY = 100_000


def first_present(record: dict[str, Any], names: list[str]) -> Any:
    for name in names:
        if name in record:
            return record[name]
    return None


def clean_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_max_length(value: Any, default: int) -> int | None:
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed


def vrp_from_record(record: dict[str, Any]) -> tuple[VrpRecord | None, str | None]:
    net = parse_network(first_present(record, ["prefix", "ipPrefix", "ip_prefix", "vrp_prefix"]))
    if net is None:
        return None, "invalid_prefix"
    asn = parse_asn(first_present(record, ["asn", "asID", "as_id", "origin_asn", "originAS", "origin", "origin_as"]))
    if asn is None:
        return None, "invalid_asn"
    max_length = parse_max_length(first_present(record, ["max_length", "maxLength", "maxlength", "maxLen", "max_len"]), net.prefixlen)
    if max_length is None or max_length < net.prefixlen or max_length > net.max_prefixlen:
        return None, "invalid_max_length"
    tal = str(first_present(record, ["tal", "ta", "trust_anchor", "trustAnchor"]) or "").strip().lower()
    if not tal:
        tal = "unknown"
    source_uri = clean_string(first_present(record, ["source_uri", "sourceUri", "uri", "object_uri"]))
    roa_uri = clean_string(first_present(record, ["roa_uri", "roaUri"]))
    manifest_uri = clean_string(first_present(record, ["manifest_uri", "manifestUri"]))
    return (
        VrpRecord(
            tal=tal,
            asn=asn,
            prefix=str(net),
            max_length=max_length,
            source_uri=source_uri,
            roa_uri=roa_uri,
            manifest_uri=manifest_uri,
        ),
        None,
    )


def load_vrp_jsonl(path: Path, probe_id: str | None = None) -> dict[str, Any]:
    index = VrpIndex()
    tal_distribution: Counter[str] = Counter()
    parse_error_count = 0
    line_count = 0
    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line_count = line_no
            if line_no % PROGRESS_EVERY == 0:
                label = probe_id or path.name
                print(f"[P10] load_vrps {label}: read {line_no} lines", file=sys.stderr, flush=True)
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                parse_error_count += 1
                continue
            if not isinstance(obj, dict):
                parse_error_count += 1
                continue
            vrp, error = vrp_from_record(obj)
            if error or vrp is None:
                parse_error_count += 1
                continue
            index.add(vrp)
            tal_distribution[vrp.tal] += 1
    return {
        "path": str(path),
        "probe_id": probe_id,
        "index": index,
        "record_count": index.record_count,
        "line_count": line_count,
        "parse_error_count": parse_error_count,
        "tal_distribution": dict(sorted(tal_distribution.items())),
    }

