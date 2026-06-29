from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .rov_validate import parse_asn, parse_network, stable_id


def first_present(record: dict[str, Any], names: list[str]) -> Any:
    for name in names:
        if name in record:
            return record[name]
    return None


def route_from_record(record: dict[str, Any], source_line: int) -> tuple[dict[str, Any] | None, str | None]:
    net = parse_network(first_present(record, ["prefix", "route_prefix", "network", "nlri"]))
    if net is None:
        return None, "invalid_prefix"
    asn = parse_asn(first_present(record, ["origin_asn", "origin", "origin_as", "asn", "originAS"]))
    if asn is None:
        return None, "invalid_origin_asn"
    collector = str(first_present(record, ["collector", "collector_id", "source_collector"]) or "").strip()
    observed_time = str(first_present(record, ["observed_time_utc", "route_time_utc", "timestamp", "time"]) or "").strip()
    peer_asn = parse_asn(first_present(record, ["peer_asn", "peer", "peerAS"]))
    source_type = str(first_present(record, ["source_type", "source"]) or "").strip()
    route = {
        "route_prefix": str(net),
        "origin_asn": asn,
        "collector": collector,
        "observed_time_utc": observed_time,
        "peer_asn": peer_asn,
        "source_type": source_type,
        "source_line": source_line,
    }
    route["route_id"] = stable_id("route", {k: route.get(k) for k in ("route_prefix", "origin_asn", "collector", "peer_asn", "observed_time_utc")})
    return route, None


def load_routes_jsonl(path: Path) -> tuple[list[dict[str, Any]], int, int]:
    routes: list[dict[str, Any]] = []
    parse_error_count = 0
    line_count = 0
    with path.open("r", encoding="utf-8-sig", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line_count = line_no
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
            route, error = route_from_record(obj, line_no)
            if error or route is None:
                parse_error_count += 1
                continue
            routes.append(route)
    return routes, parse_error_count, line_count


def load_routes_csv(path: Path) -> tuple[list[dict[str, Any]], int, int]:
    routes: list[dict[str, Any]] = []
    parse_error_count = 0
    with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            has_header = csv.Sniffer().has_header(sample)
        except csv.Error:
            has_header = True
        if has_header:
            reader = csv.DictReader(f)
            for line_no, row in enumerate(reader, 2):
                route, error = route_from_record(dict(row), line_no)
                if error or route is None:
                    parse_error_count += 1
                    continue
                routes.append(route)
            line_count = max(0, reader.line_num)
        else:
            reader2 = csv.reader(f)
            line_count = 0
            for line_no, row in enumerate(reader2, 1):
                line_count = line_no
                if len(row) < 2:
                    parse_error_count += 1
                    continue
                route, error = route_from_record({"prefix": row[0], "origin_asn": row[1]}, line_no)
                if error or route is None:
                    parse_error_count += 1
                    continue
                routes.append(route)
    return routes, parse_error_count, line_count


def load_routes(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        routes, errors, lines = load_routes_jsonl(path)
    else:
        routes, errors, lines = load_routes_csv(path)
    return {
        "path": str(path),
        "routes": routes,
        "route_count": len(routes),
        "parse_error_count": errors,
        "line_count": lines,
    }

