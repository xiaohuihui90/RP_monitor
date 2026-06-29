from __future__ import annotations

from typing import Any

from .rov_validate import VrpIndex


def compute_route_state(
    route: dict[str, Any],
    vrp_indexes: dict[str, VrpIndex],
    max_covering_vrps: int = 5,
) -> dict[str, Any]:
    states: dict[str, str] = {}
    matched_vrps: dict[str, list[dict[str, Any]]] = {}
    covering_vrps: dict[str, list[dict[str, Any]]] = {}
    for probe_id, index in sorted(vrp_indexes.items()):
        state, matched, covering = index.classify(str(route["route_prefix"]), int(route["origin_asn"]), max_covering_vrps=max_covering_vrps)
        states[probe_id] = state
        matched_vrps[probe_id] = matched
        covering_vrps[probe_id] = covering
    return {
        "states": states,
        "matched_vrps": matched_vrps,
        "covering_vrps": covering_vrps,
    }
