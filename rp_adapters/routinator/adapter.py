from __future__ import annotations

import re
from typing import Any

import httpx

from rp_adapters.base import RPAdapter
from shared.utils import utcnow


class RoutinatorAdapter(RPAdapter):
    def __init__(self, base_url: str, timeout_seconds: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    @property
    def name(self) -> str:
        return "routinator"

    async def _get_json(self, path: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = await client.get(f"{self.base_url}{path}")
            resp.raise_for_status()
            return resp.json()

    async def _get_text(self, path: str) -> str:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = await client.get(f"{self.base_url}{path}")
            resp.raise_for_status()
            return resp.text

    def _find_first(self, obj: Any, candidate_keys: set[str]) -> Any | None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_norm = str(key).lower().replace("-", "_")
                if key_norm in candidate_keys:
                    return value
                found = self._find_first(value, candidate_keys)
                if found is not None:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = self._find_first(item, candidate_keys)
                if found is not None:
                    return found
        return None

    def _count_repositories(self, status_json: dict[str, Any]) -> int | None:
        repos = self._find_first(status_json, {"repositories", "repository_statuses", "repos"})
        if isinstance(repos, list):
            return len(repos)
        if isinstance(repos, dict):
            return len(repos)
        return None

    def _collect_status_keys(self, obj: Any, max_keys: int = 50) -> list[str]:
        keys: list[str] = []

        def walk(value: Any) -> None:
            if len(keys) >= max_keys:
                return
            if isinstance(value, dict):
                for key, child in value.items():
                    keys.append(str(key))
                    if len(keys) >= max_keys:
                        return
                    walk(child)
            elif isinstance(value, list):
                for child in value[:5]:
                    walk(child)

        walk(obj)
        seen = set()
        ordered: list[str] = []
        for key in keys:
            if key not in seen:
                ordered.append(key)
                seen.add(key)
        return ordered[:max_keys]

    def _extract_metric_value(self, metrics_text: str, metric_names: list[str]) -> float | None:
        for metric in metric_names:
            pattern = re.compile(
                rf"^{re.escape(metric)}(?:\{{[^\n]*\}})?\s+([-+]?\d+(?:\.\d+)?)$",
                re.MULTILINE,
            )
            match = pattern.search(metrics_text)
            if match:
                try:
                    return float(match.group(1))
                except ValueError:
                    continue
        return None

    async def collect_cycle_metadata(self) -> dict[str, Any]:
        status_json = await self._get_json("/api/v1/status")
        return {
            "validator_type": self.name,
            "base_url": self.base_url,
            "collected_at": utcnow().isoformat(),
            "source_endpoint": "/api/v1/status",
            "serial": self._find_first(status_json, {"serial", "current_serial", "rtr_serial"}),
            "session": self._find_first(status_json, {"session", "session_id"}),
            "last_update_start": self._find_first(status_json, {"last_update_start", "update_start", "started_at"}),
            "last_update_done": self._find_first(status_json, {"last_update_done", "update_done", "completed_at", "done_at"}),
            "last_error": self._find_first(status_json, {"last_error", "error", "last_failure"}),
            "repository_count": self._count_repositories(status_json),
            "status_keys": self._collect_status_keys(status_json),
            "raw": status_json,
        }

    async def collect_repository_status(self) -> dict[str, Any]:
        status_json = await self._get_json("/api/v1/status")
        repositories = self._find_first(status_json, {"repositories", "repository_statuses", "repos"})
        return {
            "validator_type": self.name,
            "base_url": self.base_url,
            "collected_at": utcnow().isoformat(),
            "source_endpoint": "/api/v1/status",
            "repository_count": self._count_repositories(status_json),
            "repositories": repositories if isinstance(repositories, (list, dict)) else [],
            "trust_anchors": self._find_first(status_json, {"trust_anchors", "tas", "authorities"}),
            "raw": status_json,
        }

    async def collect_output_summary(self) -> dict[str, Any]:
        metrics_text = await self._get_text("/metrics")
        return {
            "validator_type": self.name,
            "base_url": self.base_url,
            "collected_at": utcnow().isoformat(),
            "source_endpoint": "/metrics",
            "vrp_count": self._extract_metric_value(
                metrics_text,
                [
                    "routinator_ta_valid_vrps_total",
                    "routinator_valid_vrps_total",
                    "valid_vrps_total",
                ],
            ),
            "router_key_count": self._extract_metric_value(
                metrics_text,
                [
                    "routinator_ta_valid_router_keys_total",
                    "routinator_valid_router_keys_total",
                    "valid_router_keys_total",
                ],
            ),
            "aspa_count": self._extract_metric_value(
                metrics_text,
                [
                    "routinator_ta_valid_aspas_total",
                    "routinator_valid_aspas_total",
                    "valid_aspas_total",
                ],
            ),
            "last_update_done": self._extract_metric_value(
                metrics_text,
                [
                    "routinator_last_update_done",
                    "routinator_ta_last_update_done",
                ],
            ),
            "metrics_excerpt": "\n".join(metrics_text.splitlines()[:80]),
        }
