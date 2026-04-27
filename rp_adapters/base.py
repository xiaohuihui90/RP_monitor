from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class RPAdapter(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    async def collect_cycle_metadata(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def collect_repository_status(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def collect_output_summary(self) -> dict[str, Any]:
        raise NotImplementedError

    async def collect_status(self) -> dict[str, Any]:
        """Backwards-compatible aggregate status collection."""
        return {
            "cycle_metadata": await self.collect_cycle_metadata(),
            "repository_status": await self.collect_repository_status(),
            "output_summary": await self.collect_output_summary(),
        }
