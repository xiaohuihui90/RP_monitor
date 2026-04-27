from __future__ import annotations

import httpx

from shared.schemas import IngestResponse, Level1Record, NotifRefsRecord, PathEvidenceRecord, ValidatorCycleMetadataRecord, ValidatorRepositoryStatusRecord, ValidatorOutputSummaryRecord


class CollectorReporter:
    def __init__(self, collector_url: str, timeout_seconds: int = 15):
        self.collector_url = collector_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    async def send_level1(self, record: Level1Record) -> IngestResponse:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = await client.post(f"{self.collector_url}/api/v1/ingest/level1", json=record.model_dump(mode="json"))
            resp.raise_for_status()
            return IngestResponse(**resp.json())

    async def send_l2_notif_refs(self, record: NotifRefsRecord) -> IngestResponse:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = await client.post(f"{self.collector_url}/api/v1/ingest/l2/notif_refs", json=record.model_dump(mode="json"))
            resp.raise_for_status()
            return IngestResponse(**resp.json())

    async def send_l2_path_evidence(self, record: PathEvidenceRecord) -> IngestResponse:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = await client.post(f"{self.collector_url}/api/v1/ingest/l2/path_evidence", json=record.model_dump(mode="json"))
            resp.raise_for_status()
            return IngestResponse(**resp.json())

    async def send_validator_cycle_metadata(self, record: ValidatorCycleMetadataRecord) -> IngestResponse:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = await client.post(f"{self.collector_url}/api/v1/ingest/rp/cycle-metadata", json=record.model_dump(mode="json"))
            resp.raise_for_status()
            return IngestResponse(**resp.json())

    async def send_validator_repository_status(self, record: ValidatorRepositoryStatusRecord) -> IngestResponse:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = await client.post(f"{self.collector_url}/api/v1/ingest/rp/repository-status", json=record.model_dump(mode="json"))
            resp.raise_for_status()
            return IngestResponse(**resp.json())

    async def send_validator_output_summary(self, record: ValidatorOutputSummaryRecord) -> IngestResponse:
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = await client.post(f"{self.collector_url}/api/v1/ingest/rp/output-summary", json=record.model_dump(mode="json"))
            resp.raise_for_status()
            return IngestResponse(**resp.json())
