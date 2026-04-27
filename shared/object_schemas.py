from __future__ import annotations
from typing import Any, Optional
from pydantic import BaseModel, Field

class ObjectInventoryItem(BaseModel):
    uri: str
    hash: str
    source: str = "snapshot"
    op: str = "present"
    object_type: Optional[str] = None
    origin_ref: Optional[str] = None

class ObjectInventoryRecord(BaseModel):
    schema_version: str = "2.0"
    probe_id: str
    timestamp: str
    pp_id: str
    session_id: str
    serial: int
    base_notif_digest: str
    inventory_source: str = "rrdp"
    inventory_type: str = "snapshot"
    object_count: int
    object_set_root: str
    inventory_digest: str
    bucket_roots_ref: Optional[str] = None
    artifact_ref: Optional[str] = None
    inventory_build_stats: dict[str, Any] = Field(default_factory=dict)

class ObjectDiffItem(BaseModel):
    uri: str
    hash_a: Optional[str] = None
    hash_b: Optional[str] = None
    diff_type: str
    bucket_id: Optional[str] = None

class ObjectDiffRecord(BaseModel):
    schema_version: str = "2.0"
    event_id: str
    pp_id: str
    session_id: str
    serial: int
    probe_a: str
    probe_b: str
    object_set_root_a: str
    object_set_root_b: str
    bucket_diff_summary: dict[str, Any] = Field(default_factory=dict)
    diff_items_ref: Optional[str] = None
    diff_item_count: int = 0
    compare_status: str = "unknown"
