from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class PPConfig(BaseModel):
    pp_id: str
    notification_uri: str
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)


class RoutinatorConfig(BaseModel):
    enabled: bool = False
    base_url: str = "http://127.0.0.1:8323"
    timeout_seconds: int = 10
    collect_status: bool = True
    collect_metrics: bool = True
    collect_validity: bool = False


class ProbeConfig(BaseModel):
    probe_id: str
    location: str
    listen_host: str = "0.0.0.0"
    listen_port: int = 28089
    public_base_url: str
    collector_url: str
    poll_interval_seconds: int = 300
    http_timeout_seconds: int = 15
    store_artifacts: bool = True
    artifact_dir: str = "./artifacts"
    log_file: str = "./logs/probes/default.log"
    pps: list[PPConfig] = Field(default_factory=list)
    routinator: RoutinatorConfig = Field(default_factory=RoutinatorConfig)


class ExpectedProbe(BaseModel):
    probe_id: str
    location: str
    base_url: str


class AutoL2Config(BaseModel):
    enabled: bool = True
    dispatch_timeout_seconds: int = 15
    e3_1_min_probes: int = 2
    e3_1_min_serial_gap: int = 3
    e3_1_max_skew_seconds: float | None = 120.0
    e3_1_trigger_on_session_divergence: bool = True
    e3_2_min_failed_probes: int = 1
    e3_2_require_success_probe: bool = True
    e3_2_trigger_notif_refs_when_success_count_at_least: int = 2


class CollectorConfig(BaseModel):
    listen_host: str = "0.0.0.0"
    listen_port: int = 28081
    db_path: str = "./data/collector.sqlite3"
    log_file: str = "./logs/collector/collector.log"
    event_window_seconds: int = 120
    expected_probes: list[ExpectedProbe] = Field(default_factory=list)
    auto_l2: AutoL2Config = Field(default_factory=AutoL2Config)


def load_yaml_model(path: str, model_type):
    with Path(path).open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return model_type(**data)


def load_probe_config(path: str) -> ProbeConfig:
    return load_yaml_model(path, ProbeConfig)


def load_collector_config(path: str) -> CollectorConfig:
    return load_yaml_model(path, CollectorConfig)
