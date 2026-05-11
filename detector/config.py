from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class SourceConfig(BaseModel):
    type: str
    # dotenv
    path: Optional[str] = None
    # vault
    addr: Optional[str] = None
    mount: str = "secret"
    vault_path: Optional[str] = Field(None, alias="path")
    # ssm
    prefix: Optional[str] = None
    region: Optional[str] = None
    # doppler
    project: Optional[str] = None
    config: Optional[str] = None
    # kubernetes
    namespace: str = "default"
    label_selector: Optional[str] = None
    # gcp
    gcp_project: Optional[str] = None

    model_config = {"populate_by_name": True, "extra": "allow"}


class TargetConfig(BaseModel):
    type: str
    # docker
    container: Optional[str] = None
    # proc
    pid_file: Optional[str] = None
    pid: Optional[int] = None
    # k8s
    pod: Optional[str] = None
    namespace: str = "default"
    # http
    url: Optional[str] = None

    model_config = {"extra": "allow"}


class SlackAlertConfig(BaseModel):
    enabled: bool = False
    webhook_url: str = ""
    min_severity: str = "warn"


class PagerDutyAlertConfig(BaseModel):
    enabled: bool = False
    integration_key: str = ""
    min_severity: str = "critical"


class WebhookAlertConfig(BaseModel):
    enabled: bool = False
    url: str = ""
    min_severity: str = "warn"


class AlertsConfig(BaseModel):
    slack:     SlackAlertConfig     = Field(default_factory=SlackAlertConfig)
    pagerduty: PagerDutyAlertConfig = Field(default_factory=PagerDutyAlertConfig)
    webhook:   WebhookAlertConfig   = Field(default_factory=WebhookAlertConfig)


class AgentConfig(BaseModel):
    interval_seconds: int = 60
    alert_on_extra:   bool = False
    fail_on_drift:    bool = True


class DetectorConfig(BaseModel):
    agent:   AgentConfig   = Field(default_factory=AgentConfig)
    sources: List[SourceConfig] = Field(default_factory=list)
    targets: List[TargetConfig] = Field(default_factory=list)
    alerts:  AlertsConfig  = Field(default_factory=AlertsConfig)

    @classmethod
    def from_toml(cls, path: str | Path = "detector.toml") -> "DetectorConfig":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p}")
        with open(p, "rb") as f:
            raw: Dict[str, Any] = tomllib.load(f)
        return cls.model_validate(raw)

    @classmethod
    def from_toml_or_default(cls, path: str | Path = "detector.toml") -> "DetectorConfig":
        try:
            return cls.from_toml(path)
        except FileNotFoundError:
            return cls()


def _resolve_env(value: str) -> str:
    if value.startswith("env:"):
        var = value[4:]
        resolved = os.environ.get(var, "")
        return resolved
    return value
