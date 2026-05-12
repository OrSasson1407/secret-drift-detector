import os
import tomllib
from pydantic import BaseModel, Field, field_validator, model_validator


def _resolve_env(value: str | None) -> str | None:
    if value and value.startswith("env:"):
        return os.environ.get(value[4:])
    return value


class SourceConfig(BaseModel):
    type:            str
    addr:            str | None = None
    path:            str | None = None
    prefix:          str | None = None
    region:          str | None = None
    token:           str | None = None
    project:         str | None = None
    config_env:      str | None = None
    namespace:       str | None = None
    label_selector:  str | None = None
    mount_version:   int        = 2
    key_prefix:      str | None = None
    max_age_days:    int | None = None   # rotation deadline in days

    @field_validator("token", "addr", mode="before")
    @classmethod
    def resolve_env_vars(cls, v):
        return _resolve_env(v)

    @model_validator(mode="after")
    def check_required_fields(self) -> "SourceConfig":
        required: dict[str, list[str]] = {
            "vault":   ["addr", "path"],
            "ssm":     ["prefix", "region"],
            "doppler": ["project", "config_env"],
            "dotenv":  ["path"],
        }
        missing = [f for f in required.get(self.type, []) if not getattr(self, f)]
        if missing:
            raise ValueError(
                f"Source type '{self.type}' is missing required field(s): {', '.join(missing)}"
            )
        return self


class TargetConfig(BaseModel):
    type:       str
    container:  str | None = None
    pid_file:   str | None = None
    pod:        str | None = None
    namespace:  str | None = None
    url:        str | None = None


class SlackAlertConfig(BaseModel):
    enabled:      bool = False
    webhook_url:  str | None = None
    min_severity: str = "warn"
    mention:      str | None = None

    @field_validator("webhook_url", mode="before")
    @classmethod
    def resolve(cls, v):
        return _resolve_env(v)


class PagerDutyAlertConfig(BaseModel):
    enabled:         bool = False
    integration_key: str | None = None
    min_severity:    str = "critical"

    @field_validator("integration_key", mode="before")
    @classmethod
    def resolve(cls, v):
        return _resolve_env(v)


class WebhookAlertConfig(BaseModel):
    enabled:      bool = False
    url:          str | None = None
    min_severity: str = "warn"
    headers:      dict[str, str] = Field(default_factory=dict)

    @field_validator("url", mode="before")
    @classmethod
    def resolve(cls, v):
        return _resolve_env(v)


class AlertsConfig(BaseModel):
    slack:      SlackAlertConfig      = Field(default_factory=SlackAlertConfig)
    pagerduty:  PagerDutyAlertConfig  = Field(default_factory=PagerDutyAlertConfig)
    webhook:    WebhookAlertConfig    = Field(default_factory=WebhookAlertConfig)


class AgentConfig(BaseModel):
    interval_seconds: int   = 60
    alert_on_extra:   bool  = False
    fail_on_drift:    bool  = True
    max_retries:      int   = 3
    retry_delay:      float = 2.0
    timeout_seconds:  float = 10.0
    db_path:          str   = "drift_history.db"
    enable_entropy:   bool  = True   # Shannon entropy weak-value scanning


class DetectorConfig(BaseModel):
    agent:   AgentConfig
    sources: list[SourceConfig]
    targets: list[TargetConfig]
    alerts:  AlertsConfig = Field(default_factory=AlertsConfig)

    @classmethod
    def load_from_file(cls, path: str) -> "DetectorConfig":
        with open(path, "r", encoding="utf-8-sig") as f:
            content = f.read()
        data = tomllib.loads(content)
        for src in data.get("sources", []):
            if "config" in src and "config_env" not in src:
                src["config_env"] = src.pop("config")
        return cls(**data)
