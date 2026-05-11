import tomllib
from pydantic import BaseModel, Field

class SourceConfig(BaseModel):
    type: str
    addr: str | None = None
    path: str | None = None
    prefix: str | None = None
    region: str | None = None

class TargetConfig(BaseModel):
    type: str
    container: str | None = None
    pid_file: str | None = None

class SlackAlertConfig(BaseModel):
    enabled: bool = False
    webhook_url: str | None = None
    min_severity: str = 'warn'

class PagerDutyAlertConfig(BaseModel):
    enabled: bool = False
    integration_key: str | None = None
    min_severity: str = 'critical'

class AlertsConfig(BaseModel):
    slack: SlackAlertConfig = Field(default_factory=SlackAlertConfig)
    pagerduty: PagerDutyAlertConfig = Field(default_factory=PagerDutyAlertConfig)

class AgentConfig(BaseModel):
    interval_seconds: int = 60
    alert_on_extra: bool = False
    fail_on_drift: bool = True

class DetectorConfig(BaseModel):
    agent: AgentConfig
    sources: list[SourceConfig]
    targets: list[TargetConfig]
    alerts: AlertsConfig

    @classmethod
    def load_from_file(cls, path: str) -> "DetectorConfig":
        # Using utf-8-sig automatically removes the Windows BOM if it exists
        with open(path, "r", encoding="utf-8-sig") as f:
            content = f.read()
        data = tomllib.loads(content)
        return cls(**data)
