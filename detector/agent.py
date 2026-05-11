import asyncio
from detector.config import DetectorConfig
from detector.sources.vault import VaultSource
from detector.sources.ssm import SSMSource
from detector.sources.dotenv_file import DotEnvSource
from detector.runtime.docker_exec import DockerExecProber
from detector.runtime.proc import ProcEnvironProber
from detector.runtime.local_env import LocalEnvProber
from detector.diff.engine import compute_drift
from detector.diff.models import DriftReport, DriftKind
from detector.sources import _hash
from detector.storage.snapshot import Storage
from detector.server import metrics
from detector.alerts.slack import SlackAlerter
from detector.alerts.pagerduty import PagerDutyAlerter

class Agent:
    def __init__(self, config: DetectorConfig):
        self.config = config
        self.sources = []
        self.targets = []
        self.alerters = []
        self.storage = Storage()
        self._init_components()

    def _init_components(self):
        for src in self.config.sources:
            if src.type == 'vault': self.sources.append(VaultSource(addr=src.addr, path=src.path))
            elif src.type == 'ssm': self.sources.append(SSMSource(prefix=src.prefix, region=src.region))
            elif src.type == 'dotenv': self.sources.append(DotEnvSource(path=src.path))
                
        for tgt in self.config.targets:
            if tgt.type == 'docker': self.targets.append(DockerExecProber(container_name=tgt.container))
            elif tgt.type == 'proc': self.targets.append(ProcEnvironProber(pid_file=tgt.pid_file))
            elif tgt.type == 'local_env': self.targets.append(LocalEnvProber())

        if self.config.alerts.slack.enabled:
            self.alerters.append(SlackAlerter(self.config.alerts.slack.webhook_url, self.config.alerts.slack.min_severity))
        if self.config.alerts.pagerduty.enabled:
            self.alerters.append(PagerDutyAlerter(self.config.alerts.pagerduty.integration_key, self.config.alerts.pagerduty.min_severity))

    async def run_once(self) -> DriftReport:
        metrics.DRIFT_CHECK_COUNT.inc()
        
        expected_secrets = {}
        snapshots = await asyncio.gather(*[src.masked_fetch() for src in self.sources])
        for snap in snapshots: expected_secrets.update(snap.secrets)

        target = self.targets[0]
        actual_raw = await target.probe()
        actual_secrets = {k: _hash(v) for k, v in actual_raw.items()}

        report = compute_drift(expected_secrets, actual_secrets)
        
        if not self.config.agent.alert_on_extra:
            report.items = [i for i in report.items if i.kind != DriftKind.EXTRA_IN_RUNTIME]

        metrics.EXPECTED_SECRETS.set(report.expected_count)
        metrics.RUNTIME_SECRETS.set(report.actual_count)
        metrics.ACTIVE_DRIFT_ITEMS.set(len(report.items))
        if report.has_drift: metrics.DRIFT_DETECTED_COUNT.inc()

        self.storage.save_report(report)

        if report.has_drift:
            src_names = ', '.join([s.type for s in self.config.sources])
            tgt_names = ', '.join([t.type for t in self.config.targets])
            await asyncio.gather(*[alerter.send_alert(report, src_names, tgt_names) for alerter in self.alerters])

        return report

    async def run_loop(self, override_interval: int = None):
        interval = override_interval or self.config.agent.interval_seconds
        while True:
            await self.run_once()
            await asyncio.sleep(interval)
            
    @classmethod
    def from_config(cls, config_path: str) -> 'Agent':
        return cls(DetectorConfig.load_from_file(config_path))
