import asyncio
import structlog
from detector.config import DetectorConfig
from detector.sources.vault       import VaultSource
from detector.sources.ssm         import SSMSource
from detector.sources.doppler     import DopplerSource
from detector.sources.dotenv_file import DotEnvSource
from detector.runtime.docker_exec    import DockerExecProber
from detector.runtime.proc           import ProcEnvironProber
from detector.runtime.local_env      import LocalEnvProber
from detector.runtime.http_introspect import HttpIntrospectProber
from detector.diff.engine  import compute_drift
from detector.diff.models  import DriftReport, DriftKind
from detector.sources      import _hash
from detector.storage.snapshot import Storage
from detector.server       import metrics
from detector.alerts.slack     import SlackAlerter
from detector.alerts.pagerduty import PagerDutyAlerter
from detector.alerts.webhook   import WebhookAlerter

log = structlog.get_logger()


class Agent:
    def __init__(self, config: DetectorConfig):
        self.config   = config
        self.sources  = []
        self.targets  = []
        self.alerters = []
        self.storage  = Storage()
        self._init_components()

    # ------------------------------------------------------------------
    def _init_components(self):
        for src in self.config.sources:
            if src.type == "vault":
                self.sources.append(VaultSource(addr=src.addr, path=src.path, token=src.token))
            elif src.type == "ssm":
                self.sources.append(SSMSource(prefix=src.prefix, region=src.region))
            elif src.type == "doppler":
                self.sources.append(DopplerSource(
                    project=src.project, config_env=src.config_env, token=src.token
                ))
            elif src.type == "dotenv":
                self.sources.append(DotEnvSource(path=src.path))

        for tgt in self.config.targets:
            if tgt.type == "docker":
                self.targets.append(DockerExecProber(container_name=tgt.container))
            elif tgt.type == "proc":
                self.targets.append(ProcEnvironProber(pid_file=tgt.pid_file))
            elif tgt.type == "local_env":
                self.targets.append(LocalEnvProber())
            elif tgt.type == "http_introspect":
                self.targets.append(HttpIntrospectProber(url=tgt.url))

        cfg = self.config.alerts
        if cfg.slack.enabled:
            self.alerters.append(SlackAlerter(cfg.slack.webhook_url, cfg.slack.min_severity))
        if cfg.pagerduty.enabled:
            self.alerters.append(PagerDutyAlerter(cfg.pagerduty.integration_key, cfg.pagerduty.min_severity))
        if cfg.webhook.enabled:
            self.alerters.append(WebhookAlerter(cfg.webhook.url, cfg.webhook.min_severity, cfg.webhook.headers))

    # ------------------------------------------------------------------
    async def run_once(self) -> DriftReport:
        metrics.DRIFT_CHECK_COUNT.inc()
        cfg = self.config.agent

        # Fetch from all sources (with retry), merge into expected dict
        snapshots = await asyncio.gather(
            *[src.fetch_with_retry(max_retries=cfg.max_retries, delay=cfg.retry_delay)
              for src in self.sources],
            return_exceptions=True,
        )

        expected: dict[str, str] = {}
        source_names: list[str] = []
        for src_obj, snap in zip(self.sources, snapshots):
            if isinstance(snap, Exception):
                log.error("source_fetch_failed", source=src_obj.type, error=str(snap))
            else:
                expected.update(snap.secrets)
                source_names.append(snap.source)

        # Probe all targets, merge actual env
        actual_raw: dict[str, str] = {}
        target_names: list[str] = []
        for tgt in self.targets:
            try:
                raw = await tgt.probe()
                actual_raw.update(raw)
                target_names.append(tgt.type)
            except Exception as exc:
                log.error("target_probe_failed", target=tgt.type, error=str(exc))

        actual = {k: _hash(v) for k, v in actual_raw.items()}

        report = compute_drift(expected, actual, sources=source_names, targets=target_names)

        if not cfg.alert_on_extra:
            report.items = [i for i in report.items if i.kind != DriftKind.EXTRA_IN_RUNTIME]

        # Metrics
        metrics.EXPECTED_SECRETS.set(report.expected_count)
        metrics.RUNTIME_SECRETS.set(report.actual_count)
        metrics.ACTIVE_DRIFT_ITEMS.set(len(report.items))
        if report.has_drift:
            metrics.DRIFT_DETECTED_COUNT.inc()

        self.storage.save_report(report)

        if report.has_drift:
            await asyncio.gather(
                *[alerter.send_alert(report) for alerter in self.alerters],
                return_exceptions=True,
            )
            log.warning("drift_detected", items=len(report.items),
                        max_severity=str(report.max_severity))
        else:
            log.info("no_drift", expected=report.expected_count, actual=report.actual_count)

        return report

    # ------------------------------------------------------------------
    async def run_loop(self, override_interval: int | None = None):
        interval = override_interval or self.config.agent.interval_seconds
        log.info("watch_started", interval=interval)
        while True:
            await self.run_once()
            await asyncio.sleep(interval)

    @classmethod
    def from_config(cls, config_path: str) -> "Agent":
        return cls(DetectorConfig.load_from_file(config_path))
