from datetime import datetime, timezone
import asyncio
import signal
import structlog

from detector.config import DetectorConfig
from detector.sources.vault           import VaultSource
from detector.sources.ssm             import SSMSource
from detector.sources.doppler         import DopplerSource
from detector.sources.dotenv_file     import DotEnvSource
from detector.sources.kubernetes      import KubernetesSource
from detector.sources.secrets_manager import SecretsManagerSource
from detector.sources.gcp             import GCPSource
from detector.runtime.docker_exec     import DockerExecProber
from detector.runtime.proc            import ProcEnvironProber
from detector.runtime.local_env       import LocalEnvProber
from detector.runtime.k8s_exec        import K8sExecProber
from detector.runtime.http_introspect import HttpIntrospectProber
from detector.diff.engine  import compute_drift
from detector.diff.models  import DriftReport, DriftKind
from detector.sources      import _hash
from detector.storage.snapshot import Storage
from detector.server       import metrics
from detector.alerts.slack     import SlackAlerter
from detector.alerts.pagerduty import PagerDutyAlerter
from detector.alerts.webhook   import WebhookAlerter
from detector.alerts.jira import JiraAlerter
from detector.alerts.stdout import StdoutAlerter
from detector.remediation.trigger import RemediationManager
from detector.server.metrics import REMEDIATION_TRIGGERED

log = structlog.get_logger()


class Agent:
    def __init__(self, config: DetectorConfig):
        self.config   = config
        self.sources  = []
        self.targets  = []
        self.alerters = []
        self.storage  = Storage(db_path=config.agent.db_path)
        self.remediation = RemediationManager(enabled=config.remediation.enabled if hasattr(config, 'remediation') else False)
        self._stop    = asyncio.Event()
        self._init_components()

    # ------------------------------------------------------------------
    def _init_components(self):
        timeout = self.config.agent.timeout_seconds

        for src in self.config.sources:
            if src.type == "vault":
                self.sources.append(VaultSource(
                    addr=src.addr, path=src.path, token=src.token,
                    mount_version=src.mount_version, key_prefix=src.key_prefix,
                    timeout=timeout,
                ))
            elif src.type == "ssm":
                self.sources.append(SSMSource(
                    prefix=src.prefix, region=src.region, key_prefix=src.key_prefix,
                ))
            elif src.type == "doppler":
                self.sources.append(DopplerSource(
                    project=src.project, config_env=src.config_env, token=src.token,
                ))
            elif src.type == "dotenv":
                self.sources.append(DotEnvSource(path=src.path))
            elif src.type == "kubernetes":
                self.sources.append(KubernetesSource(
                    namespace=src.namespace, label_selector=src.label_selector,
                ))
            elif src.type == "secrets_manager":
                self.sources.append(SecretsManagerSource(
                    path=src.path, region=src.region, key_prefix=src.key_prefix,
                ))
            elif src.type == "gcp":
                self.sources.append(GCPSource(project=src.project))
            else:
                log.warning("unknown_source_type", type=src.type)

        for tgt in self.config.targets:
            if tgt.type == "docker":
                self.targets.append(DockerExecProber(container_name=tgt.container))
            elif tgt.type == "proc":
                self.targets.append(ProcEnvironProber(pid_file=tgt.pid_file))
            elif tgt.type == "local_env":
                self.targets.append(LocalEnvProber())
            elif tgt.type == "k8s_exec":
                self.targets.append(K8sExecProber(
                    pod=tgt.pod, namespace=tgt.namespace or "default",
                    container=tgt.container, strip_system=True,
                ))
            elif tgt.type == "http_introspect":
                self.targets.append(HttpIntrospectProber(url=tgt.url))
            else:
                log.warning("unknown_target_type", type=tgt.type)

        cfg = self.config.alerts
        if cfg.slack.enabled:
            self.alerters.append(SlackAlerter(
                cfg.slack.webhook_url, cfg.slack.min_severity, mention=cfg.slack.mention,
            ))
        if cfg.pagerduty.enabled:
            self.alerters.append(PagerDutyAlerter(
                cfg.pagerduty.integration_key, cfg.pagerduty.min_severity,
            ))
        
        if hasattr(cfg, "jira") and getattr(cfg.jira, "enabled", False):
            self.alerters.append(JiraAlerter(
                cfg.jira.url, cfg.jira.username, cfg.jira.token, cfg.jira.project, cfg.jira.min_severity
            ))
        if hasattr(cfg, "stdout") and getattr(cfg.stdout, "enabled", False):
            self.alerters.append(StdoutAlerter(min_severity=cfg.stdout.min_severity))
        if cfg.webhook.enabled:
            self.alerters.append(WebhookAlerter(
                cfg.webhook.url, cfg.webhook.min_severity, cfg.webhook.headers,
            ))

    # ------------------------------------------------------------------
    async def run_once(self) -> DriftReport:
        metrics.DRIFT_CHECK_COUNT.inc()
        cfg = self.config.agent

        snapshots = await asyncio.gather(
            *[src.fetch_with_retry(max_retries=cfg.max_retries, delay=cfg.retry_delay)
              for src in self.sources],
            return_exceptions=True,
        )

        expected:      dict[str, str] = {}
        source_map:    dict[str, str] = {}
        source_names:  list[str]      = []
        failed_sources: list[str]     = []
        # Collect all keys ever seen across sources (for orphan detection)
        all_source_keys: set[str]     = set()

        # Collect rotation deadlines from source metadata
        stale_keys: set[str] = set()
        max_age_map: dict[str, int] = {}
        for s in self.sources:
            if hasattr(s, "max_age_days") and s.max_age_days:
                max_age_map[s.label] = s.max_age_days
                max_age_map[s.type] = s.max_age_days

        for src_obj, snap in zip(self.sources, snapshots):
            if isinstance(snap, Exception):
                log.error("source_fetch_failed", source=repr(src_obj), error=str(snap))
                failed_sources.append(repr(src_obj))
            else:
                for key in snap.secrets:
                    source_map[key] = snap.source
                    all_source_keys.add(key)
                    # Check rotation age via metadata timestamps
                    if snap.source in max_age_map:
                        created = snap.metadata.get("created_time", {}).get(key) or snap.metadata.get("last_modified", {}).get(key)
                        if created:

                            try:
                                age_days = (
                                    datetime.now(timezone.utc) -
                                    datetime.fromisoformat(created.replace("Z", "+00:00"))
                                ).days
                                if age_days > max_age_map.get(snap.source.split(':')[0], None):
                                    stale_keys.add(key)
                            except Exception:
                                pass
                for k, v in snap.secrets.items():
                    if k in expected and expected[k] != v:
                        log.warning("secret_collision", key=k, overwritten_by=snap.source)
                    expected[k] = v
                source_names.append(snap.source)

        if failed_sources:
            log.warning("partial_snapshot", failed=failed_sources, ok=source_names)

        # Probe targets — keep plaintext for entropy scoring
        actual_raw:  dict[str, str] = {}
        target_names: list[str]     = []
        for tgt in self.targets:
            try:
                raw = await tgt.probe()
                actual_raw.update(raw)
                target_names.append(tgt.type)
            except Exception as exc:
                log.error("target_probe_failed", target=tgt.type, error=str(exc))

        actual = {k: _hash(v) for k, v in actual_raw.items()}

        report = compute_drift(
            expected,
            actual,
            sources=source_names,
            targets=target_names,
            stale_keys=stale_keys,
            source_map=source_map,
            all_source_keys=all_source_keys,
            actual_plaintext=actual_raw,          # enables entropy scoring
            enable_entropy=cfg.enable_entropy,
        )

        if not cfg.alert_on_extra:
            report.items = [i for i in report.items
                            if i.kind != DriftKind.EXTRA_IN_RUNTIME]

        metrics.EXPECTED_SECRETS.set(report.expected_count)
        metrics.RUNTIME_SECRETS.set(report.actual_count)
        metrics.ACTIVE_DRIFT_ITEMS.set(len(report.items))
        if report.has_drift:
            metrics.DRIFT_DETECTED_COUNT.inc()

        run_id = self.storage.save_report(report)
        report.run_id = run_id

        if report.has_drift:
            alert_res = await asyncio.gather(
                *[alerter.send_alert(report) for alerter in self.alerters],
                return_exceptions=True,
            )
            for res, alerter in zip(alert_res, self.alerters):
                if isinstance(res, Exception):
                    log.error("alerter_failed", alerter=alerter.__class__.__name__, error=str(res))
            log.warning("drift_detected",
                        run_id=run_id,
                        items=len(report.items),
                        max_severity=str(report.max_severity))
            
            if self.remediation.enabled:
                await self.remediation.trigger(report)
                REMEDIATION_TRIGGERED.inc()
        else:
            log.info("no_drift",
                     run_id=run_id,
                     expected=report.expected_count,
                     actual=report.actual_count)

        return report

    # ------------------------------------------------------------------
    async def run_loop(self, override_interval: int | None = None):
        interval = override_interval or self.config.agent.interval_seconds
        log.info("watch_started", interval=interval)

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self._stop.set)
            except (NotImplementedError, OSError):
                pass

        try:
            while not self._stop.is_set():
                await self.run_once()
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=interval)
                except asyncio.TimeoutError:
                    pass
        except KeyboardInterrupt:
            self._stop.set()

        log.info("watch_stopped")

    # ------------------------------------------------------------------
    @classmethod
    def from_config(cls, config_path: str) -> "Agent":
        return cls(DetectorConfig.load_from_file(config_path))


