# Configuration Reference (detector.toml)

The detector.toml file is the central configuration for Secret Drift Detector.

## [agent]
Core agent behavior.
- interval_seconds (int): Polling interval for watch mode. Default: 60.
- lert_on_extra (bool): Alert if secrets exist in runtime but not in source. Default: false.
- ail_on_drift (bool): Exit with non-zero code in CI if drift is detected. Default: true.
- max_retries (int): Retries for fetching secrets. Default: 3.
- db_path (str): Local JSON database path. Default: "drift_history.db".
- db_uri (str): Optional Postgres connection string (e.g. postgresql://user:pass@localhost/db). Overrides db_path.
- enable_entropy (bool): Calculate Shannon entropy for secret values. Default: true.

## [[sources]]
Defines where secrets *should* come from.
- 	ype: ault, ssm, doppler, dotenv, kubernetes, secrets_manager, gcp.
- Properties: ddr, path, 	oken, prefix, project, config_env. 	oken supports env:VAR_NAME.

## [[targets]]
Defines where secrets *actually* are.
- 	ype: docker, proc, local_env, k8s_exec, http_introspect.
- Properties: container, pid_file, pod, url.

## [alerts]
Alerting integrations.
- [alerts.slack]: enabled, webhook_url (supports env:), min_severity, mention.
- [alerts.pagerduty]: enabled, integration_key, min_severity.
- [alerts.jira]: enabled, url, username, 	oken, project, min_severity.
- [alerts.stdout]: enabled, min_severity.
- [alerts.webhook]: enabled, url, headers, min_severity.

## [remediation]
- enabled: 	rue or alse.
- script: Path to an executable script to run when drift is detected.
