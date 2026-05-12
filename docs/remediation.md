# Auto-Remediation (Self-Healing)

The RemediationManager shifts the platform from purely monitoring infrastructure to actively healing it.

## Overview
When enabled via the .env.production file (ENABLE_AUTO_REMEDIATION=true), the scanner will not only alert on missing or mismatched secrets but will actively attempt to restore the target environment to its expected state.

## Execution Flow
1.  **Detection:** A drift report is generated, flagging a specific key (e.g., AWS_ACCESS_KEY_ID) as missing in the target K8s cluster but present in Vault.
2.  **Evaluation:** The system checks the severity. High and Critical severity items trigger the remediation pipeline.
3.  **Execution:** The 	rigger.py logic dispatches a command (such as a simulated kubectl patch secret or an AWS SSM parameter update) to inject the correct value back into the runtime environment.
4.  **Telemetry:** A Prometheus metric (drift_remediation_triggered_total) is incremented, ensuring DevOps teams have visibility into how often the system is self-healing.
