# Config Reference
Reference for detector.toml.

`	oml
[agent]
interval_seconds = 60
db_path = "drift_history.json" # or postgresql://...
fail_on_drift = true
enable_entropy = true

[remediation]
enabled = true
script = "./remediate.sh"

[[sources]]
type = "dotenv"
path = ".env"

[[targets]]
type = "local_env"