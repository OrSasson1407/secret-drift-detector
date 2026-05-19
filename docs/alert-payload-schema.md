# Alert Payload Schema

This document defines the JSON structure of the payload sent to webhooks and other HTTP-based alerters (like Slack). The payload is a direct JSON serialization of the DriftReport model.

## JSON Payload Example

\\\json
{
  "run_id": 1042,
  "items": [
    {
      "key": "STRIPE_SECRET_KEY",
      "kind": "changed",
      "severity": "critical",
      "detail": "Runtime value does not match the source.",
      "remediation_hint": "Rotate the key immediately.",
      "renamed_from": null,
      "entropy_score": 4.85
    },
    {
      "key": "LEGACY_API_TOKEN",
      "kind": "missing",
      "severity": "warn",
      "detail": "Secret is defined in source but missing in runtime.",
      "remediation_hint": "Ensure the container environment is injected properly.",
      "renamed_from": null,
      "entropy_score": null
    }
  ],
  "expected_count": 45,
  "actual_count": 44,
  "checked_at": "2023-10-12T10:00:00Z",
  "sources": ["doppler://dev-env"],
  "targets": ["docker://my-app-container"],
  "prev_hash": "a1b2c3d4e5f6...",
  "report_hash": "f6e5d4c3b2a1..."
}
\\\

## Field Descriptions

### Root Object (\DriftReport\)
- **\un_id\** *(integer | null)*: Unique identifier for the scan run.
- **\items\** *(array of \DriftItem\)*: List of detected drift anomalies.
- **\expected_count\** *(integer)*: Number of secrets expected from the source(s).
- **\ctual_count\** *(integer)*: Number of secrets actually found in the target(s).
- **\checked_at\** *(string)*: ISO 8601 timestamp of the check (UTC).
- **\sources\** *(array of strings)*: List of source URIs or identifiers scanned.
- **\	argets\** *(array of strings)*: List of target URIs or identifiers scanned.
- **\prev_hash\** *(string | null)*: Hash of the previous drift report (if tracking history).
- **\eport_hash\** *(string | null)*: Hash of the current drift report.

### Item Object (\DriftItem\)
- **\key\** *(string)*: The name of the secret (e.g., \AWS_ACCESS_KEY_ID\).
- **\kind\** *(string)*: The type of drift. One of: \missing\, \extra\, \changed\, \stale\, \enamed\, \orphaned\, \weak\.
- **\severity\** *(string)*: The impact level. One of: \critical\, \high\, \warn\, \info\.
- **\detail\** *(string)*: Human-readable description of the anomaly.
- **\emediation_hint\** *(string)*: Actionable suggestion to resolve the drift.
- **\enamed_from\** *(string | null)*: If \kind\ is \enamed\, the previous key name.
- **\entropy_score\** *(number | null)*: Shannon entropy score, if calculated.
