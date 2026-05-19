# Alert Payload Schema
Defines the JSON structure sent to webhooks and Slack.

`json
{
  "run_id": 123,
  "checked_at": "2023-10-12T10:00:00Z",
  "expected_count": 45,
  "actual_count": 45,
  "has_drift": true,
  "items": [
    {
      "key": "STRIPE_SECRET_KEY",
      "kind": "value_mismatch",
      "severity": "critical",
      "detail": "Runtime hash does not match expected source."
    }
  ]
}