# Agile Alerting & Workflow

The platform integrates directly into standard SDLC and project management workflows to ensure security drift is tracked and resolved systematically.

## Automated Issue Tracking (Jira)
When the detector identifies a critical configuration mismatch, the JiraAlerter automatically generates a task in the designated project board (e.g., SEC). 
* **Integration:** Populates the ticket description with the drift run ID, timestamp, and a breakdown of the specific drifted keys.
* **Lifecycle:** Allows security and DevOps teams to pull remediation efforts directly into active Sprints.

## Interactive Slack Alerts
Alerts sent to Slack are not just read-only. They utilize Slack's interactive blocks.
* **Acknowledge:** Users can click "Acknowledge" directly in the Slack channel. This triggers a webhook back to the FastAPI server, which records the user ID, updates the database, and pushes the acknowledged state to the React UI via WebSockets.
* **Snooze:** Temporarily silences alerts for a specific run ID during active debugging or expected downtime.

## CI/CD Quality Gates
The CLI features a --ci --fail-on-drift flag. When integrated into GitHub Actions, it acts as a strict blocker. If a developer's Pull Request introduces code that causes a test environment to drift from the expected secret vault state, the build fails immediately.
