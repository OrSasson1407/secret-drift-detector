# 🔐 Secret Drift Detector

> Catch configuration drift between expected secrets and live runtime environments before it becomes a production incident.

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![React 18](https://img.shields.io/badge/React-18-blue)
![License MIT](https://img.shields.io/badge/license-MIT-green)

## 📖 The Problem
In modern deployments, secrets live in multiple places simultaneously: a `.env` file, a Vault path, an AWS SSM Parameter Store, and whatever the running container actually inherited at startup. These can silently diverge. 
* An engineer updates a Vault path but forgets to restart the container.
* A CI/CD pipeline reads from SSM, but the local environment is months out of date.
* A deleted secret is still set in the container environment (a ghost variable).

**Result:** Silent authentication failures, stale API keys hitting rate limits, and security incidents.

## 🚀 How It Works
Secret Drift Detector is a focused agent that continuously snapshots your *expected* secrets from authoritative sources, compares them against what your live processes *actually* see at runtime, and surfaces anomalies in a sleek Glassmorphism dashboard.

### 🏗️ Architecture
The system consists of three main components:
1. **The Agent (CLI):** A daemon that polls sources (Vault, AWS SSM, Doppler, `.env`), probes runtime targets (Docker, Procs, Local Env), diffs the results, and logs them to SQLite.
2. **The Server (FastAPI):** A lightweight backend that serves the drift history and trend metrics to the frontend.
3. **The Dashboard (React):** A premium UI that visualizes drift runs, clean streaks, and alerts in real-time.

---

## 🛠️ Getting Started

### Prerequisites
* **Python 3.11+** (Make sure Python is added to your Windows PATH)
* **Node.js 18+** (For the React UI)
* **Poetry** (`pip install poetry`)

### 1. Installation
Clone the repository and install the backend dependencies:
```bash
poetry install
Install the frontend dependencies:

Bash
cd ui
npm install
cd ..
🔁 Running the Full System (The Magic Loop)
To see the system working in real-time, you need to run the three components simultaneously. Open three separate terminal tabs in the root directory:

Terminal 1: Start the Backend Server

Bash
poetry run uvicorn detector.server.app:app --reload --port 8000
Terminal 2: Start the Frontend UI

Bash
cd ui
npm run dev
Terminal 3: Start the Agent Daemon

Bash
poetry run python -m detector.cli watch --config config/local_test.toml --interval 10
Open http://localhost:5173 in your browser. Every 10 seconds, the agent will scan your environment, save the data to SQLite, and the React dashboard will automatically update!

💻 CLI Usage
You don't have to use the UI. The core agent can be used directly from the terminal or in CI/CD pipelines.

Run a one-shot check:

Bash
poetry run python -m detector.cli check --config config/detector.toml
View terminal history report:

Bash
poetry run python -m detector.cli report --limit 10
Note: The CLI relies on detector.toml to define which sources (e.g., Vault, SSM) and targets (e.g., Docker containers) to monitor.

🎬 See It In Action
When you run the full project, here is exactly what happens across your system in real-time:

1. The Agent (Background Daemon)
Wakes up based on your configured interval, scans the authoritative sources, probes the runtime target, and flags anomalies:

Plaintext
2026-05-11 22:07:12 [warning  ] drift_detected                 items=1 max_severity=Severity.CRITICAL

✖ DRIFT DETECTED — 1 item(s)  2026-05-11 19:07:12 UTC
  Sources : dotenv:.env.production
  Targets : local_env

┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ KEY               ┃ KIND    ┃ SEVERITY ┃ DETAIL                                           ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ DATABASE_PASSWORD │ missing │ CRITICAL │ present in source(s) but absent from runtime env │
└───────────────────┴─────────┴──────────┴──────────────────────────────────────────────────┘
2. The Server (API)
The agent saves the result to the local database, and the FastAPI server immediately begins serving the fresh data to the frontend:

Plaintext
INFO:     127.0.0.1:54321 - "GET /api/v1/runs?limit=50&only_drift=false HTTP/1.1" 200 OK
INFO:     127.0.0.1:54322 - "GET /api/v1/trend?limit=30 HTTP/1.1" 200 OK
3. The React Dashboard
Without you ever having to refresh the page, the UI automatically fetches the new data via its polling hook and visually reacts:

The Current Status card flips from a green "Secure" to a glowing red "Drifting".

The Drift Runs metric increments.

A new Threat Alert Card appears at the top of the Recent Scans list detailing the missing DATABASE_PASSWORD.

The Trend Chart renders a new critical red spike for the current run.