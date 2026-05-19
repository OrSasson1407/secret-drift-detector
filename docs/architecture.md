# System Architecture

The Secret Drift Detector has been upgraded from a localized script to a distributed, real-time platform.

## Core Components

* **Storage Layer (PostgreSQL):** Replaces the legacy SQLite implementation. Multiple scanner agents deployed across different clusters can now write drift reports and telemetry back to a single centralized database.
* **API & Real-Time Sync (FastAPI + WebSockets):** The backend serves REST endpoints for historical data and a dedicated WebSocket connection (/api/v1/ws) for bidirectional real-time state synchronization.
* **Dashboard (React + Vite + TypeScript):** A modern, type-safe frontend. It consumes the WebSocket feed to instantly reflect state changes (like alert acknowledgments) across all connected clients without requiring manual refreshes.
* **Diff Engine:** Utilizes smart secret fingerprinting via Regex to classify token types (AWS, GitHub PAT, Slack) before diffing expected Vault states against runtime environments.

## Deployment
Agents can be deployed statelessly as CronJobs or DaemonSets in Kubernetes, relying on the central PostgreSQL database for state management and historical tracking.

