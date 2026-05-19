import { useState, useEffect } from 'react';
import { useWebSocket } from './hooks/useWebSocket';
import { RunRow } from './components/RunRow';
import type { Run } from './types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const WS_BASE  = API_BASE.replace('http', 'ws');
const API_KEY  = import.meta.env.VITE_API_KEY  || 'test-secret-key';

export function App() {
  const [runs, setRuns] = useState<Run[]>([]);

  // Authenticated persistent WebSocket listener
  const wsMessage = useWebSocket(`${WS_BASE}/api/v1/ws`, API_KEY);

  // Polling fallback every 30s (WS handles real-time)
  useEffect(() => {
    const fetchRuns = () => {
      fetch(`${API_BASE}/api/v1/runs?limit=15`, {
        headers: { 'X-API-Key': API_KEY },
      })
        .then(res => res.json())
        .then(data => {
          if (!Array.isArray(data)) return;
          setRuns(prev => {
            const existingMeta = new Map(
              prev.map(r => [r.id, { jira: r.jira_task, ack: r.acknowledged }])
            );
            return data.map((run: Run) => {
              const meta = existingMeta.get(run.id);
              if (meta?.jira) run.jira_task = meta.jira;
              if (meta?.ack)  run.acknowledged = true;
              return run;
            });
          });
        })
        .catch(err => console.error('API Offline', err));
    };

    fetchRuns();
    const interval = setInterval(fetchRuns, 30000);
    return () => clearInterval(interval);
  }, []);

  // Real-time ack sync from WebSocket
  useEffect(() => {
    if (wsMessage?.actions?.[0]?.action_id === 'ack_drift') {
      const runIdToAck = parseInt(wsMessage.actions[0].value);
      setRuns(prev =>
        prev.map(r => r.id === runIdToAck ? { ...r, acknowledged: true } : r)
      );
    }
  }, [wsMessage]);

  const handleAcknowledge = async (id: number) => {
    setRuns(prev => prev.map(r => r.id === id ? { ...r, acknowledged: true } : r));

    const payload = {
      actions: [{ action_id: 'ack_drift', value: id.toString() }],
      user: { id: 'DashboardUser' },
      response_url: `${API_BASE}/api/v1/slack/interactions`,
    };

    // Broadcast to other open tabs via authenticated WS
    try {
      const ws = new WebSocket(`${WS_BASE}/api/v1/ws?token=${API_KEY}`);
      ws.onopen = () => { ws.send(JSON.stringify(payload)); ws.close(); };
    } catch (e) {}
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans p-8 selection:bg-indigo-500/30">
      <div className="max-w-5xl mx-auto space-y-8">
        <header className="flex items-center justify-between pb-6 border-b border-slate-800">
          <div>
            <h1 className="text-4xl font-extrabold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-cyan-400 to-indigo-500">
              Drift Command Center
            </h1>
            <p className="text-slate-400 mt-2 font-medium">
              Real-time infrastructure synchronization and remediation monitor
            </p>
          </div>
          <div className="flex items-center space-x-2 bg-slate-900 px-4 py-2 rounded-lg border border-slate-800">
            <span className="relative flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
            </span>
            <span className="text-sm font-semibold text-slate-300 tracking-wide uppercase">Live Sync</span>
          </div>
        </header>

        <main className="bg-slate-900/50 border border-slate-800 rounded-2xl p-6 backdrop-blur-xl shadow-2xl">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-bold text-slate-100">Telemetry Feed</h2>
          </div>
          <div className="flex flex-col space-y-1">
            {runs.map(run => (
              <RunRow key={run.id} run={run} onAcknowledge={handleAcknowledge} />
            ))}
            {runs.length === 0 && (
              <div className="text-center py-12">
                <p className="text-slate-500 font-medium">Listening for drift events...</p>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}