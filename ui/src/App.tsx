import { useEffect, useState, useCallback } from "react";
import {
  KeyRound, Activity, ShieldAlert, ShieldCheck,
  RefreshCw, Filter, AlertTriangle,
} from "lucide-react";
import { api } from "./api";
import { usePolling } from "./hooks/usePolling";
import { StatCard }   from "./components/StatCard";
import { TrendChart } from "./components/TrendChart";
import { RunRow }     from "./components/RunRow";
import type { RunSummary, TrendPoint } from "./types";

const POLL_MS = 15_000;

export default function App() {
  const [runs,       setRuns]       = useState<RunSummary[]>([]);
  const [trend,      setTrend]      = useState<TrendPoint[]>([]);
  const [loading,    setLoading]    = useState(true);
  const [error,      setError]      = useState<string | null>(null);
  const [onlyDrift,  setOnlyDrift]  = useState(false);
  const [lastRefresh,setLastRefresh]= useState<Date | null>(null);
  const [apiOk,      setApiOk]      = useState<boolean | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [r, t] = await Promise.all([api.runs(50, onlyDrift), api.trend(30)]);
      setRuns(r);
      setTrend(t);
      setError(null);
      setApiOk(true);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Unknown error");
      setApiOk(false);
    } finally {
      setLoading(false);
      setLastRefresh(new Date());
    }
  }, [onlyDrift]);

  useEffect(() => { refresh(); }, [refresh]);
  usePolling(refresh, POLL_MS);

  // Health ping
  useEffect(() => {
    api.health()
      .then(() => setApiOk(true))
      .catch(() => setApiOk(false));
  }, []);

  const latest      = runs[0] ?? null;
  const totalDrift  = runs.filter(r => r.has_drift).length;
  const cleanStreak = (() => {
    let n = 0;
    for (const r of runs) { if (!r.has_drift) n++; else break; }
    return n;
  })();

  return (
    <div className="min-h-screen" style={{ background: "var(--bg)", color: "var(--text)" }}>

      {/* ── Top nav ── */}
      <header className="sticky top-0 z-10 flex items-center justify-between px-6 py-3"
              style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}>
        <div className="flex items-center gap-2 font-semibold">
          <KeyRound className="w-5 h-5" style={{ color: "var(--blue)" }} />
          Secret Drift Detector
        </div>

        <div className="flex items-center gap-3 text-sm">
          {/* API health dot */}
          <span className="flex items-center gap-1.5 text-xs" style={{ color: "var(--muted)" }}>
            <span className="w-2 h-2 rounded-full inline-block"
                  style={{ background: apiOk === null ? "var(--muted)" : apiOk ? "var(--ok)" : "var(--critical)" }} />
            {apiOk === null ? "Checking…" : apiOk ? "API online" : "API offline"}
          </span>

          {lastRefresh && (
            <span className="text-xs" style={{ color: "var(--muted)" }}>
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}

          <button onClick={refresh}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors hover:bg-white/10"
                  style={{ border: "1px solid var(--border)" }}>
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-8 space-y-8">

        {/* ── Error banner ── */}
        {error && (
          <div className="flex items-center gap-3 px-4 py-3 rounded-lg text-sm"
               style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", color: "#fca5a5" }}>
            <AlertTriangle className="w-4 h-4 shrink-0" />
            {error}
          </div>
        )}

        {/* ── Stat cards ── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard
            label="Current Status"
            value={latest?.has_drift ? "Drifting" : "Secure"}
            sub={latest ? `Last check: Run #${latest.id}` : "No data yet"}
            accent={latest?.has_drift ? "var(--critical)" : "var(--ok)"}
            icon={latest?.has_drift
              ? <ShieldAlert className="w-5 h-5" />
              : <ShieldCheck className="w-5 h-5" />}
          />
          <StatCard
            label="Expected Secrets"
            value={latest?.expected_count ?? "—"}
            sub="from configured sources"
            accent="var(--blue)"
            icon={<Activity className="w-5 h-5" />}
          />
          <StatCard
            label="Drift Runs"
            value={totalDrift}
            sub={`of ${runs.length} total runs`}
            accent="var(--high)"
          />
          <StatCard
            label="Clean Streak"
            value={cleanStreak}
            sub="consecutive clean runs"
            accent="var(--ok)"
          />
        </div>

        {/* ── Trend chart ── */}
        <section className="rounded-xl p-5 space-y-4"
                 style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
          <h2 className="text-sm font-semibold uppercase tracking-widest"
              style={{ color: "var(--muted)" }}>
            Drift Trend — last {trend.length} runs
          </h2>
          {loading ? (
            <div className="h-28 flex items-center justify-center text-sm" style={{ color: "var(--muted)" }}>
              Loading…
            </div>
          ) : (
            <TrendChart data={trend} />
          )}
        </section>

        {/* ── Run list ── */}
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-widest"
                style={{ color: "var(--muted)" }}>
              Recent Scans
            </h2>
            <button
              onClick={() => setOnlyDrift(v => !v)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
              style={{
                border: "1px solid var(--border)",
                background: onlyDrift ? "rgba(239,68,68,0.15)" : "transparent",
                color: onlyDrift ? "#fca5a5" : "var(--muted)",
              }}>
              <Filter className="w-3.5 h-3.5" />
              {onlyDrift ? "Showing drift only" : "Show drift only"}
            </button>
          </div>

          {loading && (
            <div className="text-center py-12 text-sm" style={{ color: "var(--muted)" }}>
              Loading runs…
            </div>
          )}

          {!loading && runs.length === 0 && (
            <div className="text-center py-12 text-sm" style={{ color: "var(--muted)" }}>
              {onlyDrift ? "No drift runs found." : "No runs recorded yet. Start the agent to begin."}
            </div>
          )}

          {runs.map(run => <RunRow key={run.id} run={run} />)}
        </section>

      </main>
    </div>
  );
}
