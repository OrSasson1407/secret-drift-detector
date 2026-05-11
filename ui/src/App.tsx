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
    <div className="min-h-screen relative" style={{ background: "var(--bg)", color: "var(--text)" }}>
      {/* ── Ambient Background Glow ── */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-4xl h-[500px] opacity-20 pointer-events-none blur-[120px]" 
           style={{ background: "radial-gradient(circle, var(--blue) 0%, transparent 60%)" }} />

      {/* ── Top nav (Frosted Glass) ── */}
      <header className="sticky top-0 z-50 flex items-center justify-between px-6 py-4 backdrop-blur-xl bg-black/40"
              style={{ borderBottom: "1px solid var(--border)" }}>
        <div className="flex items-center gap-3 font-bold tracking-wide text-lg drop-shadow-md">
          <div className="p-2 rounded-lg" style={{ background: "rgba(59, 130, 246, 0.15)" }}>
            <KeyRound className="w-5 h-5" style={{ color: "var(--blue)" }} />
          </div>
          Secret Drift Detector
        </div>

        <div className="flex items-center gap-4 text-sm font-medium">
          <span className="flex items-center gap-2 text-xs uppercase tracking-wider bg-black/30 px-3 py-1.5 rounded-full" 
                style={{ color: "var(--muted)", border: "1px solid var(--border)" }}>
            <span className={`w-2 h-2 rounded-full shadow-[0_0_8px_currentColor] ${apiOk === null ? "bg-gray-500" : apiOk ? "bg-green-500" : "bg-red-500"}`} />
            {apiOk === null ? "Checking" : apiOk ? "System Online" : "System Offline"}
          </span>

          <button onClick={refresh}
                  className="group flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300 hover:bg-white/10 active:scale-95"
                  style={{ border: "1px solid var(--border)", background: "var(--surface)" }}>
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-blue-400' : 'group-hover:rotate-180 transition-transform duration-500'}`} />
            Refresh
          </button>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-10 space-y-10 relative z-10">

        {/* ── Error banner ── */}
        {error && (
          <div className="flex items-center gap-3 px-5 py-4 rounded-xl text-sm font-medium animate-in slide-in-from-top-4"
               style={{ background: "rgba(239,68,68,0.15)", border: "1px solid rgba(239,68,68,0.4)", color: "#fca5a5" }}>
            <AlertTriangle className="w-5 h-5 shrink-0" />
            <div className="flex-1">
              <span className="text-white block font-bold mb-0.5">Connection Error</span>
              {error}
            </div>
          </div>
        )}

        {/* ── Stat cards ── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
          <StatCard
            label="Current Status"
            value={latest?.has_drift ? "Drifting" : "Secure"}
            sub={latest ? `Last check: Run #${latest.id}` : "No data yet"}
            accent={latest?.has_drift ? "var(--critical)" : "var(--ok)"}
            icon={latest?.has_drift ? <ShieldAlert className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
          />
          <StatCard
            label="Expected Secrets"
            value={latest?.expected_count ?? "—"}
            sub="from configured sources"
            accent="var(--blue)"
            icon={<Activity className="w-6 h-6" />}
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
        <section className="rounded-2xl p-6 space-y-4 shadow-xl transition-all duration-300 hover:border-blue-500/30"
                 style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
          <h2 className="text-xs font-bold uppercase tracking-widest flex items-center gap-2"
              style={{ color: "var(--muted)" }}>
            <Activity className="w-4 h-4" /> Drift Trend History
          </h2>
          {loading ? (
            <div className="h-40 flex items-center justify-center text-sm animate-pulse" style={{ color: "var(--muted)" }}>
              Analyzing trend data...
            </div>
          ) : (
            <div className="h-40 mt-4">
               <TrendChart data={trend} />
            </div>
          )}
        </section>

        {/* ── Run list ── */}
        <section className="space-y-4 pt-4">
          <div className="flex items-center justify-between pb-2 border-b border-white/5">
            <h2 className="text-xl font-bold tracking-tight" style={{ color: "var(--text)" }}>
              Recent Scans
            </h2>
            <button
              onClick={() => setOnlyDrift(v => !v)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300"
              style={{
                border: "1px solid",
                borderColor: onlyDrift ? "rgba(239,68,68,0.5)" : "var(--border)",
                background: onlyDrift ? "rgba(239,68,68,0.1)" : "var(--surface)",
                color: onlyDrift ? "#fca5a5" : "var(--text)",
                boxShadow: onlyDrift ? "0 0 15px rgba(239,68,68,0.15)" : "none"
              }}>
              <Filter className="w-4 h-4" />
              {onlyDrift ? "Drift Only" : "All Runs"}
            </button>
          </div>

          <div className="flex flex-col gap-3">
            {!loading && runs.length === 0 && (
              <div className="text-center py-16 rounded-xl border border-dashed border-white/10" style={{ color: "var(--muted)" }}>
                <ShieldCheck className="w-12 h-12 mx-auto mb-3 opacity-20" />
                {onlyDrift ? "No drift runs found. Great job!" : "No runs recorded yet. Start the agent to begin."}
              </div>
            )}
            {runs.map(run => <RunRow key={run.id} run={run} />)}
          </div>
        </section>

      </main>
    </div>
  );
}
