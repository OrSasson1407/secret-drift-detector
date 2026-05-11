import { ChevronDown, ChevronRight, ShieldAlert, ShieldCheck, Database, Target, Clock } from "lucide-react";
import { useState } from "react";
import { formatDistanceToNow } from "date-fns";
import { SeverityBadge, KindBadge } from "./Badge";
import type { RunDetail, RunSummary } from "../types";
import { api } from "../api";

interface Props { run: RunSummary }

export function RunRow({ run }: Props) {
  const [open,   setOpen]   = useState(false);
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [loading, setLoading] = useState(false);

  async function toggle() {
    if (!open && !detail) {
      setLoading(true);
      try { setDetail(await api.run(run.id)); }
      finally { setLoading(false); }
    }
    setOpen(o => !o);
  }

  const accentColor = run.has_drift ? "var(--critical)" : "var(--ok)";
  const bgHighlight = run.has_drift ? "rgba(239, 68, 68, 0.05)" : "transparent";
  const ts = formatDistanceToNow(new Date(run.timestamp), { addSuffix: true });

  return (
    <div className="rounded-xl overflow-hidden transition-all duration-300 hover:shadow-lg"
         style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>

      {/* Row header */}
      <button onClick={toggle}
              className="w-full flex items-center gap-5 px-6 py-4 text-left transition-colors"
              style={{ borderLeft: `4px solid ${accentColor}`, background: bgHighlight }}>
        
        <div className="p-2 rounded-full bg-black/20" style={{ color: accentColor }}>
          {run.has_drift ? <ShieldAlert className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
        </div>

        <div className="flex-1 flex items-center gap-6">
          <span className="font-mono text-sm font-bold bg-black/30 px-3 py-1 rounded-md"
                style={{ color: "var(--muted)", border: "1px solid var(--border)" }}>
            #{run.id}
          </span>
          
          <span className="text-base font-semibold" style={{ color: "var(--text)" }}>
            {run.has_drift ? <span className="text-red-400">{run.drift_count} Secrets Drifting</span> : "Environment Clean"}
          </span>
        </div>

        {run.max_severity && <SeverityBadge value={run.max_severity} />}

        <span className="flex items-center gap-1.5 text-xs font-medium w-32 justify-end" style={{ color: "var(--muted)" }}>
          <Clock className="w-3.5 h-3.5" />
          {ts}
        </span>

        <span className="p-1 rounded bg-black/20 ml-2" style={{ color: "var(--muted)" }}>
          {open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </span>
      </button>

      {/* Expanded detail */}
      <div className={`transition-all duration-500 ease-in-out ${open ? 'max-h-[2000px] opacity-100' : 'max-h-0 opacity-0'} overflow-hidden`}>
        <div className="px-6 pb-6 pt-4 bg-black/20" style={{ borderTop: "1px solid var(--border)" }}>
          {loading && (
            <div className="py-8 text-center text-sm animate-pulse" style={{ color: "var(--muted)" }}>
              Fetching drift analysis...
            </div>
          )}

          {detail && (
            <div className="space-y-6 animate-in fade-in duration-500">
              
              {/* Meta row */}
              <div className="flex flex-wrap gap-6 p-4 rounded-lg bg-black/40 border border-white/5 text-sm">
                <div className="flex items-center gap-2">
                  <Database className="w-4 h-4 text-blue-400" />
                  <span style={{ color: "var(--muted)" }}>Sources:</span> 
                  <span className="font-medium text-white">{detail.sources.join(", ") || "—"}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Target className="w-4 h-4 text-purple-400" />
                  <span style={{ color: "var(--muted)" }}>Targets:</span> 
                  <span className="font-medium text-white">{detail.targets.join(", ") || "—"}</span>
                </div>
                <div className="ml-auto flex gap-4 font-mono text-xs">
                  <span className="px-3 py-1 rounded bg-white/5">Expected: {detail.expected_count}</span>
                  <span className="px-3 py-1 rounded bg-white/5">Runtime: {detail.actual_count}</span>
                </div>
              </div>

              {detail.report_json.items.length === 0 ? (
                <div className="p-4 rounded-lg bg-green-500/10 border border-green-500/20 text-green-400 flex items-center gap-3">
                  <ShieldCheck className="w-5 h-5" />
                  <span className="font-medium">All runtime secrets match expected sources.</span>
                </div>
              ) : (
                <div className="space-y-3">
                  <h3 className="text-xs font-bold uppercase tracking-widest" style={{ color: "var(--muted)" }}>Detected Anomalies</h3>
                  
                  {/* Grid of Alert Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {detail.report_json.items.map((item, i) => (
                      <div key={i} className="flex flex-col p-4 rounded-lg border bg-black/40 relative overflow-hidden"
                           style={{ borderColor: item.severity === "CRITICAL" ? "rgba(239, 68, 68, 0.3)" : "rgba(245, 158, 11, 0.3)" }}>
                        
                        {/* Status accent bar on top */}
                        <div className={`absolute top-0 left-0 right-0 h-1 ${item.severity === "CRITICAL" ? "bg-red-500" : "bg-orange-500"}`} />

                        <div className="flex justify-between items-start mb-3">
                          <code className="px-2 py-1 bg-black/50 rounded text-sm font-bold text-gray-200 border border-white/10">
                            {item.key}
                          </code>
                          <div className="flex gap-2">
                            <KindBadge value={item.kind} />
                            <SeverityBadge value={item.severity} />
                          </div>
                        </div>
                        
                        <p className="text-sm mt-auto font-medium" style={{ color: "var(--muted)" }}>
                          {item.detail}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
