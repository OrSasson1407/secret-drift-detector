import { ChevronDown, ChevronRight, ShieldAlert, ShieldCheck } from "lucide-react";
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
  const ts = formatDistanceToNow(new Date(run.timestamp), { addSuffix: true });

  return (
    <div className="rounded-xl overflow-hidden"
         style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>

      {/* Row header */}
      <button onClick={toggle}
              className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-white/5 transition-colors"
              style={{ borderLeft: `3px solid ${accentColor}` }}>
        <span style={{ color: accentColor }}>
          {run.has_drift
            ? <ShieldAlert className="w-5 h-5" />
            : <ShieldCheck className="w-5 h-5" />}
        </span>

        <span className="font-mono text-sm font-semibold"
              style={{ color: "var(--muted)" }}>#{run.id}</span>

        <span className="text-sm font-medium flex-1" style={{ color: "var(--text)" }}>
          {run.has_drift ? `${run.drift_count} drift item${run.drift_count !== 1 ? "s" : ""}` : "Clean"}
        </span>

        {run.max_severity && <SeverityBadge value={run.max_severity} />}

        <span className="text-xs" style={{ color: "var(--muted)" }}>{ts}</span>

        <span style={{ color: "var(--muted)" }}>
          {open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </span>
      </button>

      {/* Expanded detail */}
      {open && (
        <div className="px-5 pb-5 pt-1" style={{ borderTop: "1px solid var(--border)" }}>
          {loading && (
            <div className="py-6 text-center text-sm" style={{ color: "var(--muted)" }}>
              Loading…
            </div>
          )}

          {detail && (
            <>
              {/* Meta row */}
              <div className="flex flex-wrap gap-4 py-3 text-xs" style={{ color: "var(--muted)" }}>
                <span>Sources: <span style={{ color: "var(--text)" }}>{detail.sources.join(", ") || "—"}</span></span>
                <span>Targets: <span style={{ color: "var(--text)" }}>{detail.targets.join(", ") || "—"}</span></span>
                <span>Expected: <span style={{ color: "var(--text)" }}>{detail.expected_count}</span></span>
                <span>Runtime: <span style={{ color: "var(--text)" }}>{detail.actual_count}</span></span>
              </div>

              {detail.report_json.items.length === 0 ? (
                <p className="text-sm py-2" style={{ color: "var(--ok)" }}>✔ No drift items.</p>
              ) : (
                <table className="w-full text-left text-sm mt-2">
                  <thead>
                    <tr style={{ color: "var(--muted)" }}
                        className="text-xs uppercase tracking-wider">
                      <th className="pb-2 pr-4 font-medium">Key</th>
                      <th className="pb-2 pr-4 font-medium">Kind</th>
                      <th className="pb-2 pr-4 font-medium">Severity</th>
                      <th className="pb-2 font-medium">Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detail.report_json.items.map((item, i) => (
                      <tr key={i}
                          className="border-t"
                          style={{ borderColor: "var(--border)" }}>
                        <td className="py-2 pr-4 font-mono text-xs" style={{ color: "var(--text)" }}>
                          {item.key}
                        </td>
                        <td className="py-2 pr-4">
                          <KindBadge value={item.kind} />
                        </td>
                        <td className="py-2 pr-4">
                          <SeverityBadge value={item.severity} />
                        </td>
                        <td className="py-2 text-xs" style={{ color: "var(--muted)" }}>
                          {item.detail}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
