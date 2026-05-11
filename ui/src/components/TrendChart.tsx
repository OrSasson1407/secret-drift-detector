import type { TrendPoint } from "../types";

export function TrendChart({ data }: { data: TrendPoint[] }) {
  if (data.length === 0) return null;

  const maxDrift = Math.max(...data.map(d => d.drift_count), 5);

  return (
    <div className="h-full flex items-end gap-1.5 pt-4">
      {data.map((pt, i) => {
        const heightPct = Math.max((pt.drift_count / maxDrift) * 100, pt.has_drift ? 15 : 4);
        const color = pt.has_drift 
          ? (pt.max_severity === "CRITICAL" ? "var(--critical)" : "var(--warn)")
          : "var(--ok)";

        return (
          <div key={i} className="group relative flex-1 flex flex-col justify-end h-full">
            
            {/* Tooltip */}
            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-max px-3 py-1.5 rounded-lg text-xs font-bold opacity-0 group-hover:opacity-100 transition-opacity z-20 pointer-events-none shadow-xl"
                 style={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text)" }}>
              Run #{pt.id}: <span style={{ color }}>{pt.drift_count} items</span>
            </div>

            {/* Bar */}
            <div className="w-full rounded-t-sm transition-all duration-300 group-hover:brightness-150 group-hover:shadow-[0_0_10px_currentColor]"
                 style={{ height: `${heightPct}%`, background: color, opacity: pt.has_drift ? 0.9 : 0.3, color }} />
          </div>
        );
      })}
    </div>
  );
}
