import type { TrendPoint } from "../types";

interface Props { data: TrendPoint[] }

export function TrendChart({ data }: Props) {
  if (data.length < 2) return (
    <div className="flex items-center justify-center h-32 text-sm"
         style={{ color: "var(--muted)" }}>
      Not enough data yet — run more checks to see a trend.
    </div>
  );

  const W = 800, H = 120, PAD = 16;
  const max = Math.max(...data.map(d => d.drift_count), 1);

  const pts = data.map((d, i) => {
    const x = PAD + (i / (data.length - 1)) * (W - PAD * 2);
    const y = H - PAD - (d.drift_count / max) * (H - PAD * 2);
    return { x, y, d };
  });

  const area =
    `M ${pts[0].x} ${H - PAD} ` +
    pts.map(p => `L ${p.x} ${p.y}`).join(" ") +
    ` L ${pts[pts.length - 1].x} ${H - PAD} Z`;

  const line = pts.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x} ${p.y}`).join(" ");

  return (
    <div className="w-full overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ minWidth: 320 }}>
        <defs>
          <linearGradient id="tg" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="#ef4444" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#ef4444" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {/* Grid lines */}
        {[0, 0.25, 0.5, 0.75, 1].map(t => {
          const y = PAD + t * (H - PAD * 2);
          return <line key={t} x1={PAD} y1={y} x2={W - PAD} y2={y}
                       stroke="var(--border)" strokeWidth="1" />;
        })}
        <path d={area} fill="url(#tg)" />
        <path d={line} fill="none" stroke="#ef4444" strokeWidth="2"
              strokeLinejoin="round" strokeLinecap="round" />
        {/* Dots */}
        {pts.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r="3.5"
                  fill={p.d.has_drift ? "#ef4444" : "#22c55e"}
                  stroke="var(--surface)" strokeWidth="1.5" />
        ))}
      </svg>
    </div>
  );
}
