import type { ReactNode } from "react";

interface Props {
  label:    string;
  value:    ReactNode;
  sub?:     string;
  accent?:  string;
  icon?:    ReactNode;
}

export function StatCard({ label, value, sub, accent = "var(--blue)", icon }: Props) {
  return (
    <div className="group relative rounded-2xl p-6 flex flex-col gap-4 transition-all duration-300 hover:-translate-y-1 overflow-hidden"
         style={{ background: "var(--surface)", border: "1px solid var(--border)", boxShadow: "0 4px 20px rgba(0,0,0,0.2)" }}>
      
      {/* Dynamic Hover Glow */}
      <div className="absolute -top-10 -right-10 w-32 h-32 rounded-full blur-[40px] opacity-10 group-hover:opacity-30 transition-opacity duration-500"
           style={{ background: accent }} />

      <div className="flex items-center justify-between relative z-10">
        <span className="text-xs font-bold uppercase tracking-widest"
              style={{ color: "var(--muted)" }}>{label}</span>
        {icon && (
          <span className="p-2 rounded-lg bg-black/20" style={{ color: accent, border: `1px solid ${accent}40` }}>
            {icon}
          </span>
        )}
      </div>
      
      <div className="relative z-10">
        <div className="text-4xl font-extrabold tracking-tight mb-1" style={{ color: "var(--text)" }}>{value}</div>
        {sub && <div className="text-xs font-medium" style={{ color: "var(--muted)" }}>{sub}</div>}
      </div>
    </div>
  );
}
