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
    <div className="rounded-xl p-5 flex flex-col gap-3"
         style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-widest"
              style={{ color: "var(--muted)" }}>{label}</span>
        {icon && <span style={{ color: accent }}>{icon}</span>}
      </div>
      <div className="text-3xl font-bold" style={{ color: "var(--text)" }}>{value}</div>
      {sub && <div className="text-xs" style={{ color: "var(--muted)" }}>{sub}</div>}
    </div>
  );
}
