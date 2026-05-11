import type { Severity } from "../types";

const SEV: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-400 border border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border border-orange-500/30",
  warn:     "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30",
  info:     "bg-slate-500/15 text-slate-400 border border-slate-500/30",
};

const KIND: Record<string, string> = {
  missing: "bg-red-500/10 text-red-300 border border-red-500/20",
  extra:   "bg-blue-500/10 text-blue-300 border border-blue-500/20",
  changed: "bg-orange-500/10 text-orange-300 border border-orange-500/20",
  stale:   "bg-yellow-500/10 text-yellow-300 border border-yellow-500/20",
};

export function SeverityBadge({ value }: { value: Severity }) {
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wide ${SEV[value] ?? SEV.info}`}>
      {value}
    </span>
  );
}

export function KindBadge({ value }: { value: string }) {
  return (
    <span className={`px-2 py-0.5 rounded-md text-xs font-mono ${KIND[value] ?? KIND.changed}`}>
      {value}
    </span>
  );
}
