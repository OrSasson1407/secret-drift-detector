import type { RunSummary, RunDetail, TrendPoint } from "./types";

const BASE = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status} — ${path}`);
  return res.json() as Promise<T>;
}

export const api = {
  runs:   (limit = 50, onlyDrift = false) =>
    get<RunSummary[]>(`/api/v1/runs?limit=${limit}&only_drift=${onlyDrift}`),
  run:    (id: number) => get<RunDetail>(`/api/v1/runs/${id}`),
  trend:  (limit = 30) => get<TrendPoint[]>(`/api/v1/trend?limit=${limit}`),
  health: ()           => get<{ status: string }>("/api/v1/health"),
};
