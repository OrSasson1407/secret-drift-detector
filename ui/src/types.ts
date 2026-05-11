export type Severity = "critical" | "high" | "warn" | "info";
export type DriftKind = "missing" | "extra" | "changed" | "stale";

export interface DriftItem {
  key:      string;
  kind:     DriftKind;
  severity: Severity;
  detail:   string;
}

export interface ReportJson {
  items:          DriftItem[];
  expected_count: number;
  actual_count:   number;
  checked_at:     string;
  sources:        string[];
  targets:        string[];
}

export interface RunSummary {
  id:             number;
  timestamp:      string;
  expected_count: number;
  actual_count:   number;
  drift_count:    number;
  has_drift:      boolean;
  max_severity:   Severity | null;
  sources:        string[];
  targets:        string[];
}

export interface RunDetail extends RunSummary {
  report_json: ReportJson;
}

export interface TrendPoint {
  id:           number;
  timestamp:    string;
  drift_count:  number;
  has_drift:    0 | 1;
  max_severity: Severity | null;
}
