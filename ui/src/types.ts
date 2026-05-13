export interface DriftItem {
  key: string;
  kind: string;
  severity: string;
  detail: string;
}

export interface RunSummary {
  id: number;
  timestamp: string;
  has_drift: boolean;
  expected_count: number;
  actual_count: number;
  max_severity: string;
  acknowledged?: boolean;
  snoozed?: boolean;
  jira_task?: string;
}

