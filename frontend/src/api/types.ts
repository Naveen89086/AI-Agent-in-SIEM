export interface Alert {
  id: string;
  rule_id: string;
  rule_title: string;
  detector: string;
  count: number;
  severity: string;
  status: string;
  assignee: string | null;
  description: string | null;
  grouping: Record<string, unknown> | null;
  mitre: { tactic?: string; technique?: string; technique_name?: string }[] | null;
  tags: string[] | null;
  events: Record<string, unknown>[] | null;
  meta: Record<string, unknown> | null;
  notes: string | null;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
}

export interface Case {
  id: string;
  title: string;
  description: string | null;
  status: string;
  severity: string;
  assignee: string | null;
  tags: string[] | null;
  alert_ids: string[] | null;
  opened_at: string;
  closed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface CaseNote {
  id: string;
  case_id: string;
  author: string;
  content: string;
  created_at: string;
}

export interface CaseArtifact {
  id: string;
  case_id: string;
  artifact_type: string;
  value: string;
  source: string | null;
  note: string | null;
  created_at: string;
}

export interface TimelineEntry {
  at: string;
  type: string;
  title: string;
  detail: string;
}

export interface Source {
  id: string;
  name: string;
  source_type: string;
  format: string;
  parser: string | null;
  host: string | null;
  enabled: boolean;
  received_count: number;
  last_seen_at: string | null;
  created_at: string;
}

export interface SoarAction {
  id: string;
  playbook_id: string;
  playbook_name: string;
  alert_id: string | null;
  rule_id: string | null;
  action_type: string;
  status: string;
  target: string | null;
  detail: string | null;
  created_at: string;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  trigger: Record<string, unknown>;
  actions: { type: string; name?: string }[];
}

export interface Rule {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  condition: string;
  threshold: number;
  timeframe_seconds: number | null;
  group_by: string | null;
  logsource: Record<string, string>;
  mitre: { tactic?: string; technique?: string }[] | null;
  tags: string[] | null;
  source: string | null;
}

export interface Analysis {
  id: string;
  kind: string;
  alert_id: string | null;
  provider: string;
  analysis: string;
  summary: string | null;
  mitre: { tactic?: string; technique?: string }[] | null;
  recommended_actions: string[] | null;
  risk_score: number | null;
  confidence: number | null;
  created_at: string;
}

export interface DashboardSummary {
  events_total: number;
  events_last_24h: number;
  alerts_open: number;
  alerts_acknowledged: number;
  alerts_resolved: number;
  alerts_false_positive: number;
  alerts_active: number;
  alerts_by_severity: Record<string, number>;
  cases_open: number;
  cases_resolved: number;
  sources_total: number;
  generated_at: string;
}

export interface TimeseriesPoint {
  key: string;
  events: number;
  alerts: number;
}

export interface TopItem {
  key?: string;
  rule_id?: string;
  rule_title?: string;
  source_name?: string;
  count: number;
}

export interface SearchHit {
  "@timestamp"?: string;
  source_type?: string;
  source_name?: string;
  host?: { name?: string };
  message?: string;
  event?: { action?: string; outcome?: string; category?: string[] };
  source?: { ip?: string; port?: number };
  user?: { name?: string };
  [key: string]: unknown;
}

export interface Page<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
}
