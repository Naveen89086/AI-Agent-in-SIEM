import type {
  Alert,
  Analysis,
  Case,
  CaseArtifact,
  CaseNote,
  DashboardSummary,
  Page,
  Playbook,
  Rule,
  SearchHit,
  SoarAction,
  Source,
  TimeseriesPoint,
  TimelineEntry,
  TopItem,
} from "./types";

const TOKEN_KEY = "siem_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  auth = true
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (auth) {
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }

  const resp = await fetch(path, { ...options, headers });
  if (resp.status === 401 && auth) {
    clearToken();
    window.location.href = "/login";
    throw new ApiError(401, "Session expired");
  }
  if (!resp.ok) {
    let message = `Request failed (${resp.status})`;
    try {
      const body = await resp.json();
      message = body?.detail || body?.error?.message || message;
    } catch {
      /* ignore parse errors */
    }
    throw new ApiError(resp.status, message);
  }
  return (await resp.json()) as T;
}

export const api = {
  // auth
  login: (username: string, password: string) =>
    request<{ access_token: string; token_type: string; user?: unknown }>(
      "/api/v1/auth/login",
      { method: "POST", body: JSON.stringify({ username, password }) },
      false
    ),

  // dashboard
  dashboardSummary: () =>
    request<DashboardSummary>("/api/v1/dashboard/summary"),
  dashboardTimeseries: (hours = 24, bucketMinutes = 60) =>
    request<{ interval_seconds: number; points: TimeseriesPoint[] }>(
      `/api/v1/dashboard/timeseries?hours=${hours}&bucket_minutes=${bucketMinutes}`
    ),
  dashboardTopRules: (limit = 8) =>
    request<TopItem[]>(`/api/v1/dashboard/top-rules?limit=${limit}`),
  dashboardTopSources: (limit = 8) =>
    request<TopItem[]>(`/api/v1/dashboard/top-sources?limit=${limit}`),
  dashboardRecentAlerts: (limit = 10) =>
    request<Partial<Alert>[]>(`/api/v1/dashboard/recent-alerts?limit=${limit}`),

  // alerts
  alerts: (params: { status?: string; severity?: string; offset?: number; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    if (params.status) qs.set("status", params.status);
    if (params.severity) qs.set("severity", params.severity);
    qs.set("offset", String(params.offset ?? 0));
    qs.set("limit", String(params.limit ?? 50));
    return request<Page<Alert>>(`/api/v1/alerts?${qs}`);
  },
  alert: (id: string) => request<Alert>(`/api/v1/alerts/${id}`),
  updateAlert: (id: string, body: Partial<{ status: string; assignee: string; notes: string }>) =>
    request<Alert>(`/api/v1/alerts/${id}`, { method: "PATCH", body: JSON.stringify(body) }),

  // AI agent
  analyzeAlert: (alertId: string) =>
    request<Analysis>("/api/v1/ai/analyze-alert", {
      method: "POST",
      body: JSON.stringify({ alert_id: alertId }),
    }),
  summarizeIncident: (alertIds: string[], context = "") =>
    request<Analysis>("/api/v1/ai/summarize-incident", {
      method: "POST",
      body: JSON.stringify({ alert_ids: alertIds, context }),
    }),
  analyses: (alertId?: string, limit = 20) =>
    request<Analysis[]>(`/api/v1/ai/analyses?limit=${limit}${alertId ? `&alert_id=${alertId}` : ""}`),

  // cases
  cases: (params: { status?: string; offset?: number; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    if (params.status) qs.set("status", params.status);
    qs.set("offset", String(params.offset ?? 0));
    qs.set("limit", String(params.limit ?? 50));
    return request<Page<Case>>(`/api/v1/cases?${qs}`);
  },
  caseDetail: (id: string) => request<Case>(`/api/v1/cases/${id}`),
  createCase: (body: { title: string; description?: string; severity?: string; alert_ids?: string[] }) =>
    request<Case>("/api/v1/cases", { method: "POST", body: JSON.stringify(body) }),
  updateCase: (id: string, body: Partial<{ status: string; severity: string; title: string }>) =>
    request<Case>(`/api/v1/cases/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  caseNotes: (id: string) => request<CaseNote[]>(`/api/v1/cases/${id}/notes`),
  addCaseNote: (id: string, content: string) =>
    request<CaseNote>(`/api/v1/cases/${id}/notes`, { method: "POST", body: JSON.stringify({ content }) }),
  caseArtifacts: (id: string) => request<CaseArtifact[]>(`/api/v1/cases/${id}/artifacts`),
  addCaseArtifact: (id: string, body: { artifact_type: string; value: string; source?: string; note?: string }) =>
    request<CaseArtifact>(`/api/v1/cases/${id}/artifacts`, { method: "POST", body: JSON.stringify(body) }),
  caseTimeline: (id: string) => request<TimelineEntry[]>(`/api/v1/cases/${id}/timeline`),
  caseSummary: () =>
    request<Record<string, number>>("/api/v1/cases/summary"),

  // search
  search: (params: { q?: string; filters?: string; time_from?: string; time_to?: string; offset?: number; limit?: number }) => {
    const qs = new URLSearchParams();
    if (params.q) qs.set("q", params.q);
    if (params.filters) qs.set("filters", params.filters);
    if (params.time_from) qs.set("time_from", params.time_from);
    if (params.time_to) qs.set("time_to", params.time_to);
    qs.set("offset", String(params.offset ?? 0));
    qs.set("limit", String(params.limit ?? 50));
    return request<{ items: SearchHit[]; total: number; took_ms: number }>(
      `/api/v1/search?${qs}`
    );
  },
  searchHistogram: (intervalSeconds = 3600, q?: string, filters?: string) => {
    const qs = new URLSearchParams({ interval_seconds: String(intervalSeconds) });
    if (q) qs.set("q", q);
    if (filters) qs.set("filters", filters);
    return request<{ buckets: { key: string; count: number }[] }>(`/api/v1/search/histogram?${qs}`);
  },
  searchAggregate: (field: string, q?: string) => {
    const qs = new URLSearchParams({ field, size: "20" });
    if (q) qs.set("q", q);
    return request<{ buckets: { key: string; count: number }[] }>(`/api/v1/search/aggregate?${qs}`);
  },

  // rules
  rules: (severity?: string) =>
    request<{ items: Rule[]; total: number; counts: Record<string, number> }>(
      `/api/v1/rules${severity ? `?severity=${severity}` : ""}`
    ),

  // sources
  sources: () => request<Page<Source>>("/api/v1/sources?limit=200"),

  // SOAR
  playbooks: () => request<Playbook[]>("/api/v1/soar/playbooks"),
  soarActions: (limit = 50) => request<Page<SoarAction>>(`/api/v1/soar/actions?limit=${limit}`),
  soarStatus: () => request<{ destructive_actions_enabled: boolean; playbook_count: number }>("/api/v1/soar/status"),
  executePlaybook: (playbookId: string, alert: Record<string, unknown>) =>
    request<{ playbook_id: string; actions: number; success: number; failed: number; skipped: number }>(
      `/api/v1/soar/playbooks/${playbookId}/execute`,
      { method: "POST", body: JSON.stringify({ alert }) }
    ),

  // reports
  reportTemplates: () => request<{ id: string; name: string; description: string; framework: string }[]>("/api/v1/reports/templates"),
  generateReport: (template: string, format: "html" | "pdf") =>
    fetch(`/api/v1/reports/generate/${template}?format=${format}`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    }),

  // retention
  retentionStatus: () =>
    request<Record<string, unknown>>("/api/v1/retention/status"),
  retentionRun: () => request<Record<string, unknown>>("/api/v1/retention/run", { method: "POST" }),
};
