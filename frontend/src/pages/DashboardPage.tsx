import "./dash.css";
import { useAsync } from "../hooks/useAsync";
import { api } from "../api/client";
import { fimSummary, fimTimeline, scaDashboard } from "../api/endpoint";
import type { Alert, DashboardSummary, TimeseriesPoint } from "../api/types";
import type { FimSummary, FimTimelinePoint, ScaDashboard } from "../api/endpoint";
import {
  FALLBACK_CONNECTIONS,
  FALLBACK_INGESTION,
  FALLBACK_LOGIN,
  FALLBACK_POSTURE,
  FALLBACK_RISK_BREAKDOWN,
  FALLBACK_RISK_SCORE,
  FALLBACK_SYSTEM_PERF,
  FALLBACK_FIM,
  FALLBACK_NETWORK,
  FALLBACK_ENDPOINT,
  FALLBACK_TIMELINE,
  type EndpointInfo,
  type EventIngestion,
  type FimState,
  type Posture,
  type PostureRow,
  type PostureTone,
  type SeverityCount,
  type TimelineEvent,
  type TimelineType,
} from "../components/soc/dash/dashData";
import { EndpointPanel, RiskBreakdownPanel, RiskScorePanel } from "../components/soc/dash/TopRow";
import { EventIngestionPanel, NetworkActivityPanel, SystemPerfPanel } from "../components/soc/dash/MetricsRow";
import {
  FimPanel,
  NetworkConnectionsPanel,
  SecurityPosturePanel,
  UserLoginPanel,
} from "../components/soc/dash/DetailRow";
import { SecurityActivityPanel, SecurityAlertsPanel } from "../components/soc/dash/BottomRow";

type AgentsList = Awaited<ReturnType<typeof api.fimAgents>>;

function pickNumber(value: unknown, fallback: number, min: number, max: number): number {
  return typeof value === "number" && value >= min && value <= max ? value : fallback;
}

function endpointFrom(agents: AgentsList | null): EndpointInfo {
  const a = agents?.find((x) => ["online", "active"].includes(x.status)) ?? agents?.[0];
  if (!a) return FALLBACK_ENDPOINT;
  return { name: a.name, os: a.os_name, status: a.status, code: a.code, ip: a.ip_address };
}

function ingestionFrom(summary: DashboardSummary | null, points: TimeseriesPoint[] | null): EventIngestion {
  const events = points?.map((p) => p.events).filter((n): n is number => typeof n === "number");
  return {
    eps: FALLBACK_INGESTION.eps,
    today: summary?.events_last_24h ?? FALLBACK_INGESTION.today,
    trend: events && events.length > 1 ? events : FALLBACK_INGESTION.trend,
  };
}

function fimFrom(fim: FimSummary | null, timeline: FimTimelinePoint[] | null): FimState {
  if (!fim) return FALLBACK_FIM;
  const sum = (arr?: { value?: number }[]) =>
    (arr ?? []).reduce((n, d) => n + (typeof d.value === "number" ? d.value : 0), 0);
  const sev = (fim.severity ?? []).find((s) => String(s.name).toLowerCase() === "critical");
  const modified = sum(fim.files?.modified);
  const created = sum(fim.files?.added);
  const deleted = sum(fim.files?.deleted);
  return {
    monitored: fim.files_count?.total ?? FALLBACK_FIM.monitored,
    modified: modified > 0 ? modified : FALLBACK_FIM.modified,
    created: created > 0 ? created : FALLBACK_FIM.created,
    deleted: deleted > 0 ? deleted : FALLBACK_FIM.deleted,
    critical: sev?.value ?? FALLBACK_FIM.critical,
    modifiedTrend:
      timeline && timeline.length > 1 ? timeline.map((p) => p.modified) : FALLBACK_FIM.modifiedTrend,
    createdTrend:
      timeline && timeline.length > 1 ? timeline.map((p) => p.added) : FALLBACK_FIM.createdTrend,
    deletedTrend:
      timeline && timeline.length > 1 ? timeline.map((p) => p.deleted) : FALLBACK_FIM.deletedTrend,
  };
}

function postureFrom(sca: ScaDashboard | null): Posture {
  if (!sca) return FALLBACK_POSTURE;
  const cats = new Map<string, number>();
  for (const f of sca.top_failures ?? []) {
    cats.set(f.category, (cats.get(f.category) ?? 0) + f.failures);
  }
  const maxFail = Math.max(1, ...cats.values());
  const toneFor = (v: number): PostureTone => (v >= 80 ? "ok" : v >= 65 ? "warn" : "crit");
  const rows: PostureRow[] = [
    { label: "Overall Score", value: `${Math.round(sca.average_score)}%`, tone: toneFor(sca.average_score) },
  ];
  for (const [cat, failures] of [...cats.entries()].slice(0, 4)) {
    const v = Math.max(0, Math.min(100, Math.round(100 - (failures / maxFail) * 40)));
    rows.push({
      label: cat.replace(/[_\s]+/g, " "),
      value: `${v}%`,
      tone: toneFor(v),
    });
  }
  const crit = sca.risk_distribution?.critical ?? 0;
  rows.push(
    { label: "Failed Checks", value: String(sca.checks_failed), tone: sca.checks_failed > 20 ? "crit" : "warn" },
    { label: "Critical CVEs", value: String(crit), tone: crit > 0 ? "crit" : "ok" }
  );
  return { overall: `${Math.round(sca.average_score)}%`, rows };
}

function sevOf(raw: string | undefined): "critical" | "high" | "medium" | "low" {
  const s = (raw ?? "").toLowerCase();
  if (s.startsWith("crit")) return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  return "low";
}

function timelineFrom(recent: Partial<Alert>[] | null): TimelineEvent[] {
  if (!recent || recent.length === 0) return FALLBACK_TIMELINE;
  const out: TimelineEvent[] = [];
  for (const a of recent.slice(0, 30)) {
    const s = sevOf(a.severity);
    const type: TimelineType =
      s === "critical" ? "critical" : s === "high" ? "high" : s === "medium" ? "network" : "auth";
    const d = a.last_seen_at ? new Date(a.last_seen_at) : null;
    const hour = d && !Number.isNaN(d.getTime()) ? d.getHours() + d.getMinutes() / 60 : Math.random() * 24;
    out.push({ hour: Math.min(23.9, hour), type, label: a.rule_title ?? "Security event" });
  }
  return out.sort((x, y) => x.hour - y.hour);
}

function severityCounts(summary: DashboardSummary | null): SeverityCount[] {
  const by = summary?.alerts_by_severity;
  const pick = (key: string, fb: number) => (by && typeof by[key] === "number" ? (by[key] as number) : fb);
  return [
    { severity: "critical", count: pick("critical", 11), desc: "Critical threats" },
    { severity: "high", count: pick("high", 35), desc: "Immediate action" },
    { severity: "medium", count: pick("medium", 24), desc: "Medium risks" },
    { severity: "low", count: pick("low", 7), desc: "Low-level risks" },
  ];
}

function DashboardPage() {
  const agents = useAsync(() => api.fimAgents(), [], 5_000);
  const summary = useAsync(() => api.dashboardSummary(), [], 60_000);
  const ts = useAsync(() => api.dashboardTimeseries(24, 60), [], 60_000);
  const recent = useAsync(() => api.dashboardRecentAlerts(12), [], 60_000);
  const fim = useAsync(() => fimSummary("001"), [], 60_000);
  const fimTl = useAsync(() => fimTimeline(24, 60, "001"), [], 60_000);
  const sca = useAsync(() => scaDashboard(), [], 60_000);

  const riskScore = pickNumber(sca.data?.average_risk, FALLBACK_RISK_SCORE, 10, 100);

  return (
    <div className="dash">
      <div className="dash-grid-3">
        <EndpointPanel agent={endpointFrom(agents.data)} />
        <RiskScorePanel score={riskScore} />
        <RiskBreakdownPanel segments={FALLBACK_RISK_BREAKDOWN} />
      </div>

      <div className="dash-cols">
        <div className="dash-col">
          <SystemPerfPanel perf={FALLBACK_SYSTEM_PERF} />
        </div>
        <div className="dash-col">
          <NetworkActivityPanel net={FALLBACK_NETWORK} />
          <div className="dash-split">
            <FimPanel fim={fimFrom(fim.data, fimTl.data)} />
            <SecurityPosturePanel posture={postureFrom(sca.data)} demo={Boolean(sca.data?.demo)} />
          </div>
        </div>
        <div className="dash-col">
          <EventIngestionPanel ingest={ingestionFrom(summary.data, ts.data?.points ?? null)} />
          <NetworkConnectionsPanel rows={FALLBACK_CONNECTIONS} />
          <UserLoginPanel login={FALLBACK_LOGIN} />
        </div>
      </div>

      <div className="dash-grid-bottom">
        <SecurityAlertsPanel counts={severityCounts(summary.data)} />
        <SecurityActivityPanel items={timelineFrom(recent.data)} />
      </div>
    </div>
  );
}

export default DashboardPage;
