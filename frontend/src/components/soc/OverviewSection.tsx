import { api } from "../../api/client";
import type { DashboardSummary } from "../../api/types";
import { useAsync } from "../../hooks/useAsync";
import { mlAnomalies, tiMatches } from "../../mocks/soc";
import type { MetricNote } from "../../mocks/soc";
import { Icon } from "../icons";
import { Kpi, type KpiTone } from "./Kpi";
import { Section } from "./Widget";

export function securityScore(summary: DashboardSummary): number {
  const sev = summary.alerts_by_severity ?? {};
  const deductions =
    (sev.critical ?? 0) * 15 +
    (sev.high ?? 0) * 8 +
    (sev.medium ?? 0) * 4 +
    (sev.low ?? 0) * 2;
  return Math.max(10, 100 - deductions);
}

export function riskLevel(summary: DashboardSummary): { label: string; tone: KpiTone } {
  const sev = summary.alerts_by_severity ?? {};
  if ((sev.critical ?? 0) > 0) return { label: "Critical", tone: "crit" };
  if ((sev.high ?? 0) > 0) return { label: "High", tone: "crit" };
  if ((sev.medium ?? 0) > 0) return { label: "Elevated", tone: "warn" };
  if (summary.alerts_active > 0) return { label: "Guarded", tone: "warn" };
  return { label: "Low", tone: "ok" };
}

export function OverviewSection() {
  const summary = useAsync(() => api.dashboardSummary(), [], 30_000);
  const anomalies = useAsync<MetricNote>(() => mlAnomalies(), [], 60_000);
  const matches = useAsync<MetricNote>(() => tiMatches(), [], 60_000);

  const s = summary.data;

  const loading = summary.status === "loading";
  const error = summary.error;
  const score = s ? securityScore(s) : null;
  const risk = s ? riskLevel(s) : null;

  const kpis = [
    {
      label: "Security Score",
      value: loading ? "—" : score,
      sub: loading ? "" : "health index",
      icon: "gauge" as const,
      tone: score === null ? ("muted" as KpiTone) : score >= 80 ? ("ok" as KpiTone) : score >= 60 ? ("warn" as KpiTone) : ("crit" as KpiTone),
      onClick: undefined as (() => void) | undefined,
    },
    {
      label: "Current Risk Level",
      value: loading ? "—" : risk?.label,
      sub: loading ? "" : "from active alerts",
      icon: "alert" as const,
      tone: (loading ? "muted" : risk?.tone ?? "muted") as KpiTone,
    },
    {
      label: "Active Agents",
      value: loading ? "—" : s?.sources_total ?? 0,
      sub: loading ? "" : "reporting endpoints",
      icon: "server" as const,
      tone: "accent" as KpiTone,
    },
    {
      label: "Active Threats",
      value: loading ? "—" : s?.alerts_active ?? 0,
      sub: loading ? "" : `${s?.alerts_open ?? 0} open`,
      icon: "crosshair" as const,
      tone: (loading ? "muted" : (s?.alerts_active ?? 0) > 0 ? "crit" : "ok") as KpiTone,
    },
    {
      label: "Open Cases",
      value: loading ? "—" : s?.cases_open ?? 0,
      sub: loading ? "" : `${s?.cases_resolved ?? 0} resolved`,
      icon: "file" as const,
      tone: "warn" as KpiTone,
    },
    {
      label: "ML Anomalies",
      value: loading ? "—" : anomalies.data?.count ?? 0,
      sub: anomalies.data?.detail ?? "",
      icon: "cpu" as const,
      tone: (anomalies.data?.status === "warn" ? "warn" : anomalies.data?.status === "crit" ? "crit" : "ok") as KpiTone,
    },
    {
      label: "Threat Intel Matches",
      value: loading ? "—" : matches.data?.count ?? 0,
      sub: matches.data?.detail ?? "",
      icon: "radio" as const,
      tone: (matches.data?.status === "warn" ? "warn" : "ok") as KpiTone,
    },
  ];

  return (
    <Section icon="gauge" title="AI Security Overview" subtitle="Real-time posture across your environment">
      {error ? (
        <div className="soc-state soc-state-error">
          <Icon name="warn" size={18} />
          <span>{error}</span>
        </div>
      ) : (
        <div className="soc-grid soc-grid-7">
          {kpis.map((k) => (
            <Kpi key={k.label} {...k} />
          ))}
        </div>
      )}
    </Section>
  );
}
