import { useCallback, useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../api/client";
import type { Alert, DashboardSummary, TimeseriesPoint, TopItem } from "../api/types";
import { SeverityBadge, StatusBadge } from "../components/Badges";
import { formatNumber, formatTime } from "../components/format";
import { Card, Empty, Spinner } from "../components/ui";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ff5c6c",
  high: "#ff7a59",
  medium: "#ffb547",
  low: "#31d07e",
  informational: "#4dd0e1",
};

function Kpi({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="card kpi">
      <div className="kpi-label">{label}</div>
      <div className="kpi-value" style={color ? { color } : undefined}>
        {typeof value === "number" ? formatNumber(value) : value}
      </div>
      {sub ? <div className="kpi-sub">{sub}</div> : null}
    </div>
  );
}

function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [timeseries, setTimeseries] = useState<TimeseriesPoint[]>([]);
  const [topRules, setTopRules] = useState<TopItem[]>([]);
  const [topSources, setTopSources] = useState<TopItem[]>([]);
  const [recentAlerts, setRecentAlerts] = useState<Partial<Alert>[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [sum, ts, rules, sources, recent] = await Promise.all([
        api.dashboardSummary(),
        api.dashboardTimeseries(168, 360),
        api.dashboardTopRules(8),
        api.dashboardTopSources(8),
        api.dashboardRecentAlerts(8),
      ]);
      setSummary(sum);
      setTimeseries(ts.points);
      setTopRules(rules);
      setTopSources(sources);
      setRecentAlerts(recent);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard");
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  if (error) return <Empty message={error} />;
  if (!summary) return <Spinner />;

  const severityData = Object.entries(summary.alerts_by_severity)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));

  const totalAlerts = Object.values(summary.alerts_by_severity).reduce((a, b) => a + b, 0);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="grid grid-4">
        <Kpi label="Events total" value={summary.events_total} sub={`${formatNumber(summary.events_last_24h)} in last 24h`} color="var(--accent)" />
        <Kpi label="Active alerts" value={summary.alerts_active} sub={`${summary.alerts_open} open`} color="var(--red)" />
        <Kpi label="Open cases" value={summary.cases_open} sub={`${summary.cases_resolved} resolved`} color="var(--amber)" />
        <Kpi label="Data sources" value={summary.sources_total} color="var(--green)" />
      </div>

      <div className="grid grid-3">
        <Card title="Alerts by severity">
          {severityData.length === 0 ? (
            <Empty message="No alerts yet" />
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{ width: 180, height: 180 }}>
                <ResponsiveContainer>
                  <PieChart>
                    <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={48} outerRadius={80} paddingAngle={2}>
                      {severityData.map((s) => (
                        <Cell key={s.name} fill={SEVERITY_COLORS[s.name] ?? "#8fa3c2"} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div style={{ flex: 1 }}>
                <div className="mono" style={{ fontSize: 22, fontWeight: 700 }}>
                  {formatNumber(totalAlerts)}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-dim)" }}>total alerts</div>
                <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 4 }}>
                  {severityData.map((s) => (
                    <div key={s.name} style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
                      <span style={{ color: SEVERITY_COLORS[s.name] }} className="mono">
                        {s.name}
                      </span>
                      <span className="mono">{formatNumber(s.value)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </Card>

        <Card title="Top rules">
          {topRules.length === 0 ? (
            <Empty message="No rule activity" />
          ) : (
            topRules.map((r) => (
              <div key={r.rule_id ?? r.key} className="list-item">
                <div>
                  <div className="list-item-title" style={{ fontSize: 13 }}>
                    {r.rule_title ?? r.key}
                  </div>
                  <div className="list-item-sub mono">{r.rule_id}</div>
                </div>
                <div className="mono" style={{ fontWeight: 600 }}>{formatNumber(r.count)}</div>
              </div>
            ))
          )}
        </Card>

        <Card title="Top sources">
          {topSources.length === 0 ? (
            <Empty message="No source activity" />
          ) : (
            topSources.map((s) => (
              <div key={s.key} className="list-item">
                <div>
                  <div className="list-item-title" style={{ fontSize: 13 }}>
                    {s.key}
                  </div>
                </div>
                <div className="mono" style={{ fontWeight: 600 }}>{formatNumber(s.count)}</div>
              </div>
            ))
          )}
        </Card>
      </div>

      <Card title="Events & alerts — last 7 days (6h buckets)">
        <div style={{ height: 220 }}>
          <ResponsiveContainer>
            <BarChart data={timeseries}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="key" tick={{ fill: "var(--text-faint)", fontSize: 11 }} />
              <YAxis tick={{ fill: "var(--text-faint)", fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 6 }}
                labelStyle={{ color: "var(--text-dim)" }}
              />
              <Legend />
              <Bar dataKey="events" name="Events" fill="var(--accent)" stackId="a" />
              <Bar dataKey="alerts" name="Alerts" fill="var(--red)" stackId="a" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <Card title="Recent alerts">
        {recentAlerts.length === 0 ? (
          <Empty message="No alerts yet" />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Status</th>
                <th>Count</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts.map((a) => (
                <tr key={a.id}>
                  <td><SeverityBadge severity={a.severity ?? "informational"} /></td>
                  <td style={{ maxWidth: 380 }}>
                    <div style={{ fontWeight: 600 }}>{a.rule_title}</div>
                    <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)" }}>{a.rule_id}</div>
                  </td>
                  <td><StatusBadge status={a.status ?? "unknown"} /></td>
                  <td className="mono">{a.count}</td>
                  <td className="mono" style={{ color: "var(--text-dim)", fontSize: 12 }}>{formatTime(a.last_seen_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

export default DashboardPage;
