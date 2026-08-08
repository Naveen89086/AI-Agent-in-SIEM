import { useMemo } from "react";
import {
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Cell, Pie, PieChart } from "recharts";
import { Icon } from "../icons";
import { useAsync } from "../../hooks/useAsync";
import { fimSummary, fimTimeline } from "../../api/endpoint";
import type { FimAgentRow, FimDonutDatum, FimSummary, FimTimelinePoint } from "../../api/endpoint";

function DonutCard({ title, data }: { title: string; data: FimDonutDatum[] }) {
  const total = data.reduce((sum, d) => sum + d.value, 0);

  return (
    <div className="fim-card fim-donut-card">
      <div className="fim-card-title">{title}</div>
      <div className="fim-donut-wrap">
        <div className="fim-donut">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="name"
                innerRadius="64%"
                outerRadius="88%"
                paddingAngle={2}
                stroke="#fff"
                strokeWidth={1}
              >
                {data.map((d) => (
                  <Cell key={d.name} fill={d.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "#fff",
                  border: "1px solid #e5e7eb",
                  borderRadius: 8,
                  fontSize: 12,
                  boxShadow: "0 2px 6px rgba(0,0,0,0.06)",
                }}
                itemStyle={{ color: "#1f2937" }}
                formatter={(value: number | string, name: string) => [
                  `${value} (${total ? Number(((Number(value) / total) * 100).toFixed(2)) : 0}%)`,
                  name,
                ]}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="fim-donut-legend">
          {data.map((d) => {
            const pct = total ? ((d.value / total) * 100).toFixed(2) : "0";
            return (
              <div key={d.name} className="fim-legend-row">
                <span className="fim-legend-dot" style={{ background: d.color }} />
                <span className="fim-legend-name" title={d.name}>
                  {d.name}
                </span>
                <span className="fim-legend-value">({pct}%)</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function EventsScatterCard({ points }: { points: FimTimelinePoint[] }) {
  const series = useMemo(
    () => ({
      deleted: points.map((p, i) => ({ x: i, y: p.deleted })),
      added: points.map((p, i) => ({ x: i, y: p.added })),
      modified: points.map((p, i) => ({ x: i, y: p.modified })),
    }),
    [points]
  );

  return (
    <div className="fim-card fim-scatter-card">
      <div className="fim-card-title">Event Timeline (last 24 hours)</div>
      <div className="fim-scatter-meta">
        <span className="fim-scatter-meta-item">Y-Axis: Count</span>
        <span className="fim-scatter-meta-item">X-Axis: timestamp per 30 minutes</span>
      </div>
      <div className="fim-scatter">
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 10, right: 12, bottom: 6, left: -18 }}>
            <CartesianGrid stroke="#eef2f6" strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="x"
              type="number"
              domain={[0, points.length - 1]}
              ticks={[0, 8, 16, 24, 32, 40, 47]}
              tickFormatter={(t: number) => points[t]?.label ?? ""}
              tick={{ fontSize: 11, fill: "#6b7280" }}
              tickLine={false}
              axisLine={{ stroke: "#e5e7eb" }}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fontSize: 11, fill: "#6b7280" }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              contentStyle={{
                background: "#fff",
                border: "1px solid #e5e7eb",
                borderRadius: 8,
                fontSize: 12,
                boxShadow: "0 2px 6px rgba(0,0,0,0.06)",
              }}
              itemStyle={{ color: "#1f2937" }}
              labelFormatter={(t: number) => `Time: ${points[t]?.label ?? ""}`}
            />
            <Scatter name="deleted" data={series.deleted} fill="#E53935" line={{ stroke: "#E53935", strokeWidth: 1.5 }} />
            <Scatter name="added" data={series.added} fill="#1976D2" line={{ stroke: "#1976D2", strokeWidth: 1.5 }} />
            <Scatter name="modified" data={series.modified} fill="#FB8C00" line={{ stroke: "#FB8C00", strokeWidth: 1.5 }} />
            <Legend wrapperStyle={{ fontSize: 12 }} />
          </ScatterChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function relativeTime(iso?: string | null): string {
  if (!iso) return "never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "never";
  const s = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} hr ago`;
  return `${Math.floor(h / 24)} d ago`;
}

function AgentHealthCard({ agent }: { agent: FimAgentRow | null }) {
  if (!agent) {
    return (
      <div className="fim-card fim-health-card">
        <div className="fim-card-title">Agent health</div>
        <div className="fim-state">
          <Icon name="warn" size={16} />
          <span>No agent selected — pick an agent above to load its live status.</span>
        </div>
      </div>
    );
  }

  const online = agent.enabled && (agent.status ?? "").toLowerCase() !== "disconnected";
  const osName = agent.os_name || agent.platform || "—";

  return (
    <div className="fim-card fim-health-card">
      <div className="fim-card-head">
        <div className="fim-card-title">Agent health</div>
        <span className={`fim-health-chip${online ? " fim-health-chip-online" : ""}`}>
          {online ? "online" : "offline"}
        </span>
      </div>
      <div className="fim-health-grid">
        <div className="fim-health-item">
          <span className="fim-health-label">Agent</span>
          <span className="fim-health-value">
            {agent.name}
            {agent.code ? ` (${agent.code})` : ""}
          </span>
        </div>
        <div className="fim-health-item">
          <span className="fim-health-label">Last seen</span>
          <span className="fim-health-value">{relativeTime(agent.last_seen)}</span>
        </div>
        <div className="fim-health-item">
          <span className="fim-health-label">Version</span>
          <span className="fim-health-value mono">{agent.version ?? "—"}</span>
        </div>
        <div className="fim-health-item">
          <span className="fim-health-label">Hostname</span>
          <span className="fim-health-value mono">{agent.hostname ?? "—"}</span>
        </div>
        <div className="fim-health-item">
          <span className="fim-health-label">IP address</span>
          <span className="fim-health-value mono">{agent.ip_address ?? "—"}</span>
        </div>
        <div className="fim-health-item">
          <span className="fim-health-label">Platform / OS</span>
          <span className="fim-health-value">{osName}</span>
        </div>
        <div className="fim-health-item">
          <span className="fim-health-label">Registry entries</span>
          <span className="fim-health-value mono">{agent.registry_entries.toLocaleString()}</span>
        </div>
        <div className="fim-health-item">
          <span className="fim-health-label">Enabled</span>
          <span className="fim-health-value">{agent.enabled ? "yes" : "no"}</span>
        </div>
      </div>
    </div>
  );
}

function KpiCard({ label, value, tone }: { label: string; value: number; tone?: "ok" | "bad" }) {
  return (
    <div className="fim-card fim-kpi">
      <div className={`fim-kpi-value${tone ? ` fim-kpi-${tone}` : ""}`}>{value.toLocaleString()}</div>
      <div className="fim-kpi-label">{label}</div>
    </div>
  );
}

export function FimDashboardTab({ agentCode }: { agentCode: string }) {
  const summary = useAsync<FimSummary>(() => fimSummary(agentCode), [agentCode], 60_000);
  const timeline = useAsync<FimTimelinePoint[]>(() => fimTimeline(24, 30, agentCode), [agentCode], 60_000);

  const points = timeline.data ?? [];
  const agent = summary.data?.agent ?? null;

  const fileStatus: FimDonutDatum[] = [
    { name: "active", value: summary.data?.files_count.active ?? 0, color: "#43A047" },
    { name: "deleted", value: summary.data?.files_count.deleted ?? 0, color: "#E53935" },
  ].filter((d) => d.value > 0);

  return (
    <div className="fim-body">
      <AgentHealthCard agent={agent} />

      <div className="fim-kpi-row">
        <KpiCard label="Total events" value={summary.data?.events_total ?? 0} />
        <KpiCard label="Monitored files" value={summary.data?.files_count.total ?? 0} />
        <KpiCard label="Active files" value={summary.data?.files_count.active ?? 0} tone="ok" />
        <KpiCard label="Deleted files" value={summary.data?.files_count.deleted ?? 0} tone="bad" />
      </div>

      <EventsScatterCard points={points} />

      <div className="fim-grid fim-grid-3">
        <DonutCard title="Event severity" data={summary.data?.severity ?? []} />
        <DonutCard title="Actions" data={summary.data?.actions ?? []} />
        <DonutCard title="File inventory status" data={fileStatus} />
      </div>

      {summary.status === "loading" || timeline.status === "loading" ? (
        <div className="fim-state">
          <span className="spinner" />
          <span>Loading dashboard…</span>
        </div>
      ) : null}
      {summary.status === "error" || timeline.status === "error" ? (
        <div className="fim-state fim-state-error">
          <Icon name="warn" size={16} />
          <span>{summary.error ?? timeline.error}</span>
        </div>
      ) : null}
    </div>
  );
}
