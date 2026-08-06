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
import { api } from "../../api/client";
import type { DashboardSummary, TimeseriesPoint, TopItem } from "../../api/types";
import { useAsync } from "../../hooks/useAsync";
import { attackTimeline, mitreHeatmap } from "../../mocks/soc";
import { formatNumber } from "../format";
import { AttackTimeline } from "./AttackTimeline";
import { MitreHeatmap } from "./MitreHeatmap";
import { Section, Widget } from "./Widget";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ff5c6c",
  high: "#ff7a59",
  medium: "#ffb547",
  low: "#31d07e",
  informational: "#4dd0e1",
};

const TOOLTIP_STYLE = {
  background: "var(--bg-elevated)",
  border: "1px solid var(--border)",
  borderRadius: 6,
  fontSize: 12,
};

function SeverityDonut({ summary }: { summary: DashboardSummary }) {
  const data = Object.entries(summary.alerts_by_severity ?? {})
    .filter(([, value]) => value > 0)
    .map(([name, value]) => ({ name, value }));
  const total = data.reduce((acc, d) => acc + d.value, 0);

  if (total === 0) {
    return (
      <div className="soc-state">
        <span className="soc-state-text">No alerts to display</span>
      </div>
    );
  }

  return (
    <div className="soc-donut">
      <div className="soc-donut-chart">
        <ResponsiveContainer width="100%" height={190}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={52}
              outerRadius={80}
              paddingAngle={2}
              stroke="none"
            >
              {data.map((entry) => (
                <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] ?? "#8fa3c2"} />
              ))}
            </Pie>
            <Tooltip contentStyle={TOOLTIP_STYLE} />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div className="soc-donut-legend">
        {data.map((entry) => (
          <div key={entry.name} className="soc-donut-row">
            <span className="soc-donut-swatch" style={{ background: SEVERITY_COLORS[entry.name] }} />
            <span className="soc-donut-name">{entry.name}</span>
            <span className="soc-donut-count mono">{formatNumber(entry.value)}</span>
          </div>
        ))}
        <div className="soc-donut-total mono">{formatNumber(total)} total</div>
      </div>
    </div>
  );
}

function EventTrend({ points }: { points: TimeseriesPoint[] }) {
  if (points.length === 0) {
    return (
      <div className="soc-state">
        <span className="soc-state-text">No events in the window</span>
      </div>
    );
  }
  return (
    <div className="soc-trend-chart">
      <ResponsiveContainer width="100%" height={190}>
        <BarChart data={points} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
          <XAxis dataKey="key" tick={{ fill: "var(--text-faint)", fontSize: 10 }} tickLine={false} axisLine={false} />
          <YAxis tick={{ fill: "var(--text-faint)", fontSize: 10 }} tickLine={false} axisLine={false} />
          <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "rgba(46,168,255,0.06)" }} />
          <Legend wrapperStyle={{ fontSize: 11, color: "var(--text-dim)" }} />
          <Bar dataKey="events" name="Events" stackId="a" fill="var(--accent)" />
          <Bar dataKey="alerts" name="Alerts" stackId="a" fill="var(--red)" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function TopSources({ items }: { items: TopItem[] }) {
  if (items.length === 0) {
    return (
      <div className="soc-state">
        <span className="soc-state-text">No source activity yet</span>
      </div>
    );
  }
  return (
    <div className="soc-list">
      {items.map((item, i) => (
        <div key={item.key ?? i} className="soc-list-row">
          <span className="soc-list-rank mono">{i + 1}</span>
          <span className="soc-list-key mono">{item.key}</span>
          <span className="soc-list-count mono">{formatNumber(item.count)}</span>
        </div>
      ))}
    </div>
  );
}

function TopRules({ items }: { items: TopItem[] }) {
  if (items.length === 0) {
    return (
      <div className="soc-state">
        <span className="soc-state-text">No rule activity yet</span>
      </div>
    );
  }
  return (
    <div className="soc-list">
      {items.map((item, i) => (
        <div key={item.rule_id ?? i} className="soc-list-row soc-list-rule">
          <span className="soc-list-rank mono">{i + 1}</span>
          <div className="soc-list-rule-body">
            <span className="soc-list-rule-title">{item.rule_title}</span>
            <span className="soc-list-rule-id mono">{item.rule_id}</span>
          </div>
          <span className="soc-list-count mono">{formatNumber(item.count)}</span>
        </div>
      ))}
    </div>
  );
}

export function AnalyticsSection() {
  const summary = useAsync(() => api.dashboardSummary(), [], 30_000);
  const timeseries = useAsync(() => api.dashboardTimeseries(168, 360), [], 60_000);
  const topSources = useAsync(() => api.dashboardTopSources(8), [], 60_000);
  const topRules = useAsync(() => api.dashboardTopRules(8), [], 60_000);
  const heatmap = useAsync(() => mitreHeatmap(), [], 60_000);
  const timeline = useAsync(() => attackTimeline(), [], 60_000);

  return (
    <Section icon="chart" title="Analytics" subtitle="Detection coverage and attacker behavior">
      <div className="soc-grid soc-grid-2">
        <Widget title="Severity Distribution" icon="chart" status={summary.status} error={summary.error} empty={!summary.data}>
          {summary.data ? <SeverityDonut summary={summary.data} /> : null}
        </Widget>
        <Widget
          title="Event & Alert Trend"
          icon="trend"
          actions={<span className="soc-pill status-ok">7 days</span>}
          status={timeseries.status}
          error={timeseries.error}
          empty={!timeseries.data}
        >
          {timeseries.data ? <EventTrend points={timeseries.data.points} /> : null}
        </Widget>
      </div>

      <div className="soc-grid soc-grid-2">
        <Widget title="MITRE ATT&CK Heatmap" icon="git" status={heatmap.status} error={heatmap.error}>
          {heatmap.data ? <MitreHeatmap cells={heatmap.data} /> : null}
        </Widget>
        <Widget title="Attack Timeline" icon="activity" status={timeline.status} error={timeline.error}>
          {timeline.data ? <AttackTimeline events={timeline.data} /> : null}
        </Widget>
      </div>

      <div className="soc-grid soc-grid-2">
        <Widget title="Top Attack Sources" icon="globe" status={topSources.status} error={topSources.error} empty={!topSources.data}>
          {topSources.data ? <TopSources items={topSources.data} /> : null}
        </Widget>
        <Widget title="Top Detection Rules" icon="list" status={topRules.status} error={topRules.error} empty={!topRules.data}>
          {topRules.data ? <TopRules items={topRules.data} /> : null}
        </Widget>
      </div>
    </Section>
  );
}
