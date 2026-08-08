import { api } from "../../api/client";
import { useAsync } from "../../hooks/useAsync";
import { Widget } from "./Widget";

const LEVELS = [
  { key: "critical", label: "Critical", caption: "Rule level 15 or higher", color: "var(--red)" },
  { key: "high", label: "High", caption: "Rule level 12 to 14", color: "#ff7a59" },
  { key: "medium", label: "Medium", caption: "Rule level 7 to 11", color: "var(--amber)" },
  { key: "low", label: "Low", caption: "Rule level 0 to 6", color: "var(--green)" },
];

export function Last24Alerts() {
  const summary = useAsync(() => api.dashboardSummary(), [], 30_000);
  const sev = summary.data?.alerts_by_severity ?? {};

  return (
    <Widget
      title="Last 24 Hours Alerts"
      icon="alert"
      status={summary.status}
      error={summary.error}
      empty={!summary.data}
    >
      <div className="soc-sev-grid">
        {LEVELS.map((level) => (
          <div key={level.key} className="soc-sev-cell" style={{ borderLeftColor: level.color }}>
            <div className="soc-sev-value mono" style={{ color: level.color }}>
              {sev[level.key] ?? 0}
            </div>
            <div className="soc-sev-label">{level.label} severity</div>
            <div className="soc-sev-caption">{level.caption}</div>
          </div>
        ))}
      </div>
    </Widget>
  );
}
