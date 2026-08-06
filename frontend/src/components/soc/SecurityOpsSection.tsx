import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import type { Alert } from "../../api/types";
import { useAsync } from "../../hooks/useAsync";
import { SeverityBadge, StatusBadge } from "../Badges";
import { formatTime } from "../format";
import { Icon, type IconName } from "../icons";
import { Section } from "./Widget";

interface OpsTile {
  id: string;
  label: string;
  icon: IconName;
  value: number | null;
  sub: string;
  to: string;
  tone: "accent" | "ok" | "warn" | "crit";
}

export function SecurityOpsSection() {
  const navigate = useNavigate();

  const alerts = useAsync(() => api.alerts({ limit: 1 }), [], 30_000);
  const cases = useAsync(() => api.cases({ limit: 1 }), [], 30_000);
  const rules = useAsync(() => api.rules(), [], 60_000);
  const playbooks = useAsync(() => api.playbooks(), [], 60_000);
  const templates = useAsync(() => api.reportTemplates(), [], 60_000);
  const recent = useAsync(() => api.dashboardRecentAlerts(6), [], 30_000);

  const tiles: OpsTile[] = [
    {
      id: "alerts",
      label: "Alerts",
      icon: "alert",
      value: alerts.data?.total ?? null,
      sub: "active in queue",
      to: "/alerts",
      tone: (alerts.data?.total ?? 0) > 0 ? "crit" : "ok",
    },
    {
      id: "cases",
      label: "Cases",
      icon: "file",
      value: cases.data?.total ?? null,
      sub: "investigations",
      to: "/cases",
      tone: "warn",
    },
    {
      id: "rules",
      label: "Detection Rules",
      icon: "list",
      value: rules.data?.total ?? null,
      sub: "correlation + signature",
      to: "/rules",
      tone: "accent",
    },
    {
      id: "search",
      label: "Search",
      icon: "search",
      value: null,
      sub: "investigate events",
      to: "/search",
      tone: "accent",
    },
    {
      id: "soar",
      label: "SOAR",
      icon: "zap",
      value: playbooks.data?.length ?? null,
      sub: "active playbooks",
      to: "/soar",
      tone: "ok",
    },
    {
      id: "reports",
      label: "Reports",
      icon: "book",
      value: templates.data?.length ?? null,
      sub: "compliance templates",
      to: "/reports",
      tone: "accent",
    },
  ];

  return (
    <Section icon="shield" title="Security Operations" subtitle="Jump into the tools your team uses daily">
      <div className="soc-grid soc-grid-3">
        {tiles.map((tile) => (
          <div
            key={tile.id}
            className="soc-ops-tile is-clickable"
            role="button"
            tabIndex={0}
            onClick={() => navigate(tile.to)}
            onKeyDown={(e) => e.key === "Enter" && navigate(tile.to)}
          >
            <div className={`soc-ops-icon soc-ops-icon-${tile.tone}`}>
              <Icon name={tile.icon} size={18} />
            </div>
            <div className="soc-ops-body">
              <div className="soc-ops-label">{tile.label}</div>
              <div className="soc-ops-value mono">
                {tile.value != null ? tile.value.toLocaleString() : <span className="soc-ops-open">Open →</span>}
              </div>
              <div className="soc-ops-sub">{tile.sub}</div>
            </div>
            <Icon name="external" size={14} className="soc-ops-arrow" />
          </div>
        ))}
      </div>

      <div className="soc-subblock">
        <div className="soc-subblock-head">
          <span>Recent alerts</span>
          <button className="btn btn-sm" onClick={() => navigate("/alerts")}>
            View all <Icon name="external" size={12} />
          </button>
        </div>
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
            {recent.status === "loading" ? (
              <tr>
                <td colSpan={5}>
                  <div className="soc-state">
                    <span className="spinner" />
                  </div>
                </td>
              </tr>
            ) : recent.status === "error" ? (
              <tr>
                <td colSpan={5}>
                  <div className="soc-state soc-state-error">
                    <Icon name="warn" size={16} />
                    {recent.error}
                  </div>
                </td>
              </tr>
            ) : (recent.data ?? []).length === 0 ? (
              <tr>
                <td colSpan={5}>
                  <div className="soc-state">No alerts yet</div>
                </td>
              </tr>
            ) : (
              (recent.data as Partial<Alert>[]).map((a) => (
                <tr key={a.id} className="clickable" onClick={() => navigate("/alerts")}>
                  <td>
                    <SeverityBadge severity={a.severity ?? "informational"} />
                  </td>
                  <td style={{ maxWidth: 360 }}>
                    <div style={{ fontWeight: 600 }}>{a.rule_title}</div>
                    <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)" }}>
                      {a.rule_id}
                    </div>
                  </td>
                  <td>
                    <StatusBadge status={a.status ?? "unknown"} />
                  </td>
                  <td className="mono">{a.count}</td>
                  <td className="mono" style={{ color: "var(--text-dim)", fontSize: 12 }}>
                    {formatTime(a.last_seen_at)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </Section>
  );
}
