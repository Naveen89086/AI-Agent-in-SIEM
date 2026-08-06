import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Icon } from "../components/icons";
import { formatTime } from "../components/format";
import { useAsync } from "../hooks/useAsync";
import { endpointModules, moduleActivities } from "../mocks/soc";
import type { ActivityOutcome, ModuleActivity } from "../mocks/soc";
import { Kpi, type KpiTone } from "../components/soc/Kpi";
import { ACTIVITY_OUTCOME_LABEL, ENDPOINT_MODULE_ICONS, ENDPOINT_STATUS_LABEL } from "../components/soc/endpointMeta";
import { Section } from "../components/soc/Widget";

const SEVERITIES = ["critical", "high", "medium", "low"];
const OUTCOMES = Object.keys(ACTIVITY_OUTCOME_LABEL) as ActivityOutcome[];

function ActivityTable({ items, filterSeverity, filterOutcome }: { items: ModuleActivity[]; filterSeverity: string; filterOutcome: string }) {
  const filtered = items.filter(
    (a) => (!filterSeverity || a.severity === filterSeverity) && (!filterOutcome || a.outcome === filterOutcome)
  );

  if (filtered.length === 0) {
    return (
      <div className="soc-state">
        <Icon name="search" size={18} />
        <span className="soc-state-text">No activity matches the current filters</span>
      </div>
    );
  }

  return (
    <div className="soc-activity-list">
      {filtered.map((a) => (
        <div key={a.id} className="soc-activity">
          <div className="soc-activity-rail">
            <span className={`soc-activity-dot sev-${a.severity}`} />
            <span className="soc-activity-line" />
          </div>
          <div className="soc-activity-body">
            <div className="soc-activity-meta">
              <span className={`sev-badge ${a.severity}`}>{a.severity}</span>
              <span className={`soc-pill ${ACTIVITY_OUTCOME_LABEL[a.outcome].className}`}>
                {ACTIVITY_OUTCOME_LABEL[a.outcome].text}
              </span>
              <span className="soc-activity-time mono">{formatTime(a.time)}</span>
            </div>
            <div className="soc-activity-title">{a.title}</div>
            <div className="soc-activity-msg">{a.message}</div>
            <div className="soc-activity-foot">
              <span className="soc-activity-asset mono">{a.asset}</span>
              <span className="soc-activity-tech mono">MITRE {a.technique}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

export default function ModuleDetailPage() {
  const { moduleId } = useParams<{ moduleId: string }>();
  const navigate = useNavigate();
  const modules = useAsync(() => endpointModules(), [], 60_000);
  const activities = useAsync<ModuleActivity[]>(() => moduleActivities(moduleId ?? ""), [moduleId], 60_000);

  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterOutcome, setFilterOutcome] = useState("");

  const module = modules.data?.find((x) => x.id === moduleId);

  const stats = useMemo(() => {
    const items = activities.data ?? [];
    const critical = items.filter((a) => a.severity === "critical").length;
    const blocked = items.filter((a) => a.outcome === "blocked" || a.outcome === "quarantined").length;
    const pending = items.filter((a) => a.outcome === "pending" || a.outcome === "detected").length;
    return { total: items.length, critical, blocked, pending };
  }, [activities.data]);

  const kpis = [
    {
      label: "Total Activities",
      value: stats.total,
      sub: "in the last 24h",
      icon: "activity" as const,
      tone: "accent" as KpiTone,
    },
    {
      label: "Critical",
      value: stats.critical,
      sub: "severity events",
      icon: "alert" as const,
      tone: (stats.critical > 0 ? "crit" : "ok") as KpiTone,
    },
    {
      label: "Blocked / Quarantined",
      value: stats.blocked,
      sub: "contained automatically",
      icon: "lock" as const,
      tone: (stats.blocked > 0 ? "ok" : "muted") as KpiTone,
    },
    {
      label: "Needs Review",
      value: stats.pending,
      sub: "detected or pending",
      icon: "flag" as const,
      tone: (stats.pending > 0 ? "warn" : "ok") as KpiTone,
    },
  ];

  const status = module ? ENDPOINT_STATUS_LABEL[module.status] : null;

  return (
    <div className="soc-dash">
      <nav className="soc-breadcrumb">
        <Link to="/endpoint">Endpoint Security</Link>
        <Icon name="chevron" size={12} />
        <Link to="/endpoint">Configuration</Link>
        <Icon name="chevron" size={12} />
        <span className="soc-breadcrumb-current">{module?.name ?? moduleId ?? "Module"}</span>
      </nav>

      <button type="button" className="soc-back" onClick={() => navigate("/endpoint")}>
        <Icon name="arrowLeft" size={14} />
        Back to Configuration
      </button>

      <Section icon={ENDPOINT_MODULE_ICONS[moduleId ?? ""] ?? "shield"} title={module?.name ?? "Module"} subtitle={module?.description}>
        {modules.error ? (
          <div className="soc-state soc-state-error">
            <Icon name="warn" size={18} />
            <span>{modules.error}</span>
          </div>
        ) : (
          <div className="soc-grid soc-grid-4">
            {kpis.map((k) => (
              <Kpi key={k.label} {...k} />
            ))}
          </div>
        )}
        {module ? (
          <div className="soc-module-banner">
            <span className={`soc-pill ${status!.className}`}>{status!.text}</span>
            <span className="soc-module-scan mono">last scan {module.lastScan}</span>
            <span className="soc-module-scan mono">
              {module.protectedCount.toLocaleString()} / {module.totalCount.toLocaleString()} events tracked
            </span>
            <span className="soc-module-severity mono">
              peak severity{" "}
              <span className={`sev-badge ${module.severity}`}>{module.severity}</span>
            </span>
          </div>
        ) : null}
      </Section>

      <Section icon="list" title="Activity Feed" subtitle="Every event captured by this module">
        <div className="toolbar">
          <select className="select" style={{ width: 150 }} value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select className="select" style={{ width: 180 }} value={filterOutcome} onChange={(e) => setFilterOutcome(e.target.value)}>
            <option value="">All outcomes</option>
            {OUTCOMES.map((o) => (
              <option key={o} value={o}>{ACTIVITY_OUTCOME_LABEL[o].text}</option>
            ))}
          </select>
          <span className="mono soc-activity-count">{stats.total} events</span>
        </div>

        <div className="card">
          {activities.status === "loading" ? (
            <div className="soc-state">
              <span className="spinner" />
              <span className="soc-state-text">Loading activity…</span>
            </div>
          ) : activities.status === "error" ? (
            <div className="soc-state soc-state-error">
              <Icon name="warn" size={18} />
              <span>{activities.error}</span>
            </div>
          ) : !activities.data || activities.data.length === 0 ? (
            <div className="soc-state">
              <Icon name="shieldCheck" size={22} />
              <span className="soc-state-text">No activity recorded for this module yet</span>
            </div>
          ) : (
            <ActivityTable
              items={activities.data}
              filterSeverity={filterSeverity}
              filterOutcome={filterOutcome}
            />
          )}
        </div>
      </Section>
    </div>
  );
}
