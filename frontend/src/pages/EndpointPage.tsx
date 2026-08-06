import { useNavigate } from "react-router-dom";
import { Icon } from "../components/icons";
import { useAsync } from "../hooks/useAsync";
import { endpointModules } from "../mocks/soc";
import type { EndpointModule } from "../mocks/soc";
import { Kpi, type KpiTone } from "../components/soc/Kpi";
import {
  ENDPOINT_MODULE_ICONS,
  ENDPOINT_STATUS_COLOR,
  ENDPOINT_STATUS_LABEL,
} from "../components/soc/endpointMeta";
import { SectionGrid } from "../components/soc/SectionGrid";
import { Sparkline } from "../components/soc/Sparkline";
import { Section } from "../components/soc/Widget";

function ModuleCard({ module }: { module: EndpointModule }) {
  const navigate = useNavigate();
  const status = ENDPOINT_STATUS_LABEL[module.status];
  return (
    <button
      type="button"
      className="soc-module-card"
      onClick={() => navigate(`/endpoint/${module.id}`)}
    >
      <span className="soc-module-icon">
        <Icon name={ENDPOINT_MODULE_ICONS[module.id] ?? "shield"} size={22} />
      </span>
      <span className="soc-module-body">
        <span className="soc-module-name">{module.name}</span>
        <span className="soc-module-desc">{module.description}</span>
        <span className="soc-module-foot">
          <span className={`soc-pill ${status.className}`}>{status.text}</span>
          <span className="soc-module-scan">last scan {module.lastScan}</span>
        </span>
      </span>
      <span className="soc-module-count mono">
        {module.protectedCount.toLocaleString()}
        <span className="soc-module-total">/ {module.totalCount.toLocaleString()}</span>
      </span>
      <span className="soc-module-arrow">
        <Icon name="chevron" size={16} />
      </span>
    </button>
  );
}

export default function EndpointPage() {
  const modules = useAsync(() => endpointModules(), [], 60_000);
  const m = modules.data ?? [];

  const attention = m.filter((x) => x.status !== "ok").length;
  const critical = m.filter((x) => x.status === "crit").length;
  const totalProtected = m.reduce((acc, x) => acc + x.protectedCount, 0);

  const kpis = [
    {
      label: "Agents Under Management",
      value: m.length > 0 ? "52" : "—",
      sub: "reporting endpoints",
      icon: "server" as const,
      tone: "accent" as KpiTone,
    },
    {
      label: "Events Tracked",
      value: totalProtected > 0 ? totalProtected.toLocaleString() : "—",
      sub: "across all modules",
      icon: "activity" as const,
      tone: "ok" as KpiTone,
    },
    {
      label: "Modules Needing Attention",
      value: m.length > 0 ? attention : "—",
      sub: `${critical} critical`,
      icon: "warn" as const,
      tone: (attention > 0 ? "warn" : "ok") as KpiTone,
    },
  ];

  return (
    <div className="soc-dash">
      <nav className="soc-breadcrumb">
        <span>Endpoint Security</span>
        <Icon name="chevron" size={12} />
        <span className="soc-breadcrumb-current">Configuration</span>
      </nav>

      <Section icon="sliders" title="Endpoint Configuration" subtitle="Pick a monitoring module to review its activity">
        {modules.error ? (
          <div className="soc-state soc-state-error">
            <Icon name="warn" size={18} />
            <span>{modules.error}</span>
          </div>
        ) : (
          <div className="soc-grid soc-grid-3">
            {kpis.map((k) => (
              <Kpi key={k.label} {...k} />
            ))}
          </div>
        )}
      </Section>

      <Section icon="server" title="Monitoring Modules" subtitle="Click a module to view its full activity feed">
        <SectionGrid status={modules.status} error={modules.error}>
          {modules.data?.map((module) => (
            <ModuleCard key={module.id} module={module} />
          ))}
        </SectionGrid>
      </Section>
    </div>
  );
}
