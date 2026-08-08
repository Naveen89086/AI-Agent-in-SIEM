import { useAsync } from "../hooks/useAsync";
import { endpointModules, threatIntelModules } from "../mocks/soc";
import { ENDPOINT_MODULE_ICONS } from "../components/soc/endpointMeta";
import { AgentsSummary } from "../components/soc/AgentsSummary";
import { Last24Alerts } from "../components/soc/Last24Alerts";
import { ModulePanel, type ModuleRow } from "../components/soc/ModulePanel";
import { SecurityOpsGrid } from "../components/soc/SecurityOpsGrid";
import type { IconName } from "../components/icons";

const TI_ICONS: Record<string, IconName> = {
  hunting: "crosshair",
  vuln: "shield",
  mitre: "target",
};

const TI_ROUTE: Record<string, string> = {
  hunting: "/search",
  vuln: "/search",
  mitre: "/search",
};

function DashboardPage() {
  const endpoint = useAsync(() => endpointModules(), [], 60_000);
  const ti = useAsync(() => threatIntelModules(), [], 60_000);

  const endpointRows: ModuleRow[] | null = endpoint.data
    ? endpoint.data.slice(0, 3).map((m) => ({
        id: m.id,
        icon: ENDPOINT_MODULE_ICONS[m.id] ?? "shield",
        name: m.name,
        description: m.description,
        to: `/endpoint/${m.id}`,
      }))
    : null;

  const tiRows: ModuleRow[] | null = ti.data
    ? ti.data.slice(0, 3).map((m) => ({
        id: m.id,
        icon: TI_ICONS[m.id] ?? "shield",
        name: m.name,
        description: m.description,
        to: TI_ROUTE[m.id] ?? "/search",
      }))
    : null;

  return (
    <div className="soc-dash">
      <div className="soc-grid soc-grid-2">
        <AgentsSummary />
        <Last24Alerts />
      </div>

      <div className="soc-grid soc-grid-2">
        <ModulePanel
          title="Endpoint Security"
          icon="server"
          status={endpoint.status}
          error={endpoint.error}
          rows={endpointRows}
        />
        <ModulePanel
          title="Threat Intelligence"
          icon="radio"
          status={ti.status}
          error={ti.error}
          rows={tiRows}
        />
      </div>

      <SecurityOpsGrid />
    </div>
  );
}

export default DashboardPage;
