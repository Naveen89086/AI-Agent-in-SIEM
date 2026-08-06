import { useNavigate } from "react-router-dom";
import { useAsync } from "../../hooks/useAsync";
import { endpointModules } from "../../mocks/soc";
import type { EndpointModule } from "../../mocks/soc";
import { Icon } from "../icons";
import { ENDPOINT_MODULE_ICONS, ENDPOINT_STATUS_COLOR, ENDPOINT_STATUS_LABEL } from "./endpointMeta";
import { SectionGrid } from "./SectionGrid";
import { Sparkline } from "./Sparkline";
import { Section, Widget } from "./Widget";

function EndpointWidget({ module }: { module: EndpointModule }) {
  const navigate = useNavigate();
  const status = ENDPOINT_STATUS_LABEL[module.status];
  return (
    <Widget
      title={module.name}
      icon={ENDPOINT_MODULE_ICONS[module.id] ?? "shield"}
      actions={<span className={`soc-pill ${status.className}`}>{status.text}</span>}
      onClick={() => navigate("/endpoint")}
      hover
    >
      <div className="soc-endpoint">
        <div className="soc-endpoint-top">
          <div>
            <div className="soc-endpoint-count mono">
              {module.protectedCount.toLocaleString()}
              <span className="soc-endpoint-total"> / {module.totalCount.toLocaleString()}</span>
            </div>
            <div className="soc-endpoint-label">events tracked</div>
          </div>
          <Sparkline
            data={module.trend}
            color={ENDPOINT_STATUS_COLOR[module.status]}
          />
        </div>
        <p className="soc-endpoint-desc">{module.description}</p>
        <div className="soc-endpoint-foot">
          <span className="soc-endpoint-scan">
            <Icon name="clock" size={12} /> last scan {module.lastScan}
          </span>
          <span className="soc-endpoint-open">
            <Icon name="chevron" size={14} />
          </span>
        </div>
      </div>
    </Widget>
  );
}

export function EndpointSection() {
  const navigate = useNavigate();
  const modules = useAsync(() => endpointModules(), [], 60_000);
  return (
    <Section
      icon="server"
      title="Endpoint Security"
      subtitle="Agent coverage and monitoring posture"
      action={<span className="soc-section-link">Configuration →</span>}
      onAction={() => navigate("/endpoint")}
    >
      <SectionGrid status={modules.status} error={modules.error}>
        {modules.data?.map((module) => (
          <EndpointWidget key={module.id} module={module} />
        ))}
      </SectionGrid>
    </Section>
  );
}
