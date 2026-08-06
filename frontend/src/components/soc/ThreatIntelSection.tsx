import { useAsync } from "../../hooks/useAsync";
import { threatIntelModules } from "../../mocks/soc";
import type { TiModule } from "../../mocks/soc";
import { Icon, type IconName } from "../icons";
import { SectionGrid } from "./SectionGrid";
import { Sparkline } from "./Sparkline";
import { Section, Widget } from "./Widget";

const MODULE_ICONS: Record<string, IconName> = {
  hunting: "crosshair",
  vuln: "octagon",
  ioc: "target",
  mitre: "git",
  feed: "radio",
  geo: "globe",
};

function TiWidget({ module }: { module: TiModule }) {
  const deltaClass =
    module.deltaTone === "up" ? "delta-up" : module.deltaTone === "down" ? "delta-down" : "delta-flat";
  return (
    <Widget title={module.name} icon={MODULE_ICONS[module.id] ?? "radio"}>
      <div className="soc-ti">
        <div className="soc-ti-top">
          <div className="soc-ti-stat mono">{module.stat}</div>
          <Sparkline data={module.trend} color="var(--purple)" />
        </div>
        <div className="soc-ti-delta">
          <span className={`soc-ti-arrow ${deltaClass}`}>
            {module.deltaTone === "up" ? "▲" : module.deltaTone === "down" ? "▼" : "—"}
          </span>
          <span className={`soc-ti-delta-text ${deltaClass}`}>{module.delta}</span>
        </div>
        <p className="soc-ti-desc">{module.description}</p>
      </div>
    </Widget>
  );
}

export function ThreatIntelSection() {
  const modules = useAsync(() => threatIntelModules(), [], 60_000);
  return (
    <Section icon="radio" title="Threat Intelligence" subtitle="Feeds, hunts and ATT&CK coverage">
      <SectionGrid status={modules.status} error={modules.error}>
        {modules.data?.map((module) => (
          <TiWidget key={module.id} module={module} />
        ))}
      </SectionGrid>
    </Section>
  );
}
