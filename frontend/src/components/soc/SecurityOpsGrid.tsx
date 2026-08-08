import { useNavigate } from "react-router-dom";
import { useAsync } from "../../hooks/useAsync";
import { securityOpsModules } from "../../mocks/soc";
import { Icon } from "../icons";
import { Widget } from "./Widget";

const SEC_OPS_ROUTE: Record<string, string> = {
  hygiene: "/endpoint",
  pci: "/reports",
  gdpr: "/reports",
  hipaa: "/reports",
  nist: "/reports",
  tsc: "/reports",
};

export function SecurityOpsGrid() {
  const modules = useAsync(() => securityOpsModules(), [], 60_000);
  const navigate = useNavigate();

  return (
    <Widget
      title="Security Operations"
      icon="shield"
      status={modules.status}
      error={modules.error}
      empty={!modules.data}
    >
      <div className="soc-secops-grid">
        {modules.data?.map((m) => (
          <button
            key={m.id}
            type="button"
            className="soc-secops-card"
            onClick={() => navigate(SEC_OPS_ROUTE[m.id] ?? "/")}
          >
            <span className="soc-secops-icon">
              <Icon name={m.icon} size={20} />
            </span>
            <span className="soc-secops-body">
              <span className="soc-secops-name">{m.name}</span>
              <span className="soc-secops-desc">{m.description}</span>
            </span>
          </button>
        ))}
      </div>
    </Widget>
  );
}
