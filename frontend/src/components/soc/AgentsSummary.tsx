import { api } from "../../api/client";
import { useAsync } from "../../hooks/useAsync";
import { Widget } from "./Widget";

export function AgentsSummary() {
  const agents = useAsync(() => api.fimAgents(), [], 30_000);
  const system = agents.data?.find((a) => a.status === "active") ?? agents.data?.[0];

  return (
    <Widget
      title="Agent Summary"
      icon="server"
      status={agents.status}
      error={agents.error}
      empty={!agents.data || agents.data.length === 0}
      emptyMessage="No monitored system"
    >
      {system ? (
        <div className="soc-agents">
          <div className="soc-agent-system">
            <span
              className={`soc-agent-dot ${system.status === "active" ? "active" : "disconnected"}`}
            />
            <div>
              <div className="soc-agent-name mono">{system.name}</div>
              <div className="soc-agent-os">{system.os_name}</div>
            </div>
          </div>
          <div className="soc-agent-meta">
            <span className="soc-agent-code">Agent {system.code}</span>
            <span className={`soc-agent-state ${system.status}`}>{system.status}</span>
          </div>
        </div>
      ) : null}
    </Widget>
  );
}
