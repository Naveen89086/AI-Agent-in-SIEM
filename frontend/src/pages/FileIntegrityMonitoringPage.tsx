import { useEffect, useState } from "react";
import { Icon } from "../components/icons";
import { FimDashboardTab } from "../components/fim/FimDashboardTab";
import { FimInventoryTab } from "../components/fim/FimInventoryTab";
import { FimEventsTab } from "../components/fim/FimEventsTab";
import { useAsync } from "../hooks/useAsync";
import { fimAgents } from "../api/endpoint";
import type { FimAgentRow } from "../api/endpoint";

type Tab = "dashboard" | "inventory" | "events";

const TABS: { id: Tab; label: string }[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "inventory", label: "Inventory" },
  { id: "events", label: "Events" },
];

export default function FileIntegrityMonitoringPage() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [agentCode, setAgentCode] = useState<string | null>(null);
  const agents = useAsync<FimAgentRow[]>(() => fimAgents(), [], 60_000);

  useEffect(() => {
    const list = agents.data ?? [];
    if (!list.length) return;
    if (list.some((a) => a.code === agentCode)) return;
    const preferred = list.find((a) => !a.demo && a.enabled) ?? list[0];
    setAgentCode(preferred.code);
  }, [agents.data, agentCode]);

  const selected = agents.data?.find((a) => a.code === agentCode) ?? null;
  const demo = Boolean(selected?.demo);
  const code = agentCode ?? "001";

  return (
    <div className="fim-page">
      <header className="fim-header">
        <div className="fim-breadcrumb">
          <span className="fim-breadcrumb-current">File Integrity Monitoring</span>
          <Icon name="chevron" size={12} />
          <span className="fim-breadcrumb-page">BEAM</span>
        </div>
        <div className="fim-header-actions">
          {demo ? (
            <span className="fim-demo-badge" title="Backend in FIM demo mode - showing deterministic demo data">
              Demo data
            </span>
          ) : null}
          {selected ? (
            <span className="fim-agent-chip">
              <Icon name="radio" size={14} />
              {selected.name} ({selected.code})
            </span>
          ) : null}
          <select
            className="fim-agent-select"
            value={code}
            onChange={(e) => setAgentCode(e.target.value)}
            aria-label="Select FIM agent"
          >
            {agents.status === "loading" ? (
              <option value={code}>Loading agents…</option>
            ) : (
              (agents.data ?? []).map((a) => (
                <option key={a.code} value={a.code}>
                  {a.name} ({a.code})
                  {a.demo ? " · demo" : ""}
                </option>
              ))
            )}
          </select>
          {tab === "dashboard" && (
            <button type="button" className="fim-btn fim-btn-accent">
              <Icon name="fileText" size={14} />
              Generate Report
            </button>
          )}
        </div>
      </header>

      <nav className="fim-tabs">
        {TABS.map((t) => (
          <button
            type="button"
            key={t.id}
            className={`fim-tab${tab === t.id ? " fim-tab-active" : ""}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
            {tab === t.id ? " (Active)" : ""}
          </button>
        ))}
      </nav>

      {tab === "dashboard" && <FimDashboardTab agentCode={code} />}
      {tab === "inventory" && <FimInventoryTab agentCode={code} />}
      {tab === "events" && <FimEventsTab agentCode={code} />}
    </div>
  );
}
