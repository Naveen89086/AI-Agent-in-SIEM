import { useState } from "react";
import { Icon } from "../components/icons";
import { useAsync } from "../hooks/useAsync";
import {
  processSummary,
  processes,
  processTree,
  services,
  telemetryAgents,
  type ProcessRow,
  type ProcessSummary as ProcessSummaryType,
  type ServiceRow,
  type TelemetryAgentRow,
  type WithDemo,
} from "../api/endpoint";

type Tab = "summary" | "processes" | "services";

const TABS: { id: Tab; label: string }[] = [
  { id: "summary", label: "Summary" },
  { id: "processes", label: "Processes" },
  { id: "services", label: "Services" },
];

function formatWhen(iso?: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function StatePill({ state }: { state?: string }) {
  const s = (state ?? "").toLowerCase();
  const cls =
    s === "running" || s === "online"
      ? "ok"
      : s === "stopped" || s === "terminated" || s === "offline"
        ? "bad"
        : s === "auto" || s === "manual"
          ? "warn"
          : "muted";
  return <span className={`ep-state-pill ${cls}`}>{state ?? "-"}</span>;
}

function Kpi({ label, value, tone }: { label: string; value: number | string; tone?: "ok" | "bad" }) {
  return (
    <div className="ep-kpi">
      <span className="ep-kpi-label">{label}</span>
      <span className={`ep-kpi-value${tone ? ` ${tone}` : ""}`}>{value}</span>
    </div>
  );
}

function TopProcesses({ title, rows }: { title: string; rows: ProcessRow[] }) {
  if (!rows?.length) {
    return (
      <div className="ep-state">
        <Icon name="cpu" size={16} />
        <span>No running processes yet</span>
      </div>
    );
  }
  const max = Math.max(...rows.map((p) => Math.max(p.cpu_percent ?? 0, p.memory_rss_mb ?? 0)));
  return (
    <div>
      {rows.map((p) => {
        const value = title === "CPU" ? p.cpu_percent ?? 0 : p.memory_rss_mb ?? 0;
        return (
          <div className="ep-bar" key={p.id}>
            <span className="ep-bar-label">{p.name}</span>
            <div className="ep-bar-track">
              <div className="ep-bar-fill" style={{ width: `${max ? Math.max((value / max) * 100, 4) : 0}%` }} />
            </div>
            <span className="ep-bar-value">
              {title === "CPU" ? `${value.toFixed(1)}%` : `${value.toFixed(0)} MB`}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function SummaryTab() {
  const summary = useAsync<WithDemo<ProcessSummaryType>>(() => processSummary(), [], 10_000);
  const data = summary.data;

  return (
    <div className="ep-body">
      <div className="ep-kpi-row">
        <Kpi label="Agents" value={data?.agents_total ?? 0} />
        <Kpi label="Running processes" value={data?.processes_running ?? 0} />
        <Kpi label="Services" value={data?.services_total ?? 0} />
        <Kpi label="Services running" value={data?.services_running ?? 0} />
        <Kpi label="Service changes" value={data?.service_changes ?? 0} />
      </div>

      <div className="ep-grid">
        <div className="ep-card">
          <div className="ep-card-title">
            <Icon name="cpu" size={15} />
            Top CPU
          </div>
          <div className="ep-card-body">
            <TopProcesses title="CPU" rows={data?.top_cpu ?? []} />
          </div>
        </div>
        <div className="ep-card">
          <div className="ep-card-title">
            <Icon name="database" size={15} />
            Top memory
          </div>
          <div className="ep-card-body">
            <TopProcesses title="Memory" rows={data?.top_memory ?? []} />
          </div>
        </div>
      </div>

      <div className="ep-footnote">
        Processes and services are collected by the endpoint agent on a fixed
        cadence (network/process every few seconds, services every ~15s) and
        stored as live state. Process/service lifecycle transitions are also
        forwarded through the ingest pipeline so detection rules can alert on
        behavioral changes.
      </div>

      {summary.status === "loading" ? (
        <div className="ep-state">
          <span className="spinner" />
          <span>Loading summary…</span>
        </div>
      ) : null}
      {summary.status === "error" ? (
        <div className="ep-state ep-state-error">
          <Icon name="warn" size={16} />
          <span>{summary.error}</span>
        </div>
      ) : null}
    </div>
  );
}

function ProcessesTab({ agentId }: { agentId: string }) {
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("running");
  const [detailPid, setDetailPid] = useState<number | null>(null);
  const procs = useAsync<WithDemo<ProcessRow[]>>(
    () => processes(agentId, search, status),
    [agentId, search, status],
    10_000
  );
  const tree = useAsync<WithDemo<ProcessRow[]>>(
    () => (detailPid != null ? processTree(detailPid, agentId) : Promise.resolve(Object.assign([], { demo: false }) as WithDemo<ProcessRow[]>)),
    [detailPid, agentId],
    15_000
  );
  const rows = procs.data ?? [];
  const treeRows = tree.data ?? [];

  return (
    <div className="ep-body">
      <div className="ep-header">
        <div className="ep-header-actions">
          <input
            className="ep-input"
            placeholder="Filter by name / executable / user…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Filter processes"
          />
          <select className="ep-select" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Process status">
            <option value="running">Running</option>
            <option value="terminated">Terminated</option>
          </select>
        </div>
      </div>

      <div className="ep-table-wrap">
        <table className="ep-table">
          <thead>
            <tr>
              <th>PID</th>
              <th>Name</th>
              <th>User</th>
              <th>CPU %</th>
              <th>Memory</th>
              <th>Threads</th>
              <th>Parent</th>
              <th>Status</th>
              <th>Started</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} onClick={() => setDetailPid(r.pid)} style={{ cursor: "pointer" }}>
                <td className="ep-mono" style={{ fontWeight: 600 }}>
                  {r.pid}
                </td>
                <td>
                  {r.name}
                  {r.executable ? <div className="ep-mono">{r.executable}</div> : null}
                </td>
                <td>{r.user ?? "-"}</td>
                <td>{r.cpu_percent != null ? `${r.cpu_percent.toFixed(1)}%` : "-"}</td>
                <td>{r.memory_rss_mb != null ? `${r.memory_rss_mb.toFixed(0)} MB` : "-"}</td>
                <td>{r.threads ?? "-"}</td>
                <td>
                  {r.parent_name ?? "-"}
                  {r.parent_pid ? <span className="ep-mono"> ({r.parent_pid})</span> : null}
                </td>
                <td>
                  <StatePill state={r.status} />
                </td>
                <td>{formatWhen(r.started_at)}</td>
              </tr>
            ))}
            {!rows.length && procs.status === "success" ? (
              <tr>
                <td colSpan={9}>
                  <div className="ep-state">
                    <Icon name="cpu" size={16} />
                    <span>No processes match the current filter. Click a row to inspect its process tree.</span>
                  </div>
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      {procs.status === "loading" ? (
        <div className="ep-state">
          <span className="spinner" />
          <span>Loading processes…</span>
        </div>
      ) : null}

      {detailPid != null ? (
        <div className="ep-card">
          <div className="ep-card-title">
            <Icon name="git" size={15} />
            Process tree for PID {detailPid}
            <button type="button" className="ep-btn" onClick={() => setDetailPid(null)} style={{ marginLeft: "auto" }}>
              Close
            </button>
          </div>
          <div className="ep-card-body">
            <div className="ep-table-wrap">
              <table className="ep-table">
                <thead>
                  <tr>
                    <th>Depth</th>
                    <th>PID</th>
                    <th>Name</th>
                    <th>User</th>
                    <th>CPU %</th>
                    <th>Memory</th>
                    <th>Command</th>
                  </tr>
                </thead>
                <tbody>
                  {treeRows.map((r) => (
                    <tr key={`${r.pid}-${r.id}`}>
                      <td className="ep-mono">{r.depth ?? 0}</td>
                      <td className="ep-mono" style={{ fontWeight: 600 }}>
                        {r.pid}
                      </td>
                      <td>
                        <div className="ep-tree-row">
                          <Icon name="file" size={12} />
                          {r.name}
                        </div>
                      </td>
                      <td>{r.user ?? "-"}</td>
                      <td>{r.cpu_percent != null ? `${r.cpu_percent.toFixed(1)}%` : "-"}</td>
                      <td>{r.memory_rss_mb != null ? `${r.memory_rss_mb.toFixed(0)} MB` : "-"}</td>
                      <td className="ep-mono">{r.command_line ?? "-"}</td>
                    </tr>
                  ))}
                  {!treeRows.length && tree.status === "success" ? (
                    <tr>
                      <td colSpan={7}>
                        <div className="ep-state">
                          <Icon name="search" size={16} />
                          <span>No tree rows available for this PID.</span>
                        </div>
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function ServicesTab({ agentId }: { agentId: string }) {
  const [search, setSearch] = useState("");
  const [state, setState] = useState("");
  const svcs = useAsync<WithDemo<ServiceRow[]>>(
    () => services(agentId, search, state),
    [agentId, search, state],
    15_000
  );
  const rows = svcs.data ?? [];

  return (
    <div className="ep-body">
      <div className="ep-header">
        <div className="ep-header-actions">
          <input
            className="ep-input"
            placeholder="Filter by name / display name / account…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Filter services"
          />
          <select className="ep-select" value={state} onChange={(e) => setState(e.target.value)} aria-label="Service state">
            <option value="">All states</option>
            <option value="running">Running</option>
            <option value="stopped">Stopped</option>
          </select>
        </div>
      </div>

      <div className="ep-table-wrap">
        <table className="ep-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Display name</th>
              <th>State</th>
              <th>Start type</th>
              <th>Account</th>
              <th>PID</th>
              <th>Agent</th>
              <th>Changed</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="ep-mono" style={{ fontWeight: 600 }}>
                  {r.name}
                </td>
                <td>{r.display_name ?? "-"}</td>
                <td>
                  <StatePill state={r.state} />
                </td>
                <td>{r.start_type ?? "-"}</td>
                <td>{r.account ?? "-"}</td>
                <td className="ep-mono">{r.pid ?? "-"}</td>
                <td>{r.agent ?? "-"}</td>
                <td>{formatWhen(r.changed_at)}</td>
              </tr>
            ))}
            {!rows.length && svcs.status === "success" ? (
              <tr>
                <td colSpan={8}>
                  <div className="ep-state">
                    <Icon name="wrench" size={16} />
                    <span>No services match the current filter.</span>
                  </div>
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      {svcs.status === "loading" ? (
        <div className="ep-state">
          <span className="spinner" />
          <span>Loading services…</span>
        </div>
      ) : null}
    </div>
  );
}

export default function ProcessServicePage() {
  const [tab, setTab] = useState<Tab>("summary");
  const [agentId, setAgentId] = useState("");
  const agents = useAsync<WithDemo<TelemetryAgentRow[]>>(() => telemetryAgents(), [], 30_000);

  const list = agents.data ?? [];
  const demo = agents.data?.demo === true || !list.some((a) => !a.demo);

  return (
    <div className="ep-page">
      <header className="ep-header">
        <div className="ep-breadcrumb">
          <span className="ep-breadcrumb-current">Endpoint Security</span>
          <Icon name="chevron" size={12} />
          <span className="ep-breadcrumb-page">Process &amp; Service Monitoring</span>
        </div>
        <div className="ep-header-actions">
          {demo ? (
            <span className="ep-demo-badge" title="No real telemetry agent registered yet">
              Demo data
            </span>
          ) : null}
          <select
            className="ep-select"
            value={agentId}
            onChange={(e) => setAgentId(e.target.value)}
            aria-label="Select telemetry agent"
          >
            <option value="">All agents</option>
            {list.map((a) => (
              <option key={a.id} value={a.id}>
                {a.hostname} ({a.agent_code})
                {a.demo ? " · demo" : ""}
              </option>
            ))}
          </select>
        </div>
      </header>

      <nav className="ep-tabs">
        {TABS.map((t) => (
          <button
            type="button"
            key={t.id}
            className={`ep-tab${tab === t.id ? " ep-tab-active" : ""}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {tab === "summary" && <SummaryTab />}
      {tab === "processes" && <ProcessesTab agentId={agentId} />}
      {tab === "services" && <ServicesTab agentId={agentId} />}
    </div>
  );
}
