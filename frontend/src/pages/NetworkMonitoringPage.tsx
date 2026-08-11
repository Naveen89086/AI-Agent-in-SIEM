import { useState } from "react";
import { Icon } from "../components/icons";
import { useAsync } from "../hooks/useAsync";
import {
  networkConnections,
  networkDashboard,
  networkInterfaces,
  networkListening,
  networkStatistics,
  telemetryAgents,
  type NetworkConnectionRow,
  type NetworkDashboard,
  type NetworkInterfaceRow,
  type NetworkListenerRow,
  type NetworkStatisticRow,
  type TelemetryAgentRow,
  type WithDemo,
} from "../api/endpoint";

type Tab = "dashboard" | "connections" | "listening" | "interfaces";

const TABS: { id: Tab; label: string }[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "connections", label: "Connections" },
  { id: "listening", label: "Listening" },
  { id: "interfaces", label: "Interfaces" },
];

function formatWhen(iso?: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function formatBytes(n?: number): string {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(value >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function StatePill({ state }: { state?: string }) {
  const s = (state ?? "").toUpperCase();
  const cls =
    s === "ESTABLISHED" || s === "RUNNING" || s === "UP" || s === "ACTIVE"
      ? "ok"
      : s === "LISTEN" || s === "LISTENING" || s === "SYN_SENT"
        ? "warn"
        : s === "CLOSED" || s === "DOWN" || s === "CLOSE_WAIT" || s === "TERMINATED" || s === "STOPPED"
          ? "bad"
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

function TopProcesses({ items }: { items: { name: string; count: number }[] }) {
  if (!items?.length) {
    return (
      <div className="ep-state">
        <Icon name="search" size={16} />
        <span>No connections yet</span>
      </div>
    );
  }
  const max = Math.max(...items.map((i) => i.count));
  return (
    <div>
      {items.map((i) => (
        <div className="ep-bar" key={i.name}>
          <span className="ep-bar-label">{i.name}</span>
          <div className="ep-bar-track">
            <div className="ep-bar-fill" style={{ width: `${max ? Math.max((i.count / max) * 100, 4) : 0}%` }} />
          </div>
          <span className="ep-bar-value">{i.count}</span>
        </div>
      ))}
    </div>
  );
}

function DashboardTab() {
  const dash = useAsync<WithDemo<NetworkDashboard>>(() => networkDashboard(), [], 10_000);
  const data = dash.data;
  const stats = useAsync<WithDemo<NetworkStatisticRow[]>>(() => networkStatistics(), [], 10_000);
  const stat = stats.data?.[0];

  return (
    <div className="ep-body">
      <div className="ep-kpi-row">
        <Kpi label="Agents" value={data?.agents_total ?? 0} />
        <Kpi label="Agents online" value={data?.agents_online ?? 0} />
        <Kpi label="Active connections" value={data?.connections_total ?? 0} />
        <Kpi label="Listening sockets" value={data?.listeners_total ?? 0} />
        <Kpi label="Interfaces" value={data?.interfaces_total ?? 0} />
        <Kpi label="TX (KB/s)" value={(data?.tx_kbps ?? 0).toFixed(1)} />
        <Kpi label="RX (KB/s)" value={(data?.rx_kbps ?? 0).toFixed(1)} />
      </div>

      <div className="ep-grid">
        <div className="ep-card">
          <div className="ep-card-title">
            <Icon name="activity" size={15} />
            Top connection processes
          </div>
          <div className="ep-card-body">
            <TopProcesses items={data?.top_processes ?? []} />
          </div>
        </div>
        <div className="ep-card">
          <div className="ep-card-title">
            <Icon name="database" size={15} />
            Traffic totals
          </div>
          <div className="ep-card-body">
            <div className="ep-kpi-row">
              <Kpi label="Sent" value={formatBytes(data?.bytes_sent ?? stat?.bytes_sent)} />
              <Kpi label="Received" value={formatBytes(data?.bytes_recv ?? stat?.bytes_recv)} />
              <Kpi label="Packets out" value={stat?.packets_sent ?? 0} />
              <Kpi label="Packets in" value={stat?.packets_recv ?? 0} />
            </div>
          </div>
        </div>
      </div>

      <div className="ep-card">
        <div className="ep-card-title">
          <Icon name="server" size={15} />
          Interfaces
        </div>
        <div className="ep-card-body">
          <div className="ep-table-wrap">
            <table className="ep-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>MAC</th>
                  <th>Addresses</th>
                  <th>Status</th>
                  <th>Speed</th>
                </tr>
              </thead>
              <tbody>
                {(data?.interfaces ?? []).map((i) => (
                  <tr key={i.id}>
                    <td style={{ fontWeight: 600 }}>{i.name}</td>
                    <td className="ep-mono">{i.mac ?? "-"}</td>
                    <td>
                      {(i.addresses ?? []).map((a) => (
                        <span className="ep-tag ep-mono" key={a}>
                          {a}
                        </span>
                      ))}
                    </td>
                    <td>
                      <StatePill state={i.status} />
                    </td>
                    <td>{i.speed_mbps ? `${i.speed_mbps} Mbps` : "-"}</td>
                  </tr>
                ))}
                {!(data?.interfaces?.length) && dash.status === "success" ? (
                  <tr>
                    <td colSpan={5}>
                      <div className="ep-state">
                        <Icon name="server" size={16} />
                        <span>No interface data yet</span>
                      </div>
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {dash.status === "loading" ? (
        <div className="ep-state">
          <span className="spinner" />
          <span>Loading dashboard…</span>
        </div>
      ) : null}
      {dash.status === "error" ? (
        <div className="ep-state ep-state-error">
          <Icon name="warn" size={16} />
          <span>{dash.error}</span>
        </div>
      ) : null}
    </div>
  );
}

function ConnectionsTab({ agentId }: { agentId: string }) {
  const [search, setSearch] = useState("");
  const [state, setState] = useState("");
  const conns = useAsync<WithDemo<NetworkConnectionRow[]>>(
    () => networkConnections(agentId, state, search),
    [agentId, state, search],
    10_000
  );
  const rows = conns.data ?? [];

  return (
    <div className="ep-body">
      <div className="ep-header">
        <div className="ep-header-actions">
          <input
            className="ep-input"
            placeholder="Filter by IP / process / user…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Filter connections"
          />
          <select className="ep-select" value={state} onChange={(e) => setState(e.target.value)} aria-label="Filter by state">
            <option value="">All states</option>
            {["ESTABLISHED", "CLOSE_WAIT", "SYN_SENT", "TIME_WAIT", "LISTENING"].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="ep-table-wrap">
        <table className="ep-table">
          <thead>
            <tr>
              <th>Proto</th>
              <th>Local</th>
              <th>Remote</th>
              <th>State</th>
              <th>Process</th>
              <th>User</th>
              <th>Agent</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="ep-mono">{r.proto}</td>
                <td className="ep-mono">
                  {r.local_ip}:{r.local_port}
                </td>
                <td className="ep-mono ep-addr">
                  {r.foreign_ip}:{r.foreign_port}
                  {r.is_private ? null : (
                    <span className="ep-tag" title="Non-private / external address">
                      ext
                    </span>
                  )}
                </td>
                <td>
                  <StatePill state={r.state} />
                </td>
                <td>
                  {r.process_name ?? "-"}
                  {r.pid ? <span className="ep-mono"> ({r.pid})</span> : null}
                </td>
                <td>{r.user ?? "-"}</td>
                <td>{r.agent ?? "-"}</td>
                <td>{formatWhen(r.last_seen)}</td>
              </tr>
            ))}
            {!rows.length && conns.status === "success" ? (
              <tr>
                <td colSpan={8}>
                  <div className="ep-state">
                    <Icon name="network" size={16} />
                    <span>No active connections match the current filter.</span>
                  </div>
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      {conns.status === "loading" ? (
        <div className="ep-state">
          <span className="spinner" />
          <span>Loading connections…</span>
        </div>
      ) : null}
    </div>
  );
}

function ListeningTab({ agentId }: { agentId: string }) {
  const [search, setSearch] = useState("");
  const listeners = useAsync<WithDemo<NetworkListenerRow[]>>(
    () => networkListening(agentId, search),
    [agentId, search],
    10_000
  );
  const rows = listeners.data ?? [];

  return (
    <div className="ep-body">
      <div className="ep-header">
        <div className="ep-header-actions">
          <input
            className="ep-input"
            placeholder="Filter by process / address…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Filter listening sockets"
          />
        </div>
      </div>

      <div className="ep-table-wrap">
        <table className="ep-table">
          <thead>
            <tr>
              <th>Proto</th>
              <th>Address</th>
              <th>Port</th>
              <th>Process</th>
              <th>PID</th>
              <th>User</th>
              <th>Agent</th>
              <th>First seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="ep-mono">{r.proto}</td>
                <td className="ep-mono">{r.ip}</td>
                <td className="ep-mono" style={{ fontWeight: 600 }}>
                  {r.port}
                </td>
                <td>{r.process_name ?? "-"}</td>
                <td className="ep-mono">{r.pid ?? "-"}</td>
                <td>{r.user ?? "-"}</td>
                <td>{r.agent ?? "-"}</td>
                <td>{formatWhen(r.first_seen)}</td>
              </tr>
            ))}
            {!rows.length && listeners.status === "success" ? (
              <tr>
                <td colSpan={8}>
                  <div className="ep-state">
                    <Icon name="radio" size={16} />
                    <span>No listening sockets reported yet.</span>
                  </div>
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      {listeners.status === "loading" ? (
        <div className="ep-state">
          <span className="spinner" />
          <span>Loading listening sockets…</span>
        </div>
      ) : null}
    </div>
  );
}

function InterfacesTab({ agentId }: { agentId: string }) {
  const ifaces = useAsync<WithDemo<NetworkInterfaceRow[]>>(
    () => networkInterfaces(agentId),
    [agentId],
    15_000
  );
  const rows = ifaces.data ?? [];

  return (
    <div className="ep-body">
      <div className="ep-table-wrap">
        <table className="ep-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>MAC</th>
              <th>Addresses</th>
              <th>MTU</th>
              <th>Speed</th>
              <th>Status</th>
              <th>Agent</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td style={{ fontWeight: 600 }}>{r.name}</td>
                <td className="ep-mono">{r.mac ?? "-"}</td>
                <td>
                  {(r.addresses ?? []).map((a) => (
                    <span className="ep-tag ep-mono" key={a}>
                      {a}
                    </span>
                  ))}
                </td>
                <td className="ep-mono">{r.mtu ?? "-"}</td>
                <td>{r.speed_mbps ? `${r.speed_mbps} Mbps` : "-"}</td>
                <td>
                  <StatePill state={r.status} />
                </td>
                <td>{r.agent ?? "-"}</td>
                <td>{formatWhen(r.last_seen)}</td>
              </tr>
            ))}
            {!rows.length && ifaces.status === "success" ? (
              <tr>
                <td colSpan={8}>
                  <div className="ep-state">
                    <Icon name="server" size={16} />
                    <span>No interface data yet.</span>
                  </div>
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      {ifaces.status === "loading" ? (
        <div className="ep-state">
          <span className="spinner" />
          <span>Loading interfaces…</span>
        </div>
      ) : null}
    </div>
  );
}

export default function NetworkMonitoringPage() {
  const [tab, setTab] = useState<Tab>("dashboard");
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
          <span className="ep-breadcrumb-page">Network Monitoring</span>
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

      {tab === "dashboard" && <DashboardTab />}
      {tab === "connections" && <ConnectionsTab agentId={agentId} />}
      {tab === "listening" && <ListeningTab agentId={agentId} />}
      {tab === "interfaces" && <InterfacesTab agentId={agentId} />}
    </div>
  );
}
