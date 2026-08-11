import { useEffect, useMemo, useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { Icon } from "../components/icons";
import { useAsync } from "../hooks/useAsync";
import type { AsyncState } from "../hooks/useAsync";
import { pageWindow } from "../utils/pagination";
import {
  benchmarkSummary,
  configChecks,
  configPolicies,
  scaAgents,
  scaAnalyzeCheck,
  scaApproveRemediation,
  scaCreateScan,
  scaDashboard,
  scaDrifts,
  scaEvents,
  scaExecuteRemediation,
  scaRejectRemediation,
  scaRemediations,
  scaRequestRemediation,
  scaScanResults,
  scaScans,
  type CheckResult,
  type ConfigCheck,
  type ScaAgent,
  type ScaAnalysis,
  type ScaDashboard,
  type ScaDriftsResult,
  type ScaEventsResult,
  type ScaRemediation,
  type ScaRemediationsResult,
  type ScaResult,
  type ScaScan,
  type ScaScansResult,
  type WithDemo,
} from "../api/endpoint";

type Tab = "dashboard" | "inventory" | "events" | "policies" | "history";

const TABS: { id: Tab; label: string; icon: string }[] = [
  { id: "dashboard", label: "Dashboard", icon: "chart" },
  { id: "inventory", label: "Inventory", icon: "box" },
  { id: "events", label: "Events", icon: "activity" },
  { id: "policies", label: "Policies", icon: "shieldCheck" },
  { id: "history", label: "Scan History", icon: "history" },
];

const RESULT_LABEL: Record<string, string> = {
  passed: "Passed",
  failed: "Failed",
  not_applicable: "Not Applicable",
  error: "Error",
};

const RESULT_TONE: Record<string, string> = {
  passed: "passed",
  failed: "failed",
  not_applicable: "not_applicable",
  error: "error",
};

const SEVERITY_TONE: Record<string, string> = {
  critical: "crit",
  high: "crit",
  medium: "warn",
  low: "ok",
  info: "ok",
};

const PAGE_SIZES = [10, 20, 50, 100];

function formatScanTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function DemoBadge({ demo }: { demo: boolean }) {
  if (!demo) return null;
  return (
    <span className="cfg-demo-badge" title="Backend unavailable; showing deterministic demo data">
      <Icon name="flaskConical" size={12} />
      Demo data
    </span>
  );
}

function StateRow({
  status,
  error,
  empty,
  icon = "search",
}: {
  status: string;
  error: string | null;
  empty?: string;
  icon?: string;
}) {
  if (status === "loading") {
    return (
      <div className="soc-state">
        <span className="spinner" />
        <span className="soc-state-text">Loading…</span>
      </div>
    );
  }
  if (status === "error") {
    return (
      <div className="soc-state soc-state-error">
        <Icon name="warn" size={18} />
        <span>{error}</span>
      </div>
    );
  }
  if (empty) {
    return (
      <div className="soc-state">
        <Icon name={icon as never} size={18} />
        <span className="soc-state-text">{empty}</span>
      </div>
    );
  }
  return null;
}

function ResultPill({ result }: { result: string }) {
  return (
    <span className={`cfg-result cfg-result-${RESULT_TONE[result] ?? "not_applicable"}`}>
      <span className="cfg-result-dot" />
      {RESULT_LABEL[result] ?? result}
    </span>
  );
}

function SeverityPill({ severity }: { severity: string }) {
  return (
    <span className={`cfg-sev cfg-sev-${SEVERITY_TONE[severity] ?? "warn"}`}>{severity}</span>
  );
}

function AgentStatusPill({ status }: { status: string }) {
  const tone = status === "online" ? "ok" : status === "offline" ? "crit" : "warn";
  return (
    <span className={`cfg-sev cfg-sev-${tone}`}>
      <span className="cfg-sev-dot" />
      {status}
    </span>
  );
}

function ScaPager({
  page,
  totalPages,
  total,
  startRow,
  endRow,
  perPage,
  onPage,
  onPerPage,
}: {
  page: number;
  totalPages: number;
  total: number;
  startRow: number;
  endRow: number;
  perPage: number;
  onPage: (p: number) => void;
  onPerPage: (n: number) => void;
}) {
  return (
    <div className="cfg-pager">
      <div className="cfg-pager-size">
        <span className="cfg-pager-label">Rows per page:</span>
        <select
          className="select cfg-pager-select"
          value={perPage}
          onChange={(e) => onPerPage(Number(e.target.value))}
        >
          {PAGE_SIZES.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
        <span className="cfg-pager-count mono">
          {startRow}–{endRow} of {total}
        </span>
      </div>
      <div className="cfg-pager-nav">
        <button
          type="button"
          className="cfg-page-btn"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
          aria-label="Previous page"
        >
          ◀
        </button>
        {pageWindow(page, totalPages).map((p, i) =>
          p === "…" ? (
            <span key={`e${i}`} className="cfg-page-ellipsis">
              …
            </span>
          ) : (
            <button
              type="button"
              key={p}
              className={`cfg-page-btn${p === page ? " cfg-page-active" : ""}`}
              onClick={() => onPage(p)}
            >
              {p}
            </button>
          )
        )}
        <button
          type="button"
          className="cfg-page-btn"
          disabled={page >= totalPages}
          onClick={() => onPage(page + 1)}
          aria-label="Next page"
        >
          ▶
        </button>
      </div>
    </div>
  );
}

function Kpi({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="cfg-stat">
      <div className="cfg-stat-label">{label}</div>
      <div className={`cfg-stat-value ${tone === "ok" ? "cfg-stat-ok" : tone === "err" ? "cfg-stat-err" : ""}`}>
        {value}
      </div>
    </div>
  );
}

function DonutCard({
  passed,
  failed,
  na,
  total,
}: {
  passed: number;
  failed: number;
  na: number;
  total: number;
}) {
  const data = [
    { name: "Passed", value: passed, color: "#22c55e" },
    { name: "Failed", value: failed, color: "#ef4444" },
    { name: "N/A", value: na, color: "#64748b" },
  ];
  return (
    <div className="cfg-card cfg-donut-card">
      <div className="cfg-donut">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius="68%"
              outerRadius="88%"
              paddingAngle={2}
              stroke="none"
            >
              {data.map((d) => (
                <Cell key={d.name} fill={d.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: "#1e293b",
                border: "1px solid #334155",
                borderRadius: 8,
                fontSize: 12,
              }}
              itemStyle={{ color: "#e2e8f0" }}
              labelStyle={{ color: "#94a3b8" }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="cfg-donut-center">
          <div className="cfg-donut-value">{total}</div>
          <div className="cfg-donut-label">Checks</div>
        </div>
      </div>
      <div className="cfg-donut-legend">
        <div className="cfg-legend-row">
          <span className="cfg-legend-dot" style={{ background: "#22c55e" }} />
          <span className="cfg-legend-name">Passed</span>
          <span className="cfg-legend-value">{passed}</span>
        </div>
        <div className="cfg-legend-row">
          <span className="cfg-legend-dot" style={{ background: "#ef4444" }} />
          <span className="cfg-legend-name">Failed</span>
          <span className="cfg-legend-value">{failed}</span>
        </div>
        <div className="cfg-legend-row">
          <span className="cfg-legend-dot" style={{ background: "#64748b" }} />
          <span className="cfg-legend-name">N/A</span>
          <span className="cfg-legend-value">{na}</span>
        </div>
      </div>
    </div>
  );
}

function ChecksTable() {
  const [search, setSearch] = useState("");
  const [debounced, setDebounced] = useState("");
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(10);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(search), 300);
    return () => clearTimeout(t);
  }, [search]);

  useEffect(() => {
    setPage(1);
  }, [debounced, perPage]);

  const checks = useAsync(
    () => configChecks(page, perPage, debounced),
    [page, perPage, debounced],
    60_000
  );

  const rows: ConfigCheck[] = checks.data?.items ?? [];
  const total = checks.data?.total ?? 0;
  const totalPages = checks.data?.totalPages ?? 1;
  const startRow = total === 0 ? 0 : (page - 1) * perPage + 1;
  const endRow = Math.min(page * perPage, total);

  return (
    <div className="cfg-card cfg-checks-card">
      <div className="cfg-checks-head">
        <div className="cfg-card-title">Checks ({total})</div>
        <div className="cfg-search">
          <Icon name="search" size={14} />
          <input
            className="cfg-search-input"
            placeholder="Search…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {checks.status === "loading" ? (
        <div className="soc-state">
          <span className="spinner" />
        </div>
      ) : checks.status === "error" ? (
        <StateRow status="error" error={checks.error} />
      ) : rows.length === 0 ? (
        <StateRow status="success" error={null} empty="No checks match your search" icon="search" />
      ) : (
        <div className="cfg-table-wrap">
          <table className="cfg-table">
            <thead>
              <tr>
                <th className="cfg-th-id">ID</th>
                <th>Title</th>
                <th>Target</th>
                <th>Severity</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id}>
                  <td className="mono cfg-td-id">{c.id}</td>
                  <td className="cfg-td-title">{c.title}</td>
                  <td className="mono cfg-td-target">{c.target}</td>
                  <td>
                    <SeverityPill severity={c.severity ?? "low"} />
                  </td>
                  <td>
                    <ResultPill result={c.result} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ScaPager
        page={page}
        totalPages={totalPages}
        total={total}
        startRow={startRow}
        endRow={endRow}
        perPage={perPage}
        onPage={setPage}
        onPerPage={setPerPage}
      />
    </div>
  );
}

function PolicyList({ activeId }: { activeId: string }) {
  const policies = useAsync(() => configPolicies(), [], 60_000);
  return (
    <div className="cfg-card">
      <div className="cfg-card-title">Policy</div>
      <div className="cfg-policy-list">
        {policies.status === "loading" ? (
          <div className="soc-state">
            <span className="spinner" />
          </div>
        ) : policies.status === "error" ? (
          <StateRow status="error" error={policies.error} />
        ) : (
          (policies.data ?? []).map((p) => (
            <button type="button" key={p.id} className={`cfg-policy${p.id === activeId ? " cfg-policy-active" : ""}`}>
              <Icon name="shieldCheck" size={14} />
              <span className="cfg-policy-name">{p.name}</span>
            </button>
          ))
        )}
      </div>
      <div className="cfg-policy-foot mono">Rows/Page: {policies.data?.[0]?.rowsPerPage ?? 15}</div>
    </div>
  );
}

function TopFailures({ failures }: { failures: ScaDashboard["top_failures"] }) {
  const max = Math.max(1, ...failures.map((f) => f.failures));
  return (
    <div className="cfg-card">
      <div className="cfg-card-title">Top Failing Checks</div>
      <div className="cfg-topfail">
        {failures.length === 0 ? (
          <div className="soc-state">
            <span className="soc-state-text">No failing checks</span>
          </div>
        ) : (
          failures.map((f) => (
            <div key={f.id} className="cfg-topfail-row">
              <div className="cfg-topfail-head">
                <span className="cfg-topfail-title">{f.title}</span>
                <span className="cfg-topfail-count mono">{f.failures}</span>
              </div>
              <div className="cfg-topfail-bar">
                <div className="cfg-topfail-fill" style={{ width: `${(f.failures / max) * 100}%` }} />
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function RiskBuckets({ buckets }: { buckets: ScaDashboard["risk_distribution"] }) {
  const items = [
    { key: "critical", label: "Critical", value: buckets.critical, color: "#ef4444" },
    { key: "high", label: "High", value: buckets.high, color: "#f97316" },
    { key: "medium", label: "Medium", value: buckets.medium, color: "#eab308" },
    { key: "low", label: "Low", value: buckets.low, color: "#22c55e" },
  ];
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div className="cfg-card">
      <div className="cfg-card-title">Risk Distribution (latest scans)</div>
      <div className="cfg-risk">
        {items.map((i) => (
          <div key={i.key} className="cfg-risk-row">
            <span className="cfg-risk-label">{i.label}</span>
            <div className="cfg-risk-track">
              <div className="cfg-risk-fill" style={{ width: `${(i.value / max) * 100}%`, background: i.color }} />
            </div>
            <span className="cfg-risk-value mono">{i.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DashboardTab({ dashboard }: { dashboard: WithDemo<ScaDashboard> | null }) {
  const summary = useAsync(() => benchmarkSummary(), [], 60_000);
  const s = summary.data;
  const donut = useMemo(
    () => ({
      passed: s?.passed ?? 0,
      failed: s?.failed ?? 0,
      na: s?.not_applicable ?? 0,
      total: s?.total_checks ?? 0,
    }),
    [s]
  );
  const d = dashboard;

  return (
    <div className="cfg-cols">
      <aside className="cfg-side">
        {summary.status === "loading" ? (
          <div className="cfg-card soc-state">
            <span className="spinner" />
          </div>
        ) : summary.status === "error" ? (
          <div className="cfg-card soc-state soc-state-error">
            <Icon name="warn" size={16} />
            <span>{summary.error}</span>
          </div>
        ) : (
          <DonutCard passed={donut.passed} failed={donut.failed} na={donut.na} total={donut.total} />
        )}
        <PolicyList activeId="cis-win11" />
      </aside>

      <main className="cfg-main">
        <div className="cfg-bench">
          <Icon name="shieldCheck" size={16} />
          {s?.policy ?? "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0"}
        </div>

        <div className="cfg-summary">
          <Kpi label="Agents" value={d ? `${d.agents_online}/${d.agents_total} online` : "—"} tone={d && d.agents_online === d.agents_total ? "ok" : "err"} />
          <Kpi label="Scans" value={d?.scans_total ?? "—"} />
          <Kpi label="Avg Score" value={d ? `${d.average_score}%` : "—"} />
          <Kpi label="Avg Risk" value={d?.average_risk ?? "—"} tone={d && d.average_risk >= 60 ? "err" : "ok"} />
          <Kpi label="Events Today" value={d?.events_today ?? "—"} />
          <Kpi label="Drift" value={d?.drift_total ?? "—"} tone={d && d.drift_total > 0 ? "err" : "ok"} />
          <Kpi label="Pending Remediation" value={d?.pending_remediation ?? "—"} tone={d && d.pending_remediation > 0 ? "err" : "ok"} />
        </div>

        <div className="cfg-summary">
          <Kpi label="Passed" value={donut.passed} tone="ok" />
          <Kpi label="Failed" value={donut.failed} tone="err" />
          <Kpi label="Not Applicable" value={donut.na} />
          <Kpi label="Score" value={s ? `${s.score}%` : "—"} />
          <Kpi label="End Scan" value={formatScanTime(s?.end_scan)} />
        </div>

        {d && d.top_failures.length > 0 && (
          <div className="cfg-grid-2">
            <TopFailures failures={d.top_failures} />
            <RiskBuckets buckets={d.risk_distribution} />
          </div>
        )}

        {d && d.latest_events.length > 0 && (
          <div className="cfg-card">
            <div className="cfg-card-title">Latest Events</div>
            <div className="cfg-table-wrap">
              <table className="cfg-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Message</th>
                    <th>Agent</th>
                    <th>When</th>
                  </tr>
                </thead>
                <tbody>
                  {d.latest_events.map((e) => (
                    <tr key={e.id}>
                      <td className="mono">{e.event_type}</td>
                      <td>
                        <SeverityPill severity={e.severity} />
                      </td>
                      <td className="cfg-td-title">{e.message}</td>
                      <td className="mono">{e.agent ?? "—"}</td>
                      <td className="mono">{formatScanTime(e.occurred_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        <ChecksTable />
      </main>
    </div>
  );
}

function InventoryTab({ agents }: { agents: AsyncState<WithDemo<ScaAgent[]> | null> }) {
  const data = agents.data ?? null;
  return (
    <div className="cfg-card">
      <div className="cfg-card-title">
        Agent Inventory
        <DemoBadge demo={data?.demo ?? false} />
      </div>
      {agents.status === "loading" ? (
        <StateRow status="loading" error={null} />
      ) : agents.status === "error" ? (
        <StateRow status="error" error={agents.error} />
      ) : !data || data.length === 0 ? (
        <StateRow status="success" error={null} empty="No agents registered" icon="box" />
      ) : (
      <div className="cfg-table-wrap">
        <table className="cfg-table">
          <thead>
            <tr>
              <th>Agent</th>
              <th>Hostname</th>
              <th>OS</th>
              <th>Platform</th>
              <th>Status</th>
              <th>Version</th>
              <th>Scans</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {data.map((a) => (
              <tr key={a.id}>
                <td className="mono">{a.agent_code}</td>
                <td className="cfg-td-title">{a.hostname}</td>
                <td>{a.operating_system}</td>
                <td className="mono">{a.platform}</td>
                <td>
                  <AgentStatusPill status={a.status} />
                </td>
                <td className="mono">{a.version}</td>
                <td className="mono">{a.scans}</td>
                <td className="mono">{formatScanTime(a.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      )}
    </div>
  );
}

const EVENT_TYPES = [
  { id: "", label: "All events" },
  { id: "scan_completed", label: "Scan completed" },
  { id: "critical_check_failed", label: "Critical checks failed" },
  { id: "configuration_changed", label: "Configuration changed" },
  { id: "agent_online", label: "Agent online" },
  { id: "agent_offline", label: "Agent offline" },
  { id: "scan_failed", label: "Scan failed" },
];

function DriftTable({ drifts }: { drifts: WithDemo<ScaDriftsResult> | null }) {
  const page = drifts?.page ?? 1;
  const perPage = drifts?.perPage ?? 10;
  return (
    <div className="cfg-card">
      <div className="cfg-card-title">
        Configuration Drift
        <DemoBadge demo={drifts?.demo ?? false} />
      </div>
      <div className="cfg-table-wrap">
        <table className="cfg-table">
          <thead>
            <tr>
              <th>Check</th>
              <th>Transition</th>
              <th>Severity</th>
              <th>Agent</th>
              <th>Detected</th>
            </tr>
          </thead>
          <tbody>
            {(drifts?.items ?? []).map((dr) => (
              <tr key={dr.id}>
                <td className="cfg-td-title">{dr.title ?? dr.check_id}</td>
                <td>
                  <span className="cfg-transition">
                    <ResultPill result={dr.previous_result} />
                    <Icon name="chevron" size={12} />
                    <ResultPill result={dr.current_result} />
                  </span>
                </td>
                <td>
                  <SeverityPill severity={dr.severity} />
                </td>
                <td className="mono">{dr.agent ?? "—"}</td>
                <td className="mono">{formatScanTime(dr.detected_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function EventsTab({ events, drifts }: { events: WithDemo<ScaEventsResult> | null; drifts: WithDemo<ScaDriftsResult> | null }) {
  return (
    <div className="cfg-stack">
      <div className="cfg-card">
        <div className="cfg-card-title">
          Policy Events
          <DemoBadge demo={events?.demo ?? false} />
        </div>
        <div className="cfg-table-wrap">
          <table className="cfg-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Severity</th>
                <th>Message</th>
                <th>Agent</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {(events?.items ?? []).map((e) => (
                <tr key={e.id}>
                  <td className="mono">{e.event_type}</td>
                  <td>
                    <SeverityPill severity={e.severity} />
                  </td>
                  <td className="cfg-td-title">{e.message}</td>
                  <td className="mono">{e.agent ?? "—"}</td>
                  <td className="mono">{formatScanTime(e.occurred_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <DriftTable drifts={drifts} />
    </div>
  );
}

function PoliciesTab({
  agents,
}: {
  agents: AsyncState<WithDemo<ScaAgent[]> | null>;
}) {
  const policies = useAsync(() => configPolicies(), [], 60_000);
  const [selected, setSelected] = useState<string>("");
  const [agentId, setAgentId] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  const agentRows = agents.data ?? [];

  useEffect(() => {
    const online = agentRows.find((a) => a.status === "online");
    if (online) setAgentId((prev) => prev || online.id);
  }, [agentRows]);

  const runScan = async () => {
    if (!selected || !agentId) return;
    setBusy(true);
    setMessage(null);
    try {
      const scan = await scaCreateScan(selected, agentId);
      setMessage({ ok: true, text: `Scan queued (${scan.id.slice(0, 8)}…) — status: ${scan.status}` });
    } catch (err) {
      setMessage({ ok: false, text: `Unavailable: ${err instanceof Error ? err.message : String(err)}` });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="cfg-stack">
      <div className="cfg-card">
        <div className="cfg-card-title">Benchmark Policies</div>
        {policies.status === "loading" ? (
          <StateRow status="loading" error={null} />
        ) : policies.status === "error" ? (
          <StateRow status="error" error={policies.error} />
        ) : (
          <div className="cfg-table-wrap">
            <table className="cfg-table">
              <thead>
                <tr>
                  <th>Policy</th>
                  <th>Framework</th>
                  <th>Rows/Page</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {(policies.data ?? []).map((p) => (
                  <tr key={p.id} className={selected === p.id ? "cfg-row-active" : ""}>
                    <td className="cfg-td-title">
                      <button type="button" className="cfg-link" onClick={() => setSelected(p.id)}>
                        {p.name}
                      </button>
                    </td>
                    <td className="mono">{p.name.includes("Windows 11") ? "Windows 11" : p.name.includes("Windows 10") ? "Windows 10" : "Ubuntu"}</td>
                    <td className="mono">{p.rowsPerPage}</td>
                    <td>
                      <button
                        type="button"
                        className="cfg-action-btn"
                        onClick={() => setSelected(p.id)}
                      >
                        <Icon name="eye" size={13} />
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="cfg-card">
        <div className="cfg-card-title">Run Scan</div>
        <div className="cfg-run">
          <label className="cfg-run-field">
            <span className="cfg-run-label">Policy</span>
            <select className="select cfg-run-select" value={selected} onChange={(e) => setSelected(e.target.value)}>
              <option value="">Select a policy…</option>
              {(policies.data ?? []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <label className="cfg-run-field">
            <span className="cfg-run-label">Agent</span>
            <select className="select cfg-run-select" value={agentId} onChange={(e) => setAgentId(e.target.value)}>
              <option value="">
                {agents.status === "loading"
                  ? "Loading agents…"
                  : agents.status === "error"
                    ? "Agents unavailable"
                    : "Select an agent…"}
              </option>
              {agentRows.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname} ({a.agent_code}) — {a.status}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="cfg-action-btn cfg-action-primary"
            disabled={busy || !selected || !agentId}
            onClick={runScan}
          >
            <Icon name="scan" size={13} />
            {busy ? "Queuing…" : "Run Scan"}
          </button>
        </div>
        {message && (
          <div className={`cfg-msg ${message.ok ? "cfg-msg-ok" : "cfg-msg-err"}`}>{message.text}</div>
        )}
      </div>
    </div>
  );
}

function AnalysisPanel({ analysis }: { analysis: ScaAnalysis | null }) {
  if (!analysis) return null;
  return (
    <div className="cfg-analysis">
      <div className="cfg-analysis-head">
        <Icon name="sparkles" size={14} />
        AI Analysis
        <span className="cfg-analysis-provider">{analysis.provider}</span>
      </div>
      <p className="cfg-analysis-summary">{analysis.summary}</p>
      {analysis.extra && (
        <div className="cfg-analysis-extra mono">
          {JSON.stringify(analysis.extra, null, 0)}
        </div>
      )}
      {analysis.recommended_actions && analysis.recommended_actions.length > 0 && (
        <ul className="cfg-analysis-actions">
          {analysis.recommended_actions.map((a, i) => (
            <li key={i}>{a}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ScanResultsPanel({
  scan,
}: {
  scan: ScaScan;
}) {
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(10);
  const [resultFilter, setResultFilter] = useState("");
  const [search, setSearch] = useState("");
  const [debounced, setDebounced] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [analysisByResult, setAnalysisByResult] = useState<Record<string, ScaAnalysis>>({});

  useEffect(() => {
    const t = setTimeout(() => setDebounced(search), 300);
    return () => clearTimeout(t);
  }, [search]);
  useEffect(() => {
    setPage(1);
  }, [resultFilter, debounced, perPage]);

  const results = useAsync(
    () => scaScanResults(scan.id, page, perPage, resultFilter || undefined, debounced),
    [scan.id, page, perPage, resultFilter, debounced],
    30_000
  );

  const analyze = async (r: ScaResult) => {
    setBusyId(r.check_result_id);
    setMsg(null);
    try {
      const analysis = await scaAnalyzeCheck(r.check_result_id);
      setAnalysisByResult((prev) => ({ ...prev, [r.check_result_id]: analysis }));
    } catch (err) {
      setMsg({ ok: false, text: `Analysis unavailable: ${err instanceof Error ? err.message : String(err)}` });
    } finally {
      setBusyId(null);
    }
  };

  const remediate = async (r: ScaResult) => {
    setBusyId(r.check_result_id);
    setMsg(null);
    try {
      const rem = await scaRequestRemediation(r.check_result_id, `Apply benchmark setting: ${r.title}`);
      setMsg({ ok: true, text: `Remediation requested (${rem.status}) for ${r.title}` });
    } catch (err) {
      setMsg({ ok: false, text: `Remediation unavailable: ${err instanceof Error ? err.message : String(err)}` });
    } finally {
      setBusyId(null);
    }
  };

  const rows = results.data?.items ?? [];
  const total = results.data?.total ?? 0;
  const totalPages = results.data?.totalPages ?? 1;
  const startRow = total === 0 ? 0 : (page - 1) * perPage + 1;
  const endRow = Math.min(page * perPage, total);

  return (
    <div className="cfg-card cfg-results-card">
      <div className="cfg-checks-head">
        <div className="cfg-card-title">
          Results — {scan.policy} <span className="cfg-card-sub mono">{scan.agent}</span>
        </div>
        <div className="cfg-results-controls">
          <select className="select cfg-run-select" value={resultFilter} onChange={(e) => setResultFilter(e.target.value)}>
            <option value="">All results</option>
            <option value="failed">Failed</option>
            <option value="passed">Passed</option>
            <option value="not_applicable">N/A</option>
            <option value="error">Error</option>
          </select>
          <div className="cfg-search">
            <Icon name="search" size={14} />
            <input
              className="cfg-search-input"
              placeholder="Search…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>
      </div>

      {msg && <div className={`cfg-msg ${msg.ok ? "cfg-msg-ok" : "cfg-msg-err"}`}>{msg.text}</div>}

      {results.status === "loading" ? (
        <StateRow status="loading" error={null} />
      ) : results.status === "error" ? (
        <StateRow status="error" error={results.error} />
      ) : rows.length === 0 ? (
        <StateRow status="success" error={null} empty="No results match your filter" icon="search" />
      ) : (
        <div className="cfg-table-wrap">
          <table className="cfg-table">
            <thead>
              <tr>
                <th className="cfg-th-id">ID</th>
                <th>Title</th>
                <th>Severity</th>
                <th>Result</th>
                <th>Expected</th>
                <th>Actual</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="mono cfg-td-id">{r.check_id}</td>
                  <td className="cfg-td-title">{r.title}</td>
                  <td>
                    <SeverityPill severity={r.severity} />
                  </td>
                  <td>
                    <ResultPill result={r.result} />
                  </td>
                  <td className="mono cfg-td-target">{r.expected_value ?? "—"}</td>
                  <td className="mono cfg-td-target">{r.actual_value ?? "—"}</td>
                  <td>
                    <div className="cfg-row-actions">
                      <button
                        type="button"
                        className="cfg-action-btn"
                        disabled={busyId === r.check_result_id}
                        onClick={() => analyze(r)}
                      >
                        <Icon name="sparkles" size={13} />
                        Analyze
                      </button>
                      {r.result === "failed" && (
                        <button
                          type="button"
                          className="cfg-action-btn"
                          disabled={busyId === r.check_result_id}
                          onClick={() => remediate(r)}
                        >
                          <Icon name="wrench" size={13} />
                          Remediate
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {Object.keys(analysisByResult).length > 0 && (
        <div className="cfg-stack">
          {Object.values(analysisByResult).map((a) => (
            <AnalysisPanel key={a.id} analysis={a} />
          ))}
        </div>
      )}

      <ScaPager
        page={page}
        totalPages={totalPages}
        total={total}
        startRow={startRow}
        endRow={endRow}
        perPage={perPage}
        onPage={setPage}
        onPerPage={setPerPage}
      />
    </div>
  );
}

function RemediationQueue({ data }: { data: WithDemo<ScaRemediationsResult> | null }) {
  const [reload, setReload] = useState(0);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const remediations = useAsync(
    () => scaRemediations(1, 50),
    [reload],
    60_000
  );
  const items: ScaRemediation[] = (remediations.data ?? data)?.items ?? [];

  const act = async (label: string, fn: () => Promise<unknown>) => {
    setBusyId(label);
    setMsg(null);
    try {
      await fn();
      setMsg({ ok: true, text: `${label} completed` });
      setReload((n) => n + 1);
    } catch (err) {
      setMsg({ ok: false, text: `${label} failed: ${err instanceof Error ? err.message : String(err)}` });
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="cfg-card">
      <div className="cfg-card-title">
        Remediation Queue
        <DemoBadge demo={remediations.data?.demo ?? data?.demo ?? false} />
      </div>
      {msg && <div className={`cfg-msg ${msg.ok ? "cfg-msg-ok" : "cfg-msg-err"}`}>{msg.text}</div>}
      <div className="cfg-table-wrap">
        <table className="cfg-table">
          <thead>
            <tr>
              <th>Check</th>
              <th>Status</th>
              <th>Requested By</th>
              <th>Approved By</th>
              <th>Result</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((r) => (
              <tr key={r.id}>
                <td className="cfg-td-title">
                  {r.check_title ?? r.check_id}
                  <div className="cfg-card-sub mono">{r.agent ?? "—"}</div>
                </td>
                <td>
                  <span className={`cfg-sev cfg-sev-${r.status === "completed" ? "ok" : r.status === "rejected" ? "crit" : "warn"}`}>
                    {r.status}
                  </span>
                </td>
                <td className="mono">{r.requested_by}</td>
                <td className="mono">{r.approved_by ?? "—"}</td>
                <td className="mono cfg-td-target">{r.result ?? "—"}</td>
                <td>
                  <div className="cfg-row-actions">
                    {r.status === "pending" && (
                      <>
                        <button
                          type="button"
                          className="cfg-action-btn"
                          disabled={busyId !== null}
                          onClick={() => act("Approve", () => scaApproveRemediation(r.id))}
                        >
                          <Icon name="check" size={13} />
                          Approve
                        </button>
                        <button
                          type="button"
                          className="cfg-action-btn cfg-action-danger"
                          disabled={busyId !== null}
                          onClick={() => act("Reject", () => scaRejectRemediation(r.id))}
                        >
                          <Icon name="x" size={13} />
                          Reject
                        </button>
                      </>
                    )}
                    {r.status === "approved" && (
                      <button
                        type="button"
                        className="cfg-action-btn cfg-action-primary"
                        disabled={busyId !== null}
                        onClick={() => act("Execute", () => scaExecuteRemediation(r.id))}
                      >
                        <Icon name="play" size={13} />
                        Execute
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ScanHistoryTab({ scans }: { scans: WithDemo<ScaScansResult> | null }) {
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(10);
  const [statusFilter, setStatusFilter] = useState("");
  const [selected, setSelected] = useState<ScaScan | null>(null);

  const list = useAsync(
    () => scaScans(page, perPage, statusFilter || undefined),
    [page, perPage, statusFilter],
    60_000
  );

  const data = list.data ?? scans;
  const rows = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = data?.totalPages ?? 1;
  const startRow = total === 0 ? 0 : (page - 1) * perPage + 1;
  const endRow = Math.min(page * perPage, total);

  return (
    <div className="cfg-stack">
      <div className="cfg-card">
        <div className="cfg-checks-head">
          <div className="cfg-card-title">
            Scan History
            <DemoBadge demo={data?.demo ?? false} />
          </div>
          <select className="select cfg-run-select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="">All statuses</option>
            <option value="completed">Completed</option>
            <option value="running">Running</option>
            <option value="queued">Queued</option>
            <option value="failed">Failed</option>
          </select>
        </div>
        <div className="cfg-table-wrap">
          <table className="cfg-table">
            <thead>
              <tr>
                <th className="cfg-th-id">Scan</th>
                <th>Policy</th>
                <th>Agent</th>
                <th>Status</th>
                <th>Score</th>
                <th>Risk</th>
                <th>Passed</th>
                <th>Failed</th>
                <th>End</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.id} className={selected?.id === s.id ? "cfg-row-active" : ""}>
                  <td className="mono cfg-td-id">{s.id.slice(0, 8)}</td>
                  <td className="cfg-td-title">{s.policy}</td>
                  <td className="mono">{s.agent}</td>
                  <td>
                    <span className={`cfg-sev cfg-sev-${s.status === "completed" ? "ok" : s.status === "failed" ? "crit" : "warn"}`}>
                      {s.status}
                    </span>
                  </td>
                  <td className="mono">{s.status === "completed" ? `${s.score}%` : "—"}</td>
                  <td className="mono">{s.status === "completed" ? s.risk_score : "—"}</td>
                  <td className="mono cfg-inv-passed">{s.passed}</td>
                  <td className="mono cfg-inv-failed">{s.failed}</td>
                  <td className="mono">{formatScanTime(s.end_scan)}</td>
                  <td>
                    <button type="button" className="cfg-action-btn" onClick={() => setSelected(s)}>
                      <Icon name="eye" size={13} />
                      Results
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <ScaPager
          page={page}
          totalPages={totalPages}
          total={total}
          startRow={startRow}
          endRow={endRow}
          perPage={perPage}
          onPage={setPage}
          onPerPage={setPerPage}
        />
      </div>

      {selected && <ScanResultsPanel scan={selected} />}
      <RemediationQueue data={null} />
    </div>
  );
}

export default function ConfigurationAssessmentPage() {
  const [tab, setTab] = useState<Tab>("dashboard");

  const dashboard = useAsync(() => scaDashboard(), [], 60_000);
  const agents = useAsync(() => scaAgents(), [], 60_000);
  const events = useAsync(() => scaEvents(1, 15), [], 60_000);
  const drifts = useAsync(() => scaDrifts(1, 10), [], 60_000);
  const scans = useAsync(() => scaScans(1, 10), [], 60_000);

  return (
    <div className="soc-dash">
      <header className="cfg-header">
        <div className="cfg-breadcrumb">
          <span className="cfg-breadcrumb-link">Configuration Assessment</span>
          <Icon name="chevron" size={12} />
          <span className="cfg-breadcrumb-current">BEAM</span>
        </div>
        <div className="cfg-header-right">
          <DemoBadge demo={dashboard.data?.demo ?? agents.data?.demo ?? false} />
          <button type="button" className="cfg-beam-chip">
            <Icon name="alerting" size={14} />
            BEAM (001)
            <span className="cfg-beam-dot" />
          </button>
        </div>
      </header>

      <nav className="cfg-tabs">
        {TABS.map((t) => (
          <button
            type="button"
            key={t.id}
            className={`cfg-tab${tab === t.id ? " cfg-tab-active" : ""}`}
            onClick={() => setTab(t.id)}
          >
            <Icon name={t.icon as never} size={14} />
            {t.label}
          </button>
        ))}
      </nav>

      {tab === "dashboard" && <DashboardTab dashboard={dashboard.data} />}
      {tab === "inventory" && <InventoryTab agents={agents} />}
      {tab === "events" && <EventsTab events={events.data} drifts={drifts.data} />}
      {tab === "policies" && <PoliciesTab agents={agents} />}
      {tab === "history" && <ScanHistoryTab scans={scans.data} />}
    </div>
  );
}
