import { useEffect, useState } from "react";
import { Icon } from "../components/icons";
import { useAsync } from "../hooks/useAsync";
import {
  iocAgents,
  iocDashboard,
  iocIndicators,
  iocLookup,
  iocMatches,
  type IocAgentRow,
  type IocIndicatorRow,
  type IocLookupResult,
  type IocMatchRow,
  type IocPageResult,
  type WithDemo,
} from "../api/endpoint";

type Tab = "dashboard" | "lookup" | "indicators" | "matches";

const TABS: { id: Tab; label: string }[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "lookup", label: "Lookup" },
  { id: "indicators", label: "Indicators" },
  { id: "matches", label: "Matches & Observations" },
];

const LOOKUP_TYPES = [
  "ipv4",
  "ipv6",
  "domain",
  "url",
  "filehash",
  "email",
  "registry",
];

function verdictClass(verdict?: string): string {
  switch (verdict) {
    case "malicious":
      return "thi-verdict-malicious";
    case "suspicious":
      return "thi-verdict-suspicious";
    case "benign":
      return "thi-verdict-benign";
    default:
      return "thi-verdict-unknown";
  }
}

function Verdict({ verdict }: { verdict?: string }) {
  return (
    <span className={`thi-verdict ${verdictClass(verdict)}`}>
      {verdict ?? "unknown"}
    </span>
  );
}

function confidence(v: number | null | undefined): number {
  const n = Number(v);
  return Number.isFinite(n) ? Math.round(n * 100) / 100 : 0;
}

function Kpi({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone?: "ok" | "bad";
}) {
  return (
    <div className="thi-kpi">
      <span className="thi-kpi-label">{label}</span>
      <span className={`thi-kpi-value${tone ? ` ${tone}` : ""}`}>{value}</span>
    </div>
  );
}

function TypeBars({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data ?? {}).filter(([, n]) => n > 0);
  if (!entries.length) {
    return (
      <div className="thi-state">
        <Icon name="search" size={16} />
        <span>No indicators yet</span>
      </div>
    );
  }
  const max = Math.max(...entries.map(([, n]) => n));
  return (
    <div>
      {entries.map(([type, n]) => (
        <div className="thi-bar" key={type}>
          <span className="thi-bar-label">{type}</span>
          <div className="thi-bar-track">
            <div
              className="thi-bar-fill"
              style={{ width: `${max ? Math.max((n / max) * 100, 4) : 0}%` }}
            />
          </div>
          <span className="thi-bar-value">{n}</span>
        </div>
      ))}
    </div>
  );
}

function VerdictBars({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data ?? {}).filter(([, n]) => n > 0);
  if (!entries.length) {
    return (
      <div className="thi-state">
        <Icon name="search" size={16} />
        <span>No verdicts yet</span>
      </div>
    );
  }
  const max = Math.max(...entries.map(([, n]) => n));
  return (
    <div>
      {entries.map(([verdict, n]) => (
        <div className="thi-bar" key={verdict}>
          <span className="thi-bar-label">{verdict}</span>
          <div className="thi-bar-track">
            <div
              className="thi-bar-fill"
              style={{ width: `${max ? Math.max((n / max) * 100, 4) : 0}%` }}
            />
          </div>
          <span className="thi-bar-value">{n}</span>
        </div>
      ))}
    </div>
  );
}

function DashboardTab({ demo }: { demo: boolean }) {
  const dash = useAsync(() => iocDashboard(), [], 60_000);
  const data = dash.data;

  return (
    <div className="thi-body">
      {demo ? (
        <div className="thi-state">
          <Icon name="warn" size={16} />
          <span>
            IOC service is in demo mode (no real endpoint agent registered yet).
          </span>
        </div>
      ) : null}
      <div className="thi-kpi-row">
        <Kpi label="Agents" value={data?.agents_total ?? 0} />
        <Kpi label="Indicators" value={data?.indicators_total ?? 0} />
        <Kpi label="Observations" value={data?.observations_total ?? 0} />
        <Kpi label="Matches" value={data?.matches_total ?? 0} />
      </div>
      <div className="thi-grid">
        <div className="thi-card">
          <div className="thi-card-title">
            <Icon name="target" size={15} />
            Indicators by type
          </div>
          <div className="thi-card-body">
            <TypeBars data={data?.indicators_by_type ?? {}} />
          </div>
        </div>
        <div className="thi-card">
          <div className="thi-card-title">
            <Icon name="octagon" size={15} />
            Matches by verdict
          </div>
          <div className="thi-card-body">
            <VerdictBars data={data?.matches_verdicts ?? {}} />
          </div>
        </div>
      </div>
      {dash.status === "loading" ? (
        <div className="thi-state">
          <span className="spinner" />
          <span>Loading dashboard…</span>
        </div>
      ) : null}
      {dash.status === "error" ? (
        <div className="thi-state thi-state-error">
          <Icon name="warn" size={16} />
          <span>{dash.error}</span>
        </div>
      ) : null}
    </div>
  );
}

function LookupTab() {
  const [type, setType] = useState("ipv4");
  const [value, setValue] = useState("");
  const [result, setResult] = useState<IocLookupResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    const v = value.trim();
    if (!v) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const res = await iocLookup(type, v);
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="thi-body">
      <div className="thi-card">
        <div className="thi-card-title">
          <Icon name="search" size={15} />
          Indicator lookup
        </div>
        <div className="thi-card-body">
          <div className="thi-lookup-form">
            <select
              className="thi-select"
              value={type}
              onChange={(e) => setType(e.target.value)}
              aria-label="Indicator type"
            >
              {LOOKUP_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <input
              className="thi-input"
              placeholder="e.g. 45.83.193.105"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") run();
              }}
            />
            <button
              type="button"
              className="thi-btn thi-btn-accent"
              onClick={run}
              disabled={busy || !value.trim()}
            >
              <Icon name="search" size={14} />
              {busy ? "Looking up…" : "Lookup"}
            </button>
          </div>
        </div>
      </div>

      {error ? (
        <div className="thi-state thi-state-error">
          <Icon name="warn" size={16} />
          <span>{error}</span>
        </div>
      ) : null}

      {result ? (
        <div className="thi-card">
          <div className="thi-card-body">
            <div className="thi-grid">
              <div>
                <span className="thi-kpi-label">Value</span>
                <div className="thi-mono" style={{ fontSize: 14, marginTop: 4 }}>
                  {result.value}
                </div>
                <span className="thi-kpi-label" style={{ display: "block", marginTop: 10 }}>
                  Type
                </span>
                <div className="thi-tag" style={{ marginTop: 4 }}>
                  {result.indicator_type}
                </div>
              </div>
              <div>
                <span className="thi-kpi-label">Verdict</span>
                <div style={{ marginTop: 6 }}>
                  <Verdict verdict={result.verdict} />
                </div>
                <span className="thi-kpi-label" style={{ display: "block", marginTop: 10 }}>
                  Confidence
                </span>
                <div style={{ fontSize: 18, fontWeight: 700, marginTop: 2 }}>
                  {confidence(result.confidence)}
                </div>
              </div>
            </div>

            {(result.reasons ?? []).length ? (
              <>
                <div className="thi-kpi-label" style={{ marginTop: 14 }}>
                  Reasons
                </div>
                <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                  {(result.reasons ?? []).map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </>
            ) : null}
          </div>
        </div>
      ) : null}

      {result && (result.matches ?? []).length ? (
        <div className="thi-table-wrap">
          <table className="thi-table">
            <thead>
              <tr>
                <th>Indicator</th>
                <th>Type</th>
                <th>Verdict</th>
                <th>Confidence</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {(result.matches ?? []).map((m: IocIndicatorRow) => (
                <tr key={m.id}>
                  <td className="thi-mono">{m.value}</td>
                  <td>{m.indicator_type}</td>
                  <td>
                    <Verdict verdict={m.verdict} />
                  </td>
                  <td>{confidence(m.confidence)}</td>
                  <td>{m.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

function Pager({
  page,
  pages,
  onPage,
}: {
  page: number;
  pages: number;
  onPage: (p: number) => void;
}) {
  return (
    <div className="thi-pagination">
      <button
        type="button"
        className="thi-btn"
        disabled={page <= 1}
        onClick={() => onPage(page - 1)}
      >
        Prev
      </button>
      <span>
        Page {page} of {Math.max(pages, 1)}
      </span>
      <button
        type="button"
        className="thi-btn"
        disabled={page >= pages}
        onClick={() => onPage(page + 1)}
      >
        Next
      </button>
    </div>
  );
}

function IndicatorsTab() {
  const [page, setPage] = useState(1);
  const [typeFilter, setTypeFilter] = useState("");
  const [search, setSearch] = useState("");
  const result = useAsync<IocPageResult<IocIndicatorRow>>(
    () => iocIndicators(page, 20, typeFilter || undefined, search),
    [page, typeFilter, search],
    60_000
  );
  const rows = result.data?.items ?? [];
  const total = result.data?.total ?? 0;

  return (
    <div className="thi-body">
      <div className="thi-lookup-form">
        <select
          className="thi-select"
          value={typeFilter}
          onChange={(e) => {
            setTypeFilter(e.target.value);
            setPage(1);
          }}
          aria-label="Filter by type"
        >
          <option value="">All types</option>
          {LOOKUP_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <input
          className="thi-input"
          placeholder="Search indicators…"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
        />
      </div>

      <div className="thi-table-wrap">
        <table className="thi-table">
          <thead>
            <tr>
              <th>Indicator</th>
              <th>Type</th>
              <th>Verdict</th>
              <th>Confidence</th>
              <th>Source</th>
              <th>Tags</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="thi-mono">{r.value}</td>
                <td>{r.indicator_type}</td>
                <td>
                  <Verdict verdict={r.verdict} />
                </td>
                <td>{confidence(r.confidence)}</td>
                <td>{r.source}</td>
                <td>
                  {(r.tags ?? []).map((t) => (
                    <span className="thi-tag" key={t}>
                      {t}
                    </span>
                  ))}
                </td>
              </tr>
            ))}
            {!rows.length && result.status === "success" ? (
              <tr>
                <td colSpan={6}>
                  <div className="thi-state">
                    <Icon name="search" size={16} />
                    <span>No indicators found</span>
                  </div>
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      <div className="thi-footer">
        <span>{total} indicators</span>
        <Pager page={page} pages={Math.ceil(total / 20)} onPage={setPage} />
      </div>
    </div>
  );
}

function MatchesTab() {
  const [page, setPage] = useState(1);
  const [verdict, setVerdict] = useState("");
  const matches = useAsync<IocPageResult<IocMatchRow>>(
    () => iocMatches(page, 20, verdict || undefined),
    [page, verdict],
    60_000
  );

  return (
    <div className="thi-body">
      <div className="thi-lookup-form">
        <select
          className="thi-select"
          value={verdict}
          onChange={(e) => {
            setVerdict(e.target.value);
            setPage(1);
          }}
          aria-label="Filter by verdict"
        >
          <option value="">All verdicts</option>
          <option value="malicious">malicious</option>
          <option value="suspicious">suspicious</option>
          <option value="unknown">unknown</option>
          <option value="benign">benign</option>
        </select>
      </div>

      <div className="thi-card">
        <div className="thi-card-title">
          <Icon name="activity" size={15} />
          Recent observations &amp; matches
        </div>
        <div className="thi-table-wrap" style={{ border: "none" }}>
          <table className="thi-table">
            <thead>
              <tr>
                <th>Observed</th>
                <th>Value</th>
                <th>Type</th>
                <th>Verdict</th>
                <th>Confidence</th>
                <th>Agent</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {(matches.data?.items ?? []).map((r) => {
                const row = r as Record<string, unknown>;
                return (
                  <tr key={String(row.id)}>
                    <td>{String(row.matched_at ?? row.observed_at ?? "")}</td>
                    <td className="thi-mono">{String(row.value ?? "")}</td>
                    <td>{String(row.indicator_type ?? row.observation_type ?? "")}</td>
                    <td>
                      <Verdict verdict={String(row.verdict ?? "")} />
                    </td>
                    <td>{confidence(Number(row.confidence))}</td>
                    <td>{String(row.agent_code ?? "-")}</td>
                    <td>{String(row.source_label ?? "-")}</td>
                  </tr>
                );
              })}
              {!matches.data?.items?.length && matches.status === "success" ? (
                <tr>
                  <td colSpan={7}>
                    <div className="thi-state">
                      <Icon name="search" size={16} />
                      <span>No observations yet — register an IOC agent and ingest data</span>
                    </div>
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>

      <div className="thi-footer">
        <span>{matches.data?.total ?? 0} observations</span>
        <Pager
          page={page}
          pages={Math.ceil((matches.data?.total ?? 0) / 20)}
          onPage={setPage}
        />
      </div>
    </div>
  );
}

export default function IocLookupPage() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const agents = useAsync<WithDemo<IocAgentRow[]>>(() => iocAgents(), [], 60_000);

  const agent = (agents.data ?? []).find((a) => !a.demo);
  const demo = agents.data?.demo === true || !agent;

  return (
    <div className="thi-page">
      <header className="thi-header">
        <div className="thi-breadcrumb">
          <span className="thi-breadcrumb-current">Threat Intelligence</span>
          <Icon name="chevron" size={12} />
          <span className="thi-breadcrumb-page">IOC Lookup</span>
        </div>
        <div className="thi-header-actions">
          {demo ? (
            <span className="thi-demo-badge" title="No real IOC agent registered yet">
              Demo data
            </span>
          ) : null}
          {agent ? (
            <span className="thi-agent-chip">
              <Icon name="radio" size={14} />
              {String(agent.name ?? agent.code)} ({agent.code})
            </span>
          ) : null}
        </div>
      </header>

      <nav className="thi-tabs">
        {TABS.map((t) => (
          <button
            type="button"
            key={t.id}
            className={`thi-tab${tab === t.id ? " thi-tab-active" : ""}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {tab === "dashboard" && <DashboardTab demo={demo} />}
      {tab === "lookup" && <LookupTab />}
      {tab === "indicators" && <IndicatorsTab />}
      {tab === "matches" && <MatchesTab />}
    </div>
  );
}
