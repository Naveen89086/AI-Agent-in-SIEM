import { useEffect, useState } from "react";
import { Icon } from "../components/icons";
import { useAsync } from "../hooks/useAsync";
import {
  huntDefinitions,
  huntQueries,
  huntQueryResults,
  huntRun,
  huntAnalyze,
  type HuntDefinition,
  type HuntMatchRow,
  type HuntQuery,
  type IocPageResult,
} from "../api/endpoint";

type Tab = "definitions" | "history";

const TABS: { id: Tab; label: string }[] = [
  { id: "definitions", label: "Hunt Definitions" },
  { id: "history", label: "Hunt History" },
];

function Sev({ sev }: { sev?: string }) {
  const s = (sev ?? "").toLowerCase();
  const cls =
    s === "critical"
      ? "thi-sev-critical"
      : s === "high"
        ? "thi-sev-high"
        : s === "medium"
          ? "thi-sev-medium"
          : "thi-sev-low";
  return <span className={cls}>{sev ?? "unknown"}</span>;
}

function formatWhen(iso?: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function DefinitionsTab() {
  const defs = useAsync<HuntDefinition[]>(() => huntDefinitions(), [], 60_000);
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(id: string) {
    setRunning(id);
    setError(null);
    try {
      await huntRun(id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(null);
    }
  }

  return (
    <div className="thi-body">
      {error ? (
        <div className="thi-state thi-state-error">
          <Icon name="warn" size={16} />
          <span>{error}</span>
        </div>
      ) : null}
      <div className="thi-def-grid">
        {(defs.data ?? []).map((d) => (
          <div className="thi-def-card" key={d.id}>
            <div className="thi-def-title">{d.name}</div>
            <div className="thi-def-desc">{d.description}</div>
            <div className="thi-def-meta">
              <span className="thi-tag">{d.category}</span>
              <Sev sev={d.severity} />
              {d.tactic ? <span className="thi-tag">{d.tactic}</span> : null}
              {d.technique ? <span className="thi-tag">{d.technique}</span> : null}
            </div>
            <div className="thi-def-desc">
              {(d.queries ?? []).length} query{(d.queries ?? []).length === 1 ? "" : "ies"}
            </div>
            <button
              type="button"
              className="thi-btn thi-btn-accent"
              onClick={() => run(d.id)}
              disabled={running !== null}
            >
              <Icon name="play" size={14} />
              {running === d.id ? "Running…" : "Run hunt"}
            </button>
          </div>
        ))}
        {!defs.data?.length && defs.status === "success" ? (
          <div className="thi-state">
            <Icon name="crosshair" size={16} />
            <span>No hunt definitions available</span>
          </div>
        ) : null}
      </div>
      {defs.status === "loading" ? (
        <div className="thi-state">
          <span className="spinner" />
          <span>Loading hunt definitions…</span>
        </div>
      ) : null}
    </div>
  );
}

function HistoryTab() {
  const [page, setPage] = useState(1);
  const queries = useAsync<IocPageResult<HuntQuery>>(
    () => huntQueries(page, 10),
    [page],
    60_000
  );
  const [detail, setDetail] = useState<HuntQuery | null>(null);
  const [results, setResults] = useState<HuntMatchRow[] | null>(null);
  const [resultErr, setResultErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const rows = queries.data?.items ?? [];

  async function open(query: HuntQuery) {
    setDetail(query);
    setResults(null);
    setResultErr(null);
    try {
      const res = await huntQueryResults(query.id, 1, 100);
      setResults(res.items ?? []);
    } catch (err) {
      setResultErr(err instanceof Error ? err.message : String(err));
    }
  }

  async function analyze(id: string) {
    setBusy(id);
    try {
      const updated = await huntAnalyze(id, true);
      if (detail?.id === id) setDetail(updated);
      queries.reload();
    } catch (err) {
      setResultErr(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  const analysis = detail?.analysis as Record<string, unknown> | null | undefined;

  return (
    <div className="thi-body">
      <div className="thi-table-wrap">
        <table className="thi-table">
          <thead>
            <tr>
              <th>Hunt</th>
              <th>Status</th>
              <th>Matched</th>
              <th>Critical</th>
              <th>High</th>
              <th>Medium</th>
              <th>Low</th>
              <th>Started</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((q) => (
              <tr key={q.id} onClick={() => open(q)} style={{ cursor: "pointer" }}>
                <td>
                  <div style={{ fontWeight: 600 }}>{q.name}</div>
                  <div style={{ color: "var(--thi-muted)" }}>{q.hunt_id}</div>
                </td>
                <td>
                  <Verdict verdict={q.status} />
                </td>
                <td>{q.matched}</td>
                <td>{q.critical}</td>
                <td>{q.high}</td>
                <td>{q.medium}</td>
                <td>{q.low}</td>
                <td>{formatWhen(q.created_at)}</td>
                <td>
                  <button
                    type="button"
                    className="thi-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      analyze(q.id);
                    }}
                    disabled={busy !== null}
                    title="Run AI analysis"
                  >
                    <Icon name="sparkles" size={14} />
                    {busy === q.id ? "Analyzing…" : "Analyze"}
                  </button>
                </td>
              </tr>
            ))}
            {!rows.length && queries.status === "success" ? (
              <tr>
                <td colSpan={9}>
                  <div className="thi-state">
                    <Icon name="crosshair" size={16} />
                    <span>No hunts executed yet — run one from the Definitions tab</span>
                  </div>
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      <div className="thi-footer">
        <span>{queries.data?.total ?? 0} hunts</span>
        <Pager
          page={page}
          pages={Math.ceil((queries.data?.total ?? 0) / 10)}
          onPage={setPage}
        />
      </div>

      {detail ? (
        <div className="thi-card">
          <div className="thi-card-title">
            <Icon name="clipboard" size={15} />
            {detail.name} — results &amp; analysis
          </div>
          <div className="thi-card-body">
            {analysis ? (
              <div className="thi-analysis">
                {String(
                  analysis.summary ?? analysis.analysis ?? JSON.stringify(analysis, null, 2)
                )}
              </div>
            ) : (
              <div className="thi-state">
                <span className="spinner" />
                <span>
                  No analysis yet — click Analyze in the row above to run the AI analyst.
                </span>
              </div>
            )}

            {resultErr ? (
              <div className="thi-state thi-state-error">
                <Icon name="warn" size={16} />
                <span>{resultErr}</span>
              </div>
            ) : null}

            {results ? (
              <div className="thi-table-wrap" style={{ marginTop: 12 }}>
                <table className="thi-table">
                  <thead>
                    <tr>
                      <th>Matched</th>
                      <th>Value</th>
                      <th>Type</th>
                      <th>Verdict</th>
                      <th>Severity</th>
                      <th>Confidence</th>
                      <th>Reasons</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((m) => (
                      <tr key={m.id}>
                        <td>{formatWhen(m.matched_at)}</td>
                        <td className="thi-mono">{m.value}</td>
                        <td>{m.observation_type}</td>
                        <td>
                          <Verdict verdict={m.verdict} />
                        </td>
                        <td>
                          <Sev sev={m.severity} />
                        </td>
                        <td>{m.confidence}</td>
                        <td>
                          {(m.reasons ?? []).map((r, i) => (
                            <span className="thi-tag" key={i}>
                              {r}
                            </span>
                          ))}
                        </td>
                      </tr>
                    ))}
                    {!results.length ? (
                      <tr>
                        <td colSpan={7}>
                          <div className="thi-state">
                            <Icon name="search" size={16} />
                            <span>No matches found</span>
                          </div>
                        </td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function Verdict({ verdict }: { verdict?: string }) {
  const v = (verdict ?? "").toLowerCase();
  const cls =
    v === "completed" || v === "success" || v === "running"
      ? "thi-verdict-benign"
      : v === "failed" || v === "error"
        ? "thi-verdict-malicious"
        : "thi-verdict-unknown";
  return <span className={`thi-verdict ${cls}`}>{verdict ?? "-"}</span>;
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

export default function ThreatHuntingPage() {
  const [tab, setTab] = useState<Tab>("definitions");
  useEffect(() => {
    setTab("definitions");
  }, []);

  return (
    <div className="thi-page">
      <header className="thi-header">
        <div className="thi-breadcrumb">
          <span className="thi-breadcrumb-current">Threat Intelligence</span>
          <Icon name="chevron" size={12} />
          <span className="thi-breadcrumb-page">Threat Hunting</span>
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

      {tab === "definitions" && <DefinitionsTab />}
      {tab === "history" && <HistoryTab />}
    </div>
  );
}
