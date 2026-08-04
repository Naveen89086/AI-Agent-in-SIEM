import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { Alert, Analysis } from "../api/types";
import { MitreTags, SeverityBadge, StatusBadge } from "../components/Badges";
import { formatTime } from "../components/format";
import { Card, Empty, Spinner } from "../components/ui";

const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
const STATUSES = ["open", "acknowledged", "resolved", "false_positive", "true_positive"];

function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await api.alerts({ status: status || undefined, severity: severity || undefined, offset, limit: 50 });
      setAlerts(resp.items);
      setTotal(resp.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load alerts");
    } finally {
      setLoading(false);
    }
  }, [severity, status, offset]);

  useEffect(() => {
    load();
  }, [load]);

  async function runAnalysis() {
    if (!selected) return;
    setAnalyzing(true);
    setAiError(null);
    setAnalysis(null);
    try {
      setAnalysis(await api.analyzeAlert(selected.id));
    } catch (err) {
      setAiError(err instanceof Error ? err.message : "AI analysis failed");
    } finally {
      setAnalyzing(false);
    }
  }

  async function changeStatus(id: string, newStatus: string) {
    try {
      const updated = await api.updateAlert(id, { status: newStatus });
      setAlerts((prev) => prev.map((a) => (a.id === id ? updated : a)));
      setSelected((prev) => (prev && prev.id === id ? updated : prev));
    } catch {
      /* ignore */
    }
  }

  const pageCount = Math.ceil(total / 50);

  return (
    <div style={{ display: "flex", gap: 16, height: "calc(100vh - 110px)" }}>
      <div style={{ flex: 3, display: "flex", flexDirection: "column", gap: 14, overflow: "hidden" }}>
        <div className="card">
          <div className="toolbar" style={{ marginBottom: 0 }}>
            <select className="select" style={{ width: 150 }} value={severity} onChange={(e) => { setSeverity(e.target.value); setOffset(0); }}>
              <option value="">All severities</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <select className="select" style={{ width: 170 }} value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }}>
              <option value="">All statuses</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <span className="mono" style={{ color: "var(--text-dim)", marginLeft: "auto" }}>
              {formatNumber(total)} alerts
            </span>
          </div>
        </div>

        <div className="card" style={{ flex: 1, overflow: "auto" }}>
          {loading ? (
            <Spinner />
          ) : error ? (
            <Empty message={error} />
          ) : alerts.length === 0 ? (
            <Empty message="No alerts match the current filters" />
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>Status</th>
                  <th>Count</th>
                  <th>MITRE</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr
                    key={a.id}
                    className="clickable"
                    style={selected?.id === a.id ? { background: "var(--bg-elevated)" } : undefined}
                    onClick={() => {
                      setSelected(a);
                      setAnalysis(null);
                      setAiError(null);
                    }}
                  >
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td style={{ maxWidth: 300 }}>
                      <div style={{ fontWeight: 600 }}>{a.rule_title}</div>
                      <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)" }}>{a.rule_id}</div>
                    </td>
                    <td>
                      <div>{<StatusBadge status={a.status} />}</div>
                      <select
                        className="select"
                        style={{ width: 120, marginTop: 4, fontSize: 12, padding: "2px 6px" }}
                        value={a.status}
                        onClick={(e) => e.stopPropagation()}
                        onChange={(e) => changeStatus(a.id, e.target.value)}
                      >
                        {STATUSES.map((s) => (
                          <option key={s} value={s}>{s}</option>
                        ))}
                      </select>
                    </td>
                    <td className="mono">{a.count}</td>
                    <td><MitreTags mitre={a.mitre} /></td>
                    <td className="mono" style={{ color: "var(--text-dim)", fontSize: 12 }}>{formatTime(a.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {pageCount > 1 && !loading && (
            <div style={{ display: "flex", gap: 8, justifyContent: "center", padding: 12 }}>
              <button className="btn btn-sm" disabled={offset === 0} onClick={() => setOffset((o) => Math.max(0, o - 50))}>
                Prev
              </button>
              <span className="mono" style={{ color: "var(--text-dim)", alignSelf: "center" }}>
                page {Math.floor(offset / 50) + 1} / {pageCount}
              </span>
              <button className="btn btn-sm" disabled={offset + 50 >= total} onClick={() => setOffset((o) => o + 50)}>
                Next
              </button>
            </div>
          )}
        </div>
      </div>

      <div style={{ flex: 2, overflow: "auto" }}>
        <Card title="AI Analysis">
          {!selected ? (
            <Empty message="Select an alert to analyze" />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: 15 }}>{selected.rule_title}</div>
                <div className="mono" style={{ fontSize: 12, color: "var(--text-faint)" }}>{selected.rule_id}</div>
                <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                  <SeverityBadge severity={selected.severity} />
                  <StatusBadge status={selected.status} />
                </div>
              </div>

              <button className="btn btn-primary btn-sm" style={{ alignSelf: "flex-start" }} onClick={runAnalysis} disabled={analyzing}>
                {analyzing ? <span className="spinner" /> : "▶"} Analyze with AI
              </button>

              {aiError ? <div className="error-banner">{aiError}</div> : null}

              {analysis ? (
                <div>
                  <div className="card-title">Findings</div>
                  <div style={{ whiteSpace: "pre-wrap", fontSize: 13, background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: 6, padding: 10 }}>
                    {analysis.analysis}
                  </div>
                  {analysis.risk_score != null ? (
                    <div style={{ marginTop: 10, display: "flex", gap: 14, flexWrap: "wrap" }}>
                      <span className="mono" style={{ color: "var(--red)" }}>Risk: {analysis.risk_score.toFixed(1)}</span>
                      {analysis.confidence != null ? (
                        <span className="mono" style={{ color: "var(--accent)" }}>Confidence: {analysis.confidence.toFixed(0)}%</span>
                      ) : null}
                      <span className="mono" style={{ color: "var(--text-faint)" }}>Provider: {analysis.provider}</span>
                    </div>
                  ) : null}
                  {analysis.mitre && analysis.mitre.length > 0 ? (
                    <div style={{ marginTop: 10 }}>
                      <div className="card-title">MITRE ATT&CK</div>
                      <MitreTags mitre={analysis.mitre} />
                    </div>
                  ) : null}
                  {analysis.recommended_actions && analysis.recommended_actions.length > 0 ? (
                    <div style={{ marginTop: 10 }}>
                      <div className="card-title">Recommended actions</div>
                      <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13 }}>
                        {analysis.recommended_actions.map((a, i) => (
                          <li key={i}>{a}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="loading" style={{ padding: 12 }}>
                  {analyzing ? "Running triage…" : "No analysis yet"}
                </div>
              )}

              {selected.description ? (
                <div>
                  <div className="card-title">Description</div>
                  <div style={{ fontSize: 13, color: "var(--text-dim)" }}>{selected.description}</div>
                </div>
              ) : null}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

export default AlertsPage;
