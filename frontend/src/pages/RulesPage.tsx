import { Fragment, useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { Rule } from "../api/types";
import { MitreTags, SeverityBadge, StatusBadge, TagList } from "../components/Badges";
import { formatDuration } from "../components/format";
import { Card, Empty, Spinner } from "../components/ui";

const SEVERITIES = ["critical", "high", "medium", "low", "informational"];

function RulesPage() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [severity, setSeverity] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await api.rules(severity || undefined);
      setRules(resp.items);
      setCounts(resp.counts);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load rules");
    } finally {
      setLoading(false);
    }
  }, [severity]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="grid grid-4">
        <div className="card kpi">
          <div className="kpi-label">Total rules</div>
          <div className="kpi-value" style={{ color: "var(--accent)" }}>{rules.length}</div>
          <div className="kpi-sub">loaded from detection config</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label">Correlation rules</div>
          <div className="kpi-value" style={{ color: "var(--cyan)" }}>{counts.correlation ?? 0}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label">Signature rules</div>
          <div className="kpi-value" style={{ color: "var(--green)" }}>{counts.signature ?? 0}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label">Critical</div>
          <div className="kpi-value" style={{ color: "var(--red)" }}>{counts.critical_count ?? 0}</div>
        </div>
      </div>

      <div className="card">
        <div className="toolbar" style={{ marginBottom: 0 }}>
          <select className="select" style={{ width: 180 }} value={severity} onChange={(e) => { setSeverity(e.target.value); setExpanded(null); }}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <span className="mono" style={{ color: "var(--text-dim)", marginLeft: "auto" }}>
            {rules.filter((r) => r.status === "active" || r.status === "enabled").length} active
          </span>
        </div>
      </div>

      <div className="card">
        {loading ? (
          <Spinner />
        ) : error ? (
          <Empty message={error} />
        ) : rules.length === 0 ? (
          <Empty message="No rules match the filter" />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Rule</th>
                <th>Status</th>
                <th>Type</th>
                <th>Threshold</th>
                <th>MITRE</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <Fragment key={r.id}>
                  <tr className="clickable" onClick={() => setExpanded(expanded === r.id ? null : r.id)}>
                    <td><SeverityBadge severity={r.severity} /></td>
                    <td style={{ maxWidth: 340 }}>
                      <div style={{ fontWeight: 600 }}>{r.title}</div>
                      <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)" }}>{r.id}</div>
                    </td>
                    <td><StatusBadge status={r.status} /></td>
                    <td className="mono" style={{ color: "var(--accent)" }}>{r.source ?? "correlation"}</td>
                    <td className="mono">{r.threshold}{r.timeframe_seconds ? ` / ${formatDuration(r.timeframe_seconds)}` : ""}</td>
                    <td><MitreTags mitre={r.mitre} /></td>
                  </tr>
                  {expanded === r.id && (
                    <tr>
                      <td colSpan={6}>
                        <div style={{ background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: 6, padding: 12 }}>
                          <div className="card-title">Description</div>
                          <div style={{ fontSize: 13, color: "var(--text-dim)", marginBottom: 10 }}>{r.description || "—"}</div>
                          <div className="card-title">Condition</div>
                          <pre className="mono" style={{ margin: 0, whiteSpace: "pre-wrap", fontSize: 12 }}>{r.condition}</pre>
                          {r.group_by ? (
                            <>
                              <div className="card-title" style={{ marginTop: 10 }}>Group by</div>
                              <div className="mono" style={{ fontSize: 12 }}>{r.group_by}</div>
                            </>
                          ) : null}
                          {r.logsource && Object.keys(r.logsource).length > 0 ? (
                            <>
                              <div className="card-title" style={{ marginTop: 10 }}>Log source</div>
                              <div className="mono" style={{ fontSize: 12 }}>
                                {Object.entries(r.logsource).map(([k, v]) => `${k}: ${v}`).join(" · ")}
                              </div>
                            </>
                          ) : null}
                          <div style={{ marginTop: 10 }}><TagList tags={r.tags} /></div>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export default RulesPage;
