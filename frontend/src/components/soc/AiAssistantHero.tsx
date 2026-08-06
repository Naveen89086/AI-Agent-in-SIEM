import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import type { Alert, Analysis } from "../../api/types";
import { useAsync } from "../../hooks/useAsync";
import { SAMPLE_RECOMMENDED_ACTIONS } from "../../mocks/soc";
import { Icon } from "../icons";
import { severityRank } from "./severity";
import { Section } from "./Widget";

function pickTopAlert(alerts: Partial<Alert>[] | null): Partial<Alert> | null {
  if (!alerts || alerts.length === 0) return null;
  return [...alerts].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity)
  )[0];
}

function fallbackSummary(alert: Partial<Alert>): string {
  return (
    alert.description ??
    `The detector matched "${alert.rule_title}" ${alert.count ?? 1} time(s). The grouping suggests a coordinated event against the monitored assets.`
  );
}

export function AiAssistantHero() {
  const navigate = useNavigate();
  const alerts = useAsync(() => api.dashboardRecentAlerts(25), [], 30_000);
  const top = pickTopAlert(alerts.data);

  const analysis = useAsync<Analysis[]>(
    () => (top?.id ? api.analyses(top.id, 1) : Promise.resolve([])),
    [top?.id]
  );
  const first = analysis.data && analysis.data.length > 0 ? analysis.data[0] : null;

  const mitre = (first?.mitre?.[0] ?? top?.mitre?.[0] ?? null) as
    | { tactic?: string; technique?: string; technique_name?: string }
    | null;
  const assets = Array.isArray(top?.events)
    ? (top.events as Record<string, unknown>[])
        .map((e) => {
          const host = e?.host as Record<string, unknown> | undefined;
          const source = e?.source as Record<string, unknown> | undefined;
          return (host?.name as string) || (source?.ip as string);
        })
        .filter(Boolean)
        .slice(0, 4)
    : [];

  const confidence = first?.confidence ?? null;
  const risk = first?.risk_score ?? null;

  return (
    <Section icon="cpu" title="AI SOC Assistant" subtitle="Autonomous triage of your highest-priority incident">
      <div className="soc-hero">
        {alerts.status === "loading" ? (
          <div className="soc-state">
            <span className="spinner" />
            <span className="soc-state-text">Analyzing live telemetry…</span>
          </div>
        ) : alerts.status === "error" ? (
          <div className="soc-state soc-state-error">
            <Icon name="warn" size={18} />
            <span>{alerts.error}</span>
          </div>
        ) : !top ? (
          <div className="soc-state">
            <Icon name="shieldCheck" size={22} />
            <span className="soc-state-text">No active incidents — the environment is clear.</span>
          </div>
        ) : (
          <>
            <div className="soc-hero-main">
              <div className="soc-hero-tag">
                <span className={`sev-badge ${top.severity ?? "informational"}`}>{top.severity ?? "unknown"}</span>
                <span className="soc-hero-id mono">#{top.id?.slice(0, 13) ?? "—"}</span>
              </div>
              <h3 className="soc-hero-title">{top.rule_title ?? "Active incident"}</h3>
              <p className="soc-hero-summary">
                {analysis.status === "loading"
                  ? "Running AI triage…"
                  : first
                    ? first.analysis
                    : fallbackSummary(top)}
              </p>

              <div className="soc-hero-meta">
                {mitre ? (
                  <span className="soc-hero-chip">
                    <Icon name="target" size={13} />
                    {mitre.tactic ? `${mitre.tactic} · ` : ""}
                    {mitre.technique ? `T${mitre.technique}` : ""}
                    {mitre.technique && mitre.technique_name ? ` · ${mitre.technique_name}` : ""}
                  </span>
                ) : null}
                <span className="soc-hero-chip">
                  <Icon name="clock" size={13} />
                  last seen {top.last_seen_at ? new Date(top.last_seen_at).toLocaleString() : "—"}
                </span>
              </div>

              {assets.length > 0 ? (
                <div className="soc-hero-assets">
                  <span className="soc-hero-assets-label">Affected assets:</span>
                  {assets.map((asset, i) => (
                    <span key={i} className="soc-hero-chip mono">
                      {asset}
                    </span>
                  ))}
                </div>
              ) : null}

              <div className="soc-hero-actions">
                <button className="btn btn-primary" onClick={() => navigate("/alerts")}>
                  <Icon name="search" size={14} /> Investigate
                </button>
                <button className="btn" onClick={() => navigate("/cases")}>
                  <Icon name="file" size={14} /> Open Case
                </button>
                <button className="btn" onClick={() => navigate("/soar")}>
                  <Icon name="zap" size={14} /> Run SOAR
                </button>
              </div>
            </div>

            <div className="soc-hero-side">
              <div className="soc-hero-score">
                <div className="soc-hero-score-label">AI Confidence</div>
                <div className="soc-hero-score-value">{confidence != null ? `${Math.round(confidence)}%` : "—"}</div>
                <div className="soc-hero-score-bar">
                  <div
                    className={`soc-hero-score-fill${confidence != null && confidence >= 70 ? " is-high" : ""}`}
                    style={{ width: `${confidence ?? 0}%` }}
                  />
                </div>
              </div>
              <div className="soc-hero-score">
                <div className="soc-hero-score-label">Risk Score</div>
                <div className="soc-hero-score-value soc-hero-score-risk">
                  {risk != null ? risk.toFixed(1) : "—"}
                </div>
              </div>

              {first?.recommended_actions && first.recommended_actions.length > 0 ? (
                <div className="soc-hero-recs">
                  <div className="soc-hero-recs-title">
                    <Icon name="check" size={13} /> Recommended actions
                  </div>
                  <ul>
                    {first.recommended_actions.map((action, i) => (
                      <li key={i}>{action}</li>
                    ))}
                  </ul>
                </div>
              ) : (
                <div className="soc-hero-recs">
                  <div className="soc-hero-recs-title">
                    <Icon name="check" size={13} /> Recommended actions
                  </div>
                  <ul>
                    {SAMPLE_RECOMMENDED_ACTIONS.map((action, i) => (
                      <li key={i}>{action}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </Section>
  );
}
