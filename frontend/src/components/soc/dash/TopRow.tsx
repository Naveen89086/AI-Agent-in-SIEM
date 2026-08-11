import { DashPanel, RadialNeedle, StatusPill } from "./primitives";
import { riskLabel, type EndpointInfo, type RiskBreakdownSegment } from "./dashData";

function WindowsGlyph({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 88 88" aria-hidden="true" className="dash-win-logo">
      <path fill="#2F80ED" opacity="0.55" d="M0 12.4 36 7v34.8H0z" />
      <path fill="#35C6E8" opacity="0.45" d="M40 6 88 0v39.8H40z" />
      <path fill="#8FA6BF" opacity="0.6" d="M0 46.2h36V81L0 75.6z" />
      <path fill="#607891" opacity="0.55" d="M40 46.2h48V88L40 82z" />
    </svg>
  );
}

export function EndpointPanel({ agent }: { agent: EndpointInfo | null }) {
  const name = agent?.name ?? "BEAM";
  const os = agent?.os ?? "Windows 11 Enterprise";
  const online = agent ? ["online", "active"].includes(agent.status) : true;
  const code = agent?.code ?? "001";

  return (
    <DashPanel
      title="Endpoint"
      icon="monitor"
      badge={<StatusPill text="Online" tone={online ? "ok" : "crit"} />}
    >
      <div className="dash-endpoint">
        <div className="dash-endpoint-main">
          <span className="dash-endpoint-shield">
            <span className="dash-online-dot" />
          </span>
          <div className="dash-endpoint-id">
            <span className="dash-brand">CyberSentry AI</span>
            <span className="dash-endpoint-agent">{name}</span>
          </div>
          <span className="dash-endpoint-os-glyph">
            <WindowsGlyph />
          </span>
        </div>
        <div className="dash-endpoint-meta">
          <span>{os} · AGENT {code}</span>
        </div>
        <div className="dash-endpoint-foot">
          <span className="dash-online">
            <i /> ONLINE
          </span>
          <span className="dash-hb">Last heartbeat: 5 sec ago</span>
        </div>
      </div>
    </DashPanel>
  );
}

export function RiskScorePanel({ score }: { score: number }) {
  const label = riskLabel(score);
  const tone = label === "LOW" ? "ok" : label === "MEDIUM" ? "warn" : "crit";
  return (
    <DashPanel title="Risk Score" icon="gauge" badge={<StatusPill text={label} tone={tone} />}>
      <div className="dash-risk">
        <RadialNeedle value={score} max={100} bands={[{ to: 1, color: "var(--amber)" }]} />
        <div className="dash-risk-bracket">
          <span>[ {label} ]</span>
        </div>
      </div>
    </DashPanel>
  );
}

export function RiskBreakdownPanel({ segments }: { segments: RiskBreakdownSegment[] }) {
  return (
    <DashPanel title="Risk Breakdown" icon="layers">
      <div className="dash-risk-bd">
        {segments.map((s) => (
          <div key={s.label} className="dash-risk-bd-row">
            <span className="dash-risk-bd-label" style={{ color: s.color }}>
              [ {s.label.toUpperCase()} ]
            </span>
            <span className="dash-risk-bd-value">{s.value}</span>
          </div>
        ))}
      </div>
    </DashPanel>
  );
}
