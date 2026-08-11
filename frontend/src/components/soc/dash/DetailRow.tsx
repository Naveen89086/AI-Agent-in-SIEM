import { DashPanel, MultiArea, StatusPill } from "./primitives";
import {
  formatInt,
  type FimState,
  type NetworkConnRow,
  type Posture,
  type PostureTone,
  type UserLogin,
} from "./dashData";

export function NetworkConnectionsPanel({ rows }: { rows: NetworkConnRow[] }) {
  const blocked = rows.filter((r) => r.state === "BLOCKED").length;
  return (
    <DashPanel
      title="Network Connections"
      icon="network"
      badge={<span className="dash-chip dash-chip-crit">{blocked} BLOCKED</span>}
    >
      <div className="dash-table-wrap">
        <table className="dash-table">
          <thead>
            <tr>
              <th>Remote IP</th>
              <th>Dest Port</th>
              <th>Connection State</th>
              <th>Notes</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className={r.state === "BLOCKED" ? "dash-row-block" : "dash-row-allow"}>
                <td className="mono">{r.remote}</td>
                <td className="mono">{r.destPort}</td>
                <td>
                  <StatusPill
                    text={r.state}
                    tone={r.state === "BLOCKED" ? "crit" : "ok"}
                  />
                </td>
                <td className="dash-tbl-notes">{r.notes}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </DashPanel>
  );
}

export function FimPanel({ fim }: { fim: FimState }) {
  return (
    <DashPanel title="File Integrity Monitoring" icon="fileSearch">
      <div className="dash-fim">
        <div className="dash-fim-head">
          <span className="dash-fim-head-l">FILES MONITORED</span>
          <span className="dash-fim-head-v">{formatInt(fim.monitored)}</span>
        </div>
        <div className="dash-fim-list">
          <div className="dash-fim-row">
            <span className="dash-fim-l">Modified</span>
            <span className="dash-fim-v" style={{ color: "var(--amber)" }}>{fim.modified}</span>
          </div>
          <div className="dash-fim-row">
            <span className="dash-fim-l">Created</span>
            <span className="dash-fim-v" style={{ color: "var(--teal)" }}>{fim.created}</span>
          </div>
          <div className="dash-fim-row">
            <span className="dash-fim-l">Deleted</span>
            <span className="dash-fim-v" style={{ color: "var(--red)" }}>{fim.deleted}</span>
          </div>
          <div className="dash-fim-row">
            <span className="dash-fim-l">Critical Changes</span>
            <span className="dash-fim-chip">{fim.critical}</span>
          </div>
        </div>
        <div className="dash-fim-trend">
          <span className="dash-perf-label">FILE CHANGES · LAST 24H</span>
          <MultiArea
            series={[
              { data: fim.modifiedTrend, color: "var(--amber)" },
              { data: fim.createdTrend, color: "var(--teal)" },
              { data: fim.deletedTrend, color: "var(--red)" },
            ]}
            height={38}
          />
        </div>
      </div>
    </DashPanel>
  );
}

function toneColor(tone: PostureTone): string {
  if (tone === "ok") return "var(--green)";
  if (tone === "warn") return "var(--amber)";
  if (tone === "crit") return "var(--red)";
  return "var(--cyan)";
}

export function SecurityPosturePanel({ posture, demo = false }: { posture: Posture; demo?: boolean }) {
  return (
    <DashPanel
      title="Security Posture"
      icon="shieldCheck"
      badge={
        <span className="dash-posture-badge">
          {demo ? <span className="dash-chip dash-chip-demo">Demo</span> : null}
          <StatusPill text={posture.overall} tone="ok" />
        </span>
      }
    >
      <div className="dash-posture">
        <div className="dash-posture-list">
          {posture.rows.map((r) => (
            <div key={r.label} className="dash-posture-row">
              <span className="dash-posture-dot" style={{ background: toneColor(r.tone) }} />
              <span className="dash-posture-label">{r.label}</span>
              <span className="dash-posture-value">{r.value}</span>
            </div>
          ))}
        </div>
      </div>
    </DashPanel>
  );
}

export function UserLoginPanel({ login }: { login: UserLogin }) {
  return (
    <DashPanel
      title="User & Login Activity"
      icon="userCog"
      badge={
        <span className="dash-login-badge">
          <span className="dash-login-failed-badge">{login.failed}</span>
          <span className="dash-login-failed-l">FAILED</span>
        </span>
      }
    >
      <div className="dash-login">
        <div className="dash-login-user">
          <span className="dash-login-name" title={login.user}>
            {login.user}
          </span>
        </div>
        <div className="dash-login-row">
          <span className="dash-login-l">Last Login</span>
          <span className="mono dash-login-v">{login.lastLogin}</span>
        </div>
        <div className="dash-login-row">
          <span className="dash-login-l">Status</span>
          <StatusPill text={login.outcome} tone={login.outcome === "SUCCESS" ? "ok" : "crit"} />
        </div>
        <div className="dash-login-row">
          <span className="dash-login-l">Source IP</span>
          <span className="mono dash-login-src-v">{login.source}</span>
        </div>
      </div>
    </DashPanel>
  );
}
