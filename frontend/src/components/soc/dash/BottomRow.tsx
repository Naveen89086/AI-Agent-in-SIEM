import type { CSSProperties } from "react";
import { DashPanel, StatusPill } from "./primitives";
import { TIMELINE_TYPES, type SeverityCount, type TimelineEvent } from "./dashData";

export function SeverityCards({ counts }: { counts: SeverityCount[] }) {
  return (
    <div className="dash-sev-cards">
      {counts.map((c) => (
        <div key={c.severity} className={`dash-sev-card dash-sev-card-${c.severity}`}>
          <span className="dash-sev-card-label">{c.severity}</span>
          <span className="dash-sev-card-value">{c.count}</span>
          <span className="dash-sev-card-sub">{c.desc}</span>
        </div>
      ))}
    </div>
  );
}

export function SecurityAlertsPanel({ counts }: { counts: SeverityCount[] }) {
  const total = counts.reduce((n, c) => n + c.count, 0);
  return (
    <DashPanel title="Security Alerts — Last 24 Hours" icon="alert" badge={<StatusPill text={String(total)} tone="warn" />}>
      <SeverityCards counts={counts} />
    </DashPanel>
  );
}

const HOURS = Array.from({ length: 25 }, (_, i) => i);

export function SecurityActivityPanel({ items }: { items: TimelineEvent[] }) {
  return (
    <DashPanel
      title="Security Activity — Last 24 Hours"
      icon="activity"
      badge={<StatusPill text="Live" tone="ok" />}
    >
      <div className="dash-timeline">
        <div className="dash-timeline-head">
          <span className="dash-timeline-head-l">NOW → 24H</span>
          <span className="dash-timeline-head-r">{items.length} EVENTS</span>
        </div>
        <div className="dash-timeline-track">
          <span className="dash-tl-live" aria-label="now">
            <i />
          </span>
          {items.map((e, i) => {
            const meta = TIMELINE_TYPES.find((t) => t.type === e.type);
            return (
              <span
                key={i}
                data-type={e.type}
                className="dash-tl-marker"
                style={{ left: `${(e.hour / 24) * 100}%`, "--tl-c": meta?.color ?? "var(--accent)" } as CSSProperties}
                title={`${e.hour.toFixed(1).padStart(2, "0")}:00 — ${e.label}`}
              >
                <i />
                <b>{meta?.label}</b>
              </span>
            );
          })}
        </div>
        <div className="dash-timeline-axis">
          {HOURS.map((h) => (
            <span key={h} className="dash-timeline-hour" style={{ left: `${(h / 24) * 100}%` }}>
              {String(h).padStart(2, "0")}
            </span>
          ))}
        </div>
        <div className="dash-timeline-legend">
          {TIMELINE_TYPES.map((t) => (
            <div key={t.type} className="dash-timeline-legend-item">
              <span className="dash-tl-legend-sym" data-type={t.type} style={{ "--tl-c": t.color } as CSSProperties} />
              <span>{t.label}</span>
            </div>
          ))}
        </div>
      </div>
    </DashPanel>
  );
}
