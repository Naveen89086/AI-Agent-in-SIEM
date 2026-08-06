import type { AttackEvent } from "../../mocks/soc";

const SEV_DOT: Record<string, string> = {
  critical: "var(--red)",
  high: "#ff7a59",
  medium: "var(--amber)",
  low: "var(--green)",
  informational: "var(--cyan)",
};

export function AttackTimeline({ events }: { events: AttackEvent[] }) {
  if (!events || events.length === 0) return null;
  return (
    <div className="soc-timeline">
      {events.map((event, i) => (
        <div key={i} className="soc-timeline-item">
          <div className="soc-timeline-rail">
            <span
              className="soc-timeline-dot"
              style={{ background: SEV_DOT[event.severity] ?? "var(--text-faint)" }}
            />
            {i < events.length - 1 ? <span className="soc-timeline-line" /> : null}
          </div>
          <div className="soc-timeline-body">
            <div className="soc-timeline-meta">
              <span className="mono soc-timeline-time">{event.time}</span>
              <span className="soc-timeline-tactic">{event.tactic}</span>
            </div>
            <div className="soc-timeline-title">{event.title}</div>
            <div className="soc-timeline-source mono">{event.source}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
