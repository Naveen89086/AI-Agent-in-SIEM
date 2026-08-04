export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`sev-badge ${severity ?? "informational"}`}>{severity ?? "unknown"}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  return <span className={`status-badge ${status ?? ""}`}>{status ?? "unknown"}</span>;
}

export function MitreTags({
  mitre,
}: {
  mitre?: { tactic?: string; technique?: string; technique_name?: string }[] | null;
}) {
  if (!mitre || mitre.length === 0) return <span className="mono" style={{ color: "var(--text-faint)" }}>—</span>;
  return (
    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
      {mitre.map((m, i) => (
        <span key={i} className="mono" style={{ color: "var(--purple)", fontSize: 11 }}>
          {m.tactic ? `${m.tactic} · ` : ""}
          {m.technique ? `T${m.technique}` : ""}
          {m.technique_name ? ` ${m.technique_name}` : ""}
        </span>
      ))}
    </div>
  );
}

export function TagList({ tags }: { tags?: string[] | null }) {
  if (!tags || tags.length === 0) return <span style={{ color: "var(--text-faint)" }}>—</span>;
  return (
    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
      {tags.map((t) => (
        <span
          key={t}
          className="mono"
          style={{ fontSize: 11, background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: 4, padding: "0 6px" }}
        >
          {t}
        </span>
      ))}
    </div>
  );
}
