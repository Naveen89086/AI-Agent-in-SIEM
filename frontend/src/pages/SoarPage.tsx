import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { Playbook, SoarAction } from "../api/types";
import { formatTime } from "../components/format";
import { Card, Empty, Spinner } from "../components/ui";

function SoarPage() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [actions, setActions] = useState<SoarAction[]>([]);
  const [status, setStatus] = useState<{ destructive_actions_enabled: boolean; playbook_count: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [p, a, s] = await Promise.all([api.playbooks(), api.soarActions(50), api.soarStatus()]);
      setPlaybooks(p);
      setActions(a.items);
      setStatus(s);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load SOAR data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="grid grid-4">
        <div className="card kpi">
          <div className="kpi-label">Playbooks</div>
          <div className="kpi-value" style={{ color: "var(--accent)" }}>{playbooks.length}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label">Destructive actions</div>
          <div className="kpi-value" style={{ color: status?.destructive_actions_enabled ? "var(--red)" : "var(--green)" }}>
            {status?.destructive_actions_enabled ? "ENABLED" : "SAFE"}
          </div>
          <div className="kpi-sub">safety gate on block/isolate</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label">Actions (recent)</div>
          <div className="kpi-value" style={{ color: "var(--cyan)" }}>{actions.length}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label">Playbook count (API)</div>
          <div className="kpi-value" style={{ color: "var(--amber)" }}>{status?.playbook_count ?? 0}</div>
        </div>
      </div>

      <div className="grid grid-2">
        <Card title="Playbooks">
          {loading ? (
            <Spinner />
          ) : error ? (
            <Empty message={error} />
          ) : playbooks.length === 0 ? (
            <Empty message="No playbooks deployed" />
          ) : (
            playbooks.map((p) => (
              <div key={p.id} className="list-item">
                <div>
                  <div className="list-item-title">{p.name}</div>
                  <div className="list-item-sub">{p.description}</div>
                  <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 2 }}>
                    {p.actions.map((a) => a.type).join(" → ")}
                  </div>
                </div>
                <span
                  className="status-badge"
                  style={p.enabled ? { background: "rgba(49,208,126,0.12)", color: "var(--green)" } : undefined}
                >
                  {p.enabled ? "enabled" : "disabled"}
                </span>
              </div>
            ))
          )}
        </Card>

        <Card title="Recent actions">
          {loading ? (
            <Spinner />
          ) : actions.length === 0 ? (
            <Empty message="No automation actions recorded yet" />
          ) : (
            <div style={{ maxHeight: 460, overflow: "auto" }}>
              {actions.map((a) => (
                <div key={a.id} className="list-item">
                  <div>
                    <div className="list-item-title" style={{ fontSize: 13 }}>{a.playbook_name}</div>
                    <div className="list-item-sub mono">{a.action_type} · {a.target ?? "—"}</div>
                    <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 2 }}>{formatTime(a.created_at)}</div>
                  </div>
                  <span className={`status-badge${a.status === "completed" ? " true_positive" : ""}`}>{a.status}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

export default SoarPage;
