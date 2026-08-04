import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { Source } from "../api/types";
import { formatNumber, formatTime } from "../components/format";
import { Card, Empty, Spinner } from "../components/ui";

function SourcesPage() {
  const [sources, setSources] = useState<Source[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await api.sources();
      setSources(resp.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load sources");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const enabledCount = sources.filter((s) => s.enabled).length;
  const totalReceived = sources.reduce((acc, s) => acc + s.received_count, 0);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="grid grid-4">
        <div className="card kpi">
          <div className="kpi-label">Total sources</div>
          <div className="kpi-value" style={{ color: "var(--accent)" }}>{sources.length}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label">Enabled</div>
          <div className="kpi-value" style={{ color: "var(--green)" }}>{enabledCount}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label">Events received</div>
          <div className="kpi-value" style={{ color: "var(--cyan)" }}>{formatNumber(totalReceived)}</div>
        </div>
        <div className="card kpi">
          <div className="kpi-label">Formats</div>
          <div className="kpi-value">{new Set(sources.map((s) => s.format)).size}</div>
        </div>
      </div>

      <div className="card">
        {loading ? (
          <Spinner />
        ) : error ? (
          <Empty message={error} />
        ) : sources.length === 0 ? (
          <Empty message="No data sources configured" />
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Name</th>
                <th>Type</th>
                <th>Format</th>
                <th>Parser</th>
                <th>Host</th>
                <th>Received</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {sources.map((s) => (
                <tr key={s.id}>
                  <td>
                    <span
                      className="status-badge"
                      style={
                        s.enabled
                          ? { background: "rgba(49,208,126,0.12)", color: "var(--green)" }
                          : undefined
                      }
                    >
                      {s.enabled ? "enabled" : "disabled"}
                    </span>
                  </td>
                  <td style={{ fontWeight: 600 }}>{s.name}</td>
                  <td className="mono" style={{ color: "var(--accent)" }}>{s.source_type}</td>
                  <td className="mono">{s.format}</td>
                  <td className="mono">{s.parser ?? "—"}</td>
                  <td className="mono" style={{ color: "var(--text-dim)" }}>{s.host ?? "—"}</td>
                  <td className="mono">{formatNumber(s.received_count)}</td>
                  <td className="mono" style={{ fontSize: 12, color: "var(--text-dim)" }}>{formatTime(s.last_seen_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export default SourcesPage;
