import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import { Card, Empty, Spinner } from "../components/ui";

interface Template {
  id: string;
  name: string;
  description: string;
  framework: string;
}

function ReportsPage() {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setTemplates(await api.reportTemplates());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load report templates");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function generate(template: string, format: "html" | "pdf") {
    try {
      const resp = await api.generateReport(template, format);
      if (!resp.ok) throw new Error(`Report generation failed (${resp.status})`);
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `report-${template}.${format === "html" ? "html" : "pdf"}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate report");
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="card">
        <div className="card-title">Report templates</div>
        {loading ? (
          <Spinner />
        ) : error ? (
          <Empty message={error} />
        ) : templates.length === 0 ? (
          <Empty message="No report templates available" />
        ) : (
          templates.map((t) => (
            <div key={t.id} className="list-item">
              <div>
                <div className="list-item-title">
                  {t.name} <span className="mono" style={{ fontSize: 11, color: "var(--purple)", marginLeft: 6 }}>{t.framework}</span>
                </div>
                <div className="list-item-sub">{t.description}</div>
                <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)", marginTop: 2 }}>{t.id}</div>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn btn-sm" onClick={() => generate(t.id, "html")}>HTML</button>
                <button className="btn btn-sm btn-primary" onClick={() => generate(t.id, "pdf")}>PDF</button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default ReportsPage;
