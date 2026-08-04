import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { Case, CaseArtifact, CaseNote, TimelineEntry } from "../api/types";
import { SeverityBadge, StatusBadge, TagList } from "../components/Badges";
import { formatTime } from "../components/format";
import { Card, Empty, Spinner } from "../components/ui";

const CASE_STATUSES = ["open", "in_progress", "resolved", "closed"];
const ARTIFACT_TYPES = ["ip", "domain", "url", "hash", "hostname", "email", "file", "other"];

function CasesPage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [total, setTotal] = useState(0);
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Case | null>(null);
  const [notes, setNotes] = useState<CaseNote[]>([]);
  const [artifacts, setArtifacts] = useState<CaseArtifact[]>([]);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [tab, setTab] = useState<"overview" | "notes" | "artifacts" | "timeline">("overview");
  const [newNote, setNewNote] = useState("");
  const [newArtifactType, setNewArtifactType] = useState("ip");
  const [newArtifactValue, setNewArtifactValue] = useState("");
  const [newTitle, setNewTitle] = useState("");
  const [newSeverity, setNewSeverity] = useState("high");
  const [creating, setCreating] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadList = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await api.cases({ status: status || undefined, offset, limit: 50 });
      setCases(resp.items);
      setTotal(resp.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load cases");
    } finally {
      setLoading(false);
    }
  }, [status, offset]);

  useEffect(() => {
    loadList();
  }, [loadList]);

  const loadDetail = useCallback(async (id: string) => {
    setSelectedId(id);
    try {
      const [c, n, a, t] = await Promise.all([
        api.caseDetail(id),
        api.caseNotes(id),
        api.caseArtifacts(id),
        api.caseTimeline(id),
      ]);
      setDetail(c);
      setNotes(n);
      setArtifacts(a);
      setTimeline(t);
      setTab("overview");
    } catch {
      /* ignore */
    }
  }, []);

  async function createCase() {
    if (!newTitle.trim()) return;
    setCreating(true);
    try {
      const created = await api.createCase({ title: newTitle.trim(), severity: newSeverity });
      setNewTitle("");
      await loadList();
      await loadDetail(created.id);
    } catch {
      /* ignore */
    } finally {
      setCreating(false);
    }
  }

  async function addNote() {
    if (!selectedId || !newNote.trim()) return;
    try {
      await api.addCaseNote(selectedId, newNote.trim());
      setNewNote("");
      setNotes(await api.caseNotes(selectedId));
      setTimeline(await api.caseTimeline(selectedId));
    } catch {
      /* ignore */
    }
  }

  async function addArtifact() {
    if (!selectedId || !newArtifactValue.trim()) return;
    try {
      await api.addCaseArtifact(selectedId, { artifact_type: newArtifactType, value: newArtifactValue.trim() });
      setNewArtifactValue("");
      setArtifacts(await api.caseArtifacts(selectedId));
      setTimeline(await api.caseTimeline(selectedId));
    } catch {
      /* ignore */
    }
  }

  async function updateCaseStatus(id: string, next: string) {
    try {
      const updated = await api.updateCase(id, { status: next });
      setDetail(updated);
      await loadList();
    } catch {
      /* ignore */
    }
  }

  const pageCount = Math.ceil(total / 50);

  return (
    <div style={{ display: "flex", gap: 16, height: "calc(100vh - 110px)" }}>
      <div style={{ flex: 3, display: "flex", flexDirection: "column", gap: 14, overflow: "hidden" }}>
        <div className="card">
          <div className="toolbar" style={{ marginBottom: 0 }}>
            <select className="select" style={{ width: 170 }} value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }}>
              <option value="">All statuses</option>
              {CASE_STATUSES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <input className="input" style={{ width: 220 }} placeholder="New case title…" value={newTitle} onChange={(e) => setNewTitle(e.target.value)} />
            <select className="select" style={{ width: 130 }} value={newSeverity} onChange={(e) => setNewSeverity(e.target.value)}>
              {["critical", "high", "medium", "low", "informational"].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
            <button className="btn btn-primary btn-sm" onClick={createCase} disabled={creating || !newTitle.trim()}>
              {creating ? <span className="spinner" /> : "+"} New Case
            </button>
            <span className="mono" style={{ color: "var(--text-dim)", marginLeft: "auto" }}>{total} cases</span>
          </div>
        </div>

        <div className="card" style={{ flex: 1, overflow: "auto" }}>
          {loading ? (
            <Spinner />
          ) : error ? (
            <Empty message={error} />
          ) : cases.length === 0 ? (
            <Empty message="No cases yet" />
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Title</th>
                  <th>Status</th>
                  <th>Assignee</th>
                  <th>Opened</th>
                </tr>
              </thead>
              <tbody>
                {cases.map((c) => (
                  <tr key={c.id} className="clickable" style={selectedId === c.id ? { background: "var(--bg-elevated)" } : undefined} onClick={() => loadDetail(c.id)}>
                    <td><SeverityBadge severity={c.severity} /></td>
                    <td style={{ maxWidth: 320 }}>
                      <div style={{ fontWeight: 600 }}>{c.title}</div>
                      <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)" }}>{c.id.slice(0, 13)}…</div>
                    </td>
                    <td><StatusBadge status={c.status} /></td>
                    <td>{c.assignee ?? "—"}</td>
                    <td className="mono" style={{ color: "var(--text-dim)", fontSize: 12 }}>{formatTime(c.opened_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {pageCount > 1 && !loading && (
            <div style={{ display: "flex", gap: 8, justifyContent: "center", padding: 12 }}>
              <button className="btn btn-sm" disabled={offset === 0} onClick={() => setOffset((o) => Math.max(0, o - 50))}>Prev</button>
              <span className="mono" style={{ color: "var(--text-dim)", alignSelf: "center" }}>page {Math.floor(offset / 50) + 1} / {pageCount}</span>
              <button className="btn btn-sm" disabled={offset + 50 >= total} onClick={() => setOffset((o) => o + 50)}>Next</button>
            </div>
          )}
        </div>
      </div>

      <div style={{ flex: 2, overflow: "auto" }}>
        <Card title={detail ? detail.title : "Case details"}>
          {!detail ? (
            <Empty message="Select a case to view details" />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <SeverityBadge severity={detail.severity} />
                <select
                  className="select"
                  style={{ width: 130 }}
                  value={detail.status}
                  onChange={(e) => updateCaseStatus(detail.id, e.target.value)}
                >
                  {CASE_STATUSES.map((s) => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
                <span className="mono" style={{ color: "var(--text-faint)", fontSize: 12 }}>opened {formatTime(detail.opened_at)}</span>
              </div>

              {detail.description ? <div style={{ fontSize: 13, color: "var(--text-dim)" }}>{detail.description}</div> : null}
              <TagList tags={detail.tags} />

              <div className="tabs">
                <button className={`tab${tab === "overview" ? " active" : ""}`} onClick={() => setTab("overview")}>Overview</button>
                <button className={`tab${tab === "notes" ? " active" : ""}`} onClick={() => setTab("notes")}>Notes ({notes.length})</button>
                <button className={`tab${tab === "artifacts" ? " active" : ""}`} onClick={() => setTab("artifacts")}>Artifacts ({artifacts.length})</button>
                <button className={`tab${tab === "timeline" ? " active" : ""}`} onClick={() => setTab("timeline")}>Timeline</button>
              </div>

              {tab === "overview" && (
                <div>
                  {detail.alert_ids && detail.alert_ids.length > 0 ? (
                    <div>
                      <div className="card-title">Linked alerts</div>
                      {detail.alert_ids.map((id) => (
                        <div key={id} className="mono" style={{ fontSize: 12, color: "var(--accent)" }}>{id}</div>
                      ))}
                    </div>
                  ) : null}
                </div>
              )}

              {tab === "notes" && (
                <div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {notes.length === 0 ? <Empty message="No notes yet" /> : notes.map((n) => (
                      <div key={n.id} style={{ background: "var(--bg-input)", border: "1px solid var(--border)", borderRadius: 6, padding: 10 }}>
                        <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)", marginBottom: 4 }}>
                          {n.author} · {formatTime(n.created_at)}
                        </div>
                        <div style={{ fontSize: 13 }}>{n.content}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                    <textarea className="textarea" placeholder="Add a note…" value={newNote} onChange={(e) => setNewNote(e.target.value)} />
                    <button className="btn btn-primary btn-sm" onClick={addNote}>Add</button>
                  </div>
                </div>
              )}

              {tab === "artifacts" && (
                <div>
                  <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
                    <select className="select" style={{ width: 120 }} value={newArtifactType} onChange={(e) => setNewArtifactType(e.target.value)}>
                      {ARTIFACT_TYPES.map((t) => (
                        <option key={t} value={t}>{t}</option>
                      ))}
                    </select>
                    <input className="input input-mono" placeholder="value (IP, domain, hash…)" value={newArtifactValue} onChange={(e) => setNewArtifactValue(e.target.value)} />
                    <button className="btn btn-primary btn-sm" onClick={addArtifact}>Add</button>
                  </div>
                  {artifacts.length === 0 ? (
                    <Empty message="No artifacts yet" />
                  ) : (
                    <table className="table">
                      <thead>
                        <tr><th>Type</th><th>Value</th><th>Added</th></tr>
                      </thead>
                      <tbody>
                        {artifacts.map((a) => (
                          <tr key={a.id}>
                            <td className="mono" style={{ color: "var(--accent)" }}>{a.artifact_type}</td>
                            <td className="mono">{a.value}</td>
                            <td className="mono" style={{ fontSize: 12, color: "var(--text-dim)" }}>{formatTime(a.created_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {tab === "timeline" && (
                <div>
                  {timeline.length === 0 ? (
                    <Empty message="No timeline entries" />
                  ) : (
                    timeline.map((e, i) => (
                      <div key={i} style={{ display: "flex", gap: 10, padding: "6px 0", borderBottom: "1px solid var(--border)" }}>
                        <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)", minWidth: 140 }}>{formatTime(e.at)}</div>
                        <div>
                          <div className="mono" style={{ fontSize: 12, color: "var(--accent)", textTransform: "uppercase", letterSpacing: 0.5 }}>{e.type}</div>
                          <div style={{ fontSize: 13 }}>{e.title}</div>
                          {e.detail ? <div style={{ fontSize: 12, color: "var(--text-dim)" }}>{e.detail}</div> : null}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

export default CasesPage;
