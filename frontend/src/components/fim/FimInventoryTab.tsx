import { useMemo, useState } from "react";
import { Icon } from "../icons";
import { useAsync } from "../../hooks/useAsync";
import { fimFiles } from "../../api/endpoint";
import type { FimFileRow } from "../../api/endpoint";

type SortKey = "file" | "lastModified" | "user" | "size";
type SortDir = "asc" | "desc";

const SORTABLE: { key: SortKey; label: string }[] = [
  { key: "file", label: "File" },
  { key: "lastModified", label: "Last Modified" },
  { key: "user", label: "User" },
  { key: "size", label: "Size" },
];

function formatDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatSize(n: number): string {
  return n.toLocaleString();
}

function shortHash(hash?: string | null): string {
  if (!hash) return "—";
  return `${hash.slice(0, 12)}…${hash.slice(-8)}`;
}

export function FimInventoryTab({ agentCode }: { agentCode: string }) {
  const files = useAsync<FimFileRow[]>(() => fimFiles(agentCode), [agentCode], 60_000);
  const [section, setSection] = useState<"files" | "registry">("files");
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("file");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  const demo = files.data?.length ? files.data[0].demo : false;
  const fileCount = files.data?.length ?? 0;

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = (files.data ?? []).filter(
      (f) => !q || f.file.toLowerCase().includes(q) || f.user.toLowerCase().includes(q)
    );
    return [...filtered].sort((a, b) => {
      const va = a[sortKey];
      const vb = b[sortKey];
      const cmp = typeof va === "number" && typeof vb === "number" ? va - vb : String(va).localeCompare(String(vb));
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [files.data, query, sortKey, sortDir]);

  function toggleSort(key: SortKey) {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  }

  return (
    <div className="fim-body">
      <div className="fim-sections">
        <button
          type="button"
          className={`fim-section-link${section === "files" ? " fim-section-active" : ""}`}
          onClick={() => setSection("files")}
        >
          Files ({fileCount})
        </button>
        <button
          type="button"
          className={`fim-section-link${section === "registry" ? " fim-section-active" : ""}`}
          onClick={() => setSection("registry")}
        >
          Windows Registry (9699)
        </button>
        {demo ? (
          <span className="fim-demo-badge" title="Backend in FIM demo mode - showing deterministic demo data">
            Demo data
          </span>
        ) : null}
      </div>

      {section === "files" && (
        <>
          <div className="fim-card">
            <div className="fim-card-head">
              <div className="fim-card-title">Files ({fileCount})</div>
              <div className="fim-card-actions">
                <button type="button" className="fim-icon-btn" title="Refresh" onClick={() => files.reload()}>
                  <Icon name="refresh" size={15} />
                </button>
                <button type="button" className="fim-icon-btn" title="Export">
                  <Icon name="download" size={15} />
                </button>
                <button type="button" className="fim-icon-btn" title="Settings">
                  <Icon name="settings" size={15} />
                </button>
              </div>
            </div>

            <div className="fim-search">
              <Icon name="search" size={14} />
              <input
                className="fim-search-input"
                placeholder="Search…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <button type="button" className="fim-btn fim-btn-wql">
                WQL
              </button>
            </div>

            <div className="fim-table-wrap">
              <table className="fim-table fim-table-sticky">
                <thead>
                  <tr>
                    {SORTABLE.map((s) => (
                      <th key={s.key} onClick={() => toggleSort(s.key)}>
                        <span className="fim-th-inner">
                          {s.label}
                          {sortKey === s.key ? (
                            <span className="fim-sort-arrow">{sortDir === "asc" ? "▲" : "▼"}</span>
                          ) : null}
                        </span>
                      </th>
                    ))}
                    <th>User ID</th>
                    <th>SHA-256</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {files.status === "loading" ? (
                    <tr>
                      <td colSpan={7}>
                        <div className="fim-state">
                          <span className="spinner" />
                          <span>Loading files…</span>
                        </div>
                      </td>
                    </tr>
                  ) : files.status === "error" ? (
                    <tr>
                      <td colSpan={7}>
                        <div className="fim-state fim-state-error">
                          <Icon name="warn" size={16} />
                          <span>{files.error}</span>
                        </div>
                      </td>
                    </tr>
                  ) : rows.length === 0 ? (
                    <tr>
                      <td colSpan={7}>
                        <div className="fim-state">
                          <Icon name="search" size={16} />
                          <span>No files match your search</span>
                        </div>
                      </td>
                    </tr>
                  ) : (
                    rows.map((f) => (
                      <tr key={f.file}>
                        <td className="fim-td-file mono">{f.file}</td>
                        <td className="mono">{formatDate(f.lastModified)}</td>
                        <td>{f.user}</td>
                        <td className="mono">{f.userId}</td>
                        <td className="mono fim-td-size">{formatSize(f.size)}</td>
                        <td className="mono" title={f.sha256 ?? undefined}>
                          {shortHash(f.sha256)}
                        </td>
                        <td>
                          {f.status === "deleted" ? (
                            <span className="fim-status-badge fim-status-deleted">deleted</span>
                          ) : f.status ? (
                            <span className="fim-status-badge fim-status-active">active</span>
                          ) : (
                            <span className="fim-muted">—</span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div className="fim-pager">
              <span className="fim-pager-label">Rows per page: 15</span>
              <span className="fim-pager-nav">
                <span className="fim-page-btn fim-page-disabled">◀</span>
                <span className="fim-page-btn fim-page-active">1</span>
                <span className="fim-page-btn fim-page-disabled">▶</span>
              </span>
            </div>
          </div>
        </>
      )}

      {section === "registry" && (
        <div className="fim-card">
          <div className="fim-card-head">
            <div className="fim-card-title">Windows Registry (9699)</div>
            <div className="fim-card-actions">
              <button type="button" className="fim-icon-btn" title="Refresh">
                <Icon name="refresh" size={15} />
              </button>
              <button type="button" className="fim-icon-btn" title="Export">
                <Icon name="download" size={15} />
              </button>
              <button type="button" className="fim-icon-btn" title="Settings">
                <Icon name="settings" size={15} />
              </button>
            </div>
          </div>
          <div className="fim-state">
            <Icon name="database" size={18} />
            <span>Registry entries inventory is not enabled for this agent.</span>
          </div>
        </div>
      )}
    </div>
  );
}
