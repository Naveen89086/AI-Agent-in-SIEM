import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Icon } from "../icons";
import { useAsync } from "../../hooks/useAsync";
import { fimEvents, fimTimeline } from "../../api/endpoint";
import type { FimEventRow, FimTimelinePoint } from "../../api/endpoint";
import { pageWindow } from "../../utils/pagination";
import { FimSearchBar } from "./FimSearchBar";

const PAGE_SIZES = [10, 15, 25, 50];

function formatEventTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const base = d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  return `${base}.${String(d.getMilliseconds()).padStart(3, "0")}`;
}

function formatRangeTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${d.toLocaleDateString(undefined, { month: "short", day: "2-digit", year: "numeric" })} @ ${hh}:${mm}:${ss}.${ms}`;
}

function EventBadge({ event, eventType }: { event: FimEventRow["event"]; eventType?: string }) {
  const kind = eventType ?? event;
  return <span className={`fim-event-badge fim-event-${kind}`}>{kind}</span>;
}

function LevelBadge({ level }: { level: number }) {
  const tone = level >= 6 ? "high" : level >= 5 ? "mid" : "low";
  return <span className={`fim-level fim-level-${tone}`}>{level}</span>;
}

function SeverityBadge({ severity }: { severity?: string | null }) {
  if (!severity) return <span className="fim-muted">—</span>;
  return <span className={`fim-sev fim-sev-${severity}`}>{severity}</span>;
}

function shortHash(hash?: string | null): string {
  if (!hash) return "—";
  return `${hash.slice(0, 12)}…${hash.slice(-8)}`;
}

function HashRow({ label, hash }: { label: string; hash?: string | null }) {
  return (
    <div className="fim-hash-row">
      <span className="fim-hash-label">{label}</span>
      <code className="mono fim-hash-value" title={hash ?? undefined}>
        {shortHash(hash)}
      </code>
    </div>
  );
}

function EventDetail({ row }: { row: FimEventRow }) {
  const isRenamed = (row.eventType ?? row.event) === "renamed";
  return (
    <div className="fim-event-detail">
      <div className="fim-event-detail-grid">
        <div>
          <div className="fim-detail-label">Syscheck Path</div>
          <div className="mono fim-detail-path" title={row.path}>
            {row.path}
          </div>
          {isRenamed && row.oldPath ? (
            <>
              <div className="fim-detail-label">Previous Path</div>
              <div className="mono fim-detail-path" title={row.oldPath}>
                {row.oldPath}
              </div>
            </>
          ) : null}
        </div>
        <div>
          <div className="fim-detail-label">Integrity (SHA-256)</div>
          {isRenamed || row.oldSha256 ? (
            <>
              <HashRow label="OLD" hash={row.oldSha256 ?? row.sha256} />
              <HashRow label="NEW" hash={row.newSha256 ?? row.sha256} />
            </>
          ) : (
            <HashRow label="CURRENT" hash={row.sha256} />
          )}
          <div className="fim-detail-label fim-detail-meta">
            Severity: <SeverityBadge severity={row.severity} /> · Level {row.level} ·{" "}
            {row.ruleId} · {row.demo ? "demo data" : "real agent evidence"}
          </div>
        </div>
      </div>
    </div>
  );
}

export function FimEventsTab({ agentCode }: { agentCode: string }) {
  const [showDates, setShowDates] = useState(false);
  const [search, setSearch] = useState("");
  const [debounced, setDebounced] = useState("");
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(15);
  const [expanded, setExpanded] = useState<string | null>(null);

  const timeline = useAsync<FimTimelinePoint[]>(() => fimTimeline(24, 30, agentCode), [agentCode], 60_000);
  const events = useAsync(
    () => fimEvents(page, perPage, debounced, agentCode),
    [page, perPage, debounced, agentCode],
    60_000
  );

  useEffect(() => {
    const t = setTimeout(() => setDebounced(search), 300);
    return () => clearTimeout(t);
  }, [search]);

  useEffect(() => {
    setPage(1);
  }, [debounced, perPage]);

  const chartData = (timeline.data ?? []).map((p) => ({
    ...p,
    label: showDates ? `${p.label < "12:00" ? "Aug 7" : "Aug 6"} ${p.label}` : p.label,
  }));

  const rows: FimEventRow[] = events.data?.items ?? [];
  const total = events.data?.total ?? 0;
  const totalPages = events.data?.totalPages ?? 1;
  const startRow = total === 0 ? 0 : (page - 1) * perPage + 1;
  const endRow = Math.min(page * perPage, total);

  const rangeFrom = chartData[0]?.label ?? "—";
  const rangeTo = chartData[chartData.length - 1]?.label ?? "—";

  return (
    <div className="fim-body">
      <FimSearchBar />

      <div className="fim-card">
        <div className="fim-card-head">
          <div className="fim-card-title">Event Timeline (Bar Chart)</div>
          <button type="button" className="fim-link" onClick={() => setShowDates((s) => !s)}>
            <span className="fim-link-dot" />
            Show dates
          </button>
        </div>
        <div className="fim-timeline">
          {timeline.status === "loading" ? (
            <div className="fim-state">
              <span className="spinner" />
              <span>Loading timeline…</span>
            </div>
          ) : timeline.status === "error" ? (
            <div className="fim-state fim-state-error">
              <Icon name="warn" size={16} />
              <span>{timeline.error}</span>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={chartData} margin={{ top: 8, right: 8, bottom: 0, left: -14 }} barCategoryGap="20%">
                <CartesianGrid stroke="#eef2f6" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="label"
                  interval="preserveStartEnd"
                  minTickGap={24}
                  tick={{ fontSize: 11, fill: "#6b7280" }}
                  tickLine={false}
                  axisLine={{ stroke: "#e5e7eb" }}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fontSize: 11, fill: "#6b7280" }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "#fff",
                    border: "1px solid #e5e7eb",
                    borderRadius: 8,
                    fontSize: 12,
                    boxShadow: "0 2px 6px rgba(0,0,0,0.06)",
                  }}
                  itemStyle={{ color: "#1f2937" }}
                />
                <Bar dataKey="deleted" name="deleted" fill="#E53935" radius={[2, 2, 0, 0]} />
                <Bar dataKey="added" name="added" fill="#1976D2" radius={[2, 2, 0, 0]} />
                <Bar dataKey="modified" name="modified" fill="#FB8C00" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="fim-hits">
        <div className="fim-hits-count">{total} Hits</div>
        <div className="fim-hits-range mono">{rangeFrom} → {rangeTo}</div>
        {events.data?.demo ? (
          <span className="fim-demo-badge" title="Backend in FIM demo mode - showing deterministic demo data">
            Demo data
          </span>
        ) : null}
      </div>

      <div className="fim-card">
        <div className="fim-table-toolbar">
          <button type="button" className="fim-btn">
            <Icon name="download" size={13} />
            Export
          </button>
          <button type="button" className="fim-btn" onClick={() => { setSearch(""); setPage(1); }}>
            Reset View
          </button>
          <button type="button" className="fim-btn">754 Available Fields</button>
          <button type="button" className="fim-btn">
            Columns
            <Icon name="chevron" size={11} />
          </button>
          <button type="button" className="fim-btn">
            Density
            <Icon name="chevron" size={11} />
          </button>
          <button type="button" className="fim-btn">1 Field Sorted</button>
          <div className="fim-table-toolbar-spacer" />
          <button type="button" className="fim-btn">Full Screen</button>
        </div>

        <div className="fim-table-wrap">
          <table className="fim-table fim-table-sticky">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Agent Name</th>
                <th>Syscheck Path</th>
                <th>Event</th>
                <th>Rule Description</th>
                <th>Level</th>
                <th>Rule ID</th>
              </tr>
            </thead>
            <tbody>
              {events.status === "loading" ? (
                <tr>
                  <td colSpan={7}>
                    <div className="fim-state">
                      <span className="spinner" />
                      <span>Loading events…</span>
                    </div>
                  </td>
                </tr>
              ) : events.status === "error" ? (
                <tr>
                  <td colSpan={7}>
                    <div className="fim-state fim-state-error">
                      <Icon name="warn" size={16} />
                      <span>{events.error}</span>
                    </div>
                  </td>
                </tr>
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={7}>
                    <div className="fim-state">
                      <Icon name="search" size={16} />
                      <span>No events match your search</span>
                    </div>
                  </td>
                </tr>
              ) : (
                rows.flatMap((e) => {
                  const detailOpen = expanded === e.timestamp;
                  const row = (
                    <tr
                      key={e.timestamp}
                      className={`fim-event-row${detailOpen ? " fim-event-row-open" : ""}`}
                      onClick={() => setExpanded(detailOpen ? null : e.timestamp)}
                    >
                      <td className="mono fim-td-ts">{formatEventTime(e.timestamp)}</td>
                      <td>{e.agent}</td>
                      <td className="mono fim-td-path" title={e.path}>
                        {e.path}
                      </td>
                      <td>
                        <EventBadge event={e.event} eventType={e.eventType} />
                      </td>
                      <td>{e.rule}</td>
                      <td>
                        <LevelBadge level={e.level} />
                      </td>
                      <td className="mono">{e.ruleId}</td>
                    </tr>
                  );
                  return detailOpen
                    ? [
                        row,
                        <tr key={`${e.timestamp}-detail`}>
                          <td colSpan={7}>
                            <EventDetail row={e} />
                          </td>
                        </tr>,
                      ]
                    : [row];
                })
              )}
            </tbody>
          </table>
        </div>

        <div className="fim-pager">
          <div className="fim-pager-size">
            <span className="fim-pager-label">Rows per page:</span>
            <select
              className="fim-select"
              value={perPage}
              onChange={(e) => setPerPage(Number(e.target.value))}
            >
              {PAGE_SIZES.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
            <span className="fim-pager-count mono">
              {startRow}–{endRow} of {total}
            </span>
          </div>
          <div className="fim-pager-nav">
            <button
              type="button"
              className="fim-page-btn"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              aria-label="Previous page"
            >
              ◀
            </button>
            {pageWindow(page, totalPages).map((p, i) =>
              p === "…" ? (
                <span key={`e${i}`} className="fim-page-ellipsis">
                  …
                </span>
              ) : (
                <button
                  type="button"
                  key={p}
                  className={`fim-page-btn${p === page ? " fim-page-active" : ""}`}
                  onClick={() => setPage(p)}
                >
                  {p}
                </button>
              )
            )}
            <button
              type="button"
              className="fim-page-btn"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              aria-label="Next page"
            >
              ▶
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
