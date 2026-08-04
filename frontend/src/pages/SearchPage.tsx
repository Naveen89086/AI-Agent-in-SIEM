import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api/client";
import type { SearchHit } from "../api/types";
import { formatNumber } from "../components/format";
import { Card, Empty, Spinner } from "../components/ui";

function eventTime(hit: SearchHit): string {
  const t = hit["@timestamp"];
  return typeof t === "string" ? new Date(t).toLocaleString() : "";
}

function eventSourceType(hit: SearchHit): string {
  return typeof hit.source_type === "string" ? hit.source_type : "";
}

function eventMessage(hit: SearchHit): string {
  const msg = hit.message;
  if (typeof msg === "string") return msg;
  const ev = hit.event;
  if (ev && typeof ev === "object" && "action" in ev) return JSON.stringify(ev.action);
  const host = hit.host;
  if (host && typeof host === "object" && "name" in host) return String(host.name);
  return JSON.stringify(hit).slice(0, 300);
}

function SearchPage() {
  const [q, setQ] = useState("");
  const [filters, setFilters] = useState("");
  const [results, setResults] = useState<SearchHit[]>([]);
  const [total, setTotal] = useState(0);
  const [took, setTook] = useState(0);
  const [histogram, setHistogram] = useState<{ key: string; count: number }[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runSearch = useCallback(async (offset = 0) => {
    setLoading(true);
    setError(null);
    try {
      const [resp, hist] = await Promise.all([
        api.search({ q: q || undefined, filters: filters || undefined, offset, limit: 50 }),
        api.searchHistogram(3600, q || undefined, filters || undefined),
      ]);
      setResults(resp.items);
      setTotal(resp.total);
      setTook(resp.took_ms);
      setHistogram(hist.buckets);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
    } finally {
      setLoading(false);
    }
  }, [q, filters]);

  useEffect(() => {
    runSearch(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    runSearch(0);
  }

  const pageCount = Math.ceil(total / 50);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <Card>
        <form className="search-bar" onSubmit={onSubmit}>
          <input
            className="input input-mono"
            placeholder="Search events…  e.g. ssh OR sudo OR 10.0.0.7"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <input
            className="input input-mono"
            style={{ width: 300 }}
            placeholder="filters: source_type:firewall,event.action:blocked"
            value={filters}
            onChange={(e) => setFilters(e.target.value)}
          />
          <button className="btn btn-primary" type="submit">
            Search
          </button>
        </form>
      </Card>

      <div className="grid grid-2">
        <Card title={`Results — ${formatNumber(total)} events`}>
          {took > 0 ? (
            <div className="mono" style={{ fontSize: 11, color: "var(--text-faint)", marginBottom: 8 }}>
              took {took}ms
            </div>
          ) : null}
          {loading ? (
            <Spinner />
          ) : error ? (
            <Empty message={error} />
          ) : results.length === 0 ? (
            <Empty message="No events matched" />
          ) : (
            <div style={{ maxHeight: 480, overflow: "auto" }}>
              {results.map((hit, i) => (
                <div key={i} style={{ padding: "8px 2px", borderBottom: "1px solid var(--border)" }}>
                  <div className="mono" style={{ fontSize: 11, color: "var(--text-dim)" }}>
                    {eventTime(hit)} · {eventSourceType(hit) || "event"}
                  </div>
                  <div style={{ fontSize: 13, fontFamily: "var(--font-mono)" }}>{eventMessage(hit)}</div>
                </div>
              ))}
              {pageCount > 1 && (
                <div style={{ display: "flex", gap: 8, justifyContent: "center", paddingTop: 10 }}>
                  <button className="btn btn-sm" disabled={loading} onClick={() => runSearch(0)}>Reset</button>
                </div>
              )}
            </div>
          )}
        </Card>

        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <Card title="Event timeline (hourly)">
            <div style={{ height: 220 }}>
              <ResponsiveContainer>
                <BarChart data={histogram}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                  <XAxis dataKey="key" tick={{ fill: "var(--text-faint)", fontSize: 11 }} />
                  <YAxis tick={{ fill: "var(--text-faint)", fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 6 }}
                    labelStyle={{ color: "var(--text-dim)" }}
                  />
                  <Bar dataKey="count" name="Events" fill="var(--cyan)" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
          <Card title="Top source types">
            <Aggregations q={q} filters={filters} />
          </Card>
        </div>
      </div>
    </div>
  );
}

function Aggregations({ q, filters }: { q: string; filters: string }) {
  const [buckets, setBuckets] = useState<{ key: string; count: number }[]>([]);
  useEffect(() => {
    api.searchAggregate("source_type", q || undefined)
      .then((resp) => setBuckets(resp.buckets))
      .catch(() => {});
  }, [q, filters]);
  if (buckets.length === 0) return <Empty message="No aggregation data" />;
  return (
    <div>
      {buckets.map((b) => (
        <div key={b.key} className="list-item">
          <span className="mono">{b.key}</span>
          <span className="mono" style={{ fontWeight: 600 }}>{formatNumber(b.count)}</span>
        </div>
      ))}
    </div>
  );
}

export default SearchPage;
