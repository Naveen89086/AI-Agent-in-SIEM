import { useState } from "react";
import { Icon } from "../icons";

const DEFAULT_FILTERS = [
  { key: "manager.name", value: "kaliinux" },
  { key: "rule.groups", value: "syscheck" },
  { key: "agent.id", value: "001" },
];

export function FimSearchBar() {
  const [query, setQuery] = useState("");
  const [filters, setFilters] = useState(DEFAULT_FILTERS);

  function addFilter() {
    setFilters((prev) => [...prev, { key: "new field", value: "" }]);
  }

  function removeFilter(index: number) {
    setFilters((prev) => prev.filter((_, i) => i !== index));
  }

  return (
    <div className="fim-toolbar">
      <div className="fim-toolbar-row">
        <div className="fim-search">
          <Icon name="search" size={14} />
          <input
            className="fim-search-input"
            placeholder="Search…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <button type="button" className="fim-btn fim-btn-dql">
            DQL
          </button>
        </div>
        <div className="fim-toolbar-spacer" />
        <button type="button" className="fim-btn">
          <Icon name="bookmark" size={14} />
          Last 24 hours
        </button>
        <button type="button" className="fim-btn">
          <Icon name="refresh" size={14} />
          Refresh
        </button>
      </div>
      <div className="fim-filter-chips">
        {filters.map((f, i) => (
          <span key={`${f.key}-${i}`} className="fim-chip">
            <span className="fim-chip-key">{f.key}</span>
            {f.value ? (
              <>
                <span className="fim-chip-colon">:</span>
                <span className="fim-chip-value">{f.value}</span>
              </>
            ) : null}
            <button type="button" className="fim-chip-x" onClick={() => removeFilter(i)} aria-label="Remove filter">
              ×
            </button>
          </span>
        ))}
        <button type="button" className="fim-chip-add" onClick={addFilter}>
          <Icon name="plus" size={12} />
          Add filter
        </button>
      </div>
    </div>
  );
}
