import { useMemo, useState } from "react";

const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, None: 4 };

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="copy-btn"
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
    >
      {copied ? "copied" : "copy"}
    </button>
  );
}

function FindingCard({ f, forceOpen }) {
  const [openOverride, setOpenOverride] = useState(null);
  const open = openOverride === null ? forceOpen : openOverride;

  return (
    <div className={`finding-card ${f.severity}`}>
      <div className="finding-row" onClick={() => setOpenOverride(!open)}>
        <span className={`sev-badge ${f.severity}`}>{f.severity}</span>
        <span className="finding-title">{f.title}</span>
        <span className="finding-endpoint">{f.method} {f.endpoint} <em>({f.auth_context})</em></span>
        <span className="finding-score">{f.cvss_score.toFixed(1)}</span>
        <span className={`chevron ${open ? "open" : ""}`}>&#9656;</span>
      </div>
      {open && (
        <div className="finding-detail">
          <div className="field-label">Check</div>
          <div>{f.check_id}</div>

          <div className="field-label">Description</div>
          <div>{f.description}</div>

          <div className="field-label">Evidence <CopyButton text={f.evidence} /></div>
          <code>{f.evidence}</code>

          <div className="field-label">Remediation</div>
          <div>{f.remediation}</div>

          <div className="field-label">CVSS Vector <CopyButton text={f.cvss_vector} /></div>
          <code>{f.cvss_vector}</code>
        </div>
      )}
    </div>
  );
}

export default function FindingsTable({ findings, filter, onFilterChange }) {
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("severity"); // severity | score | title
  const [expandAll, setExpandAll] = useState(false);
  const severities = ["All", "Critical", "High", "Medium", "Low"];

  const visible = useMemo(() => {
    let list = filter === "All" ? findings : findings.filter((f) => f.severity === filter);
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.endpoint.toLowerCase().includes(q) ||
          f.check_id.toLowerCase().includes(q)
      );
    }
    const sorted = [...list];
    if (sortBy === "severity") sorted.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.cvss_score - a.cvss_score);
    if (sortBy === "score") sorted.sort((a, b) => b.cvss_score - a.cvss_score);
    if (sortBy === "title") sorted.sort((a, b) => a.title.localeCompare(b.title));
    return sorted;
  }, [findings, filter, search, sortBy]);

  return (
    <div className="findings-section">
      <h2>
        Findings ({visible.length})
        <span style={{ float: "right", display: "flex", gap: 6, alignItems: "center" }}>
          {severities.map((s) => (
            <button
              key={s}
              className="btn secondary"
              style={{
                padding: "4px 10px",
                fontSize: 11,
                borderColor: filter === s ? "var(--accent)" : "var(--border)",
                color: filter === s ? "var(--accent)" : "var(--muted)",
              }}
              onClick={() => onFilterChange(s)}
            >
              {s}
            </button>
          ))}
        </span>
      </h2>

      <div className="findings-toolbar">
        <input
          className="search-input"
          placeholder="search title, endpoint, check id…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select className="sort-select" value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
          <option value="severity">Sort: Severity</option>
          <option value="score">Sort: CVSS Score</option>
          <option value="title">Sort: Title</option>
        </select>
        <button className="btn secondary" style={{ padding: "7px 12px", fontSize: 11 }} onClick={() => setExpandAll(!expandAll)}>
          {expandAll ? "Collapse all" : "Expand all"}
        </button>
      </div>

      {visible.length === 0 ? (
        <div className="empty-state">No findings match this filter/search.</div>
      ) : (
        visible.map((f, i) => <FindingCard key={i} f={f} forceOpen={expandAll} />)
      )}
    </div>
  );
}
