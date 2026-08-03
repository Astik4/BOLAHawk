import { useMemo, useState } from "react";
import { groupFindings, owaspFor, contextLabel, fingerprint, SEVERITIES, SEVERITY_ORDER } from "../owasp";

function Copy({ text, onCopied }) {
  return (
    <button
      className="copy-btn"
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard?.writeText(text);
        onCopied?.();
      }}
    >
      copy
    </button>
  );
}

function Finding({ g, forceOpen, isNew, onCopied }) {
  const [override, setOverride] = useState(null);
  const open = override === null ? forceOpen : override;
  const owasp = owaspFor(g.check_id);

  return (
    <div className={`finding ${g.severity}`}>
      <button className="finding-head" onClick={() => setOverride(!open)} aria-expanded={open}>
        <span className={`sev ${g.severity}`}>{g.severity}</span>
        <span>
          <span className="f-title">{g.title}</span>
          <span className="f-sub">
            <span>{g.method} {g.endpoint}</span>
            <span>{g.contexts.map(contextLabel).join(", ")}</span>
          </span>
        </span>
        <span className="f-tags">
          {owasp.url ? (
            <a
              className="owasp-tag" href={owasp.url} target="_blank" rel="noreferrer"
              title={owasp.name} onClick={(e) => e.stopPropagation()}
            >
              {owasp.id}
            </a>
          ) : null}
          {g.occurrences.length > 1 && (
            <span className="count-tag" title="Times this same flaw was proven">
              ×{g.occurrences.length}
            </span>
          )}
          {isNew && <span className="new-tag">NEW</span>}
        </span>
        <span className="score">{g.cvss_score.toFixed(1)}</span>
        <span className={`chev ${open ? "open" : ""}`}>&#9656;</span>
      </button>

      {open && (
        <div className="finding-body">
          <div className="field">
            <div className="field-label">OWASP category</div>
            <div>{owasp.id} — {owasp.name}</div>
          </div>

          <div className="field">
            <div className="field-label">What the scanner saw</div>
            <div>{g.description}</div>
          </div>

          <div className="field">
            <div className="field-label">
              Evidence <Copy text={g.evidence} onCopied={onCopied} />
            </div>
            <div className="mono-block">{g.evidence}</div>
          </div>

          {g.occurrences.length > 1 && (
            <div className="field">
              <div className="field-label">Proven {g.occurrences.length} times</div>
              <div className="occ-list">
                {g.occurrences.map((o, i) => (
                  <span key={i} className="occ">
                    {contextLabel(o.auth_context)} → {o.method} {o.endpoint}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="field">
            <div className="field-label">How to fix it</div>
            <div>{g.remediation}</div>
          </div>

          <div className="field">
            <div className="field-label">
              CVSS v3.1 vector <Copy text={g.cvss_vector} onCopied={onCopied} />
            </div>
            <div className="mono-block">{g.cvss_vector}</div>
          </div>

          <div className="field">
            <div className="field-label">Detection module</div>
            <div className="mono-block">{g.check_id}</div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function FindingsTable({ findings, filter, onFilterChange, newKeys, onCopied }) {
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState("severity");
  const [expandAll, setExpandAll] = useState(false);
  const [grouped, setGrouped] = useState(true);

  const rows = useMemo(() => {
    const base = grouped
      ? groupFindings(findings)
      : findings.map((f) => ({ ...f, key: `${fingerprint(f)}|${f.auth_context}`, occurrences: [f], contexts: [f.auth_context] }));

    let list = filter === "All" ? base : base.filter((f) => f.severity === filter);

    const q = search.trim().toLowerCase();
    if (q) {
      list = list.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.endpoint.toLowerCase().includes(q) ||
          f.check_id.toLowerCase().includes(q) ||
          owaspFor(f.check_id).id.toLowerCase().includes(q)
      );
    }

    const sorted = [...list];
    if (sortBy === "severity")
      sorted.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.cvss_score - a.cvss_score);
    if (sortBy === "score") sorted.sort((a, b) => b.cvss_score - a.cvss_score);
    if (sortBy === "owasp") sorted.sort((a, b) => owaspFor(a.check_id).id.localeCompare(owaspFor(b.check_id).id));
    if (sortBy === "title") sorted.sort((a, b) => a.title.localeCompare(b.title));
    return sorted;
  }, [findings, filter, search, sortBy, grouped]);

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Findings — {rows.length} shown</h2>
        <div className="chips">
          {["All", ...SEVERITIES].map((s) => (
            <button key={s} className={`chip ${filter === s ? "on" : ""}`} onClick={() => onFilterChange(s)}>
              {s}
            </button>
          ))}
        </div>
      </div>

      <div className="toolbar">
        <input
          className="search-input"
          placeholder="Search by title, endpoint, module or OWASP ID"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search findings"
        />
        <select className="select" value={sortBy} onChange={(e) => setSortBy(e.target.value)} aria-label="Sort findings">
          <option value="severity">Sort: severity</option>
          <option value="score">Sort: CVSS score</option>
          <option value="owasp">Sort: OWASP category</option>
          <option value="title">Sort: title</option>
        </select>
        <button className={`btn ghost ${grouped ? "on" : ""}`} onClick={() => setGrouped(!grouped)}>
          {grouped ? "Grouped" : "Every occurrence"}
        </button>
        <button className="btn ghost" onClick={() => setExpandAll(!expandAll)}>
          {expandAll ? "Collapse all" : "Expand all"}
        </button>
      </div>

      {rows.length === 0 ? (
        <div className="empty">
          <strong>Nothing matches those filters</strong>
          Clear the search box or pick a different severity.
        </div>
      ) : (
        rows.map((g) => (
          <Finding
            key={g.key}
            g={g}
            forceOpen={expandAll}
            isNew={newKeys?.has(fingerprint(g))}
            onCopied={onCopied}
          />
        ))
      )}
    </div>
  );
}
